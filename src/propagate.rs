//! Pushing what a container passes down into what is already inside it
//! (PCDS §5.6, Re-propagation), for a program that holds a tree of things
//! with descriptors: a folder's files, a registry key's subkeys.
//!
//! The program says how to get about its tree ([`Tree`]); [`walk`] does
//! the rest, the same for every kind of tree: parents first, each item
//! re-propagated from its parent as just rewritten through libpeios'
//! `reinherit_with`, a list an item protects left as it is, a failure
//! noted and the walk carried on past it.

use std::sync::atomic::{AtomicBool, Ordering};

use peios::file::SecInfo;
use peios::security::{Control, GenericMapping, SdView, reinherit_with};

use crate::{Failure, Generic, Part, Walked};

/// A tree of things with descriptors, as the program holding it gets
/// about it.
pub trait Tree {
    type Node: Clone;

    /// What is directly inside `node`.
    fn children(&mut self, node: &Self::Node) -> Result<Vec<Self::Node>, String>;

    /// What `node` is called where the person knows it, for progress and
    /// failures: `/srv/finance/q3.xlsx`.
    fn name(&self, node: &Self::Node) -> String;

    /// Whether `node` is a container, which things inherit from.
    fn container(&self, node: &Self::Node) -> bool;

    /// The parts of `node`'s descriptor `info` asks for.
    fn read(&mut self, node: &Self::Node, info: SecInfo) -> Result<Vec<u8>, String>;

    /// Applies the parts of `sd` that `info` names to `node`.
    fn write(&mut self, node: &Self::Node, sd: &[u8], info: SecInfo) -> Result<(), String>;
}

/// Which lists `parts` re-propagates: as they are read and written, and as
/// libpeios is asked to work them out. The integrity label alone is read
/// and written as the label, and worked out as a SACL holding only it.
fn lists(parts: &[Part]) -> (SecInfo, SecInfo) {
    let mut io = SecInfo::empty();
    let mut work = SecInfo::empty();
    if parts.contains(&Part::Dacl) {
        io |= SecInfo::DACL;
        work |= SecInfo::DACL;
    }
    if parts.contains(&Part::Sacl) {
        io |= SecInfo::SACL;
        work |= SecInfo::SACL;
    } else if parts.contains(&Part::Label) {
        io |= SecInfo::LABEL;
        work |= SecInfo::SACL;
    }
    (io, work)
}

/// Pushes what `root` passes down, in the lists `parts` names, into
/// everything inside it, `generic` being the mapping of the things in the
/// tree. Says how far it has got as each item is done, and stops after the
/// item in hand once `stop` is set.
pub fn walk<T: Tree>(tree: &mut T, root: &T::Node, parts: &[Part], generic: Generic, stop: &AtomicBool, progress: &mut dyn FnMut(u64, &str)) -> Walked {
    let mut out = Walked::default();
    let (io, work) = lists(parts);
    if io.is_empty() {
        return out;
    }
    let mapping = GenericMapping::new(generic.read, generic.write, generic.execute, generic.all);
    let root_sd = match tree.read(root, io | SecInfo::OWNER | SecInfo::GROUP) {
        Ok(sd) => sd,
        Err(why) => {
            out.failed.push(Failure { name: tree.name(root), why });
            return out;
        }
    };
    // Containers whose insides are still to be done, with their
    // descriptors as they are now.
    let mut todo = vec![(root.clone(), root_sd)];
    while let Some((node, sd)) = todo.pop() {
        let inside = match tree.children(&node) {
            Ok(inside) => inside,
            Err(why) => {
                out.failed.push(Failure { name: tree.name(&node), why: format!("what is inside could not be listed: {why}") });
                continue;
            }
        };
        for item in inside {
            if stop.load(Ordering::Relaxed) {
                out.stopped = true;
                return out;
            }
            let name = tree.name(&item);
            match one(tree, &item, &sd, io, work, &mapping) {
                Ok(now) => {
                    out.done += 1;
                    progress(out.done, &name);
                    if tree.container(&item) {
                        todo.push((item, now));
                    }
                }
                // What is inside one that could not be done is left: it
                // would be worked out from what that one passes down now.
                Err(why) => out.failed.push(Failure { name, why }),
            }
        }
    }
    out
}

/// Re-propagates one item from its parent's descriptor `parent`, and gives
/// its descriptor as it is afterwards.
fn one<T: Tree>(tree: &mut T, item: &T::Node, parent: &[u8], io: SecInfo, work: SecInfo, mapping: &GenericMapping) -> Result<Vec<u8>, String> {
    // The owner and group too, which CREATOR OWNER and CREATOR GROUP
    // resolve to.
    let sd = tree.read(item, io | SecInfo::OWNER | SecInfo::GROUP)?;
    let control = SdView::parse(&sd).map_err(|e| format!("its descriptor could not be read ({e})"))?.control();
    let (mut io, mut work) = (io, work);
    if control.contains(Control::DACL_PROTECTED) {
        io.remove(SecInfo::DACL);
        work.remove(SecInfo::DACL);
    }
    if control.contains(Control::SACL_PROTECTED) {
        io.remove(SecInfo::SACL | SecInfo::LABEL);
        work.remove(SecInfo::SACL);
    }
    if io.is_empty() {
        return Ok(sd);
    }
    let new = reinherit_with(parent, &sd, tree.container(item), Some(mapping), work).map_err(|e| format!("what it inherits could not be worked out ({e})"))?;
    tree.write(item, new.as_bytes(), io)?;
    Ok(new.as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use peios::security::sddl;
    use std::collections::HashMap;

    /// A tree held in memory: each item's descriptor as SDDL, and what is
    /// inside it.
    struct Mem {
        sd: HashMap<String, Vec<u8>>,
        inside: HashMap<String, Vec<String>>,
        refuse: Option<String>,
        written: Vec<String>,
    }

    impl Tree for Mem {
        type Node = String;
        fn children(&mut self, node: &String) -> Result<Vec<String>, String> {
            Ok(self.inside.get(node).cloned().unwrap_or_default())
        }
        fn name(&self, node: &String) -> String {
            node.clone()
        }
        fn container(&self, node: &String) -> bool {
            self.inside.contains_key(node)
        }
        fn read(&mut self, node: &String, _: SecInfo) -> Result<Vec<u8>, String> {
            Ok(self.sd[node].clone())
        }
        fn write(&mut self, node: &String, sd: &[u8], _: SecInfo) -> Result<(), String> {
            if self.refuse.as_ref() == Some(node) {
                return Err("permission denied".into());
            }
            self.written.push(node.clone());
            self.sd.insert(node.clone(), sd.to_vec());
            Ok(())
        }
    }

    const FILE: Generic = Generic { read: 0x120089, write: 0x120116, execute: 0x1200a0, all: 0x1f01ff };

    fn mem(items: &[(&str, &str, &[&str])]) -> Mem {
        Mem {
            sd: items.iter().map(|(n, s, _)| (n.to_string(), sddl::parse(s).unwrap().as_bytes().to_vec())).collect(),
            inside: items.iter().filter(|(_, _, i)| !i.is_empty()).map(|(n, _, i)| (n.to_string(), i.iter().map(|s| s.to_string()).collect())).collect(),
            refuse: None,
            written: vec![],
        }
    }

    fn text(m: &Mem, n: &str) -> String {
        sddl::format(&m.sd[n]).unwrap()
    }

    #[test]
    fn everything_inside_gets_what_is_passed_down_but_what_protects_itself() {
        let mut m = mem(&[
            ("root", "O:BAG:BAD:(A;OICI;FA;;;BA)(A;OICIIO;GA;;;CO)", &["a", "locked", "file"]),
            ("a", "O:S-1-5-21-1-2-3-1001G:BAD:(A;ID;FR;;;WD)", &["a/deep"]),
            ("a/deep", "O:S-1-5-21-1-2-3-1002G:BAD:", &[]),
            ("locked", "O:BAG:BAD:P(A;;FA;;;SY)", &["locked/in"]),
            ("locked/in", "O:BAG:BAD:(A;ID;FA;;;SY)", &[]),
            ("file", "O:BAG:BAD:", &[]),
        ]);
        m.inside.insert("a/deep".into(), vec![]);
        let mut said = vec![];
        let walked = walk(&mut m, &"root".to_string(), &[Part::Dacl], FILE, &AtomicBool::new(false), &mut |n, at| said.push((n, at.to_string())));
        assert_eq!(walked, Walked { done: 6 - 1, failed: vec![], stopped: false });
        assert_eq!(said.len(), 5);
        // The old inherited entry is gone, CREATOR OWNER is a's owner, and
        // the rule goes on unresolved.
        assert!(text(&m, "a").ends_with("D:AI(A;CIOIID;FA;;;BA)(A;ID;FA;;;S-1-5-21-1-2-3-1001)(A;CIOIIOID;GA;;;CO)"), "{}", text(&m, "a"));
        // a's inside resolves it to its own owner, from a as just written.
        assert!(text(&m, "a/deep").ends_with("D:AI(A;CIOIID;FA;;;BA)(A;ID;FA;;;S-1-5-21-1-2-3-1002)(A;CIOIIOID;GA;;;CO)"), "{}", text(&m, "a/deep"));
        // What protects itself is left, and what is inside it is done from
        // it as it is.
        assert!(!m.written.contains(&"locked".to_string()));
        assert!(text(&m, "locked/in").ends_with("D:AI"), "{}", text(&m, "locked/in"));
    }

    #[test]
    fn a_refusal_is_noted_and_the_walk_goes_on() {
        let mut m = mem(&[("root", "O:BAG:BAD:(A;OICI;FA;;;BA)", &["x", "y"]), ("x", "O:BAG:BAD:", &[]), ("y", "O:BAG:BAD:", &[])]);
        m.refuse = Some("x".into());
        let walked = walk(&mut m, &"root".to_string(), &[Part::Dacl], FILE, &AtomicBool::new(false), &mut |_, _| {});
        assert_eq!(walked.done, 1);
        assert_eq!(walked.failed, [Failure { name: "x".into(), why: "permission denied".into() }]);
    }

    #[test]
    fn stopping_stops_before_the_next() {
        let mut m = mem(&[("root", "O:BAG:BAD:(A;OICI;FA;;;BA)", &["x", "y"]), ("x", "O:BAG:BAD:", &[]), ("y", "O:BAG:BAD:", &[])]);
        let stop = AtomicBool::new(false);
        let walked = walk(&mut m, &"root".to_string(), &[Part::Dacl], FILE, &stop, &mut |_, _| stop.store(true, Ordering::Relaxed));
        assert_eq!((walked.done, walked.stopped), (1, true));
    }

    #[test]
    fn only_lists_that_are_passed_down_are_walked() {
        let mut m = mem(&[("root", "O:BAG:BAD:(A;OICI;FA;;;BA)", &["x"]), ("x", "O:BAG:BAD:", &[])]);
        let walked = walk(&mut m, &"root".to_string(), &[Part::Owner], FILE, &AtomicBool::new(false), &mut |_, _| {});
        assert_eq!(walked, Walked::default());
        assert!(m.written.is_empty());
    }
}
