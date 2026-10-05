//! gxwi-sd-editor — a security descriptor editor for GXWI desktops: a dialog
//! of its own, opened by a program that wants a descriptor edited, which
//! says what the object is and applies what comes back (the library, and
//! PSPU, set out how the two speak).
//!
//! The whole descriptor is edited: who may do what with it (the access
//! list), auditing, its integrity label and process trust label, its claims
//! and the central access policies it names. The descriptor's own entries
//! are what is edited (`sd`); the tabs are views of them (`view`), changed
//! by `edit`, and Advanced mode shows and changes the entries themselves.
//! Effective Access works out what someone could do (`eff`). Apply sends
//! the program the descriptor and the parts of it that changed, OK does
//! that and closes once it has been applied, and Cancel, or closing the
//! dialog, sends nothing more.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::io::{BufRead, Write};
use std::sync::Arc;

use gxwi_sd_editor::names::Names;
use gxwi_sd_editor::{Can, FromEditor, Part, Request, ToEditor, Walked, line};
use libgxwi::{App, Closer, Facts, Fields, Live, Value};
use peios::security::Sid;

mod adv;
mod caller;
mod claim;
mod cond;
mod edit;
mod eff;
mod known;
mod learned;
mod people;
mod sd;
mod text;
mod ui;
mod view;

use caller::Caller;
use cond::{Cond, Node};
use edit::CondOf;
use known::Known;
use learned::Learned;
use sd::{Acl, Ace, Descriptor, Found, Guid, Ids, Way};
use view::{Obj, PartDef, Simple};

// What this program looks like on its dialog's strip. The icon itself is
// `gxwi-sd-editor.svg`, installed as the base theme's.
libgxwi::icon!(b"dev.peios.gxwi-sd-editor");

/// The dialog's own tabs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Top {
    Access,
    Claims,
    Policy,
    Effective,
}

/// The tabs of what the one picked can do.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tab {
    Access,
    Cond,
    Specific,
    Audit,
}

/// Which of the descriptor's lists, as inheritance and Advanced mode
/// speak of them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Side {
    Access,
    Sacl,
}

/// Advanced mode's tabs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AdvTab {
    Dacl,
    Sacl,
    Desc,
    Effective,
}

/// Advanced mode: both lists, entry by entry.
#[derive(Clone, Debug)]
pub struct Adv {
    pub tab: AdvTab,
    pub dacl: Option<u32>,
    pub sacl: Option<u32>,
    /// Whether the rarely needed rights are shown for every entry.
    pub more: bool,
    /// The access list as it was when "No access list at all" was ticked.
    pub stash: Option<Acl>,
}

/// What is being asked of the person before anything more is done.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Asking {
    /// Whom to add, typed.
    Add,
    /// The owner, the group and the labels, in their dropdown.
    Owner,
    /// Whether to keep or remove what is inherited, on stopping it.
    Stop(Side),
    /// Whether to push what this container now passes down into what is
    /// already inside it, on Apply or OK.
    Push { then_close: bool },
}

/// Where the descriptor is with the program.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Sending {
    No,
    Yes { then_close: bool },
}

/// How far pushing into what is inside has got, while it goes on.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Pushing {
    pub done: u64,
    /// The last item done.
    pub at: String,
    /// Whether the person asked for it to stop.
    pub stopping: bool,
}

pub struct Editor {
    pub obj: Obj,
    pub can: Can,
    /// Whether the request carries the whole SACL, and the label.
    pub read_sacl: bool,
    pub read_label: bool,
    pub caller: Caller,
    pub names: Names,
    pub learned: Learned,
    /// The claims the machine defines.
    pub known: Known,
    /// The descriptor as it is being edited, what each entry was read as,
    /// and the ids for new ones.
    pub sd: Descriptor,
    pub found: Found,
    pub ids: Ids,
    /// The descriptor as the program has it: what it sent, or what it last
    /// applied.
    pub applied: Descriptor,
    /// The parent's descriptor, for inheriting again.
    pub parent: Option<Vec<u8>>,
    pub top: Top,
    pub adv: Option<Adv>,
    /// Who is listed: everyone the descriptor names, and whoever has been
    /// added since, until they are removed.
    pub listed: Vec<Sid>,
    /// Who was added here with Add, until they are removed.
    pub added: Vec<Sid>,
    pub picked: Option<Sid>,
    pub tab: Tab,
    /// Where the boxes of Access are for: on a container, the scope.
    pub scope: u8,
    /// Whether Access shows every right one at a time.
    pub advanced: bool,
    /// The rules showing every right one at a time, by key.
    pub shows_advanced: HashSet<u32>,
    pub asking: Option<Asking>,
    /// What is wrong with what was typed, by field.
    pub wrong: HashMap<String, String>,
    /// Whether Apply was pressed with something unfinished: everything
    /// unfinished is then said where it is.
    pub checked: bool,
    /// What a field holds while it is typed in, where that is not what the
    /// descriptor holds: a name not yet found, rights not yet hex, values
    /// with a comma still to come.
    pub typed: HashMap<String, String>,
    pub trouble: Option<String>,
    pub status: String,
    pub sending: Sending,
    /// Pushing into what is inside, while it goes on; how it went, after;
    /// and the parts it was for, to push them again.
    pub pushing: Option<Pushing>,
    pub pushed: Option<Walked>,
    pub push_parts: Vec<Part>,
    pub closer: Option<Closer>,
    /// Whom Effective Access is for, and for which part.
    pub eff_who: Option<Sid>,
    pub eff_part: Option<Guid>,
    pub people: HashMap<Sid, Result<eff::Person, String>>,
    /// The fields the last render drew, and what each holds, for putting
    /// the surface's fields right after a change.
    pub seen: RefCell<Vec<(String, String)>>,
}

impl Editor {
    pub fn new(request: Request, mut names: Names, caller: Caller, learned: Learned) -> Result<Editor, String> {
        let (mut found, mut ids) = (Found::default(), Ids::default());
        let sd = Descriptor::parse(&request.sd, &mut ids, &mut found)?;
        let read = request.read.clone().unwrap_or_else(|| {
            let mut all = vec![Part::Owner, Part::Group, Part::Dacl];
            if sd.sacl.is_some() {
                all.extend([Part::Sacl, Part::Label]);
            }
            all
        });
        let (general, mut specific): (Vec<_>, Vec<_>) = request.rights.into_iter().partition(|r| r.general);
        // A program that names only general rights still has the rights one
        // at a time shown: each bit of them, by its standard name where it
        // has one.
        if specific.is_empty() {
            let all = general.iter().fold(0, |a, r| a | r.mask) & !sd::SYNCHRONIZE;
            let standard = [(0x10000, "Delete"), (sd::READ_CONTROL, "Read permissions"), (sd::WRITE_DAC, "Change permissions"), (0x80000, "Take ownership")];
            specific = (0..32)
                .map(|b| 1u32 << b)
                .filter(|bit| all & bit != 0)
                .map(|bit| gxwi_sd_editor::Right { name: standard.iter().find(|(m, _)| *m == bit).map_or_else(|| format!("Right 0x{bit:x}"), |(_, n)| n.to_string()), mask: bit, general: false })
                .collect();
        }
        let object = request.object;
        let obj = Obj {
            name: object.name,
            kind: object.kind,
            container: object.container,
            children: object.children,
            from: object.parent.as_ref().map(|p| p.name.clone()),
            general,
            specific,
            generic: request.generic,
            parts: object
                .parts
                .iter()
                .filter_map(|p| Some(PartDef { guid: sd::guid_parse(&p.guid)?, name: p.name.clone(), kind: p.kind, set: p.set.as_deref().and_then(sd::guid_parse) }))
                .collect(),
            kinds: object.kinds.iter().filter_map(|k| Some((sd::guid_parse(&k.guid)?, k.name.clone()))).collect(),
        };
        for ace in sd.dacl.iter().chain(&sd.sacl).flat_map(|a| &a.aces) {
            if let Some(sid) = &ace.sid {
                names.learn(sid);
            }
        }
        for sid in sd.owner.iter().chain(&sd.group).chain(&caller.may_own()) {
            names.learn(sid);
        }
        let mut editor = Editor {
            obj,
            can: request.can,
            read_sacl: read.contains(&Part::Sacl),
            read_label: read.contains(&Part::Label) || read.contains(&Part::Sacl),
            caller,
            names,
            learned,
            known: Known::default(),
            applied: sd.clone(),
            sd,
            found,
            ids,
            parent: object.parent.and_then(|p| p.sd),
            top: Top::Access,
            adv: None,
            listed: vec![],
            added: vec![],
            picked: None,
            tab: Tab::Access,
            scope: 0,
            advanced: false,
            shows_advanced: HashSet::new(),
            asking: None,
            wrong: HashMap::new(),
            checked: false,
            typed: HashMap::new(),
            trouble: None,
            status: String::new(),
            sending: Sending::No,
            pushing: None,
            pushed: None,
            push_parts: Vec::new(),
            closer: None,
            eff_who: None,
            eff_part: None,
            people: HashMap::new(),
            seen: RefCell::new(Vec::new()),
        };
        editor.listed = editor.simple().principals(editor.read_sacl);
        editor.pick(editor.listed.first().copied());
        Ok(editor)
    }

    // ---- what can be changed

    /// Whether the access list can be changed: the program can, and nothing
    /// is waiting on it.
    pub fn may_dacl(&self) -> bool {
        self.can.dacl && self.sending == Sending::No
    }

    /// Whether the SACL as a whole is shown, and whether it can be changed.
    pub fn shows_sacl(&self) -> bool {
        self.read_sacl
    }

    pub fn may_sacl(&self) -> bool {
        self.can.audit && self.read_sacl && self.sending == Sending::No
    }

    /// Whether the integrity label can be changed: by itself, or with the
    /// whole SACL.
    pub fn may_label(&self) -> bool {
        self.read_label && (self.can.label || self.may_sacl()) && self.sending == Sending::No
    }

    pub fn may_owner(&self) -> bool {
        self.can.owner && self.sending == Sending::No
    }

    // ---- the simple view

    pub fn simple(&self) -> Simple {
        Simple::read(&self.obj, self.sd.dacl.as_ref().map(|a| a.aces.as_slice()), self.sd.sacl.as_ref().map(|a| a.aces.as_slice()))
    }

    /// Changes the simple view, and the entries it is written back as.
    pub fn edit<R>(&mut self, change: impl FnOnce(&mut Simple, &Obj, &mut Ids, &Found) -> R) -> R {
        let mut s = self.simple();
        let out = change(&mut s, &self.obj, &mut self.ids, &self.found);
        self.put(&s);
        out
    }

    pub fn put(&mut self, s: &Simple) {
        let (dacl, sacl) = s.write(&self.obj, &mut self.ids);
        let revision = |acl: &Option<Acl>| acl.as_ref().map_or(2, |a| a.revision);
        let (dr, sr) = (revision(&self.sd.dacl), revision(&self.sd.sacl));
        self.sd.dacl = dacl.map(|aces| Acl { revision: dr, aces });
        self.sd.sacl = sacl.map(|aces| Acl { revision: sr, aces });
    }

    /// Who is picked, and Access at the scope of their first plain entry.
    pub fn pick(&mut self, sid: Option<Sid>) {
        self.picked = sid;
        let Some(sid) = sid else { return };
        let s = self.simple();
        let first = s.entries().iter().find(|e| edit::plain(e) && e.ace.sid == Some(sid));
        self.scope = match first {
            Some(e) if self.obj.container => e.ace.flags & sd::SHAPE,
            _ => self.obj.home(),
        };
        self.advanced = !s.simple_for(&self.obj, &sid, self.scope);
    }

    /// Keeps the list of who is listed in step with the descriptor: those
    /// gone from it go, and those new to it come at the end.
    pub fn relist(&mut self) {
        let now = self.simple().principals(self.read_sacl);
        // Whoever was added here stays, given anything yet or not.
        let listed = std::mem::take(&mut self.listed);
        self.listed = listed.into_iter().filter(|s| now.contains(s) || self.added.contains(s)).collect();
        for s in now {
            // Inheriting again can bring in someone not named before.
            self.names.learn(&s);
            if !self.listed.contains(&s) {
                self.listed.push(s);
            }
        }
        if !self.picked.is_some_and(|p| self.listed.contains(&p)) {
            self.pick(self.listed.first().copied());
        }
    }

    /// The entry an Advanced mode id names, and which list it is in.
    pub fn entry(&self, id: u32) -> Option<(&Ace, view::List)> {
        if let Some(a) = self.sd.dacl.as_ref().and_then(|l| l.aces.iter().find(|a| a.id == id)) {
            return Some((a, view::List::Dacl));
        }
        self.sd.sacl.as_ref().and_then(|l| l.aces.iter().find(|a| a.id == id)).map(|a| (a, view::List::Sacl))
    }

    pub fn entry_mut(&mut self, id: u32) -> Option<&mut Ace> {
        self.sd.dacl.iter_mut().chain(self.sd.sacl.iter_mut()).flat_map(|a| a.aces.iter_mut()).find(|a| a.id == id)
    }

    /// The condition a key names.
    pub fn cond_of(&self, of: CondOf) -> Option<Node> {
        match of {
            CondOf::Entry(id) => self.entry(id)?.0.cond.as_ref()?.tree().cloned(),
            other => self.simple().cond(other).cloned(),
        }
    }

    /// Changes the condition a key names. Taking the last test out of it
    /// takes the condition away: the rule is then an ordinary one.
    pub fn change_cond(&mut self, of: CondOf, change: impl Fn(&mut Node)) {
        let apply = |c: &mut Option<Cond>| {
            if let Some(Cond::Tree(node)) = c {
                change(node);
                if matches!(node, Node::Group(_, items) if items.is_empty()) {
                    *c = None;
                }
            }
        };
        match of {
            CondOf::Entry(id) => {
                if let Some(ace) = self.entry_mut(id) {
                    apply(&mut ace.cond);
                }
            }
            other => self.edit(|s, _, _, _| s.with_cond(other, apply)),
        }
    }

    /// Whether the condition a key names may be changed.
    pub fn may_cond(&self, of: CondOf) -> bool {
        match of {
            CondOf::Card(key) => self.may_dacl() && self.simple().card(key).is_some_and(|c| !c.inherited),
            CondOf::Rule(_) => self.may_dacl(),
            CondOf::Audit(key) => self.may_sacl() && self.simple().audits.iter().any(|a| a.ids.first() == Some(&key) && !a.inherited),
            CondOf::Entry(id) => self.entry(id).is_some_and(|(a, l)| adv::may_entry(self, a, l) && !a.inherited()),
        }
    }

    // ---- applying

    /// The parts of the descriptor that differ from what the program has,
    /// as they are to be sent: the SACL carries the label when it goes, and
    /// the label goes alone only to a program that said it can apply it.
    pub fn changed(&self) -> Vec<Part> {
        let mut parts = Vec::new();
        if self.sd.owner != self.applied.owner {
            parts.push(Part::Owner);
        }
        if self.sd.group != self.applied.group {
            parts.push(Part::Group);
        }
        let bytes = |acl: &Option<Acl>, keep: &dyn Fn(&Ace) -> bool| -> Option<Vec<Option<Vec<u8>>>> {
            acl.as_ref().map(|a| a.aces.iter().filter(|x| keep(x)).map(|x| sd::ace_bytes(x, &self.found).ok()).collect())
        };
        let all = |_: &Ace| true;
        let control = |d: &Descriptor, bits: u16| d.control & bits;
        if bytes(&self.sd.dacl, &all) != bytes(&self.applied.dacl, &all) || control(&self.sd, sd::PD | sd::DI) != control(&self.applied, sd::PD | sd::DI) {
            parts.push(Part::Dacl);
        }
        let label = |a: &Ace| a.way == Way::Label;
        let rest = |a: &Ace| a.way != Way::Label;
        let sorted = |mut v: Option<Vec<Option<Vec<u8>>>>| {
            if let Some(v) = &mut v {
                v.sort();
            }
            v
        };
        let sacl_changed = sorted(bytes(&self.sd.sacl, &rest)) != sorted(bytes(&self.applied.sacl, &rest)) || control(&self.sd, sd::PS | sd::SI) != control(&self.applied, sd::PS | sd::SI);
        let label_changed = bytes(&self.sd.sacl, &label) != bytes(&self.applied.sacl, &label);
        if (sacl_changed || (label_changed && !self.can.label)) && self.read_sacl {
            parts.push(Part::Sacl);
        } else if label_changed {
            parts.push(Part::Label);
        }
        parts
    }

    /// What the program can apply of what changed.
    fn sendable(&self, parts: &[Part]) -> Vec<Part> {
        parts
            .iter()
            .copied()
            .filter(|p| match p {
                Part::Owner | Part::Group => self.can.owner,
                Part::Dacl => self.can.dacl,
                Part::Sacl => self.can.audit && self.read_sacl,
                Part::Label => self.can.label,
            })
            .collect()
    }

    /// Whether what this container passes down differs, in the parts to be
    /// sent, from what the program has: its entries that go on to what is
    /// inside, inherited or its own.
    pub fn passes_changed(&self, parts: &[Part]) -> bool {
        let passed = |acl: &Option<Acl>| -> Option<Vec<Option<Vec<u8>>>> {
            acl.as_ref().map(|a| {
                let mut v: Vec<_> = a.aces.iter().filter(|x| x.flags & (sd::OI | sd::CI) != 0).map(|x| sd::ace_bytes(x, &self.found).ok()).collect();
                v.sort();
                v
            })
        };
        (parts.contains(&Part::Dacl) && passed(&self.sd.dacl) != passed(&self.applied.dacl))
            || ((parts.contains(&Part::Sacl) || parts.contains(&Part::Label)) && passed(&self.sd.sacl) != passed(&self.applied.sacl))
    }

    /// On Apply or OK: asks whether to push into what is inside first,
    /// where that is what changed and the program can, or else sends.
    /// Whether anything is under way.
    fn apply_or_ask(&mut self, then_close: bool) -> bool {
        if self.sending != Sending::No {
            return false;
        }
        let parts = self.sendable(&self.changed());
        if self.can.propagate && self.obj.container && !parts.is_empty() && self.passes_changed(&parts) {
            if let Some((why, place)) = self.fault() {
                self.checked = true;
                self.trouble = Some(why);
                self.go(place);
                return false;
            }
            self.asking = Some(Asking::Push { then_close });
            return true;
        }
        self.send(then_close, false)
    }

    /// Sends the program the descriptor as it stands, if anything changed
    /// that it can apply, and asks it to push into what is inside if
    /// `push`. Whether anything was sent.
    fn send(&mut self, then_close: bool, push: bool) -> bool {
        if self.sending != Sending::No {
            return false;
        }
        let parts = self.sendable(&self.changed());
        // Pushing again what was pushed before, when nothing has changed
        // since: it is applied again as it is, which changes nothing.
        let parts = if parts.is_empty() && push { self.push_parts.clone() } else { parts };
        if parts.is_empty() {
            return false;
        }
        if let Some((why, place)) = self.fault() {
            self.checked = true;
            self.trouble = Some(why);
            self.go(place);
            return false;
        }
        let sd = match self.sd.build(&self.found) {
            Ok(sd) => sd,
            Err(why) => {
                self.trouble = Some(why);
                return false;
            }
        };
        let push = push && self.can.propagate;
        if !say(&FromEditor::Apply { sd, parts: parts.clone(), propagate: push }) {
            self.trouble = Some("The program that opened this has gone, and nothing can be applied.".into());
            return false;
        }
        self.checked = false;
        self.sending = Sending::Yes { then_close };
        self.pushed = None;
        if push {
            self.pushing = Some(Pushing::default());
            self.push_parts = parts;
        }
        self.status = "Applying…".into();
        true
    }

    /// Asks the program to stop pushing into what is inside.
    fn stop_pushing(&mut self) {
        if let Some(p) = &mut self.pushing
            && !p.stopping
            && say(&FromEditor::Stop)
        {
            p.stopping = true;
        }
    }

    /// What the program answered. Whether the dialog is done with.
    fn answered(&mut self, answer: ToEditor) -> bool {
        if let ToEditor::Progress { done, at } = answer {
            if let Some(p) = &mut self.pushing {
                p.done = done;
                p.at = at;
            }
            return false;
        }
        let Sending::Yes { then_close } = std::mem::replace(&mut self.sending, Sending::No) else { return false };
        self.status.clear();
        let pushed = self.pushing.take().is_some();
        match answer {
            ToEditor::Applied { done, failed, stopped } => {
                self.learn();
                self.applied = self.sd.clone();
                self.trouble = None;
                if !pushed {
                    self.status = "Applied.".into();
                    return then_close;
                }
                let whole = failed.is_empty() && !stopped;
                if whole {
                    self.status = format!("Applied, and {} inside updated.", items(done));
                }
                self.pushed = Some(Walked { done, failed, stopped });
                then_close && whole
            }
            ToEditor::Failed { why } => {
                self.trouble = Some(format!("This could not be applied: {why}"));
                false
            }
            ToEditor::Progress { .. } => false,
        }
    }

    /// Learns the claims tested in conditions that were not there before,
    /// and the object's own claims, as `@Resource`.
    fn learn(&mut self) {
        let tested = |d: &Descriptor| -> Vec<(String, Vec<String>)> {
            let mut out = Vec::new();
            for ace in d.dacl.iter().chain(&d.sacl).flat_map(|a| &a.aces) {
                if let Some(node) = ace.cond.as_ref().and_then(Cond::tree) {
                    for c in node.claims() {
                        if let Node::Claim { src, name, op, val } = c {
                            out.push((format!("{}.{}", src.word(), name.trim()), if op.valued() { cond::values(*op, val) } else { vec![] }));
                            if let cond::Val::Claim(other, n) = val {
                                out.push((format!("{}.{}", other.word(), n.trim()), vec![]));
                            }
                        }
                    }
                }
                if let Some(c) = &ace.claim
                    && !matches!(c.kind, claim::ClaimType::Sid | claim::ClaimType::Bytes)
                {
                    out.push((format!("Resource.{}", c.name.trim()), c.values.clone()));
                }
            }
            out
        };
        let before = tested(&self.applied);
        let new: Vec<_> = tested(&self.sd).into_iter().filter(|t| !before.contains(t)).collect();
        // Only whoever may write the machine's key teaches it.
        if new.is_empty() || !self.learned.writable {
            return;
        }
        // Counted onto what is there now, which another program may have
        // added to since this one opened.
        let mut now = Learned::read();
        for (name, values) in &new {
            now.learn(name, values);
        }
        let _ = now.write();
        self.learned = now;
    }

    fn close(&self) {
        if let Some(closer) = &self.closer {
            closer.close();
        }
    }

    // ---- fields

    /// The HTML attributes of a named field, noting what it holds.
    pub fn field(&self, name: &str, value: &str) -> String {
        self.seen.borrow_mut().push((name.to_string(), value.to_string()));
        format!("name=\"{}\"", libgxwi::escape(name))
    }

    /// What a text field shows: what is being typed in it, or `value`.
    pub fn shown_text(&self, name: &str, value: &str) -> String {
        self.typed.get(name).cloned().unwrap_or_else(|| value.to_string())
    }

    /// Puts every field the next render draws right, after a change: a
    /// field whose value the descriptor changed underneath it shows the new
    /// one, and none holds what another thing in its place held.
    fn sync(&mut self, fields: &mut Fields) {
        self.seen.borrow_mut().clear();
        let _ = self.html();
        for (name, value) in self.seen.take() {
            if fields.get(&name) != value {
                fields.set(&name, &value);
            }
        }
    }
}

impl Live for Editor {
    fn render(&self, _: &Facts) -> String {
        self.seen.borrow_mut().clear();
        self.html()
    }

    fn event(&mut self, name: &str, value: &Value, fields: &mut Fields) {
        if name != "pick" && !name.starts_with("x-sel") {
            self.trouble = None;
        }
        if name != "apply" {
            self.status.clear();
        }
        // What was being typed is in the descriptor by now, but for the
        // owner dropdown's draft, which waits for Done.
        self.typed.retain(|k, _| k.starts_with("own."));
        let v = |k: &str| value[k].as_str().unwrap_or("").to_string();
        match name {
            "apply" => {
                self.apply_or_ask(false);
            }
            "ok" => {
                if self.sending == Sending::No && !self.apply_or_ask(true) && self.trouble.is_none() && self.sendable(&self.changed()).is_empty() {
                    self.close();
                }
            }
            "push" => {
                if let Some(Asking::Push { then_close }) = self.asking {
                    self.asking = None;
                    self.send(then_close, v("v") == "all");
                }
            }
            "push-again" => {
                self.send(false, true);
            }
            "push-done" => self.pushed = None,
            // Cancel while what is inside is being pushed into stops that,
            // and the dialog stays to say how far it got.
            "cancel" | "stop-push" if self.pushing.is_some() => self.stop_pushing(),
            "cancel" => self.close(),
            "keep" => {
                self.asking = None;
                self.wrong.clear();
            }
            "escape" => {
                if self.pushing.is_some() {
                    self.stop_pushing();
                } else if self.asking.is_some() {
                    self.asking = None;
                    self.wrong.clear();
                } else {
                    self.close();
                }
            }
            "top" => {
                match (&mut self.adv, v("v").as_str()) {
                    (Some(adv), t) => {
                        adv.tab = match t {
                            "sacl" => AdvTab::Sacl,
                            "desc" => AdvTab::Desc,
                            "eff" => AdvTab::Effective,
                            _ => AdvTab::Dacl,
                        }
                    }
                    (None, t) => {
                        self.top = match t {
                            "claims" => Top::Claims,
                            "cap" => Top::Policy,
                            "eff" => Top::Effective,
                            _ => Top::Access,
                        }
                    }
                }
                if v("v") == "eff" {
                    self.look_up();
                }
            }
            _ if name.starts_with("x-") => adv::event(self, name, value, fields),
            _ => ui::event(self, name, value, fields),
        }
        self.sync(fields);
    }

    fn input(&mut self, name: &str, fields: &mut Fields) {
        let value = fields.get(name).to_string();
        self.status.clear();
        if name.starts_with("x.") || name == "advmode" {
            adv::input(self, name, &value);
        } else {
            ui::input(self, name, &value, fields);
        }
        self.sync(fields);
    }
}

/// The request, from the first line of the input.
fn request() -> Result<Request, String> {
    let mut first = String::new();
    std::io::stdin().lock().read_line(&mut first).map_err(|e| format!("the request could not be read: {e}"))?;
    if first.trim().is_empty() {
        return Err("no request: it is opened by a program, which says what to edit on its first line (see gxwi-sd-editor(1))".into());
    }
    serde_json::from_str(&first).map_err(|e| format!("the request is not one: {e}"))
}

fn main() {
    // Gone with whatever opened it, however that went.
    // SAFETY: prctl with these arguments only sets a signal for later.
    unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) };
    if unsafe { libc::getppid() } == 1 {
        std::process::exit(0);
    }
    let request = request().unwrap_or_else(|why| die(&why));
    let title = format!("Permissions for {}", request.object.name);
    let mut editor = Editor::new(request, Names::new(), Caller::own(), Learned::read()).unwrap_or_else(|why| die(&why));
    editor.known = Known::read();
    let mut app = App::connect().unwrap_or_else(|e| die(&format!("no desktop to open on: {e}")));
    app.stylesheet("/editor.css", include_str!("editor.css"));
    let dialog = app.dialog(&title, editor);
    let closer = dialog.closer();
    dialog.update(|editor, _| editor.closer = Some(closer));
    // The program's answers, and its going.
    let heard = Arc::clone(&dialog);
    std::thread::spawn(move || {
        for said in std::io::stdin().lock().lines() {
            let Ok(said) = said else { break };
            let Ok(answer) = serde_json::from_str::<ToEditor>(&said) else { continue };
            let mut done = false;
            heard.update(|editor, fields| {
                done = editor.answered(answer);
                editor.sync(fields);
            });
            if done {
                heard.close();
            }
        }
        // Whoever opened it has gone: so does the dialog.
        std::process::exit(0);
    });
    if let Err(e) = app.run() {
        die(&e.to_string());
    }
}

/// Writes one line to the program. Whether it could.
fn say(message: &FromEditor) -> bool {
    let mut out = std::io::stdout().lock();
    out.write_all(line(message).as_bytes()).and_then(|()| out.flush()).is_ok()
}

/// "1 item", "1,204 items".
pub fn items(n: u64) -> String {
    let digits = n.to_string();
    let mut grouped = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            grouped.push(',');
        }
        grouped.push(c);
    }
    format!("{grouped} item{}", if n == 1 { "" } else { "s" })
}

fn die(why: &str) -> ! {
    eprintln!("gxwi-sd-editor: {why}");
    std::process::exit(1);
}

#[cfg(test)]
mod tests;
