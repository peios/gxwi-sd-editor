//! Effective access: what a person could do with the object, worked out the
//! way KACS's access check works it out (KACS TRM, access check), and why.
//!
//! In order: the integrity label, then process trust, then the owner's own
//! rights, then the access list in its real order, the first entry to
//! decide a right deciding it, then the central access policies it names.
//! The person is taken to open it with an ordinary program, at Medium
//! integrity unless said otherwise, with the groups and claims authd gives
//! them. Conditions are three-valued: a fact that is not known is UNKNOWN,
//! which an allow does not count and a refusal does (PCDS §5.8).

use std::collections::HashMap;

use peios::security::Sid;

use crate::cond::{Cond, MemberOp, Mode, Node, Op, Src, Val, values};
use crate::sd::*;
use crate::view::*;

/// What someone is, for working out what they can do.
#[derive(Clone, Debug, PartialEq)]
pub struct Person {
    pub sid: Sid,
    pub name: String,
    /// Every SID their token would carry: theirs, their groups, Everyone
    /// and Authenticated Users.
    pub sids: Vec<Sid>,
    /// Their device's groups: none, when it is not known.
    pub device: Vec<Sid>,
    /// Their claims, as `User.Name` (lower-cased) to values.
    pub claims: HashMap<String, Vec<String>>,
    pub integrity: u32,
}

/// TRUE, FALSE or UNKNOWN.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Three {
    T,
    F,
    U,
}

impl Three {
    fn not(self) -> Three {
        match self {
            Three::T => Three::F,
            Three::F => Three::T,
            Three::U => Three::U,
        }
    }
}

/// How a step of the trace went: gave, refused, or said nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mark {
    Yes,
    No,
    Skip,
}

pub struct Step {
    pub stage: &'static str,
    pub lines: Vec<(Mark, String)>,
}

pub struct Result {
    pub granted: u32,
    /// For each right the object names, by mask: whether it was given, and
    /// what decided it.
    pub by: HashMap<u32, (bool, String)>,
    pub steps: Vec<Step>,
}

pub struct Facts<'a> {
    pub obj: &'a Obj,
    pub simple: &'a Simple,
    /// The access list in its real order, as written.
    pub dacl: Option<&'a [Ace]>,
    pub owner: Option<Sid>,
    /// Whether the SACL was read: without it, trust, claims and policy are
    /// not known.
    pub sacl: bool,
    /// What a name is called, for the trace.
    pub name: &'a dyn Fn(&Sid) -> String,
}

/// A claim's values, as a test sees them. One that is off cannot be seen;
/// one only for refusals only by a refusal's condition.
fn claim_of(facts: &Facts, who: &Person, src: Src, name: &str, deny: bool) -> Option<Vec<String>> {
    let name = name.trim();
    match src {
        Src::Resource => {
            if !facts.sacl {
                return None;
            }
            let c = facts.simple.claims.iter().find(|c| c.claim.name.eq_ignore_ascii_case(name))?;
            let f = c.claim.flags;
            if f & crate::claim::DISABLED != 0 || (f & crate::claim::DENY_ONLY != 0 && !deny) || c.claim.values.is_empty() {
                return None;
            }
            Some(c.claim.values.clone())
        }
        Src::Local | Src::Device => None,
        Src::User => who.claims.get(&format!("user.{}", name.to_lowercase())).cloned(),
    }
}

fn eval_claim(facts: &Facts, who: &Person, src: Src, name: &str, op: Op, val: &Val, deny: bool) -> Three {
    let have = claim_of(facts, who, src, name, deny);
    if op == Op::NotExists {
        return if have.is_none() { Three::T } else { Three::F };
    }
    let Some(have) = have else { return Three::U };
    if op == Op::Exists {
        return Three::T;
    }
    let want = match val {
        Val::Claim(other, n) => match claim_of(facts, who, *other, n, deny) {
            Some(w) => w,
            None => return Three::U,
        },
        Val::Value(_) => values(op, val),
    };
    let Some(first) = want.first() else { return Three::U };
    let num = |v: &str| v.parse::<i64>().ok();
    let eq = |a: &str, b: &str| match (num(a), num(b)) {
        (Some(x), Some(y)) => x == y,
        _ => a.eq_ignore_ascii_case(b),
    };
    let cmp = |f: fn(i64, i64) -> bool| if have.iter().any(|v| matches!((num(v), num(first)), (Some(a), Some(b)) if f(a, b))) { Three::T } else { Three::F };
    let yes = |b: bool| if b { Three::T } else { Three::F };
    match op {
        Op::Eq => yes(have.iter().any(|v| eq(v, first))),
        Op::Ne => yes(!have.iter().any(|v| eq(v, first))),
        Op::AnyOf => yes(have.iter().any(|v| want.iter().any(|w| eq(v, w)))),
        Op::Contains => yes(want.iter().all(|w| have.iter().any(|v| eq(v, w)))),
        Op::Ge => cmp(|a, b| a >= b),
        Op::Gt => cmp(|a, b| a > b),
        Op::Le => cmp(|a, b| a <= b),
        Op::Lt => cmp(|a, b| a < b),
        Op::Exists | Op::NotExists => Three::U,
    }
}

pub fn eval(facts: &Facts, who: &Person, node: &Node, deny: bool) -> Three {
    match node {
        Node::Group(mode, items) => {
            let vals: Vec<Three> = items.iter().map(|n| eval(facts, who, n, deny)).collect();
            let and = if vals.contains(&Three::F) { Three::F } else if vals.contains(&Three::U) { Three::U } else { Three::T };
            let or = if vals.contains(&Three::T) { Three::T } else if vals.contains(&Three::U) { Three::U } else { Three::F };
            match mode {
                Mode::All => and,
                Mode::Any => or,
                Mode::None => or.not(),
                Mode::NotAll => and.not(),
            }
        }
        Node::Member { device, op, sids } => {
            let set = if *device { &who.device } else { &who.sids };
            let hit = match op {
                MemberOp::OfAny | MemberOp::NotOfAny => sids.iter().any(|s| set.contains(s)),
                MemberOp::Of | MemberOp::NotOf => sids.iter().all(|s| set.contains(s)),
            };
            let r = if hit { Three::T } else { Three::F };
            if matches!(op, MemberOp::NotOf | MemberOp::NotOfAny) { r.not() } else { r }
        }
        Node::Claim { src, name, op, val } => eval_claim(facts, who, *src, name, *op, val, deny),
    }
}

/// What `who` can do with the object, for all of it or for one `part`.
pub fn effective(facts: &Facts, who: &Person, part: Option<Guid>) -> Result {
    let obj = facts.obj;
    let s = facts.simple;
    let name = facts.name;
    let all = obj.all_rights() & !GENERIC & !ACCESS_SYSTEM_SECURITY & !MAXIMUM_ALLOWED;
    let listed = |m: u32| -> String {
        let names: Vec<String> = obj.specific.iter().filter(|r| m & r.mask != 0).map(|r| r.name.to_lowercase()).collect();
        if names.is_empty() { "nothing".into() } else { names.join(", ") }
    };
    let mut by: HashMap<u32, (bool, String)> = HashMap::new();
    let (mut decided, mut granted) = (0u32, 0u32);
    let mut steps = Vec::new();
    let set = |by: &mut HashMap<u32, (bool, String)>, bits: u32, ok: bool, why: &str| {
        for r in &obj.specific {
            if bits & r.mask != 0 {
                by.insert(r.mask, (ok, why.to_string()));
            }
        }
    };
    let level = |n: u32| level_name(n).map_or_else(|| n.to_string(), String::from);

    // Integrity.
    // No label counts as Medium, with no write up.
    let (label, policy) = s.label.as_ref().map_or((8192, 1), |l| (l.level, l.policy));
    let read = obj.generic.read & all;
    let exec = obj.generic.execute & !obj.generic.read & all;
    let write = all & !read & !exec;
    if who.integrity < label {
        let blocked = (if policy & 1 != 0 { write } else { 0 }) | (if policy & 2 != 0 { read } else { 0 }) | (if policy & 4 != 0 { exec } else { 0 });
        decided |= blocked;
        set(&mut by, blocked, false, &format!("Integrity: a {} label, and they run at {}", level(label), level(who.integrity)));
        steps.push(Step { stage: "Integrity", lines: vec![(Mark::No, format!("Labelled {}; {} runs at {}, so {} is held back.", level(label), who.name, level(who.integrity), listed(blocked)))] });
    } else {
        let what = if s.label.is_some() { level(label) } else { "No label, so Medium".into() };
        steps.push(Step { stage: "Integrity", lines: vec![(Mark::Skip, format!("{what}; {} runs at {}. Nothing held back.", who.name, level(who.integrity)))] });
    }

    // Process trust: an ordinary program is less trusted than any.
    if !facts.sacl {
        steps.push(Step { stage: "Process Trust", lines: vec![(Mark::Skip, "Not known: it's in the SACL, which the program that opened this can't read.".into())] });
    } else if let Some(t) = &s.trust {
        let blocked = all & !core(t.mask) & !decided;
        decided |= blocked;
        set(&mut by, blocked, false, "Process trust");
        steps.push(Step { stage: "Process Trust", lines: vec![(Mark::No, format!("Protected at trust {}. An ordinary program may only do: {}.", t.trust, listed(core(t.mask))))] });
    } else {
        steps.push(Step { stage: "Process Trust", lines: vec![(Mark::Skip, "Not protected.".into())] });
    }

    // The owner.
    let owner_rights: Sid = "S-1-3-4".parse().expect("Owner Rights");
    let is_owner = facts.owner.is_some_and(|o| who.sids.contains(&o));
    let ruled = facts.dacl.unwrap_or(&[]).iter().any(|a| a.sid == Some(owner_rights) && a.applies() && matches!(a.way, Way::Allow | Way::Deny));
    if is_owner && !ruled {
        let b = (READ_CONTROL | WRITE_DAC) & !decided & all;
        decided |= b;
        granted |= b;
        set(&mut by, b, true, "Owner");
        steps.push(Step { stage: "Owner", lines: vec![(Mark::Yes, format!("{} owns it, so may always see and change its permissions.", who.name))] });
    } else {
        let line = if is_owner {
            "Owns it, but an Owner Rights rule decides instead.".to_string()
        } else {
            format!("{} owns it, not {}.", facts.owner.map_or("Nobody".into(), |o| name(&o)), who.name)
        };
        steps.push(Step { stage: "Owner", lines: vec![(Mark::Skip, line)] });
    }

    // The access list, in its real order.
    match facts.dacl {
        None => {
            let b = all & !decided;
            granted |= b;
            set(&mut by, b, true, "No access list");
            steps.push(Step { stage: "Access List", lines: vec![(Mark::Yes, "There's no access list, so everything not already held back is allowed.".into())] });
        }
        Some(aces) => {
            let mut lines = Vec::new();
            let in_set = |object: &Guid| part.is_some_and(|p| *object == p || obj.part(&p).and_then(|d| d.set) == Some(*object));
            for ace in aces {
                if ace.way == Way::Unknown {
                    lines.push((Mark::Skip, format!("An entry of type 0x{:02x}: skipped, as KACS skips every type it doesn't act on.", ace.byte)));
                    continue;
                }
                if !matches!(ace.way, Way::Allow | Way::Deny) || !ace.applies() {
                    continue;
                }
                let Some(sid) = ace.sid else { continue };
                let matches = who.sids.contains(&sid) || (sid == owner_rights && is_owner);
                if !matches {
                    continue;
                }
                let part_name = ace.object.map(|o| obj.part(&o).map_or_else(|| "a part".to_string(), |d| d.name.clone()));
                let mut label = format!("{} {}", if ace.way == Way::Allow { "Allow" } else { "Deny" }, name(&sid));
                if let Some(p) = &part_name {
                    label.push_str(&format!(" on {p}"));
                }
                if let Some(cond) = &ace.cond {
                    label.push_str(&format!(" when {}", cond.text()));
                }
                if let Some(o) = &ace.object
                    && !in_set(o)
                {
                    lines.push((Mark::Skip, format!("{label}: skipped, it's only for {}.", part_name.unwrap_or_default())));
                    continue;
                }
                if let Some(cond) = &ace.cond {
                    let v = match cond {
                        Cond::Tree(node) => eval(facts, who, node, ace.way == Way::Deny),
                        Cond::Opaque(_) => Three::U,
                    };
                    let skip = if ace.way == Way::Allow { v != Three::T } else { v == Three::F };
                    if skip {
                        lines.push((Mark::Skip, format!("{label}: skipped, the condition is {}.", if v == Three::F { "false" } else { "not known" })));
                        continue;
                    }
                }
                let b = core(obj.mapped(ace.mask)) & all & !decided;
                if b == 0 {
                    lines.push((Mark::Skip, format!("{label}: everything it covers was already decided.")));
                    continue;
                }
                decided |= b;
                let allow = ace.way == Way::Allow;
                if allow {
                    granted |= b;
                }
                set(&mut by, b, allow, &label);
                lines.push((if allow { Mark::Yes } else { Mark::No }, format!("{label}: {} {}.", if allow { "gives" } else { "refuses" }, listed(b))));
            }
            if lines.is_empty() {
                lines.push((Mark::Skip, format!("No rule mentions {} or their groups.", who.name)));
            }
            steps.push(Step { stage: "Access List", lines });
        }
    }

    // Central access policies. None are pushed to KACS on a standalone
    // machine yet, so each one named is replaced by the recovery policy:
    // Administrators, Local System and the owner keep their access, and
    // everyone else loses it.
    if !facts.sacl {
        steps.push(Step { stage: "Central Policy", lines: vec![(Mark::Skip, "Not known: it's in the SACL, which the program that opened this can't read.".into())] });
    } else if s.policies.is_empty() {
        steps.push(Step { stage: "Central Policy", lines: vec![(Mark::Skip, "None named.".into())] });
    } else {
        let admins: Sid = "S-1-5-32-544".parse().expect("Administrators");
        let system: Sid = "S-1-5-18".parse().expect("Local System");
        let mut lines = Vec::new();
        for p in &s.policies {
            let kept = who.sids.contains(&admins) || who.sids.contains(&system) || is_owner;
            let allow = if kept { all } else { 0 };
            let cut = granted & !allow;
            granted &= allow;
            set(&mut by, cut, false, "Central policy (recovery)");
            let line = if cut != 0 {
                format!("{}: not defined on this machine, so KACS applies the recovery policy, which takes away {}.", p.sid, listed(cut))
            } else {
                format!("{}: not defined on this machine, so KACS applies the recovery policy, which lets {} keep what the list gave.", p.sid, who.name)
            };
            lines.push((if cut != 0 { Mark::No } else { Mark::Skip }, line));
        }
        steps.push(Step { stage: "Central Policy", lines });
    }
    Result { granted, by, steps }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::view::tests::{folder, read};

    fn person(sid: &str, groups: &[&str], claims: &[(&str, &str)]) -> Person {
        let mut sids: Vec<Sid> = groups.iter().map(|g| g.parse().unwrap()).collect();
        sids.push(sid.parse().unwrap());
        sids.push("S-1-1-0".parse().unwrap());
        sids.push("S-1-5-11".parse().unwrap());
        Person {
            sid: sid.parse().unwrap(),
            name: "alice".into(),
            sids,
            device: vec![],
            claims: claims.iter().map(|(k, v)| (k.to_lowercase(), vec![v.to_string()])).collect(),
            integrity: 8192,
        }
    }

    fn check(text: &str, who: &Person) -> Result {
        let f = folder();
        let (sd, _, mut ids) = read(text);
        let s = Simple::read(&f, sd.dacl.as_ref().map(|a| a.aces.as_slice()), sd.sacl.as_ref().map(|a| a.aces.as_slice()));
        let (dacl, _) = s.write(&f, &mut ids);
        let name = |s: &Sid| s.to_string();
        let facts = Facts { obj: &f, simple: &s, dacl: dacl.as_deref(), owner: sd.owner, sacl: true, name: &name };
        effective(&facts, who, None)
    }

    #[test]
    fn the_list_is_read_in_its_real_order() {
        let alice = person("S-1-5-21-1-2-3-1002", &["S-1-5-21-1-2-3-1105", "S-1-5-21-1-2-3-1106"], &[]);
        // Out of order, Finance's allow decides Write before the refusal.
        let r = check("O:SYG:SYD:(A;OICI;0x1301bf;;;S-1-5-21-1-2-3-1105)(D;OICI;0x10156;;;S-1-5-21-1-2-3-1106)", &alice);
        assert_eq!(r.granted & 0x2, 0x2);
        let r = check("O:SYG:SYD:(D;OICI;0x10156;;;S-1-5-21-1-2-3-1106)(A;OICI;0x1301bf;;;S-1-5-21-1-2-3-1105)", &alice);
        assert_eq!(r.granted & 0x2, 0);
        assert!(!r.by[&0x2].0);
    }

    #[test]
    fn a_condition_that_is_not_known_does_not_allow() {
        let dana = person("S-1-5-21-1-2-3-1001", &[], &[("User.Department", "Finance")]);
        let r = check("O:SYG:SYD:(XA;;0x1;;;WD;(@User.Department == \"Finance\"))S:", &dana);
        assert_eq!(r.granted & 1, 1);
        let kim = person("S-1-5-21-1-2-3-1004", &[], &[]);
        let r = check("O:SYG:SYD:(XA;;0x1;;;WD;(@User.Department == \"Finance\"))S:", &kim);
        assert_eq!(r.granted & 1, 0);
        // A refusal whose condition isn't known still refuses.
        let r = check("O:SYG:SYD:(XD;;0x1;;;WD;(@User.Department == \"Finance\"))(A;;0x1;;;WD)S:", &kim);
        assert_eq!(r.granted & 1, 0);
    }

    #[test]
    fn the_owner_may_always_change_permissions_and_a_label_holds_back_writes() {
        let owner = person("S-1-5-18", &[], &[]);
        let r = check("O:SYG:SYD:S:(ML;;NW;;;HI)", &owner);
        assert_eq!(r.granted & WRITE_DAC, 0, "WRITE_DAC is a write, held back by the High label");
        assert_eq!(r.granted & READ_CONTROL, READ_CONTROL);
        let r = check("O:SYG:SYD:", &owner);
        assert_eq!(r.granted & (READ_CONTROL | WRITE_DAC), READ_CONTROL | WRITE_DAC);
    }
}
