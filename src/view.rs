//! The simple view of a descriptor: what the tabs show and change, drawn
//! from the descriptor's own entries and written back as them.
//!
//! The entries are what is edited. [`Simple::read`] reads them into the
//! rules a person sees: plain entries in place, conditional entries in
//! place, the rules for parts of an object, auditing, the label, process
//! trust, claims and central policies. [`Simple::write`] writes the rules
//! back as entries. Every change to the simple view is read, changed and
//! written, and anything the simple view cannot say is kept where it was
//! found, so reading and writing an unchanged list gives back that list.
//! Each rule carries the ids of the entries it came from, which the entries
//! it is written as take, so the rule stays the same rule as it is changed,
//! and an entry that comes out the same goes back as the bytes it came as.

use std::collections::HashSet;

use gxwi_sd_editor::{Children, Generic, PartKind, Right};
use peios::security::Sid;

use crate::claim::{self, Claim};
use crate::cond::Cond;
use crate::sd::*;

/// The integrity levels the simple view names, by RID.
pub const INTEGRITY: &[(&str, u32)] = &[("Untrusted", 0), ("Low", 4096), ("Medium", 8192), ("High", 12288), ("System", 16384)];

pub fn level_name(rid: u32) -> Option<&'static str> {
    INTEGRITY.iter().find(|(_, n)| *n == rid).map(|(k, _)| *k)
}

/// A part of the object, by its GUID.
#[derive(Clone, Debug, PartialEq)]
pub struct PartDef {
    pub guid: Guid,
    pub name: String,
    pub kind: PartKind,
    /// The set it is in, for a property.
    pub set: Option<Guid>,
}

/// What the object is, as the simple view needs it.
#[derive(Clone, Debug)]
pub struct Obj {
    pub name: String,
    pub kind: String,
    pub container: bool,
    pub children: Children,
    /// What its inherited entries come from, as the person knows it.
    pub from: Option<String>,
    /// The general rights, from the most to the least, and the rest.
    pub general: Vec<Right>,
    pub specific: Vec<Right>,
    pub generic: Generic,
    pub parts: Vec<PartDef>,
    pub kinds: Vec<(Guid, String)>,
    /// What a rule for a part can give, where the program says.
    pub part_rights: Vec<(String, u32)>,
    /// How a part not listed is named, where one can be.
    pub naming: Option<NamingDef>,
}

/// How a part not listed is named: its GUID is UUID v5 of its name in
/// `namespace`.
#[derive(Clone, Debug, PartialEq)]
pub struct NamingDef {
    pub namespace: Guid,
    pub noun: String,
    pub example: Option<String>,
}

impl Obj {
    /// What a rule for a part can give: what the program says, or what a
    /// directory's parts take.
    pub fn part_rights(&self) -> Vec<(String, u32)> {
        if self.part_rights.is_empty() {
            return vec![("Read".into(), 0x10), ("Write".into(), 0x20), ("Use (actions)".into(), 0x100)];
        }
        self.part_rights.clone()
    }

    /// Every right a rule for a part can give.
    pub fn part_mask(&self) -> u32 {
        self.part_rights().iter().fold(0, |a, (_, m)| a | m)
    }

    /// The part `name` names, added to the parts if it isn't one already.
    pub fn named(&mut self, name: &str) -> Option<Guid> {
        let naming = self.naming.as_ref()?;
        let name = name.trim();
        if name.is_empty() {
            return None;
        }
        let guid = named_guid(&naming.namespace, name);
        if self.part(&guid).is_none() {
            self.parts.push(PartDef { guid, name: name.to_string(), kind: PartKind::Property, set: None });
        }
        Some(guid)
    }

    /// Where an entry can apply on it: the shape flags, and what they are
    /// called. "One level down" is a box of its own.
    pub fn scopes(&self) -> Vec<(u8, String)> {
        if !self.container {
            return vec![];
        }
        let k = self.kind.to_lowercase();
        let folder = k == "folder";
        match self.children {
            Children::Containers => vec![
                (CI, format!("This {k} and everything in it")),
                (0, format!("This {k} only")),
                (CI | IO, "Only what's inside".into()),
            ],
            Children::All if folder => vec![
                (OI | CI, "This folder, subfolders and files".into()),
                (0, "This folder only".into()),
                (OI | CI | IO, "Subfolders and files only".into()),
                (CI, "This folder and subfolders".into()),
                (OI, "This folder and files".into()),
                (CI | IO, "Subfolders only".into()),
                (OI | IO, "Files only".into()),
            ],
            Children::All => vec![
                (OI | CI, format!("This {k} and everything in it")),
                (0, format!("This {k} only")),
                (OI | CI | IO, "Only what's inside".into()),
                (CI, format!("This {k} and the containers in it")),
                (OI, format!("This {k} and the other items in it")),
                (CI | IO, "Only the containers inside".into()),
                (OI | IO, "Only the other items inside".into()),
            ],
        }
    }

    /// The scope a new rule gets: on a container, the whole of it.
    pub fn home(&self) -> u8 {
        self.scopes().first().map_or(0, |(f, _)| *f)
    }

    pub fn scope_label(&self, flags: u8) -> String {
        let base = flags & !NP;
        let label = self.scopes().into_iter().find(|(f, _)| *f == base).map_or_else(|| "Custom".to_string(), |(_, l)| l);
        if flags & NP != 0 && passes(flags) { format!("{label}, one level down") } else { label }
    }

    /// Whether the scope picker has a choice for these shape flags.
    pub fn placed(&self, shape: u8) -> bool {
        if !self.container {
            return shape == 0;
        }
        self.scopes().iter().any(|(f, _)| *f == shape & !NP) && (shape & NP == 0 || passes(shape))
    }

    /// The flags a label, trust label, claim or policy is passed on with.
    pub fn sacl_flags(&self, inherit: bool) -> u8 {
        if inherit && self.container { self.home() & !IO } else { 0 }
    }

    /// `mask` with its generic rights as the rights they stand for here.
    pub fn mapped(&self, mask: u32) -> u32 {
        let g = &self.generic;
        let mut out = mask & !GENERIC;
        for (bit, means) in [(GENERIC_READ, g.read), (GENERIC_WRITE, g.write), (GENERIC_EXECUTE, g.execute), (GENERIC_ALL, g.all)] {
            if mask & bit != 0 {
                out |= means;
            }
        }
        out
    }

    /// Whether the general rights can say all of `mask` between them.
    pub fn fits_general(&self, mask: u32) -> bool {
        let m = core(self.mapped(mask));
        let covered = self.general.iter().filter(|r| m & core(r.mask) == core(r.mask)).fold(0, |a, r| a | core(r.mask));
        m == covered
    }

    /// Whether Synchronize goes with what is allowed, as it does wherever a
    /// general right includes it.
    pub fn synced(&self) -> bool {
        self.general.iter().any(|r| r.mask & SYNCHRONIZE != 0)
    }

    pub fn part(&self, guid: &Guid) -> Option<&PartDef> {
        self.parts.iter().find(|p| p.guid == *guid)
    }

    pub fn kind_name(&self, guid: &Guid) -> Option<&str> {
        self.kinds.iter().find(|(g, _)| g == guid).map(|(_, n)| n.as_str())
    }

    /// The general right a mask is exactly, by name.
    pub fn level_name(&self, mask: u32) -> Option<&str> {
        self.general.iter().find(|r| core(r.mask) == core(self.mapped(mask))).map(|r| r.name.as_str())
    }

    /// Every right it names, specific first.
    pub fn all_rights(&self) -> u32 {
        self.specific.iter().chain(&self.general).fold(0, |a, r| a | r.mask)
    }
}

/// A mask without Synchronize, which no comparison counts.
pub fn core(mask: u32) -> u32 {
    mask & !SYNCHRONIZE
}

/// An entry of the access list as the simple view keeps it.
#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    pub ace: Ace,
    /// Why the simple view cannot show it, if it cannot: it is then kept
    /// where it was, and only Advanced mode shows it.
    pub kept: Option<String>,
}

/// A rule for parts of the object: one entry for each part, allowing and
/// denying.
#[derive(Clone, Debug, PartialEq)]
pub struct PartRule {
    pub ids: Vec<u32>,
    pub sid: Sid,
    pub parts: Vec<Guid>,
    pub allow: u32,
    pub deny: u32,
    pub cond: Option<Cond>,
    pub flags: u8,
    pub kind: Option<Guid>,
    /// Where its refusals and its allows were read, for writing them back
    /// in that order: a new rule's go after the rest.
    pub deny_at: usize,
    pub allow_at: usize,
}

/// An auditing rule.
#[derive(Clone, Debug, PartialEq)]
pub struct Audit {
    pub ids: Vec<u32>,
    pub sid: Sid,
    /// Where it applies: shape flags only.
    pub flags: u8,
    pub ok: u32,
    pub fail: u32,
    pub cond: Option<Cond>,
    /// `None` covers all of the object.
    pub parts: Option<Vec<Guid>>,
    pub kind: Option<Guid>,
    /// Every use while it is open, not just the opening: an alarm entry.
    pub every: bool,
    pub inherited: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Label {
    pub id: u32,
    pub level: u32,
    /// No write up, no read up, no execute up.
    pub policy: u32,
    pub inherit: bool,
    pub inherited: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Trust {
    pub id: u32,
    pub pip_type: u32,
    pub trust: u32,
    /// What less trusted programs may do.
    pub mask: u32,
    pub inherit: bool,
    pub inherited: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ClaimItem {
    pub id: u32,
    pub claim: Claim,
    pub inherit: bool,
    pub inherited: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Policy {
    pub id: u32,
    pub sid: Sid,
    pub inherit: bool,
    pub inherited: bool,
}

/// The simple view of both lists.
#[derive(Clone, Debug, PartialEq)]
pub struct Simple {
    /// The access list without its rules for parts, in its order, or `None`
    /// where there is none.
    pub dacl: Option<Vec<Entry>>,
    pub parts: Vec<PartRule>,
    /// Whether there is a SACL at all.
    pub sacl: bool,
    pub audits: Vec<Audit>,
    pub label: Option<Label>,
    pub trust: Option<Trust>,
    pub claims: Vec<ClaimItem>,
    pub policies: Vec<Policy>,
    /// What the simple view cannot show of the SACL, with why.
    pub skept: Vec<Entry>,
}

/// Which list an entry is in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum List {
    Dacl,
    Sacl,
}

pub fn level_sid(rid: u32) -> Sid {
    format!("S-1-16-{rid}").parse().expect("an integrity SID")
}

/// The level of an integrity SID, `S-1-16-n`.
pub fn sid_level(sid: &Sid) -> Option<u32> {
    sid.to_string().strip_prefix("S-1-16-")?.parse().ok()
}

/// The type and trust of a process trust SID, `S-1-19-type-trust`.
pub fn sid_trust(sid: &Sid) -> Option<(u32, u32)> {
    let text = sid.to_string();
    let (t, l) = text.strip_prefix("S-1-19-")?.split_once('-')?;
    Some((t.parse().ok()?, l.parse().ok()?))
}

pub fn trust_sid(pip_type: u32, trust: u32) -> Option<Sid> {
    format!("S-1-19-{pip_type}-{trust}").parse().ok()
}

pub fn everyone() -> Sid {
    "S-1-1-0".parse().expect("Everyone")
}

/// Why the simple view cannot show `ace`, or `None` if it can. `labelled`
/// and `trusted` say whether a label or trust label came before it.
pub fn kept_why(obj: &Obj, ace: &Ace, list: List, labelled: bool, trusted: bool) -> Option<String> {
    if ace.way == Way::Unknown {
        let name = crate::sd::unacted(ace.byte).map(|n| format!(" ({n})")).unwrap_or_default();
        return Some(format!("KACS doesn't act on entries of type 0x{:02x}{name}. It skips it when it checks access, and it's kept exactly as found.", ace.byte));
    }
    let shape = ace.flags & SHAPE;
    if ace.flags & IO != 0 && !passes(ace.flags) {
        return Some("It's only for what's inside, but it isn't passed down, so it never applies anywhere.".into());
    }
    if list == List::Dacl && !matches!(ace.way, Way::Allow | Way::Deny) {
        return Some("It's an entry of the SACL's, which does nothing in an access list.".into());
    }
    if list == List::Dacl && ace.flags & (SA | FA) != 0 {
        return Some("It has auditing flags (SA, FA), which do nothing in an access list.".into());
    }
    if list == List::Sacl && matches!(ace.way, Way::Allow | Way::Deny) {
        return Some("It's an access entry, which does nothing in the SACL.".into());
    }
    if ace.way.accessy() {
        if !obj.placed(shape) {
            return Some("It applies in a way the simple view has no choice for.".into());
        }
        if ace.inherited_object.is_some() && ace.object.is_none() {
            return Some("It's passed to one kind of item only but covers all of it, which the simple view can only do for particular parts.".into());
        }
        if ace.inherited_object.is_some_and(|k| obj.kind_name(&k).is_none()) {
            return Some("It's passed to a kind of item the program that opened this doesn't name.".into());
        }
        if matches!(ace.cond, Some(Cond::Opaque(_))) {
            return Some("Its condition is one the simple view can't show.".into());
        }
        if list == List::Sacl && ace.flags & (SA | FA) == 0 {
            return Some("It records neither successes nor failures, so it does nothing.".into());
        }
        return None;
    }
    if shape != 0 && shape != obj.sacl_flags(true) {
        return Some("It's passed down in a way the simple view has no choice for.".into());
    }
    match ace.way {
        Way::Label => {
            if labelled {
                return Some("Only the first integrity label counts, so KACS ignores this one.".into());
            }
            if ace.sid.and_then(|s| sid_level(&s)).and_then(level_name).is_none() {
                return Some("It sets an integrity level the simple view doesn't name.".into());
            }
            if ace.mask & !7 != 0 {
                return Some("Its policy has bits the simple view doesn't name.".into());
            }
        }
        Way::Trust => {
            if trusted {
                return Some("Only the first process trust label counts, so KACS ignores this one.".into());
            }
            if ace.sid.and_then(|s| sid_trust(&s)).is_none() {
                return Some("Its SID isn't a process trust SID.".into());
            }
        }
        Way::Claim => {
            if ace.claim.as_ref().is_some_and(|c| c.flags & !claim::SHOWN != 0) {
                return Some("It has claim flags the simple view doesn't show.".into());
            }
        }
        _ => {}
    }
    None
}

/// Why each entry of a list is kept, by id.
pub fn kept_in(obj: &Obj, aces: &[Ace], list: List) -> Vec<(u32, String)> {
    let mut out = Vec::new();
    let (mut labelled, mut trusted) = (false, false);
    for ace in aces {
        if let Some(why) = kept_why(obj, ace, list, labelled, trusted) {
            out.push((ace.id, why));
        }
        labelled |= ace.way == Way::Label && ace.applies();
        trusted |= ace.way == Way::Trust && ace.applies();
    }
    if list == List::Dacl {
        let kept: HashSet<u32> = out.iter().map(|(id, _)| *id).collect();
        for id in misplaced_parts(obj, aces, &kept) {
            out.push((id, "It's a rule for a particular part that isn't where the standard order puts those rules, so the simple view would move it.".into()));
        }
    }
    out
}

/// The access list read back: plain entries in place, rules for parts
/// grouped, and the entries named in `kept` left where they are.
fn dacl_from(obj: &Obj, aces: &[Ace], kept: &[(u32, String)]) -> (Vec<Entry>, Vec<PartRule>) {
    let mut entries = Vec::new();
    // The runs of entries for parts, before they are paired up: entries
    // that differ only in their part are one run.
    let mut runs: Vec<PartRule> = Vec::new();
    let mut last_part = false;
    for (at, ace) in aces.iter().enumerate() {
        if let Some((_, why)) = kept.iter().find(|(id, _)| *id == ace.id) {
            entries.push(Entry { ace: ace.clone(), kept: Some(why.clone()) });
            last_part = false;
            continue;
        }
        if let (Some(part), Some(sid)) = (ace.object, ace.sid) {
            let allow = ace.way == Way::Allow;
            let joins = last_part
                && runs.last().is_some_and(|r| {
                    r.sid == sid && r.flags == ace.flags && r.kind == ace.inherited_object && r.cond == ace.cond && (if allow { r.allow == ace.mask && r.deny == 0 } else { r.deny == ace.mask && r.allow == 0 }) && !r.parts.contains(&part)
                });
            if joins {
                let r = runs.last_mut().expect("a run");
                r.parts.push(part);
                r.ids.push(ace.id);
            } else {
                runs.push(PartRule {
                    ids: vec![ace.id],
                    sid,
                    parts: vec![part],
                    allow: if allow { ace.mask } else { 0 },
                    deny: if allow { 0 } else { ace.mask },
                    cond: ace.cond.clone(),
                    flags: ace.flags,
                    kind: ace.inherited_object,
                    deny_at: if allow { usize::MAX } else { at },
                    allow_at: if allow { at } else { usize::MAX },
                });
            }
            last_part = true;
            continue;
        }
        last_part = false;
        entries.push(Entry { ace: ace.clone(), kept: None });
    }
    // A refusal and an allow for the same parts, said the same way, are one
    // rule, as the person made it.
    let mut rules: Vec<PartRule> = Vec::new();
    for run in runs {
        let pair = rules.iter_mut().find(|r| {
            let opposite = if run.allow != 0 { r.deny != 0 && r.allow == 0 } else { r.allow != 0 && r.deny == 0 };
            opposite && r.sid == run.sid && r.parts == run.parts && r.flags == run.flags && r.kind == run.kind && r.cond == run.cond
        });
        match pair {
            Some(r) if run.allow != 0 => {
                r.allow = run.allow;
                r.allow_at = run.allow_at;
                r.ids.extend(run.ids);
            }
            Some(r) => {
                r.deny = run.deny;
                r.deny_at = run.deny_at;
                let mut ids = run.ids;
                ids.extend(r.ids.drain(..));
                r.ids = ids;
            }
            None => rules.push(run),
        }
    }
    let _ = obj;
    (entries, rules)
}

/// The entries of a rule for parts, refusals and allows apart.
fn part_aces(r: &PartRule, ids: &mut Ids) -> (Vec<Ace>, Vec<Ace>) {
    let mut taken = r.ids.iter().copied();
    let mut make = |way: Way, mask: u32| -> Vec<Ace> {
        if mask == 0 {
            return vec![];
        }
        r.parts
            .iter()
            .map(|part| {
                let id = taken.next().unwrap_or_else(|| ids.next());
                Ace { object: Some(*part), inherited_object: r.kind, cond: r.cond.clone(), ..Ace::new(id, way, r.flags, mask, r.sid) }
            })
            .collect()
    };
    let deny = make(Way::Deny, r.deny);
    let allow = make(Way::Allow, r.allow);
    (deny, allow)
}

/// The access list in its real order. Rules for parts are written where
/// the standard order puts them: their refusals before the first allow,
/// their allows before what is inherited.
fn write_dacl(entries: &[Entry], rules: &[PartRule], ids: &mut Ids) -> Vec<Ace> {
    let mut denies: Vec<(usize, usize, Vec<Ace>)> = Vec::new();
    let mut allows: Vec<(usize, usize, Vec<Ace>)> = Vec::new();
    for (n, r) in rules.iter().enumerate() {
        let (d, a) = part_aces(r, ids);
        denies.push((r.deny_at, n, d));
        allows.push((r.allow_at, n, a));
    }
    denies.sort_by_key(|(at, n, _)| (*at, *n));
    allows.sort_by_key(|(at, n, _)| (*at, *n));
    let mut denies: Option<Vec<Ace>> = Some(denies.into_iter().flat_map(|(_, _, a)| a).collect());
    let mut allows: Option<Vec<Ace>> = Some(allows.into_iter().flat_map(|(_, _, a)| a).collect());
    let mut out = Vec::new();
    for e in entries {
        if (e.ace.way == Way::Allow || e.ace.inherited())
            && let Some(d) = denies.take()
        {
            out.extend(d);
        }
        if e.ace.inherited()
            && let Some(a) = allows.take()
        {
            out.extend(a);
        }
        out.push(e.ace.clone());
    }
    out.extend(denies.into_iter().flatten());
    out.extend(allows.into_iter().flatten());
    out
}

/// The entries for parts that are not where the standard order puts them,
/// so the simple view would move them: those are kept where they are. Only
/// the ones out of place are kept.
fn misplaced_parts(obj: &Obj, aces: &[Ace], kept: &HashSet<u32>) -> Vec<u32> {
    let mut out: HashSet<u32> = kept.clone();
    let as_kept = |out: &HashSet<u32>| -> Vec<(u32, String)> { out.iter().map(|id| (*id, String::new())).collect() };
    for _ in 0..=aces.len() {
        let (entries, rules) = dacl_from(obj, aces, &as_kept(&out));
        let got = write_dacl(&entries, &rules, &mut Ids::default());
        let differs = (0..aces.len().max(got.len())).find(|&i| match (aces.get(i), got.get(i)) {
            (Some(a), Some(b)) => !a.same(b),
            _ => true,
        });
        let Some(i) = differs else {
            return out.difference(kept).copied().collect();
        };
        // Either the entry found here moved away, or one from further down
        // moved up into its place: keep whichever is the part's.
        let here = aces.get(i).filter(|a| a.object.is_some() && !out.contains(&a.id));
        let moved = || got.get(i).and_then(|g| aces[i..].iter().find(|a| a.object.is_some() && !out.contains(&a.id) && a.same(g)));
        let Some(x) = here.or_else(moved) else { break };
        out.insert(x.id);
    }
    aces.iter().filter(|a| a.object.is_some() && !kept.contains(&a.id)).map(|a| a.id).collect()
}

impl Simple {
    /// The simple view of a descriptor's lists.
    pub fn read(obj: &Obj, dacl: Option<&[Ace]>, sacl: Option<&[Ace]>) -> Simple {
        let mut s = Simple { dacl: None, parts: vec![], sacl: sacl.is_some(), audits: vec![], label: None, trust: None, claims: vec![], policies: vec![], skept: vec![] };
        if let Some(sacl) = sacl {
            let kept = kept_in(obj, sacl, List::Sacl);
            for ace in sacl {
                if let Some((_, why)) = kept.iter().find(|(id, _)| *id == ace.id) {
                    s.skept.push(Entry { ace: ace.clone(), kept: Some(why.clone()) });
                    continue;
                }
                let (inherit, inherited) = (ace.passes(), ace.inherited());
                let sid = ace.sid.expect("a known entry names someone");
                match ace.way {
                    Way::Label => s.label = Some(Label { id: ace.id, level: sid_level(&sid).unwrap_or(8192), policy: ace.mask, inherit, inherited }),
                    Way::Trust => {
                        let (pip_type, trust) = sid_trust(&sid).unwrap_or((0, 0));
                        s.trust = Some(Trust { id: ace.id, pip_type, trust, mask: ace.mask, inherit, inherited });
                    }
                    Way::Claim => s.claims.push(ClaimItem { id: ace.id, claim: ace.claim.clone().expect("a claim entry has its claim"), inherit, inherited }),
                    Way::Policy => s.policies.push(Policy { id: ace.id, sid, inherit, inherited }),
                    _ => {
                        // Auditing: entries that differ only in their parts,
                        // or that record successes and failures of one
                        // thing, are one rule.
                        let a = Audit {
                            ids: vec![ace.id],
                            sid,
                            flags: ace.flags & SHAPE,
                            ok: if ace.flags & SA != 0 { ace.mask } else { 0 },
                            fail: if ace.flags & FA != 0 { ace.mask } else { 0 },
                            cond: ace.cond.clone(),
                            parts: ace.object.map(|p| vec![p]),
                            kind: ace.inherited_object,
                            every: ace.way == Way::Alarm,
                            inherited,
                        };
                        let like = s.audits.last().filter(|l| l.sid == a.sid && l.flags == a.flags && l.kind == a.kind && l.every == a.every && l.inherited == a.inherited && l.cond == a.cond);
                        let joins_parts = like.is_some_and(|l| l.parts.is_some() && a.parts.is_some() && l.ok == a.ok && l.fail == a.fail && !l.parts.as_ref().expect("parts").contains(&a.parts.as_ref().expect("parts")[0]));
                        let joins_fail = like.is_some_and(|l| l.parts == a.parts && l.ok != 0 && l.fail == 0 && a.ok == 0 && a.fail != 0);
                        if joins_parts {
                            let l = s.audits.last_mut().expect("a rule");
                            l.parts.as_mut().expect("parts").push(a.parts.expect("parts")[0]);
                            l.ids.push(ace.id);
                        } else if joins_fail {
                            let l = s.audits.last_mut().expect("a rule");
                            l.fail = a.fail;
                            l.ids.push(ace.id);
                        } else {
                            s.audits.push(a);
                        }
                    }
                }
            }
        }
        if let Some(dacl) = dacl {
            let kept = kept_in(obj, dacl, List::Dacl);
            let (entries, rules) = dacl_from(obj, dacl, &kept);
            s.dacl = Some(entries);
            s.parts = rules;
        }
        s
    }

    /// Both lists, as entries. The SACL is written in the standard order:
    /// label, trust, auditing, claims, policies, then the rest, since its
    /// order changes nothing.
    pub fn write(&self, obj: &Obj, ids: &mut Ids) -> (Option<Vec<Ace>>, Option<Vec<Ace>>) {
        let dacl = self.dacl.as_ref().map(|entries| write_dacl(entries, &self.parts, ids));
        let flags = |inherit: bool, inherited: bool| obj.sacl_flags(inherit) | if inherited { ID } else { 0 };
        let mut sacl = Vec::new();
        if let Some(l) = &self.label {
            sacl.push(Ace::new(l.id, Way::Label, flags(l.inherit, l.inherited), l.policy, level_sid(l.level)));
        }
        if let Some(t) = &self.trust
            && let Some(sid) = trust_sid(t.pip_type, t.trust)
        {
            sacl.push(Ace::new(t.id, Way::Trust, flags(t.inherit, t.inherited), t.mask, sid));
        }
        for a in &self.audits {
            let mut taken = a.ids.iter().copied();
            let way = if a.every { Way::Alarm } else { Way::Audit };
            let base = a.flags | if a.inherited { ID } else { 0 };
            let parts: Vec<Option<Guid>> = match &a.parts {
                Some(parts) => parts.iter().copied().map(Some).collect(),
                None => vec![None],
            };
            for part in parts {
                let mut push = |extra: u8, mask: u32| {
                    let id = taken.next().unwrap_or_else(|| ids.next());
                    sacl.push(Ace { object: part, inherited_object: if part.is_some() { a.kind } else { None }, cond: a.cond.clone(), ..Ace::new(id, way, base | extra, mask, a.sid) });
                };
                if a.ok != 0 && a.ok == a.fail {
                    push(SA | FA, a.ok);
                } else {
                    if a.ok != 0 {
                        push(SA, a.ok);
                    }
                    if a.fail != 0 {
                        push(FA, a.fail);
                    }
                }
            }
        }
        for c in &self.claims {
            sacl.push(Ace { claim: Some(c.claim.clone()), ..Ace::new(c.id, Way::Claim, flags(c.inherit, c.inherited), 0, everyone()) });
        }
        for p in &self.policies {
            sacl.push(Ace::new(p.id, Way::Policy, flags(p.inherit, p.inherited), 0, p.sid));
        }
        sacl.extend(self.skept.iter().map(|e| e.ace.clone()));
        let sacl = (self.sacl || !sacl.is_empty()).then_some(sacl);
        (dacl, sacl)
    }

    pub fn entries(&self) -> &[Entry] {
        self.dacl.as_deref().unwrap_or(&[])
    }

    /// Everyone the lists name, in the order they first come; the SACL's
    /// only if it is to be shown.
    pub fn principals(&self, sacl: bool) -> Vec<Sid> {
        let mut out: Vec<Sid> = Vec::new();
        let mut add = |sid: Sid| {
            if !out.contains(&sid) {
                out.push(sid);
            }
        };
        for e in self.entries() {
            if let (Some(sid), true) = (e.ace.sid, e.ace.way.accessy()) {
                add(sid);
            }
        }
        for r in &self.parts {
            add(r.sid);
        }
        if sacl {
            for a in &self.audits {
                add(a.sid);
            }
        }
        out
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use gxwi_sd_editor::Children;
    use peios::security::sddl;

    pub fn folder() -> Obj {
        let r = |name: &str, mask| Right { name: name.into(), mask, general: true };
        let s = |name: &str, mask| Right { name: name.into(), mask, general: false };
        Obj {
            name: "finance".into(),
            kind: "Folder".into(),
            container: true,
            children: Children::All,
            from: Some("/srv".into()),
            general: vec![r("Full control", 0x1f01ff), r("Modify", 0x1301bf), r("Read & execute", 0x1200a9), r("Read", 0x120089), r("Write", 0x100116)],
            specific: vec![s("List folder / read data", 0x1), s("Create files / write data", 0x2), s("Delete", 0x10000)],
            generic: Generic { read: 0x120089, write: 0x100116, execute: 0x1200a0, all: 0x1f01ff },
            parts: vec![],
            kinds: vec![],
            part_rights: vec![],
            naming: None,
        }
    }

    pub fn container_of_accounts() -> Obj {
        let part = |guid: &str, name: &str, kind| PartDef { guid: guid_parse(guid).unwrap(), name: name.into(), kind, set: None };
        Obj {
            name: "people".into(),
            kind: "Container".into(),
            children: Children::Containers,
            parts: vec![
                part("00299570-246d-11d0-a768-00aa006e0529", "Reset password", PartKind::Right),
                part("bc0ac240-79a9-11d0-9020-00c04fc2d4cf", "Group membership", PartKind::Set),
                part("5805bc62-bdc9-4428-a5e2-856a0f4c185e", "Sign-in details", PartKind::Set),
            ],
            kinds: vec![(guid_parse("bf967aba-0de6-11d0-a285-00aa003049e2").unwrap(), "Accounts".into()), (guid_parse("bf967a9c-0de6-11d0-a285-00aa003049e2").unwrap(), "Groups".into())],
            ..folder()
        }
    }

    pub fn read(text: &str) -> (Descriptor, Found, Ids) {
        let bytes = sddl::parse(text).unwrap().as_bytes().to_vec();
        let (mut found, mut ids) = (Found::default(), Ids::default());
        let sd = Descriptor::parse(&bytes, &mut ids, &mut found).unwrap();
        (sd, found, ids)
    }

    fn round(obj: &Obj, text: &str) -> Simple {
        let (sd, _, mut ids) = read(text);
        let s = Simple::read(obj, sd.dacl.as_ref().map(|a| a.aces.as_slice()), sd.sacl.as_ref().map(|a| a.aces.as_slice()));
        let (dacl, sacl) = s.write(obj, &mut ids);
        assert_eq!(dacl.as_ref(), sd.dacl.as_ref().map(|a| &a.aces), "{text}");
        if let (Some(got), Some(was)) = (&sacl, &sd.sacl) {
            let mut got: Vec<_> = got.iter().map(|a| a.id).collect();
            let mut was: Vec<_> = was.aces.iter().map(|a| a.id).collect();
            got.sort();
            was.sort();
            assert_eq!(got, was, "the SACL's entries, in whatever order: {text}");
        }
        s
    }

    #[test]
    fn reading_and_writing_an_unchanged_list_gives_it_back() {
        let f = folder();
        let s = round(&f, "O:SYG:BAD:(D;OICI;0x10156;;;S-1-5-21-1-2-3-1106)(A;OICI;0x1301bf;;;S-1-5-21-1-2-3-1105)(XA;OICI;0x1200a9;;;S-1-5-21-1-2-3-1107;(@Device.Compliance == \"Compliant\" || Device_Member_of_Any {SID(S-1-5-21-1-2-3-2002)}))(A;;0x1200a9;;;AU)(A;OICIIO;GA;;;CO)(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)S:(ML;OICI;NW;;;ME)(AU;OICISAFA;0x120089;;;S-1-5-21-1-2-3-1106)(AU;OICIFA;0x10156;;;WD)(RA;OICI;;;;WD;(\"Department\",TS,0x0,\"Finance\"))");
        assert!(s.entries().iter().all(|e| e.kept.is_none()));
        assert_eq!(s.label.as_ref().map(|l| (l.level, l.inherit)), Some((8192, true)));
        assert_eq!(s.audits.len(), 2);
        assert_eq!(s.claims[0].claim.values, ["Finance"]);
        // Out of order, and with entries only Advanced mode can show.
        let s = round(&f, "O:SYG:BAD:(A;OICI;0x1301bf;;;S-1-5-21-1-2-3-1105)(D;OICI;0x10156;;;S-1-5-21-1-2-3-1106)(A;IO;0x1200a9;;;S-1-5-21-1-2-3-1003)(A;CIOI;0x1;;;WD)");
        let kept: Vec<_> = s.entries().iter().filter(|e| e.kept.is_some()).map(|e| e.ace.sid.unwrap().to_string()).collect();
        assert_eq!(kept, ["S-1-5-21-1-2-3-1003"]);
    }

    #[test]
    fn rules_for_parts_are_grouped_and_only_the_misplaced_one_is_kept() {
        let c = container_of_accounts();
        // rowan's rule and Auditors' are where the simple view puts them;
        // Contractors' refusal comes after an allow, so it alone is kept.
        let s = round(&c, "O:BAG:BAD:(A;CI;0x20094;;;AU)(OD;CIIO;0x100;00299570-246d-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-21-1-2-3-1106)(OA;CIIO;0x100;00299570-246d-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-21-1-2-3-1000)(OA;CIIO;0x10;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967a9c-0de6-11d0-a285-00aa003049e2;S-1-5-21-1-2-3-1107)(A;CIID;0xf01ff;;;BA)");
        assert_eq!(s.parts.len(), 2);
        let kept: Vec<_> = s.entries().iter().filter(|e| e.kept.is_some()).map(|e| e.ace.sid.unwrap().to_string()).collect();
        assert_eq!(kept, ["S-1-5-21-1-2-3-1106"]);
        // A refusal and an allow for the same parts are one rule.
        let s = round(&c, "O:BAG:BAD:(OD;;0x20;5805bc62-bdc9-4428-a5e2-856a0f4c185e;;S-1-5-21-1-2-3-1106)(A;;0x20094;;;AU)(OA;;0x10;5805bc62-bdc9-4428-a5e2-856a0f4c185e;;S-1-5-21-1-2-3-1106)");
        assert_eq!(s.parts.len(), 1);
        assert_eq!((s.parts[0].allow, s.parts[0].deny), (0x10, 0x20));
    }

    #[test]
    fn what_the_simple_view_cannot_say_is_kept_and_why() {
        let f = folder();
        let s = round(&f, "O:SYG:SYD:(AU;SA;0x1;;;WD)(A;OICISA;0x1;;;WD)(A;OIIO;0x1;;;WD)(XA;OICI;0x1;;;WD;(1 == @User.X))S:(ML;;NW;;;ME)(ML;;NR;;;LW)(ML;;NW;;;S-1-16-5000)");
        let whys: Vec<_> = s.entries().iter().filter_map(|e| e.kept.clone()).collect();
        assert_eq!(whys.len(), 3, "{whys:?}");
        assert!(whys[0].contains("SACL's") && whys[1].contains("auditing flags") && whys[2].contains("condition"), "{whys:?}");
        // OIIO is a folder's "Files only", which the picker has.
        assert_eq!(s.skept.len(), 2);
        assert!(s.skept[0].kept.as_ref().unwrap().contains("Only the first integrity label"));
    }
}
