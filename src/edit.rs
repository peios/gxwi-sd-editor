//! What the simple view's controls do to it: ticking a right, the rules
//! that depend on a condition, the rules for parts, auditing, claims,
//! policies, and taking someone away. Each changes only the rules it is
//! about; the rest of the view is written back as it was read.

use peios::security::Sid;

use crate::claim::{Claim, ClaimType};
use crate::cond::{Cond, Node};
use crate::sd::*;
use crate::view::*;

/// How one box shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tick {
    No,
    /// Ticked by what was made here, which the box changes.
    Yes,
    /// Ticked by what is inherited, which it cannot.
    Inherited,
}

/// A rule that depends on a condition: up to two entries, an allow and a
/// refusal, for one person and one scope, sharing one condition.
#[derive(Clone, Debug, PartialEq)]
pub struct Card {
    /// The id of its first entry, which is the card's.
    pub key: u32,
    pub sid: Sid,
    pub flags: u8,
    pub allow: Option<u32>,
    pub deny: Option<u32>,
    pub allow_mask: u32,
    pub deny_mask: u32,
    pub node: Node,
    pub inherited: bool,
}

/// Whose condition: a card's, a rule for parts', an auditing rule's, or an
/// entry's in Advanced mode, by its key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CondOf {
    Card(u32),
    Rule(u32),
    Audit(u32),
    Entry(u32),
}

impl CondOf {
    pub fn key(self) -> String {
        match self {
            CondOf::Card(k) => format!("d{k}"),
            CondOf::Rule(k) => format!("r{k}"),
            CondOf::Audit(k) => format!("a{k}"),
            CondOf::Entry(k) => format!("x{k}"),
        }
    }

    pub fn parse(text: &str) -> Option<CondOf> {
        let (kind, n) = text.split_at_checked(1)?;
        let n = n.parse().ok()?;
        Some(match kind {
            "d" => CondOf::Card(n),
            "r" => CondOf::Rule(n),
            "a" => CondOf::Audit(n),
            "x" => CondOf::Entry(n),
            _ => return None,
        })
    }
}

/// Whether an entry is one the boxes of Access stand for.
pub fn plain(e: &Entry) -> bool {
    e.kept.is_none() && e.ace.cond.is_none() && e.ace.object.is_none() && matches!(e.ace.way, Way::Allow | Way::Deny)
}

/// Its rank in the standard order: what is made here before what is
/// inherited, refusals before allows.
pub fn rank(ace: &Ace) -> u8 {
    (if ace.inherited() { 2 } else { 0 }) + (if ace.way == Way::Allow { 1 } else { 0 })
}

/// The standard order of a list, keeping each entry KACS does not act on
/// next to the one it followed.
pub fn in_order(aces: Vec<Ace>) -> Vec<Ace> {
    let mut last = 0;
    let mut keyed: Vec<(u8, usize, Ace)> = aces
        .into_iter()
        .enumerate()
        .map(|(i, a)| {
            if matches!(a.way, Way::Allow | Way::Deny) {
                last = rank(&a);
            }
            (last, i, a)
        })
        .collect();
    keyed.sort_by_key(|(r, i, _)| (*r, *i));
    keyed.into_iter().map(|(_, _, a)| a).collect()
}

/// The first two entries out of the standard order, if there are any.
/// Entries KACS does not act on do not count: it skips them.
pub fn disorder(aces: &[Ace]) -> Option<(Ace, Ace)> {
    let known: Vec<&Ace> = aces.iter().filter(|a| matches!(a.way, Way::Allow | Way::Deny)).collect();
    for j in 1..known.len() {
        for i in 0..j {
            if rank(known[j]) < rank(known[i]) {
                return Some((known[i].clone(), known[j].clone()));
            }
        }
    }
    None
}

impl Simple {
    fn dacl_mut(&mut self) -> &mut Vec<Entry> {
        self.dacl.get_or_insert_with(Vec::new)
    }

    /// The plain entries for `sid` in `scope` (on a container), made here
    /// and inherited, by the masks they make between them, mapped.
    pub fn masks(&self, obj: &Obj, sid: &Sid, scope: u8) -> ((u32, u32), (u32, u32)) {
        let (mut made, mut inh) = ((0, 0), (0, 0));
        for e in self.entries().iter().filter(|e| plain(e) && e.ace.sid.as_ref() == Some(sid) && (!obj.container || e.ace.flags & SHAPE == scope)) {
            let pair = if e.ace.inherited() { &mut inh } else { &mut made };
            if e.ace.way == Way::Allow {
                pair.0 |= obj.mapped(e.ace.mask);
            } else {
                pair.1 |= obj.mapped(e.ace.mask);
            }
        }
        (made, inh)
    }

    /// How the boxes for `rights` show for `sid` in `scope`: allowed, denied.
    pub fn shown(&self, obj: &Obj, sid: &Sid, scope: u8, rights: &[u32]) -> Vec<(Tick, Tick)> {
        let (made, inh) = self.masks(obj, sid, scope);
        let tick = |m: u32, i: u32, mask: u32| {
            if core(m) & core(mask) == core(mask) {
                Tick::Yes
            } else if core(m | i) & core(mask) == core(mask) {
                Tick::Inherited
            } else {
                Tick::No
            }
        };
        rights.iter().map(|&r| (tick(made.0, inh.0, r), tick(made.1, inh.1, r))).collect()
    }

    /// Whether the general rights can say everything `sid` has in `scope`.
    pub fn simple_for(&self, obj: &Obj, sid: &Sid, scope: u8) -> bool {
        let (made, inh) = self.masks(obj, sid, scope);
        [made.0, made.1, inh.0, inh.1].into_iter().all(|m| obj.fits_general(m))
    }

    /// Puts a new entry where the standard order puts it: refusals before
    /// allows, what is made here before what is inherited.
    pub fn place(&mut self, ace: Ace) {
        let list = self.dacl_mut();
        let first_inherited = list.iter().position(|e| e.ace.inherited()).unwrap_or(list.len());
        let at = if ace.way == Way::Deny { list[..first_inherited].iter().position(|e| e.ace.way == Way::Allow).unwrap_or(first_inherited) } else { first_inherited };
        list.insert(at, Entry { ace, kept: None });
    }

    /// Ticks or unticks `mask` for `sid` in `scope`, allowing or denying.
    /// Ticking one way unticks the other. An entry whose rights come back to
    /// what it was read as takes back the mask it was read with, generic
    /// rights and all (`was`). Whether anything changed.
    pub fn tick(&mut self, obj: &Obj, ids: &mut Ids, was: &dyn Fn(u32) -> Option<u32>, sid: Sid, scope: u8, mask: u32, way: Way, on: bool) -> bool {
        let before = self.dacl.clone();
        let ours = |e: &Entry, w: Way| plain(e) && !e.ace.inherited() && e.ace.way == w && e.ace.sid == Some(sid) && (!obj.container || e.ace.flags & SHAPE == scope);
        let settle = |e: &mut Entry, m: u32| {
            e.ace.mask = match was(e.ace.id) {
                Some(orig) if obj.mapped(orig) == m && orig != m => orig,
                _ => m,
            };
        };
        let take = |list: &mut Vec<Entry>, w: Way| {
            for e in list.iter_mut().filter(|e| ours(e, w)) {
                let m = obj.mapped(e.ace.mask) & !core(mask);
                settle(e, m);
            }
            list.retain(|e| !(ours(e, w) && core(obj.mapped(e.ace.mask)) == 0));
        };
        if on {
            let other = if way == Way::Allow { Way::Deny } else { Way::Allow };
            take(self.dacl_mut(), other);
            let add = if way == Way::Allow && obj.synced() { mask | SYNCHRONIZE } else { core(mask) };
            match self.dacl_mut().iter_mut().find(|e| ours(e, way)) {
                Some(e) => {
                    let m = obj.mapped(e.ace.mask) | add;
                    settle(e, m);
                }
                None => {
                    let flags = if obj.container { scope } else { 0 };
                    self.place(Ace::new(ids.next(), way, flags, add, sid));
                }
            }
        } else if self.dacl.is_some() {
            take(self.dacl_mut(), way);
        }
        self.dacl != before
    }

    /// Takes away everything made here for `sid`: its entries, its rules for
    /// parts, and its auditing, if the SACL may be changed. What it inherits
    /// stays. Whether anything changed.
    pub fn remove(&mut self, sid: &Sid, sacl: bool) -> bool {
        let before = self.clone();
        if let Some(list) = &mut self.dacl {
            list.retain(|e| e.ace.sid.as_ref() != Some(sid) || e.ace.inherited());
        }
        self.parts.retain(|r| r.sid != *sid);
        if sacl {
            self.audits.retain(|a| a.sid != *sid || a.inherited);
        }
        *self != before
    }

    /// The rules for `sid` that depend on a condition.
    pub fn cards(&self, sid: &Sid) -> Vec<Card> {
        let mut cards: Vec<Card> = Vec::new();
        for e in self.entries() {
            let (Some(Cond::Tree(node)), true, Some(s)) = (&e.ace.cond, e.kept.is_none() && e.ace.object.is_none(), e.ace.sid) else { continue };
            if s != *sid {
                continue;
            }
            let shape = e.ace.flags & SHAPE;
            let card = cards.iter_mut().find(|c| c.flags == shape && c.inherited == e.ace.inherited() && c.node == *node && (if e.ace.way == Way::Allow { c.allow.is_none() } else { c.deny.is_none() }));
            let card = match card {
                Some(c) => c,
                None => {
                    cards.push(Card { key: e.ace.id, sid: s, flags: shape, allow: None, deny: None, allow_mask: 0, deny_mask: 0, node: node.clone(), inherited: e.ace.inherited() });
                    cards.last_mut().expect("a card")
                }
            };
            if e.ace.way == Way::Allow {
                card.allow = Some(e.ace.id);
                card.allow_mask = e.ace.mask;
            } else {
                card.deny = Some(e.ace.id);
                card.deny_mask = e.ace.mask;
            }
        }
        cards
    }

    pub fn card(&self, key: u32) -> Option<Card> {
        let sid = self.entries().iter().find(|e| e.ace.id == key)?.ace.sid?;
        self.cards(&sid).into_iter().find(|c| c.key == key || c.allow == Some(key) || c.deny == Some(key))
    }

    fn entry_mut(&mut self, id: u32) -> Option<&mut Entry> {
        self.dacl.as_mut()?.iter_mut().find(|e| e.ace.id == id)
    }

    /// A new rule depending on a condition for `sid`, allowing the
    /// second-least general right. Its key.
    pub fn new_card(&mut self, obj: &Obj, ids: &mut Ids, sid: Sid) -> u32 {
        let mask = obj.general.iter().rev().nth(1).or(obj.general.last()).map_or(0, |r| r.mask);
        let id = ids.next();
        self.place(Ace { cond: Some(Cond::Tree(Node::fresh())), ..Ace::new(id, Way::Allow, obj.home(), mask, sid) });
        id
    }

    pub fn remove_card(&mut self, key: u32) {
        if let Some(card) = self.card(key) {
            let gone = [card.allow, card.deny];
            self.dacl_mut().retain(|e| !gone.contains(&Some(e.ace.id)));
        }
    }

    /// Ticks or unticks `mask` on a card. A card that is left giving and
    /// refusing nothing keeps one entry, with no rights, which Apply then
    /// refuses: it is not taken away under the person.
    pub fn card_tick(&mut self, obj: &Obj, ids: &mut Ids, key: u32, mask: u32, way: Way, on: bool) {
        let Some(card) = self.card(key) else { return };
        let (mine, other) = if way == Way::Allow { (card.allow, card.deny) } else { (card.deny, card.allow) };
        if on {
            if let Some(e) = other.and_then(|id| self.entry_mut(id)) {
                e.ace.mask &= !core(mask);
            }
            let add = if way == Way::Allow && obj.synced() { mask | SYNCHRONIZE } else { core(mask) };
            match mine.and_then(|id| self.entry_mut(id)) {
                Some(e) => e.ace.mask |= add,
                None => {
                    let ace = Ace { cond: Some(Cond::Tree(card.node.clone())), ..Ace::new(ids.next(), way, card.flags, add, card.sid) };
                    self.place(ace);
                }
            }
        } else if let Some(e) = mine.and_then(|id| self.entry_mut(id)) {
            e.ace.mask &= !core(mask);
        }
        let Some(now) = self.card(key) else { return };
        let ids_now: Vec<u32> = [now.allow, now.deny].into_iter().flatten().collect();
        let empty: Vec<u32> = ids_now.iter().copied().filter(|id| self.entries().iter().any(|e| e.ace.id == *id && core(e.ace.mask) == 0)).collect();
        let drop: Vec<u32> = if empty.len() < ids_now.len() { empty } else { empty.into_iter().skip(1).collect() };
        self.dacl_mut().retain(|e| !drop.contains(&e.ace.id));
    }

    /// Sets where a card applies, for both its entries.
    pub fn card_scope(&mut self, key: u32, flags: u8) {
        let Some(card) = self.card(key) else { return };
        for id in [card.allow, card.deny].into_iter().flatten() {
            if let Some(e) = self.entry_mut(id) {
                e.ace.flags = (e.ace.flags & !SHAPE) | flags;
            }
        }
    }

    /// The condition a key names.
    pub fn cond(&self, of: CondOf) -> Option<&Node> {
        match of {
            CondOf::Card(key) => {
                let card = self.card(key)?;
                let id = card.allow.or(card.deny)?;
                self.entries().iter().find(|e| e.ace.id == id)?.ace.cond.as_ref()?.tree()
            }
            CondOf::Rule(key) => self.parts.iter().find(|r| r.ids.first() == Some(&key))?.cond.as_ref()?.tree(),
            CondOf::Audit(key) => self.audits.iter().find(|a| a.ids.first() == Some(&key))?.cond.as_ref()?.tree(),
            CondOf::Entry(_) => None,
        }
    }

    /// Changes the condition a key names, everywhere it is: a card's two
    /// entries share theirs. `None` takes the condition away.
    pub fn with_cond(&mut self, of: CondOf, change: impl Fn(&mut Option<Cond>)) {
        match of {
            CondOf::Card(key) => {
                let Some(card) = self.card(key) else { return };
                for id in [card.allow, card.deny].into_iter().flatten() {
                    if let Some(e) = self.entry_mut(id) {
                        change(&mut e.ace.cond);
                    }
                }
            }
            CondOf::Rule(key) => {
                if let Some(r) = self.parts.iter_mut().find(|r| r.ids.first() == Some(&key)) {
                    change(&mut r.cond);
                }
            }
            CondOf::Audit(key) => {
                if let Some(a) = self.audits.iter_mut().find(|a| a.ids.first() == Some(&key)) {
                    change(&mut a.cond);
                }
            }
            CondOf::Entry(_) => {}
        }
    }

    pub fn rule_mut(&mut self, key: u32) -> Option<&mut PartRule> {
        self.parts.iter_mut().find(|r| r.ids.first() == Some(&key))
    }

    /// A new rule for parts of the object, for `sid`, reading the first
    /// part. Its key.
    pub fn new_rule(&mut self, obj: &Obj, ids: &mut Ids, sid: Sid) -> Option<u32> {
        let part = obj.parts.first()?.guid;
        let id = ids.next();
        let flags = if obj.container { obj.home() } else { 0 };
        let read = obj.part_rights().first().map_or(0x10, |(_, m)| *m);
        self.parts.push(PartRule { ids: vec![id], sid, parts: vec![part], allow: read, deny: 0, cond: None, flags, kind: None, deny_at: usize::MAX, allow_at: usize::MAX });
        Some(id)
    }

    pub fn audit_mut(&mut self, key: u32) -> Option<&mut Audit> {
        self.audits.iter_mut().find(|a| a.ids.first() == Some(&key))
    }

    /// A new auditing rule for `sid`, recording failures to write. Its key.
    pub fn new_audit(&mut self, obj: &Obj, ids: &mut Ids, sid: Sid) -> u32 {
        let write = obj.general.iter().find(|r| r.name.eq_ignore_ascii_case("Write")).map_or(obj.generic.write, |r| r.mask);
        let id = ids.next();
        self.sacl = true;
        self.audits.push(Audit { ids: vec![id], sid, flags: obj.home(), ok: 0, fail: write, cond: None, parts: None, kind: None, every: false, inherited: false });
        id
    }

    pub fn new_claim(&mut self, obj: &Obj, ids: &mut Ids) -> u32 {
        let id = ids.next();
        self.sacl = true;
        self.claims.push(ClaimItem { id, claim: Claim { name: String::new(), kind: ClaimType::Text, flags: 0, values: vec![] }, inherit: obj.container, inherited: false });
        id
    }

    /// Puts the access list in the standard order.
    pub fn put_in_order(&mut self) {
        if let Some(list) = self.dacl.take() {
            let aces: Vec<Ace> = list.iter().map(|e| e.ace.clone()).collect();
            let ordered = in_order(aces);
            self.dacl = Some(ordered.into_iter().map(|a| list.iter().find(|e| e.ace.id == a.id).expect("the same entries").clone()).collect());
        }
    }

    /// Stops taking access from the parent: keeping what it gives now as
    /// this object's own, or removing it.
    pub fn stop_access(&mut self, keep: bool) {
        if let Some(list) = &mut self.dacl {
            if keep {
                for e in list.iter_mut() {
                    e.ace.flags &= !ID;
                }
            } else {
                list.retain(|e| !e.ace.inherited());
            }
        }
    }

    /// Stops taking auditing, labels, claims and policies from the parent.
    pub fn stop_sacl(&mut self, keep: bool) {
        if keep {
            for a in &mut self.audits {
                a.inherited = false;
            }
            for c in &mut self.claims {
                c.inherited = false;
            }
            for p in &mut self.policies {
                p.inherited = false;
            }
            if let Some(l) = &mut self.label {
                l.inherited = false;
            }
            if let Some(t) = &mut self.trust {
                t.inherited = false;
            }
            for e in &mut self.skept {
                e.ace.flags &= !ID;
            }
        } else {
            self.audits.retain(|a| !a.inherited);
            self.claims.retain(|c| !c.inherited);
            self.policies.retain(|p| !p.inherited);
            self.skept.retain(|e| !e.ace.inherited());
            if self.label.as_ref().is_some_and(|l| l.inherited) {
                self.label = None;
            }
            if self.trust.as_ref().is_some_and(|t| t.inherited) {
                self.trust = None;
            }
        }
    }

    /// What the SACL takes from the parent, in words: auditing, and the
    /// label, trust, claims and policies it passes down.
    pub fn sacl_inherited(&self) -> Vec<String> {
        let mut bits = Vec::new();
        let count = |n: usize, one: &str, many: &str, bits: &mut Vec<String>| match n {
            0 => {}
            1 => bits.push(one.into()),
            n => bits.push(format!("{n} {many}")),
        };
        count(self.audits.iter().filter(|a| a.inherited).count(), "1 auditing rule", "auditing rules", &mut bits);
        if self.label.as_ref().is_some_and(|l| l.inherited) {
            bits.push("the integrity label".into());
        }
        if self.trust.as_ref().is_some_and(|t| t.inherited) {
            bits.push("the process trust label".into());
        }
        count(self.claims.iter().filter(|c| c.inherited).count(), "1 claim", "claims", &mut bits);
        count(self.policies.iter().filter(|p| p.inherited).count(), "1 central access policy", "central access policies", &mut bits);
        bits
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::view::tests::{folder, read};

    fn simple(text: &str) -> (Simple, Ids) {
        let (sd, _, ids) = read(text);
        (Simple::read(&folder(), sd.dacl.as_ref().map(|a| a.aces.as_slice()), sd.sacl.as_ref().map(|a| a.aces.as_slice())), ids)
    }

    fn sid(text: &str) -> Sid {
        text.parse().unwrap()
    }

    const OICI: u8 = OI | CI;

    #[test]
    fn a_tick_changes_the_entry_it_stands_for_and_a_refusal_goes_first() {
        let f = folder();
        let (mut s, mut ids) = simple("O:SYG:SYD:(A;OICI;0x1200a9;;;WD)(A;OICIID;FA;;;SY)");
        let everyone = sid("S-1-1-0");
        let none = |_: u32| None;
        let write = 0x100116;
        assert!(s.tick(&f, &mut ids, &none, everyone, OICI, write, Way::Allow, true));
        assert_eq!(s.entries()[0].ace.mask, 0x1200a9 | write);
        assert!(s.tick(&f, &mut ids, &none, everyone, OICI, write, Way::Deny, true));
        let ways: Vec<_> = s.entries().iter().map(|e| (e.ace.way, e.ace.mask)).collect();
        assert_eq!(ways[0], (Way::Deny, core(write)));
        assert_eq!(s.shown(&f, &everyone, OICI, &[write])[0], (Tick::No, Tick::Yes));
        // Inherited ticks show, and are not the box's to untick.
        assert_eq!(s.shown(&f, &sid("S-1-5-18"), OICI, &[0x120089])[0], (Tick::Inherited, Tick::No));
        assert!(!s.tick(&f, &mut ids, &none, sid("S-1-5-18"), OICI, 0x120089, Way::Allow, false));
    }

    #[test]
    fn a_generic_right_goes_back_as_it_came_once_ticked_back() {
        let f = folder();
        let (mut s, mut ids) = simple("O:SYG:SYD:(A;OICI;GA;;;WD)");
        let was = |_: u32| Some(GENERIC_ALL);
        let everyone = sid("S-1-1-0");
        assert!(s.tick(&f, &mut ids, &was, everyone, OICI, 0x100116, Way::Allow, false));
        assert_ne!(s.entries()[0].ace.mask, GENERIC_ALL);
        s.tick(&f, &mut ids, &was, everyone, OICI, 0x1f01ff, Way::Allow, true);
        assert_eq!(s.entries()[0].ace.mask, GENERIC_ALL);
    }

    #[test]
    fn cards_share_a_condition_and_keep_one_entry_when_emptied() {
        let f = folder();
        let (mut s, mut ids) = simple("O:SYG:SYD:(XA;OICI;0x1200a9;;;WD;(@User.X == 1))");
        let key = s.cards(&sid("S-1-1-0"))[0].key;
        s.card_tick(&f, &mut ids, key, 0x100116, Way::Deny, true);
        let card = s.card(key).unwrap();
        assert!(card.allow.is_some() && card.deny.is_some());
        assert_eq!(s.entries()[0].ace.way, Way::Deny, "the refusal goes first");
        s.with_cond(CondOf::Card(key), |c| *c = Some(Cond::Tree(Node::fresh())));
        assert!(s.entries().iter().all(|e| e.ace.cond == Some(Cond::Tree(Node::fresh()))));
        s.card_tick(&f, &mut ids, key, 0x100116, Way::Deny, false);
        s.card_tick(&f, &mut ids, key, 0x1200a9, Way::Allow, false);
        assert_eq!(s.entries().len(), 1, "one entry stays, with nothing in it");
        assert_eq!(core(s.entries()[0].ace.mask), 0);
    }

    #[test]
    fn the_standard_order_keeps_what_kacs_skips_beside_what_it_followed() {
        let (s, _) = simple("O:SYG:SYD:(A;;0x1;;;WD)(D;;0x1;;;AU)(A;ID;0x1;;;SY)");
        let aces: Vec<Ace> = s.entries().iter().map(|e| e.ace.clone()).collect();
        assert!(disorder(&aces).is_some());
        let ordered = in_order(aces);
        assert_eq!(ordered[0].way, Way::Deny);
        assert!(disorder(&ordered).is_none());
    }

    #[test]
    fn stopping_inheritance_keeps_or_removes_what_came_down() {
        let (mut s, _) = simple("O:SYG:SYD:(A;;0x1;;;WD)(A;OICIID;FA;;;SY)S:(ML;OICIID;NW;;;ME)(AU;OICIIDFA;0x1;;;WD)");
        assert_eq!(s.sacl_inherited(), ["1 auditing rule", "the integrity label"]);
        let mut kept = s.clone();
        kept.stop_access(true);
        kept.stop_sacl(true);
        assert!(kept.entries().iter().all(|e| !e.ace.inherited()) && kept.sacl_inherited().is_empty());
        s.stop_access(false);
        s.stop_sacl(false);
        assert_eq!(s.entries().len(), 1);
        assert!(s.label.is_none() && s.audits.is_empty());
    }
}
