//! The descriptor being edited, and what ticking a box does to it.
//!
//! The person is shown, for each user or group, the general rights the
//! program named, each allowed, denied or neither, as Windows' editor shows
//! them. Underneath is the access list itself, and a tick changes it as
//! little as it can: the entries the boxes stand for are changed, and every
//! other entry is kept as it was, in its place.
//!
//! The boxes stand for SIMPLE entries: allowing or denying, made here and
//! not inherited, and applying to the object itself, and, on a container,
//! to everything in it as well, which is what a folder's entries usually
//! are. An entry that is anything else, or one granting more than the
//! general rights can say between them, is shown as special and left alone.
//! What is inherited is shown greyed, and is the container's to change.

use gxwi_sd_editor::{Generic, Part, Right};
use peios::security::{AccessMask, Ace, AceFlags, AceType, AclBuilder, Control, SdBuilder, SdView, Sid};

/// An entry of the access list, owned, so it can be changed and written back
/// as it was.
#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    pub ace_type: AceType,
    pub flags: AceFlags,
    pub mask: u32,
    pub sid: Sid,
    pub object_type: Option<[u8; 16]>,
    pub inherited_object_type: Option<[u8; 16]>,
    pub app_data: Option<Vec<u8>>,
}

impl Entry {
    fn simple(ace_type: AceType, flags: AceFlags, mask: u32, sid: Sid) -> Entry {
        Entry { ace_type, flags, mask, sid, object_type: None, inherited_object_type: None, app_data: None }
    }

    pub fn inherited(&self) -> bool {
        self.flags.contains(AceFlags::INHERITED)
    }

    /// Whether it says anything about the object itself, and not only about
    /// what is in it.
    fn applies(&self) -> bool {
        !self.flags.contains(AceFlags::INHERIT_ONLY)
    }
}

/// Which way a box is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Way {
    Allow,
    Deny,
}

impl Way {
    fn of(ace_type: AceType) -> Option<Way> {
        match ace_type {
            AceType::AccessAllowed => Some(Way::Allow),
            AceType::AccessDenied => Some(Way::Deny),
            _ => None,
        }
    }

    fn ace_type(self) -> AceType {
        match self {
            Way::Allow => AceType::AccessAllowed,
            Way::Deny => AceType::AccessDenied,
        }
    }
}

/// How one box shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tick {
    No,
    /// Ticked by an entry made here, which the box changes.
    Yes,
    /// Ticked by an inherited entry, which the box cannot change.
    Inherited,
}

/// What a principal has, as the boxes show it.
#[derive(Clone, Debug, PartialEq)]
pub struct Shown {
    /// For each general right, in the program's order: allowed, denied.
    pub rights: Vec<(Tick, Tick)>,
    /// Whether there is more than the boxes say, made here, allowing and
    /// denying.
    pub special: (bool, bool),
}

/// The descriptor as it is being edited.
#[derive(Clone, Debug)]
pub struct Descriptor {
    pub owner: Option<Sid>,
    pub group: Option<Sid>,
    pub control: Control,
    /// The access list, in order, or `None` where there is none at all,
    /// which lets everyone do anything.
    pub dacl: Option<Vec<Entry>>,
}

impl Descriptor {
    pub fn parse(bytes: &[u8]) -> Result<Descriptor, String> {
        let view = SdView::parse(bytes).map_err(|e| format!("This is not a security descriptor: {e}."))?;
        let dacl = match view.dacl() {
            None => None,
            Some(acl) => Some(
                acl.iter()
                    .map(|ace| {
                        let sid = ace.sid().ok_or("The access list has an entry with nobody in it, which this cannot show.")?;
                        Ok(Entry {
                            ace_type: ace.ace_type(),
                            flags: ace.flags(),
                            mask: ace.mask(),
                            sid: sid.to_sid(),
                            object_type: ace.object_type().copied(),
                            inherited_object_type: ace.inherited_object_type().copied(),
                            app_data: ace.app_data().map(<[u8]>::to_vec),
                        })
                    })
                    .collect::<Result<Vec<_>, String>>()?,
            ),
        };
        Ok(Descriptor { owner: view.owner().map(|sid| sid.to_sid()), group: view.group().map(|sid| sid.to_sid()), control: view.control(), dacl })
    }

    /// The descriptor as bytes: the owner, the group and the access list, and
    /// whether the access list is protected from inheritance, as it was.
    pub fn build(&self) -> Result<Vec<u8>, String> {
        let mut sd = SdBuilder::new();
        if let Some(owner) = &self.owner {
            sd.owner(owner);
        }
        if let Some(group) = &self.group {
            sd.group(group);
        }
        let kept = self.control & (Control::DACL_PROTECTED | Control::DACL_AUTO_INHERITED);
        sd.control(kept, Control::empty());
        if let Some(entries) = &self.dacl {
            let mut acl = AclBuilder::new();
            for entry in entries {
                acl.add(&Ace {
                    ace_type: entry.ace_type,
                    flags: entry.flags,
                    mask: entry.mask,
                    sid: &entry.sid,
                    object_type: entry.object_type.as_ref(),
                    inherited_object_type: entry.inherited_object_type.as_ref(),
                    app_data: entry.app_data.as_deref(),
                });
            }
            let acl = acl.build().map_err(|e| format!("The access list could not be made: {e}."))?;
            sd.dacl(&acl);
        }
        let sd = sd.build().map_err(|e| format!("The security descriptor could not be made: {e}."))?;
        Ok(sd.as_bytes().to_vec())
    }

    /// Everyone with an entry, in the order they first come.
    pub fn principals(&self) -> Vec<Sid> {
        let mut out: Vec<Sid> = Vec::new();
        for entry in self.dacl.iter().flatten() {
            if !out.contains(&entry.sid) {
                out.push(entry.sid);
            }
        }
        out
    }
}

/// The rules the boxes go by, for one object: what its rights are called,
/// what its generic rights stand for, and whether it is a container.
pub struct Rules {
    pub general: Vec<Right>,
    pub generic: Generic,
    pub container: bool,
}

impl Rules {
    /// The flags of an entry the boxes stand for: on a container, it applies
    /// to the container and everything in it.
    fn flags(&self) -> AceFlags {
        if self.container { AceFlags::OBJECT_INHERIT | AceFlags::CONTAINER_INHERIT } else { AceFlags::empty() }
    }

    /// Whether the boxes stand for `entry`.
    fn simple(&self, entry: &Entry) -> bool {
        let shape = AceFlags::OBJECT_INHERIT | AceFlags::CONTAINER_INHERIT | AceFlags::NO_PROPAGATE_INHERIT | AceFlags::INHERIT_ONLY;
        Way::of(entry.ace_type).is_some()
            && !entry.inherited()
            && entry.object_type.is_none()
            && entry.inherited_object_type.is_none()
            && entry.app_data.is_none()
            // A file has nothing in it to inherit, so whether its entries
            // say to pass them on says nothing.
            && if self.container { entry.flags & shape == self.flags() } else { entry.applies() }
    }

    /// `mask` with its generic rights as the rights they stand for.
    fn mapped(&self, mask: u32) -> u32 {
        let generic = [
            (AccessMask::GENERIC_READ, self.generic.read),
            (AccessMask::GENERIC_WRITE, self.generic.write),
            (AccessMask::GENERIC_EXECUTE, self.generic.execute),
            (AccessMask::GENERIC_ALL, self.generic.all),
        ];
        generic.iter().fold(mask, |mask, (bit, means)| if mask & bit.bits() != 0 { (mask & !bit.bits()) | means } else { mask })
    }

    /// What of `mask` the general rights do not cover between them, counting
    /// only those it has all of.
    fn beyond(&self, mask: u32) -> u32 {
        let covered = self.general.iter().filter(|right| mask & right.mask == right.mask).fold(0, |all, right| all | right.mask);
        mask & !covered
    }

    /// What `sid` has, as the boxes show it.
    pub fn shown(&self, descriptor: &Descriptor, sid: &Sid) -> Shown {
        let mut made = (0, 0);
        let mut inherited = (0, 0);
        let mut special = (false, false);
        for entry in descriptor.dacl.iter().flatten().filter(|entry| entry.sid == *sid) {
            let Some(way) = Way::of(entry.ace_type) else {
                special.0 |= !entry.inherited();
                continue;
            };
            let side = |pair: &mut (u32, u32), mask| if way == Way::Allow { pair.0 |= mask } else { pair.1 |= mask };
            if entry.inherited() {
                if entry.applies() {
                    side(&mut inherited, self.mapped(entry.mask));
                }
            } else if self.simple(entry) {
                side(&mut made, self.mapped(entry.mask));
            } else if way == Way::Allow {
                special.0 = true;
            } else {
                special.1 = true;
            }
        }
        special.0 |= self.beyond(made.0) != 0;
        special.1 |= self.beyond(made.1) != 0;
        let tick = |made: u32, inherited: u32, mask: u32| {
            if made & mask == mask {
                Tick::Yes
            } else if (made | inherited) & mask == mask {
                Tick::Inherited
            } else {
                Tick::No
            }
        };
        let rights = self.general.iter().map(|right| (tick(made.0, inherited.0, right.mask), tick(made.1, inherited.1, right.mask))).collect();
        Shown { rights, special }
    }

    /// Ticks or unticks the box for right `which` of the general rights,
    /// allowing or denying, for `sid`. Ticking one way unticks the other,
    /// for that right. Whether anything changed.
    pub fn tick(&self, descriptor: &mut Descriptor, sid: &Sid, which: usize, way: Way, on: bool) -> bool {
        let Some(right) = self.general.get(which) else { return false };
        // Without an access list everything is allowed already, and nothing
        // is unticked: an empty one would let nobody do anything.
        if !on && descriptor.dacl.is_none() {
            return false;
        }
        let before = descriptor.dacl.clone();
        let entries = descriptor.dacl.get_or_insert_with(Vec::new);
        let ours = |entry: &Entry, way: Way| entry.sid == *sid && Way::of(entry.ace_type) == Some(way) && self.simple(entry);
        let other = if way == Way::Allow { Way::Deny } else { Way::Allow };
        let take = |entries: &mut Vec<Entry>, way: Way| {
            for entry in entries.iter_mut().filter(|entry| ours(entry, way)) {
                entry.mask = self.mapped(entry.mask) & !right.mask;
            }
            entries.retain(|entry| !(ours(entry, way) && entry.mask == 0));
        };
        if on {
            take(entries, other);
            match entries.iter_mut().find(|entry| ours(entry, way)) {
                Some(entry) => entry.mask = self.mapped(entry.mask) | right.mask,
                None => {
                    // Where it goes in the order an access list is read in:
                    // denials before what is allowed, and what is made here
                    // before what is inherited.
                    let first_inherited = entries.iter().position(Entry::inherited).unwrap_or(entries.len());
                    let at = match way {
                        Way::Deny => entries[..first_inherited].iter().position(|entry| Way::of(entry.ace_type) == Some(Way::Allow)).unwrap_or(first_inherited),
                        Way::Allow => first_inherited,
                    };
                    entries.insert(at, Entry::simple(way.ace_type(), self.flags(), right.mask, *sid));
                }
            }
        } else {
            take(entries, way);
        }
        descriptor.dacl != before
    }

    /// Takes away everything made here for `sid`. What it inherits stays.
    /// Whether anything changed.
    pub fn remove(&self, descriptor: &mut Descriptor, sid: &Sid) -> bool {
        let Some(entries) = &mut descriptor.dacl else { return false };
        let was = entries.len();
        entries.retain(|entry| entry.sid != *sid || entry.inherited());
        entries.len() != was
    }
}

/// What the person has changed of the descriptor, as the program applies it.
pub fn parts(owner: bool, dacl: bool) -> Vec<Part> {
    [(owner, Part::Owner), (dacl, Part::Dacl)].into_iter().filter(|(changed, _)| *changed).map(|(_, part)| part).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // A file's rights, as Gexora names them (its `rights`).
    const READ: u32 = 0x0012_0089;
    const WRITE: u32 = 0x0010_0116;
    const EXECUTE: u32 = 0x0012_00a0;
    const ALL: u32 = 0x001f_01ff;

    fn rules(container: bool) -> Rules {
        let right = |name: &str, mask| Right { name: name.into(), mask, general: true };
        Rules {
            general: vec![right("Full control", ALL), right("Read & execute", READ | EXECUTE), right("Read", READ), right("Write", WRITE)],
            generic: Generic { read: READ, write: WRITE, execute: EXECUTE, all: ALL },
            container,
        }
    }

    fn sid(text: &str) -> Sid {
        text.parse().unwrap()
    }

    fn descriptor(entries: Vec<Entry>) -> Descriptor {
        Descriptor { owner: Some(sid("S-1-5-18")), group: None, control: Control::empty(), dacl: Some(entries) }
    }

    fn allow(who: &str, mask: u32) -> Entry {
        Entry::simple(AceType::AccessAllowed, AceFlags::empty(), mask, sid(who))
    }

    #[test]
    fn a_descriptor_comes_back_as_it_went() {
        let mut inherited = allow("S-1-5-32-544", ALL);
        inherited.flags = AceFlags::INHERITED;
        let mut odd = allow("S-1-1-0", 0x1);
        odd.ace_type = AceType::Other(9);
        odd.app_data = Some(b"artx".to_vec());
        let mut first = descriptor(vec![allow("S-1-1-0", READ), odd, inherited]);
        first.group = Some(sid("S-1-5-32-545"));
        first.control = Control::DACL_PROTECTED;
        let bytes = first.build().unwrap();
        let again = Descriptor::parse(&bytes).unwrap();
        assert_eq!((again.owner, again.group, again.dacl.clone()), (first.owner, first.group, first.dacl.clone()));
        assert!(again.control.contains(Control::DACL_PROTECTED));
        assert_eq!(again.build().unwrap(), bytes);
        assert_eq!(again.principals(), [sid("S-1-1-0"), sid("S-1-5-32-544")]);
        // No access list at all is no access list, and stays so.
        let open = Descriptor { dacl: None, ..first };
        assert_eq!(Descriptor::parse(&open.build().unwrap()).unwrap().dacl, None);
        assert!(Descriptor::parse(b"nonsense").is_err());
    }

    #[test]
    fn the_boxes_say_what_an_entry_allows_and_generic_rights_count() {
        let rules = rules(false);
        let everyone = sid("S-1-1-0");
        let d = descriptor(vec![allow("S-1-1-0", READ | EXECUTE)]);
        let shown = rules.shown(&d, &everyone);
        assert_eq!(shown.rights.iter().map(|(allowed, _)| *allowed).collect::<Vec<_>>(), [Tick::No, Tick::Yes, Tick::Yes, Tick::No]);
        assert_eq!(shown.special, (false, false));
        let d = descriptor(vec![allow("S-1-1-0", AccessMask::GENERIC_ALL.bits())]);
        assert!(rules.shown(&d, &everyone).rights.iter().all(|(allowed, _)| *allowed == Tick::Yes));
        // More than the boxes can say is special.
        let d = descriptor(vec![allow("S-1-1-0", READ | 0x0001_0000)]);
        assert_eq!(rules.shown(&d, &everyone).special, (true, false));
    }

    #[test]
    fn ticking_changes_the_entry_the_box_stands_for_and_nothing_else() {
        let rules = rules(false);
        let everyone = sid("S-1-1-0");
        let mut inherited = allow("S-1-1-0", READ);
        inherited.flags = AceFlags::INHERITED;
        let mut d = descriptor(vec![allow("S-1-5-18", ALL), inherited.clone()]);
        // What is inherited shows greyed, and cannot be unticked here.
        assert_eq!(rules.shown(&d, &everyone).rights[2], (Tick::Inherited, Tick::No));
        assert!(!rules.tick(&mut d, &everyone, 2, Way::Allow, false));
        // Ticked here, it comes after what else is made here and before what is inherited.
        assert!(rules.tick(&mut d, &everyone, 3, Way::Allow, true));
        assert_eq!(d.dacl.as_ref().unwrap()[1], allow("S-1-1-0", WRITE));
        assert_eq!(d.dacl.as_ref().unwrap()[2], inherited);
        // A denial comes first, and takes the right from what is allowed.
        assert!(rules.tick(&mut d, &everyone, 3, Way::Deny, true));
        let entries = d.dacl.as_ref().unwrap();
        assert_eq!(entries[0], Entry::simple(AceType::AccessDenied, AceFlags::empty(), WRITE, everyone));
        assert_eq!(entries.len(), 3, "the allowing entry that had nothing left went");
        assert_eq!(rules.shown(&d, &everyone).rights[3], (Tick::No, Tick::Yes));
        // Unticking the last of a denial takes it away.
        assert!(rules.tick(&mut d, &everyone, 3, Way::Deny, false));
        assert_eq!(d.dacl.as_ref().unwrap(), &vec![allow("S-1-5-18", ALL), inherited]);
    }

    #[test]
    fn unticking_part_of_full_control_leaves_the_rest_as_special() {
        let rules = rules(false);
        let system = sid("S-1-5-18");
        let mut d = descriptor(vec![allow("S-1-5-18", ALL)]);
        assert!(rules.tick(&mut d, &system, 2, Way::Allow, false));
        let shown = rules.shown(&d, &system);
        assert_eq!(shown.rights.iter().map(|(allowed, _)| *allowed).collect::<Vec<_>>(), [Tick::No, Tick::No, Tick::No, Tick::No]);
        assert_eq!(shown.special, (true, false));
        // Ticking Full control again gives it all back.
        assert!(rules.tick(&mut d, &system, 0, Way::Allow, true));
        assert_eq!(d.dacl.as_ref().unwrap(), &vec![allow("S-1-5-18", ALL)]);
    }

    #[test]
    fn on_a_container_the_boxes_stand_for_what_applies_to_everything_in_it() {
        let rules = rules(true);
        let everyone = sid("S-1-1-0");
        let mut d = descriptor(vec![allow("S-1-1-0", READ)]);
        // On a folder, an entry for the folder alone is special.
        assert_eq!(rules.shown(&d, &everyone).special, (true, false));
        assert!(rules.tick(&mut d, &everyone, 3, Way::Allow, true));
        let made = &d.dacl.as_ref().unwrap()[1];
        assert_eq!((made.flags, made.mask), (AceFlags::OBJECT_INHERIT | AceFlags::CONTAINER_INHERIT, WRITE));
        // An access list that was not there is made.
        let mut open = Descriptor { dacl: None, ..d.clone() };
        assert!(rules.tick(&mut open, &everyone, 2, Way::Allow, true));
        assert_eq!(open.dacl.unwrap().len(), 1);
    }

    #[test]
    fn removing_someone_takes_what_was_made_here_and_leaves_what_is_inherited() {
        let rules = rules(false);
        let everyone = sid("S-1-1-0");
        let mut inherited = allow("S-1-1-0", READ);
        inherited.flags = AceFlags::INHERITED;
        let mut d = descriptor(vec![allow("S-1-1-0", WRITE), allow("S-1-5-18", ALL), inherited.clone()]);
        assert!(rules.remove(&mut d, &everyone));
        assert_eq!(d.dacl.as_ref().unwrap(), &vec![allow("S-1-5-18", ALL), inherited]);
        assert!(!rules.remove(&mut d, &everyone));
        assert_eq!(parts(true, false), [Part::Owner]);
        assert_eq!(parts(true, true), [Part::Owner, Part::Dacl]);
    }
}
