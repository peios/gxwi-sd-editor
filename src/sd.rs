//! The descriptor being edited, entry by entry, as KACS reads it.
//!
//! Both lists are kept as they are, in their order, and every entry is
//! read into fields a person can change: its type, flags, mask and SID, its
//! object GUIDs, its condition and its claim. An entry whose type this
//! editor does not know is kept as its bytes. Written back, an entry whose
//! fields are as they were read goes back as the very bytes it came as, so
//! what was not touched is not changed, however this editor would have
//! written it: a condition's own encoding, a claim's layout, a type KACS
//! skips (PCDS §5.4).

use std::collections::HashMap;

use peios::security::{Sid, SidRef};

use crate::claim::Claim;
use crate::cond::Cond;

/// An object or inherited object type: a GUID, as its bytes are on the wire.
pub type Guid = [u8; 16];

// The flags an entry carries (PCDS §5.4).
pub const OI: u8 = 0x01;
pub const CI: u8 = 0x02;
pub const NP: u8 = 0x04;
pub const IO: u8 = 0x08;
pub const ID: u8 = 0x10;
/// An auditing entry's: record successes, and failures.
pub const SA: u8 = 0x40;
pub const FA: u8 = 0x80;
/// The flags that say where an entry applies.
pub const SHAPE: u8 = OI | CI | NP | IO;

// The control bits a descriptor carries (PCDS §5.1).
pub const DP: u16 = 0x0004;
pub const SP: u16 = 0x0010;
/// Each list's "auto-inherit required", which SDDL writes as AR.
pub const DR: u16 = 0x0100;
pub const SR_REQ: u16 = 0x0200;
pub const DI: u16 = 0x0400;
pub const SI: u16 = 0x0800;
pub const PD: u16 = 0x1000;
pub const PS: u16 = 0x2000;
pub const SR: u16 = 0x8000;

// Rights every kind of object has.
pub const SYNCHRONIZE: u32 = 0x0010_0000;
/// ACCESS_SYSTEM_SECURITY: only ever granted by SeSecurityPrivilege.
pub const ACCESS_SYSTEM_SECURITY: u32 = 0x0100_0000;
pub const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
pub const GENERIC_ALL: u32 = 0x1000_0000;
pub const GENERIC_EXECUTE: u32 = 0x2000_0000;
pub const GENERIC_WRITE: u32 = 0x4000_0000;
pub const GENERIC_READ: u32 = 0x8000_0000;
pub const GENERIC: u32 = GENERIC_ALL | GENERIC_EXECUTE | GENERIC_WRITE | GENERIC_READ;
pub const READ_CONTROL: u32 = 0x0002_0000;
pub const WRITE_DAC: u32 = 0x0004_0000;

/// What an entry does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Way {
    Allow,
    Deny,
    Audit,
    /// Auditing every use while the object is open, not just the opening:
    /// Peios' continuous audit, an alarm entry.
    Alarm,
    Label,
    Trust,
    Claim,
    Policy,
    /// A type this editor does not know, or one KACS does not act on.
    Unknown,
}

impl Way {
    /// Whether it is an entry about a person's access: allowing, denying or
    /// recording it.
    pub fn accessy(self) -> bool {
        matches!(self, Way::Allow | Way::Deny | Way::Audit | Way::Alarm)
    }
}

/// An entry type, by the byte KACS reads.
pub struct Type {
    pub byte: u8,
    /// How SDDL writes it.
    pub code: &'static str,
    pub way: Way,
    /// Whether it carries object GUIDs, and a condition.
    pub object: bool,
    pub callback: bool,
    pub name: &'static str,
}

pub const TYPES: &[Type] = &[
    Type { byte: 0x00, code: "A", way: Way::Allow, object: false, callback: false, name: "ACCESS_ALLOWED_ACE" },
    Type { byte: 0x01, code: "D", way: Way::Deny, object: false, callback: false, name: "ACCESS_DENIED_ACE" },
    Type { byte: 0x02, code: "AU", way: Way::Audit, object: false, callback: false, name: "SYSTEM_AUDIT_ACE" },
    Type { byte: 0x03, code: "AL", way: Way::Alarm, object: false, callback: false, name: "SYSTEM_ALARM_ACE" },
    Type { byte: 0x05, code: "OA", way: Way::Allow, object: true, callback: false, name: "ACCESS_ALLOWED_OBJECT_ACE" },
    Type { byte: 0x06, code: "OD", way: Way::Deny, object: true, callback: false, name: "ACCESS_DENIED_OBJECT_ACE" },
    Type { byte: 0x07, code: "OU", way: Way::Audit, object: true, callback: false, name: "SYSTEM_AUDIT_OBJECT_ACE" },
    Type { byte: 0x08, code: "OL", way: Way::Alarm, object: true, callback: false, name: "SYSTEM_ALARM_OBJECT_ACE" },
    Type { byte: 0x09, code: "XA", way: Way::Allow, object: false, callback: true, name: "ACCESS_ALLOWED_CALLBACK_ACE" },
    Type { byte: 0x0a, code: "XD", way: Way::Deny, object: false, callback: true, name: "ACCESS_DENIED_CALLBACK_ACE" },
    Type { byte: 0x0b, code: "ZA", way: Way::Allow, object: true, callback: true, name: "ACCESS_ALLOWED_CALLBACK_OBJECT_ACE" },
    Type { byte: 0x0c, code: "ZD", way: Way::Deny, object: true, callback: true, name: "ACCESS_DENIED_CALLBACK_OBJECT_ACE" },
    Type { byte: 0x0d, code: "XU", way: Way::Audit, object: false, callback: true, name: "SYSTEM_AUDIT_CALLBACK_ACE" },
    Type { byte: 0x0e, code: "XL", way: Way::Alarm, object: false, callback: true, name: "SYSTEM_ALARM_CALLBACK_ACE" },
    Type { byte: 0x0f, code: "ZU", way: Way::Audit, object: true, callback: true, name: "SYSTEM_AUDIT_CALLBACK_OBJECT_ACE" },
    Type { byte: 0x10, code: "ZL", way: Way::Alarm, object: true, callback: true, name: "SYSTEM_ALARM_CALLBACK_OBJECT_ACE" },
    Type { byte: 0x11, code: "ML", way: Way::Label, object: false, callback: false, name: "SYSTEM_MANDATORY_LABEL_ACE" },
    Type { byte: 0x12, code: "RA", way: Way::Claim, object: false, callback: false, name: "SYSTEM_RESOURCE_ATTRIBUTE_ACE" },
    Type { byte: 0x13, code: "SP", way: Way::Policy, object: false, callback: false, name: "SYSTEM_SCOPED_POLICY_ID_ACE" },
    Type { byte: 0x14, code: "TL", way: Way::Trust, object: false, callback: false, name: "SYSTEM_PROCESS_TRUST_LABEL_ACE" },
];

/// Types KACS names but does not act on. Like every unknown type, it skips
/// them when it checks access and keeps them byte for byte.
pub fn unacted(byte: u8) -> Option<&'static str> {
    match byte {
        0x04 => Some("ACCESS_ALLOWED_COMPOUND_ACE"),
        0x15 => Some("SYSTEM_ACCESS_FILTER_ACE"),
        _ => None,
    }
}

pub fn type_by_byte(byte: u8) -> Option<&'static Type> {
    TYPES.iter().find(|t| t.byte == byte)
}

/// One entry of either list.
#[derive(Clone, Debug, PartialEq)]
pub struct Ace {
    /// Which entry it is while the dialog is open: it stays the same as the
    /// entry is changed and moved, and is never written.
    pub id: u32,
    pub way: Way,
    pub flags: u8,
    pub mask: u32,
    pub sid: Option<Sid>,
    /// The part it is about, for an object entry, and the kind of child it
    /// is passed to.
    pub object: Option<Guid>,
    pub inherited_object: Option<Guid>,
    /// The condition of a callback entry.
    pub cond: Option<Cond>,
    /// The claim of a resource attribute entry.
    pub claim: Option<Claim>,
    /// The whole entry as its bytes, for a type this editor does not know.
    pub bytes: Vec<u8>,
    /// The type byte, for a type this editor does not know.
    pub byte: u8,
}

impl Ace {
    pub fn new(id: u32, way: Way, flags: u8, mask: u32, sid: Sid) -> Ace {
        Ace { id, way, flags, mask, sid: Some(sid), object: None, inherited_object: None, cond: None, claim: None, bytes: Vec::new(), byte: 0 }
    }

    pub fn inherited(&self) -> bool {
        self.flags & ID != 0
    }

    /// Whether it says anything about the object itself.
    pub fn applies(&self) -> bool {
        self.flags & IO == 0
    }

    /// Whether it is passed on to what is inside.
    pub fn passes(&self) -> bool {
        passes(self.flags)
    }

    /// Its type, if it is one this editor knows.
    pub fn kind(&self) -> Option<&'static Type> {
        if self.way == Way::Unknown {
            return None;
        }
        let object = self.way.accessy() && (self.object.is_some() || self.inherited_object.is_some());
        let callback = self.way.accessy() && self.cond.is_some();
        TYPES.iter().find(|t| t.way == self.way && t.object == object && t.callback == callback)
    }

    /// The type byte it is written with.
    pub fn type_byte(&self) -> u8 {
        self.kind().map_or(self.byte, |t| t.byte)
    }

    /// The same entry, by everything but which one it is.
    pub fn same(&self, other: &Ace) -> bool {
        Ace { id: 0, ..self.clone() } == Ace { id: 0, ..other.clone() }
    }
}

/// Whether flags pass an entry on to what is inside.
pub fn passes(flags: u8) -> bool {
    flags & (OI | CI) != 0
}

/// A list, as its entries and the revision it was written at.
#[derive(Clone, Debug, PartialEq)]
pub struct Acl {
    pub revision: u8,
    pub aces: Vec<Ace>,
}

/// A whole descriptor.
#[derive(Clone, Debug, PartialEq)]
pub struct Descriptor {
    pub owner: Option<Sid>,
    pub group: Option<Sid>,
    /// Every control bit but those that say which parts are present, which
    /// are the lists' own.
    pub control: u16,
    /// The access list, or `None` where there is none at all, which lets
    /// everyone do anything.
    pub dacl: Option<Acl>,
    pub sacl: Option<Acl>,
}

/// What an entry was read as: its fields, and its bytes.
#[derive(Clone, Debug, Default)]
pub struct Found(HashMap<u32, (Ace, Vec<u8>)>);

impl Found {
    /// The bytes `ace` was read as, while it is as it was read.
    fn bytes(&self, ace: &Ace) -> Option<&[u8]> {
        self.0.get(&ace.id).filter(|(was, _)| was.same(ace)).map(|(_, bytes)| bytes.as_slice())
    }

    /// The entry `id` as it was read.
    pub fn ace(&self, id: u32) -> Option<&Ace> {
        self.0.get(&id).map(|(ace, _)| ace)
    }
}

/// Hands out entry ids.
#[derive(Clone, Debug, Default)]
pub struct Ids(u32);

impl Ids {
    pub fn next(&mut self) -> u32 {
        self.0 += 1;
        self.0
    }
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// The SID that starts at `at`, and how long it is.
fn sid_at(b: &[u8], at: usize) -> Option<(Sid, usize)> {
    let count = *b.get(at + 1)? as usize;
    let len = 8 + 4 * count;
    let sid = SidRef::from_bytes(b.get(at..at + len)?)?;
    Some((sid.to_sid(), len))
}

impl Descriptor {
    /// Reads a self-relative descriptor, numbering its entries from `ids`,
    /// and says in `found` what each was read as.
    pub fn parse(bytes: &[u8], ids: &mut Ids, found: &mut Found) -> Result<Descriptor, String> {
        // Read here, entry by entry, so each entry's own bytes are known.
        let bad = || "This is not a security descriptor this editor can read.".to_string();
        if bytes.len() < 20 || bytes[0] != 1 {
            return Err(bad());
        }
        let control = u16_at(bytes, 2).ok_or_else(bad)?;
        let at = |n: usize| u32_at(bytes, 4 + 4 * n).map(|v| v as usize).ok_or_else(bad);
        let (owner, group, sacl, dacl) = (at(0)?, at(1)?, at(2)?, at(3)?);
        let sid = |off: usize| -> Result<Option<Sid>, String> { if off == 0 { Ok(None) } else { sid_at(bytes, off).map(|(s, _)| Some(s)).ok_or_else(bad) } };
        let mut list = |present: bool, off: usize| -> Result<Option<Acl>, String> {
            if !present || off == 0 {
                return Ok(None);
            }
            parse_acl(bytes.get(off..).ok_or_else(bad)?, ids, found).map(Some)
        };
        Ok(Descriptor {
            owner: sid(owner)?,
            group: sid(group)?,
            control: control & !(DP | SP | SR),
            dacl: list(control & DP != 0, dacl)?,
            sacl: list(control & SP != 0, sacl)?,
        })
    }

    /// The descriptor as a self-relative one: the owner, the group, the SACL
    /// and the access list, in that order.
    pub fn build(&self, found: &Found) -> Result<Vec<u8>, String> {
        let mut out = vec![0u8; 20];
        out[0] = 1;
        let mut control = (self.control & !(DP | SP)) | SR;
        let place = |out: &mut Vec<u8>, slot: usize, bytes: Option<Vec<u8>>| {
            if let Some(bytes) = bytes {
                let at = out.len() as u32;
                out[4 + 4 * slot..8 + 4 * slot].copy_from_slice(&at.to_le_bytes());
                out.extend_from_slice(&bytes);
            }
        };
        place(&mut out, 0, self.owner.map(|s| s.as_bytes().to_vec()));
        place(&mut out, 1, self.group.map(|s| s.as_bytes().to_vec()));
        if let Some(sacl) = &self.sacl {
            control |= SP;
            place(&mut out, 2, Some(build_acl(sacl, found)?));
        }
        if let Some(dacl) = &self.dacl {
            control |= DP;
            place(&mut out, 3, Some(build_acl(dacl, found)?));
        }
        out[2..4].copy_from_slice(&control.to_le_bytes());
        Ok(out)
    }

    /// The control bits as written, with the lists' presence.
    pub fn control_bits(&self) -> u16 {
        self.control | SR | if self.dacl.is_some() { DP } else { 0 } | if self.sacl.is_some() { SP } else { 0 }
    }
}

fn parse_acl(b: &[u8], ids: &mut Ids, found: &mut Found) -> Result<Acl, String> {
    let bad = || "A list in the security descriptor is not one this editor can read.".to_string();
    let revision = *b.first().ok_or_else(bad)?;
    let size = u16_at(b, 2).ok_or_else(bad)? as usize;
    let count = u16_at(b, 4).ok_or_else(bad)? as usize;
    let b = b.get(..size).ok_or_else(bad)?;
    let mut at = 8;
    let mut aces = Vec::with_capacity(count);
    for _ in 0..count {
        let len = u16_at(b, at + 2).ok_or_else(bad)? as usize;
        let bytes = b.get(at..at + len).filter(|_| len >= 8).ok_or_else(bad)?;
        let ace = parse_ace(bytes, ids.next()).ok_or_else(bad)?;
        found.0.insert(ace.id, (ace.clone(), bytes.to_vec()));
        aces.push(ace);
        at += len;
    }
    Ok(Acl { revision, aces })
}

/// One entry from its bytes. `None` if it is a type this editor knows and
/// is not one.
pub fn parse_ace(b: &[u8], id: u32) -> Option<Ace> {
    let byte = b[0];
    let flags = b[1];
    let Some(kind) = type_by_byte(byte) else {
        return Some(Ace { id, way: Way::Unknown, flags, mask: 0, sid: None, object: None, inherited_object: None, cond: None, claim: None, bytes: b.to_vec(), byte });
    };
    let mask = u32_at(b, 4)?;
    let mut at = 8;
    let (mut object, mut inherited_object) = (None, None);
    if kind.object {
        let which = u32_at(b, 8)?;
        at = 12;
        let mut guid = || -> Option<Guid> {
            let g = b.get(at..at + 16)?.try_into().ok()?;
            at += 16;
            Some(g)
        };
        if which & 1 != 0 {
            object = Some(guid()?);
        }
        if which & 2 != 0 {
            inherited_object = Some(guid()?);
        }
    }
    let (sid, len) = sid_at(b, at)?;
    let data = &b[at + len..];
    let mut ace = Ace { id, way: kind.way, flags, mask, sid: Some(sid), object, inherited_object, cond: None, claim: None, bytes: Vec::new(), byte: 0 };
    if kind.callback {
        ace.cond = Some(Cond::read(data));
    }
    if kind.way == Way::Claim {
        match Claim::read(data) {
            Some(claim) => ace.claim = Some(claim),
            // A claim this editor cannot read is kept as it came.
            None => return Some(Ace { way: Way::Unknown, bytes: b.to_vec(), mask: 0, sid: None, byte, ..ace }),
        }
    }
    Some(ace)
}

/// One entry as its bytes: as it came, if it is as it came.
pub fn ace_bytes(ace: &Ace, found: &Found) -> Result<Vec<u8>, String> {
    if let Some(bytes) = found.bytes(ace) {
        return Ok(bytes.to_vec());
    }
    if ace.way == Way::Unknown {
        return Ok(ace.bytes.clone());
    }
    let kind = ace.kind().ok_or("An entry has no type it can be written as.")?;
    let sid = ace.sid.ok_or("An entry names nobody.")?;
    let mut out = vec![kind.byte, ace.flags, 0, 0];
    out.extend_from_slice(&ace.mask.to_le_bytes());
    if kind.object {
        let which = ace.object.map_or(0, |_| 1) | ace.inherited_object.map_or(0, |_| 2);
        out.extend_from_slice(&(which as u32).to_le_bytes());
        out.extend(ace.object.iter().chain(&ace.inherited_object).flatten());
    }
    out.extend_from_slice(sid.as_bytes());
    if let Some(cond) = &ace.cond {
        out.extend(cond.bytes()?);
    }
    if let Some(claim) = &ace.claim {
        out.extend(claim.bytes()?);
    }
    while out.len() % 4 != 0 {
        out.push(0);
    }
    let len = u16::try_from(out.len()).map_err(|_| "An entry is too long to be written.")?;
    out[2..4].copy_from_slice(&len.to_le_bytes());
    Ok(out)
}

fn build_acl(acl: &Acl, found: &Found) -> Result<Vec<u8>, String> {
    // An object entry needs the list's revision to say it may have them.
    let object = acl.aces.iter().any(|ace| ace.kind().is_some_and(|t| t.object));
    let revision = if object { acl.revision.max(4) } else { acl.revision.max(2) };
    let mut out = vec![revision, 0, 0, 0, 0, 0, 0, 0];
    for ace in &acl.aces {
        out.extend(ace_bytes(ace, found)?);
    }
    let size = u16::try_from(out.len()).map_err(|_| "A list is too long to be written.")?;
    let count = u16::try_from(acl.aces.len()).map_err(|_| "A list has too many entries.")?;
    out[2..4].copy_from_slice(&size.to_le_bytes());
    out[4..6].copy_from_slice(&count.to_le_bytes());
    Ok(out)
}

/// A GUID as it is written: `bf967aba-0de6-11d0-a285-00aa003049e2`. Its
/// first three groups are little-endian on the wire.
pub fn guid_text(g: &Guid) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{}",
        g[3], g[2], g[1], g[0], g[5], g[4], g[7], g[6], g[8], g[9],
        g[10..].iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}

pub fn guid_parse(text: &str) -> Option<Guid> {
    let text = text.trim();
    let groups: Vec<&str> = text.split('-').collect();
    if groups.iter().map(|g| g.len()).collect::<Vec<_>>() != [8, 4, 4, 4, 12] {
        return None;
    }
    let hex: String = groups.concat();
    let mut b = [0u8; 16];
    for (i, byte) in b.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    b[0..4].reverse();
    b[4..6].reverse();
    b[6..8].reverse();
    Some(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use peios::security::sddl;

    fn read(text: &str) -> (Descriptor, Found, Vec<u8>) {
        let bytes = sddl::parse(text).unwrap().as_bytes().to_vec();
        let mut found = Found::default();
        let sd = Descriptor::parse(&bytes, &mut Ids::default(), &mut found).unwrap();
        (sd, found, bytes)
    }

    #[test]
    fn a_descriptor_goes_back_as_it_came() {
        for text in [
            "O:SYG:BAD:P(A;;0x1f01ff;;;SY)(D;OICI;0x10156;;;S-1-5-21-1-2-3-1106)(A;OICIID;GA;;;BA)",
            "O:BAG:BAD:(OA;CIIO;0x100;00299570-246d-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-21-1-2-3-1000)",
            "O:BAG:BAD:(XA;OICI;0x1200a9;;;AU;(@User.Department == @Resource.Department))S:(ML;;NW;;;ME)(AU;SAFA;0x10000;;;WD)",
            "O:SYG:SY",
            "O:SYG:SYD:S:(RA;;;;;WD;(\"Budget\",TU,0x20,250000))(AU;FA;0x10000;;;WD)",
        ] {
            let (sd, found, bytes) = read(text);
            let again = sd.build(&found).unwrap();
            assert_eq!(sddl::format(&again).unwrap(), sddl::format(&bytes).unwrap(), "{text}");
            let mut found2 = Found::default();
            let reread = Descriptor::parse(&again, &mut Ids::default(), &mut found2).unwrap();
            assert_eq!(reread, sd, "{text}");
        }
    }

    #[test]
    fn a_changed_entry_is_written_afresh_and_the_rest_stay_as_they_were() {
        let (mut sd, found, _) = read("O:SYG:SYD:(A;;0x1;;;WD)(XA;;0x2;;;AU;(@User.X == 1))");
        let dacl = sd.dacl.as_mut().unwrap();
        let before = ace_bytes(&dacl.aces[1], &found).unwrap();
        dacl.aces[0].mask = 0x3;
        assert_eq!(ace_bytes(&dacl.aces[1], &found).unwrap(), before);
        let built = sd.build(&found).unwrap();
        assert!(sddl::format(&built).unwrap().contains("(A;;0x3;;;WD)"));
    }

    #[test]
    fn an_unknown_type_is_kept_byte_for_byte() {
        let unknown = [0x15u8, 0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x00, 0xaa, 0xbb, 0xcc, 0xdd];
        let ace = parse_ace(&unknown, 7).unwrap();
        assert_eq!((ace.way, ace.byte), (Way::Unknown, 0x15));
        let sd = Descriptor { owner: Some("S-1-5-18".parse().unwrap()), group: None, control: 0, dacl: None, sacl: Some(Acl { revision: 2, aces: vec![ace] }) };
        let built = sd.build(&Found::default()).unwrap();
        assert!(built.windows(unknown.len()).any(|w| w == unknown));
    }

    #[test]
    fn guids_are_written_as_people_write_them() {
        let text = "bf967aba-0de6-11d0-a285-00aa003049e2";
        let g = guid_parse(text).unwrap();
        assert_eq!(&g[..4], &[0xba, 0x7a, 0x96, 0xbf]);
        assert_eq!(guid_text(&g), text);
        assert!(guid_parse("bf967aba").is_none());
    }
}
