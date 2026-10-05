//! A resource attribute entry's claim (PCDS §5.9): its name, its kind, its
//! flags and its values. The values are held as a person types them, and
//! read and written in the claim's own encoding.

use peios::security::{Sid, SidRef};

/// What kind of values a claim holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimType {
    Int,
    UInt,
    Text,
    Sid,
    Bool,
    Bytes,
}

impl ClaimType {
    pub const ALL: [ClaimType; 6] = [ClaimType::Text, ClaimType::Int, ClaimType::UInt, ClaimType::Bool, ClaimType::Sid, ClaimType::Bytes];

    fn wire(self) -> u16 {
        match self {
            ClaimType::Int => 0x01,
            ClaimType::UInt => 0x02,
            ClaimType::Text => 0x03,
            ClaimType::Sid => 0x05,
            ClaimType::Bool => 0x06,
            ClaimType::Bytes => 0x10,
        }
    }

    fn from_wire(w: u16) -> Option<ClaimType> {
        ClaimType::ALL.into_iter().find(|t| t.wire() == w)
    }

    pub fn key(self) -> &'static str {
        match self {
            ClaimType::Text => "text",
            ClaimType::Int => "number",
            ClaimType::UInt => "unumber",
            ClaimType::Bool => "yesno",
            ClaimType::Sid => "sid",
            ClaimType::Bytes => "bytes",
        }
    }

    pub fn from_key(key: &str) -> Option<ClaimType> {
        ClaimType::ALL.into_iter().find(|t| t.key() == key)
    }

    /// What a person calls it.
    pub fn label(self) -> &'static str {
        match self {
            ClaimType::Text => "Text",
            ClaimType::Int => "Number",
            ClaimType::UInt => "Number, 0 or More",
            ClaimType::Bool => "Yes or No",
            ClaimType::Sid => "Users or Groups",
            ClaimType::Bytes => "Bytes (Hex)",
        }
    }

    /// How SDDL writes it.
    pub fn sddl(self) -> &'static str {
        match self {
            ClaimType::Text => "TS",
            ClaimType::Int => "TI",
            ClaimType::UInt => "TU",
            ClaimType::Bool => "TB",
            ClaimType::Sid => "TD",
            ClaimType::Bytes => "TX",
        }
    }

    pub fn from_sddl(code: &str) -> Option<ClaimType> {
        ClaimType::ALL.into_iter().find(|t| t.sddl().eq_ignore_ascii_case(code))
    }
}

// A claim's flags.
pub const CASE_SENSITIVE: u32 = 0x02;
pub const DENY_ONLY: u32 = 0x04;
pub const DISABLED: u32 = 0x10;
/// Only something with SeTcbPrivilege can change or remove it.
pub const MANDATORY: u32 = 0x20;
/// The flags the simple view shows: the rest are Advanced mode's.
pub const SHOWN: u32 = CASE_SENSITIVE | DENY_ONLY | DISABLED | MANDATORY;

#[derive(Clone, Debug, PartialEq)]
pub struct Claim {
    pub name: String,
    pub kind: ClaimType,
    pub flags: u32,
    /// Each as it is written: a number, true or false, a SID, hex.
    pub values: Vec<String>,
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], at: usize) -> Option<usize> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?) as usize)
}

fn string_at(b: &[u8], at: usize) -> Option<String> {
    let mut units = Vec::new();
    let mut i = at;
    loop {
        let unit = u16_at(b, i)?;
        if unit == 0 {
            break;
        }
        units.push(unit);
        i += 2;
    }
    String::from_utf16(&units).ok()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if text.is_empty() || text.len() % 2 != 0 {
        return None;
    }
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok()).collect()
}

impl Claim {
    /// A claim entry, as a resource attribute entry carries it. Trailing
    /// padding is allowed.
    pub fn read(b: &[u8]) -> Option<Claim> {
        let name = string_at(b, u32_at(b, 0)?)?;
        let kind = ClaimType::from_wire(u16_at(b, 4)?)?;
        let flags = u32_at(b, 8)? as u32;
        let count = u32_at(b, 12)?;
        let mut values = Vec::with_capacity(count.min(1024));
        for i in 0..count {
            let at = u32_at(b, 16 + 4 * i)?;
            let scalar = || Some(u64::from_le_bytes(b.get(at..at + 8)?.try_into().ok()?));
            values.push(match kind {
                ClaimType::Int => (scalar()? as i64).to_string(),
                ClaimType::UInt => scalar()?.to_string(),
                ClaimType::Bool => (scalar()? != 0).to_string(),
                ClaimType::Text => string_at(b, u32_at(b, at)?)?,
                ClaimType::Sid => {
                    let off = u32_at(b, at)?;
                    let count = *b.get(off + 1)? as usize;
                    SidRef::from_bytes(b.get(off..off + 8 + 4 * count)?)?.to_string()
                }
                ClaimType::Bytes => {
                    let off = u32_at(b, at)?;
                    let len = u32_at(b, off)?;
                    hex(b.get(off + 4..off + 4 + len)?)
                }
            });
        }
        Some(Claim { name, kind, flags, values })
    }

    /// What is wrong with it, if anything.
    pub fn problem(&self) -> Option<String> {
        let name = self.name.trim();
        if name.is_empty() {
            return Some("Name the claim.".into());
        }
        if !crate::cond::name_ok(name) {
            return Some("A claim's name can use letters, digits, _, : and . only.".into());
        }
        if self.values.is_empty() {
            return Some("Give it at least one value.".into());
        }
        let bad = |ok: &dyn Fn(&str) -> bool| self.values.iter().find(|v| !ok(v)).cloned();
        match self.kind {
            ClaimType::Int => bad(&|v| v.parse::<i64>().is_ok()).map(|_| "A number claim takes whole numbers only.".into()),
            ClaimType::UInt => bad(&|v| v.parse::<u64>().is_ok()).map(|_| "This claim takes whole numbers of 0 or more.".into()),
            ClaimType::Bool => bad(&|v| v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("false")).map(|_| "A yes-or-no claim takes true or false.".into()),
            ClaimType::Sid => bad(&|v| v.starts_with("S-") && v.parse::<Sid>().is_ok()).map(|v| format!("There is nobody called {v}.")),
            ClaimType::Bytes => bad(&|v| unhex(v).is_some()).map(|_| "Bytes are written as hex, two digits each.".into()),
            ClaimType::Text => None,
        }
    }

    /// The claim entry: the header, the value offsets, the name, then each
    /// value, as Windows lays one out.
    pub fn bytes(&self) -> Result<Vec<u8>, String> {
        if let Some(why) = self.problem() {
            return Err(format!("A claim isn't finished: {why}"));
        }
        let utf16 = |s: &str| -> Vec<u8> { s.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect() };
        let n = self.values.len();
        let mut out = vec![0u8; 16 + 4 * n];
        let name_at = out.len() as u32;
        out.extend(utf16(self.name.trim()));
        out[0..4].copy_from_slice(&name_at.to_le_bytes());
        out[4..6].copy_from_slice(&self.kind.wire().to_le_bytes());
        out[8..12].copy_from_slice(&self.flags.to_le_bytes());
        out[12..16].copy_from_slice(&(n as u32).to_le_bytes());
        for (i, value) in self.values.iter().enumerate() {
            while out.len() % 4 != 0 {
                out.push(0);
            }
            let at = out.len() as u32;
            out[16 + 4 * i..20 + 4 * i].copy_from_slice(&at.to_le_bytes());
            let scalar = |out: &mut Vec<u8>, v: u64| out.extend_from_slice(&v.to_le_bytes());
            // Text, SIDs and bytes are reached through an offset of their own.
            let indirect = |out: &mut Vec<u8>, data: Vec<u8>| {
                let to = (out.len() + 4) as u32;
                out.extend_from_slice(&to.to_le_bytes());
                out.extend(data);
            };
            match self.kind {
                ClaimType::Int => scalar(&mut out, value.parse::<i64>().map_err(|e| e.to_string())? as u64),
                ClaimType::UInt => scalar(&mut out, value.parse::<u64>().map_err(|e| e.to_string())?),
                ClaimType::Bool => scalar(&mut out, value.eq_ignore_ascii_case("true") as u64),
                ClaimType::Text => indirect(&mut out, utf16(value)),
                ClaimType::Sid => indirect(&mut out, value.parse::<Sid>().map_err(|_| format!("There is nobody called {value}."))?.as_bytes().to_vec()),
                ClaimType::Bytes => {
                    let data = unhex(value).ok_or("Bytes are written as hex, two digits each.")?;
                    let mut with_len = (data.len() as u32).to_le_bytes().to_vec();
                    with_len.extend(data);
                    indirect(&mut out, with_len);
                }
            }
        }
        Ok(out)
    }

    /// As SDDL writes it, inside an RA entry.
    pub fn sddl(&self) -> String {
        let value = |v: &String| match self.kind {
            ClaimType::Text => format!("\"{v}\""),
            ClaimType::Bool => if v.eq_ignore_ascii_case("true") { "1".into() } else { "0".into() },
            ClaimType::Sid => format!("SID({v})"),
            _ => v.clone(),
        };
        format!("(\"{}\",{},0x{:x},{})", self.name, self.kind.sddl(), self.flags, self.values.iter().map(value).collect::<Vec<_>>().join(","))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_kind_goes_round() {
        for (kind, values) in [
            (ClaimType::Text, vec!["Confidential", "Internal"]),
            (ClaimType::Int, vec!["-3", "250000"]),
            (ClaimType::UInt, vec!["7"]),
            (ClaimType::Bool, vec!["true", "false"]),
            (ClaimType::Sid, vec!["S-1-5-32-544"]),
            (ClaimType::Bytes, vec!["9f86d081884c"]),
        ] {
            let claim = Claim { name: "Thing".into(), kind, flags: DENY_ONLY | MANDATORY, values: values.iter().map(|v| v.to_string()).collect() };
            let bytes = claim.bytes().unwrap();
            assert_eq!(Claim::read(&bytes), Some(claim), "{kind:?}");
        }
    }

    #[test]
    fn what_libpeios_writes_is_read() {
        use crate::sd::{Descriptor, Found, Ids};
        use peios::security::sddl;
        let sd = sddl::parse("O:SYG:SYD:S:(RA;;;;;WD;(\"Budget\",TU,0x20,250000))").unwrap();
        let read = Descriptor::parse(sd.as_bytes(), &mut Ids::default(), &mut Found::default()).unwrap();
        let claim = read.sacl.unwrap().aces[0].claim.clone().unwrap();
        assert_eq!(claim,Claim { name: "Budget".into(), kind: ClaimType::UInt, flags: MANDATORY, values: vec!["250000".into()] });
    }

    #[test]
    fn an_unfinished_claim_says_why() {
        let mut claim = Claim { name: String::new(), kind: ClaimType::Int, flags: 0, values: vec![] };
        assert_eq!(claim.problem().unwrap(), "Name the claim.");
        claim.name = "N".into();
        assert_eq!(claim.problem().unwrap(), "Give it at least one value.");
        claim.values = vec!["x".into()];
        assert_eq!(claim.problem().unwrap(), "A number claim takes whole numbers only.");
        assert!(claim.bytes().is_err());
    }
}
