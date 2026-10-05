//! How entries read: as SDDL, and in words.
//!
//! SDDL is written here rather than by libpeios, whose grammar has no codes
//! for alarm entries or the trust label (written as AL/OL/XL/ZL and TL, as
//! they would be), and whose formatter leaves alarm entries out without a
//! word. A type SDDL cannot say at all is written as a comment: the
//! descriptor goes back to the program as bytes (PSPU §8.5), so it still
//! goes back exactly as it came.

use peios::security::Sid;

use crate::sd::*;
use crate::view::*;

/// The SIDs SDDL writes as two letters.
pub const ALIASES: &[(&str, &str)] = &[
    ("S-1-1-0", "WD"),
    ("S-1-3-0", "CO"),
    ("S-1-3-1", "CG"),
    ("S-1-3-4", "OW"),
    ("S-1-5-10", "PS"),
    ("S-1-5-11", "AU"),
    ("S-1-5-18", "SY"),
    ("S-1-5-19", "LS"),
    ("S-1-5-20", "NS"),
    ("S-1-5-32-544", "BA"),
    ("S-1-5-32-545", "BU"),
    ("S-1-16-4096", "LW"),
    ("S-1-16-8192", "ME"),
    ("S-1-16-12288", "HI"),
    ("S-1-16-16384", "SI"),
];

pub fn sid_text(sid: &Sid) -> String {
    let s = sid.to_string();
    ALIASES.iter().find(|(full, _)| *full == s).map_or(s, |(_, a)| a.to_string())
}

pub fn flags_text(f: u8) -> String {
    [(OI, "OI"), (CI, "CI"), (NP, "NP"), (IO, "IO"), (ID, "ID"), (SA, "SA"), (FA, "FA")].iter().filter(|(b, _)| f & b != 0).map(|(_, t)| *t).collect()
}

/// A mask as written: generic rights by name, a folder's Full control as
/// FA, hex otherwise.
pub fn mask_text(m: u32) -> String {
    if m != 0 && m & !GENERIC == 0 {
        return generic_name(m);
    }
    if m == 0x1f01ff { "FA".into() } else { format!("0x{m:x}") }
}

pub fn generic_name(m: u32) -> String {
    [(GENERIC_ALL, "GA"), (GENERIC_READ, "GR"), (GENERIC_WRITE, "GW"), (GENERIC_EXECUTE, "GX")].iter().filter(|(b, _)| m & b != 0).map(|(_, t)| *t).collect()
}

/// The entry's type code, or its byte where it has none.
pub fn code(ace: &Ace) -> String {
    ace.kind().map_or_else(|| format!("0x{:02x}", ace.byte), |t| t.code.to_string())
}

/// One entry, as SDDL writes it.
pub fn ace_text(ace: &Ace) -> String {
    let Some(kind) = ace.kind() else {
        return format!("/* type 0x{:02x}, {} bytes, kept as found */", ace.byte, ace.bytes.len());
    };
    let sid = ace.sid.as_ref().map(sid_text).unwrap_or_default();
    let fl = flags_text(ace.flags);
    match ace.way {
        Way::Label => {
            let pol = if ace.mask & !7 != 0 {
                format!("0x{:x}", ace.mask)
            } else {
                [(1, "NW"), (2, "NR"), (4, "NX")].iter().filter(|(b, _)| ace.mask & b != 0).map(|(_, t)| *t).collect()
            };
            format!("(ML;{fl};{pol};;;{sid})")
        }
        Way::Trust => format!("(TL;{fl};0x{:x};;;{sid})", ace.mask),
        Way::Claim => format!("(RA;{fl};;;;WD;{})", ace.claim.as_ref().map(|c| c.sddl()).unwrap_or_default()),
        Way::Policy => format!("(SP;{fl};;;;{sid})"),
        _ => {
            let obj = ace.object.as_ref().map(guid_text).unwrap_or_default();
            let kind_guid = ace.inherited_object.as_ref().map(guid_text).unwrap_or_default();
            let cond = ace.cond.as_ref().map(|c| format!(";({})", c.text())).unwrap_or_default();
            format!("({};{fl};{};{obj};{kind_guid};{sid}{cond})", kind.code, mask_text(ace.mask))
        }
    }
}

/// The whole descriptor, one entry a line.
pub fn sd_text(sd: &Descriptor) -> String {
    let mut s = format!(
        "O:{}\nG:{}\n",
        sd.owner.as_ref().map(sid_text).unwrap_or_default(),
        sd.group.as_ref().map(sid_text).unwrap_or_default()
    );
    let flags = |p: u16, ai: u16| format!("{}{}", if sd.control & p != 0 { "P" } else { "" }, if sd.control & ai != 0 { "AI" } else { "" });
    match &sd.dacl {
        Some(dacl) => {
            s.push_str(&format!("D:{}", flags(PD, DI)));
            for ace in &dacl.aces {
                s.push_str(&format!("\n  {}", ace_text(ace)));
            }
        }
        None => s.push_str("D:NO_ACCESS_CONTROL"),
    }
    if let Some(sacl) = &sd.sacl {
        s.push_str(&format!("\nS:{}", flags(PS, SI)));
        for ace in &sacl.aces {
            s.push_str(&format!("\n  {}", ace_text(ace)));
        }
    }
    s
}

/// Rights in words: a general right's name where the mask is exactly one,
/// the rights it names otherwise.
pub fn rights_text(obj: &Obj, m: u32) -> String {
    if m == 0 {
        return "Nothing".into();
    }
    let (generic, rest) = (m & GENERIC, m & !GENERIC);
    let mut out = Vec::new();
    if generic != 0 {
        let as_level = obj.level_name(generic).filter(|_| rest == 0);
        out.push(generic_name(generic) + &as_level.map(|l| format!(" ({l})")).unwrap_or_default());
    }
    if rest != 0 {
        let known: Vec<(String, u32)> = obj
            .specific
            .iter()
            .map(|r| (r.name.clone(), r.mask))
            .chain([("Synchronize".to_string(), SYNCHRONIZE), ("Read or change auditing".into(), ACCESS_SYSTEM_SECURITY), ("Maximum allowed".into(), MAXIMUM_ALLOWED)])
            .collect();
        let names: Vec<String> = match obj.level_name(rest).filter(|_| obj.mapped(rest) == rest) {
            Some(level) => vec![level.to_string()],
            None => {
                let mut names: Vec<String> = known.iter().filter(|(_, b)| rest & b == *b && *b != 0).map(|(n, _)| n.clone()).collect();
                let left = rest & !known.iter().fold(0, |a, (_, b)| a | b);
                if left != 0 {
                    names.push(format!("0x{left:x}"));
                }
                names
            }
        };
        out.push(if names.len() > 3 { format!("{} +{}", names[..2].join(", "), names.len() - 2) } else { names.join(", ") });
    }
    out.join(", ")
}

/// A possessive: dana's, Contractors'.
pub fn poss(name: &str) -> String {
    if name.ends_with('s') || name.ends_with('S') { format!("{name}'") } else { format!("{name}'s") }
}

/// A list in words: a, b and c.
pub fn and_list(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// What the PIP types are called.
pub fn pip_type_name(t: u32) -> String {
    match t {
        0 => "None".into(),
        512 => "Protected".into(),
        1024 => "Isolated".into(),
        t => format!("Type {t}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::view::tests::{folder, read};
    use peios::security::sddl;

    #[test]
    fn entries_read_as_sddl_writes_them() {
        for text in [
            "(A;OICI;FA;;;SY)",
            "(D;OICI;0x10156;;;S-1-5-21-1-2-3-1106)",
            "(XA;OICI;0x1200a9;;;AU;(@User.Department == @Resource.Department))",
            "(OA;CIIO;0x100;00299570-246d-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-21-1-2-3-1000)",
            "(A;OICIIO;GA;;;CO)",
        ] {
            let (sd, _, _) = read(&format!("O:SYG:SYD:{text}"));
            assert_eq!(ace_text(&sd.dacl.unwrap().aces[0]), text);
        }
        let (sd, found, _) = read("O:SYG:SYD:(A;;0x1;;;WD)S:(ML;;NWNR;;;LW)(RA;;;;;WD;(\"Budget\",TU,0x20,250000))");
        let text = sd_text(&sd);
        assert!(text.contains("(ML;;NWNR;;;LW)") && text.contains("(RA;;;;;WD;(\"Budget\",TU,0x20,250000))"), "{text}");
        // What it writes, libpeios reads as the same descriptor.
        let flat = text.replace("\n  ", "").replace('\n', "");
        assert_eq!(sddl::format(sddl::parse(&flat).unwrap().as_bytes()).unwrap(), sddl::format(&sd.build(&found).unwrap()).unwrap());
    }

    #[test]
    fn rights_read_as_their_names() {
        let f = folder();
        assert_eq!(rights_text(&f, 0x1301bf), "Modify");
        assert_eq!(rights_text(&f, GENERIC_ALL), "GA (Full control)");
        assert_eq!(rights_text(&f, 0x3), "List folder / read data, Create files / write data");
        assert_eq!(and_list(&["a".into(), "b".into(), "c".into()]), "a, b and c");
    }
}
