//! How entries read: as SDDL, and in words.
//!
//! SDDL is written here rather than by libpeios, which refuses a whole
//! descriptor holding a type SDDL can't say. Here such a type is written as
//! a numbered comment, and the rest as libpeios writes it, so the text an
//! administrator edits is read back by libpeios (PEI-1391). The descriptor
//! goes back to the program as bytes (PSPU §8.5), so an entry that is a
//! comment still goes back exactly as it came.

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

/// The whole descriptor, one entry a line. An entry SDDL can't say is a
/// comment numbered within its list, which is how [`from_text`] finds it
/// again.
pub fn sd_text(sd: &Descriptor) -> String {
    let mut s = format!(
        "O:{}\nG:{}\n",
        sd.owner.as_ref().map(sid_text).unwrap_or_default(),
        sd.group.as_ref().map(sid_text).unwrap_or_default()
    );
    let flags = |p: u16, ar: u16, ai: u16| [(p, "P"), (ar, "AR"), (ai, "AI")].iter().filter(|(bit, _)| sd.control & bit != 0).map(|(_, t)| *t).collect::<String>();
    let entries = |s: &mut String, acl: &Acl| {
        let mut kept = 0;
        for ace in &acl.aces {
            let text = match ace.kind() {
                Some(_) => ace_text(ace),
                None => {
                    kept += 1;
                    format!("/* #{kept} kept as found: type 0x{:02x}, {} bytes */", ace.byte, ace.bytes.len())
                }
            };
            s.push_str(&format!("\n  {text}"));
        }
    };
    match &sd.dacl {
        Some(dacl) => {
            s.push_str(&format!("D:{}", flags(PD, DR, DI)));
            entries(&mut s, dacl);
        }
        None => s.push_str("D:NO_ACCESS_CONTROL"),
    }
    if let Some(sacl) = &sd.sacl {
        s.push_str(&format!("\nS:{}", flags(PS, SR_REQ, SI)));
        entries(&mut s, sacl);
    }
    s
}

/// The control bits the text says: each list's protection and inheriting.
const SAID: u16 = PD | PS | DI | SI | DR | SR_REQ;

/// What the text the person edited comes to, read by libpeios. Each entry
/// they left as it was is the very one it was, so it goes back as the bytes
/// it came as; an entry kept as found is put back where its comment stands.
/// The control bits SDDL can't say are kept from `now`.
pub fn from_text(text: &str, now: &Descriptor, ids: &mut Ids) -> Result<Descriptor, String> {
    // libpeios takes no spaces between the parts of an entry, so the layout
    // goes; inside a condition or a claim, spaces are the text's own.
    let (mut flat, mut kept, mut sections, mut entries) = (String::new(), Vec::new(), Vec::new(), Vec::new());
    let (mut depth, mut quote, mut section, mut count, mut from) = (0usize, false, ' ', 0usize, 0usize);
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if quote {
            quote = c != '"';
            flat.push(c);
            continue;
        }
        if c == '(' && depth == 0 {
            from = flat.len();
        }
        match c {
            '"' => {
                quote = true;
                flat.push(c);
            }
            '/' if depth == 0 && chars.peek() == Some(&'*') => {
                chars.next();
                let mut body = String::new();
                loop {
                    match chars.next() {
                        Some('*') if chars.peek() == Some(&'/') => {
                            chars.next();
                            break;
                        }
                        Some(c) => body.push(c),
                        None => return Err("A comment isn't closed with */.".into()),
                    }
                }
                // Any other comment is the person's own, and goes.
                let number: String = body.trim().strip_prefix('#').map(|r| r.chars().take_while(char::is_ascii_digit).collect()).unwrap_or_default();
                if let Ok(n) = number.parse::<usize>() {
                    kept.push((section, count, n));
                }
            }
            '(' => {
                depth += 1;
                flat.push(c);
            }
            ')' => {
                depth = depth.saturating_sub(1);
                flat.push(c);
                if depth == 0 {
                    count += 1;
                    entries.push((section, count, flat[from..].to_string()));
                }
            }
            c if c.is_whitespace() && depth <= 1 => {}
            ':' if depth == 0 => {
                section = flat.chars().last().unwrap_or(' ').to_ascii_uppercase();
                sections.push(section);
                count = 0;
                flat.push(c);
            }
            c => flat.push(c),
        }
    }
    if !sections.contains(&'D') {
        return Err("Say the access list with D:, or write D:NO_ACCESS_CONTROL for none at all.".into());
    }
    // libpeios has no word for no access list at all: the section goes,
    // and so does the list.
    let none = flat.to_ascii_uppercase().find("D:NO_ACCESS_CONTROL").map(|at| flat.replace_range(at..at + "D:NO_ACCESS_CONTROL".len(), "")).is_some();
    if depth != 0 || quote {
        return Err(if quote { "A quotation isn't closed with \".".into() } else { "A bracket isn't closed.".into() });
    }
    // libpeios says only that it can't, so each entry is tried alone to
    // say which.
    let bytes = peios::security::sddl::parse(&flat).map_err(|_| {
        let bad = entries.iter().find(|(s, _, e)| peios::security::sddl::parse(&format!("{s}:{e}")).is_err());
        match bad {
            Some((s, n, e)) => format!("Entry {n} of the {} isn't SDDL libpeios can read: {e}", if *s == 'S' { "SACL" } else { "access list" }),
            None => "libpeios can't read this as SDDL. Check the owner and group, and the letters before each list's entries.".into(),
        }
    })?;
    let mut new = Descriptor::parse(bytes.as_bytes(), ids, &mut Found::default())?;
    if none {
        new.dacl = None;
    }
    new.control = (now.control & !SAID) | (new.control & SAID);
    // The entries kept as found, back where their comments are: after the
    // entries before them, and the kept ones put back before them.
    let (mut put, mut put_in) = (Vec::new(), [0usize; 2]);
    for (section, at, n) in kept {
        let (was, into, before) = match section {
            'D' => (&now.dacl, &mut new.dacl, &mut put_in[0]),
            'S' => (&now.sacl, &mut new.sacl, &mut put_in[1]),
            _ => continue,
        };
        let ace = was.iter().flat_map(|a| &a.aces).filter(|a| a.kind().is_none()).nth(n.wrapping_sub(1)).ok_or_else(|| format!("There's no entry #{n} kept as found in that list."))?;
        if put.contains(&ace.id) {
            return Err(format!("Entry #{n} kept as found is there twice."));
        }
        put.push(ace.id);
        if let Some(into) = into {
            into.aces.insert((at + *before).min(into.aces.len()), ace.clone());
            *before += 1;
        }
    }
    // What is as it was is what it was.
    for (was, list) in [(&now.dacl, &mut new.dacl), (&now.sacl, &mut new.sacl)] {
        let (Some(was), Some(list)) = (was, list) else { continue };
        list.revision = was.revision;
        let mut taken = put.clone();
        for ace in list.aces.iter_mut().filter(|a| a.kind().is_some()) {
            if let Some(same) = was.aces.iter().find(|w| !taken.contains(&w.id) && w.same(ace)) {
                ace.id = same.id;
                taken.push(same.id);
            }
        }
    }
    Ok(new)
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

    /// What the descriptor read from `sddl` comes to with its text edited
    /// by `edit`, with the bytes it is then written as.
    fn edited(sddl: &str, edit: impl Fn(String) -> String) -> Result<(Descriptor, Descriptor, Vec<u8>), String> {
        let (sd, found, mut ids) = read(sddl);
        let new = from_text(&edit(sd_text(&sd)), &sd, &mut ids)?;
        let bytes = new.build(&found)?;
        Ok((sd, new, bytes))
    }

    #[test]
    fn text_left_alone_is_the_descriptor_it_was() {
        for sddl in [
            "O:SYG:SYD:PAI(A;OICI;FA;;;SY)(XA;OICI;0x1200a9;;;AU;(@User.Department == @Resource.Department))(A;OICIID;0x1301bf;;;BA)S:(ML;;NW;;;ME)(RA;;;;;WD;(\"Budget\",TU,0x20,250000))(AL;SA;0x10000;;;WD)(TL;;0x20000;;;S-1-19-512-1024)",
            "O:BAG:BAD:(OA;CIIO;0x100;00299570-246d-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-21-1-2-3-1000)",
        ] {
            let (sd, new, _) = edited(sddl, |t| t).unwrap();
            assert_eq!(new, sd, "{sddl}");
        }
    }

    #[test]
    fn only_what_the_text_changes_is_new() {
        let (sd, new, bytes) = edited("O:SYG:SYD:(A;;FA;;;SY)(XA;;0x1200a9;;;AU;(@User.X == 1))(A;;0x1;;;WD)", |t| t.replace("(A;;0x1;;;WD)", "(D;;0x1;;;WD)")).unwrap();
        let (was, now) = (&sd.dacl.as_ref().unwrap().aces, &new.dacl.as_ref().unwrap().aces);
        assert_eq!((now[0].id, now[1].id), (was[0].id, was[1].id));
        assert_ne!(now[2].id, was[2].id);
        assert_eq!(now[2].way, Way::Deny);
        assert!(sddl::format(&bytes).unwrap().ends_with("(D;;0x1;;;WD)"));
    }

    #[test]
    fn an_entry_kept_as_found_stays_where_its_comment_is() {
        let (mut sd, found, mut ids) = read("O:SYG:SYD:(A;;FA;;;SY)(A;;0x1;;;WD)");
        // An entry of a type nobody has, between the two.
        let odd = crate::sd::parse_ace(&[0x16, 0, 12, 0, 1, 0, 0, 0, 0xaa, 0xbb, 0xcc, 0xdd], ids.next()).unwrap();
        sd.dacl.as_mut().unwrap().aces.insert(1, odd.clone());
        let text = sd_text(&sd);
        assert!(text.contains("/* #1 kept as found: type 0x16, 12 bytes */"), "{text}");
        let moved = text.replace("  /* #1 kept as found: type 0x16, 12 bytes */\n", "").replace("(A;;0x1;;;WD)", "(A;;0x1;;;WD)\n/* #1 */");
        let new = from_text(&moved, &sd, &mut ids).unwrap();
        let aces = &new.dacl.as_ref().unwrap().aces;
        assert_eq!(aces.iter().map(|a| a.way).collect::<Vec<_>>(), [Way::Allow, Way::Allow, Way::Unknown]);
        assert_eq!(aces[2].bytes, odd.bytes);
        assert!(new.build(&found).unwrap().windows(12).any(|w| w == odd.bytes));
        // Taken out, it is gone.
        let gone = from_text(&text.replace("/* #1 kept as found: type 0x16, 12 bytes */", ""), &sd, &mut ids).unwrap();
        assert_eq!(gone.dacl.unwrap().aces.len(), 2);
        assert!(from_text(&format!("{text}\n/* #1 */"), &sd, &mut ids).unwrap_err().contains("twice"));
        assert!(from_text(&text.replace("#1 kept", "#4 kept"), &sd, &mut ids).unwrap_err().contains("#4"));
    }

    #[test]
    fn text_says_no_access_list_and_the_flags_it_has_words_for() {
        let (sd, new, _) = edited("O:SYG:SYD:PAI(A;;FA;;;SY)", |t| t.replace("D:PAI\n  (A;;FA;;;SY)", "D:NO_ACCESS_CONTROL")).unwrap();
        assert!(new.dacl.is_none() && sd.dacl.is_some());
        assert_eq!(new.control & PD, 0);
        let (_, new, _) = edited("O:SYG:SYD:(A;;FA;;;SY)", |t| t.replace("D:", "D:PAR")).unwrap();
        assert_eq!(new.control & (PD | DR), PD | DR);
        assert!(sd_text(&new).contains("D:PAR\n"));
    }

    #[test]
    fn what_is_wrong_with_the_text_is_said_where_it_is() {
        let err = edited("O:SYG:SYD:(A;;FA;;;SY)(A;;0x1;;;WD)", |t| t.replace("(A;;0x1;;;WD)", "(QQ;;0x1;;;WD)")).unwrap_err();
        assert_eq!(err, "Entry 2 of the access list isn't SDDL libpeios can read: (QQ;;0x1;;;WD)");
        assert!(edited("O:SYG:SYD:(A;;FA;;;SY)", |t| t.replace("D:", "")).unwrap_err().contains("D:NO_ACCESS_CONTROL"));
        assert!(edited("O:SYG:SYD:(A;;FA;;;SY)", |t| t.replace(";SY)", ";SY")).unwrap_err().contains("bracket"));
        assert!(edited("O:SYG:SYD:(A;;FA;;;SY)", |t| format!("{t} /* not closed")).unwrap_err().contains("*/"));
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
