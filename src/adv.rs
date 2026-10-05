//! Advanced mode: the access list and the SACL entry by entry, as KACS
//! reads them, and the descriptor's owner, group and control flags.
//!
//! Every entry can be read here, and every entry the program can change can
//! be changed, moved, duplicated or removed, whatever the simple view can
//! show. An inherited entry's fields wait for "Make It This Folder's Own":
//! KACS replaces inherited entries whenever the parent passes its entries
//! down again. An entry of a type this editor does not know can only be
//! moved or removed, and goes back exactly as it came.

use libgxwi::{Fields, Value, escape as h};
use peios::file::SecInfo;
use peios::security::{GenericMapping, Sid};

use crate::claim::{self, Claim, ClaimType};
use crate::cond::{self, Cond, Node};
use crate::edit::{self, CondOf};
use crate::sd::*;
use crate::text::*;
use crate::ui::{Place, banner, link, title_case, wrapped_note};
use crate::view::*;
use crate::{Adv, AdvTab, Editor};

/// Whether an entry may be changed: the access list takes the right to
/// change it, the SACL its own, a label the right to change the owner as
/// well, and a locked claim SeTcbPrivilege.
pub fn may_entry(e: &Editor, ace: &Ace, list: List) -> bool {
    match list {
        List::Dacl => e.may_dacl(),
        List::Sacl if ace.way == Way::Label => e.may_label(),
        List::Sacl if ace.claim.as_ref().is_some_and(|c| c.flags & claim::MANDATORY != 0) => e.may_sacl() && e.caller.tcb,
        List::Sacl => e.may_sacl(),
    }
}

/// Whether a list as a whole may be changed: entries added, put in order.
fn may_list(e: &Editor, list: List) -> bool {
    match list {
        List::Dacl => e.may_dacl(),
        List::Sacl => e.may_sacl(),
    }
}

pub fn enter(e: &mut Editor) {
    let picked = e.picked;
    let first_dacl = e.sd.dacl.as_ref().and_then(|d| d.aces.iter().find(|a| a.sid.is_some() && a.sid == picked).or(d.aces.first())).map(|a| a.id);
    let first_sacl = e.sd.sacl.as_ref().and_then(|s| s.aces.first()).map(|a| a.id);
    e.adv = Some(Adv { tab: AdvTab::Dacl, dacl: first_dacl, sacl: first_sacl, more: false, stash: None, text: None });
    e.asking = None;
    e.checked = false;
}

pub fn leave(e: &mut Editor) {
    e.adv = None;
    e.checked = false;
    e.relist();
}

fn acl(e: &Editor, list: List) -> Option<&Acl> {
    match list {
        List::Dacl => e.sd.dacl.as_ref(),
        List::Sacl => e.sd.sacl.as_ref(),
    }
}

fn acl_mut(e: &mut Editor, list: List) -> Option<&mut Acl> {
    match list {
        List::Dacl => e.sd.dacl.as_mut(),
        List::Sacl => e.sd.sacl.as_mut(),
    }
}

fn selected(e: &Editor, list: List) -> Option<u32> {
    let adv = e.adv.as_ref()?;
    match list {
        List::Dacl => adv.dacl,
        List::Sacl => adv.sacl,
    }
}

fn select(e: &mut Editor, list: List, id: Option<u32>) {
    if let Some(adv) = &mut e.adv {
        match list {
            List::Dacl => adv.dacl = id,
            List::Sacl => adv.sacl = id,
        }
    }
}

fn current(e: &Editor) -> Option<List> {
    match e.adv.as_ref()?.tab {
        AdvTab::Dacl => Some(List::Dacl),
        AdvTab::Sacl => Some(List::Sacl),
        _ => None,
    }
}

// ---- how entries read

fn who(e: &Editor, ace: &Ace) -> String {
    match ace.way {
        Way::Unknown => unacted(ace.byte).unwrap_or("Unknown type").to_string(),
        Way::Label => format!("{} integrity", ace.sid.and_then(|s| sid_level(&s)).and_then(level_name).map_or_else(|| ace.sid.map(|s| s.to_string()).unwrap_or_default(), String::from)),
        Way::Trust => ace.sid.and_then(|s| sid_trust(&s)).map_or_else(|| ace.sid.map(|s| s.to_string()).unwrap_or_default(), |(t, l)| format!("{} · {l}", pip_type_name(t))),
        Way::Claim => format!("@Resource.{}", ace.claim.as_ref().map_or("?", |c| if c.name.is_empty() { "?" } else { c.name.as_str() })),
        Way::Policy => ace.sid.map(|s| s.to_string()).unwrap_or_default(),
        _ => ace.sid.map_or_else(|| "Nobody yet".to_string(), |s| e.name(&s)),
    }
}

fn recorded(ace: &Ace) -> String {
    let mut out = Vec::new();
    if ace.flags & SA != 0 {
        out.push("successes".to_string());
    }
    if ace.flags & FA != 0 {
        out.push("failures".to_string());
    }
    out.join(" and ")
}

fn what(e: &Editor, ace: &Ace) -> String {
    match ace.way {
        Way::Unknown => format!("{} bytes", ace.bytes.len()),
        Way::Label => {
            let names: Vec<&str> = [(1, "No write up"), (2, "No read up"), (4, "No execute up")].iter().filter(|(b, _)| ace.mask & b != 0).map(|(_, n)| *n).collect();
            if names.is_empty() { "No policy".into() } else { names.join(", ") }
        }
        Way::Claim => ace.claim.as_ref().map_or_else(String::new, |c| if c.values.is_empty() { "No values".into() } else { c.values.join(", ") }),
        Way::Policy => "Central access policy".into(),
        Way::Trust => format!("Others may: {}", rights_text(&e.obj, ace.mask)),
        _ => {
            let part = ace.object.map(|o| format!(" · {}", e.obj.part(&o).map_or("a part", |p| p.name.as_str()))).unwrap_or_default();
            if matches!(ace.way, Way::Audit | Way::Alarm) {
                let r = recorded(ace);
                format!("{}{part} · {}", rights_text(&e.obj, ace.mask), if r.is_empty() { "nothing recorded".into() } else { r })
            } else {
                rights_text(&e.obj, ace.mask) + &part
            }
        }
    }
}

fn where_(e: &Editor, ace: &Ace) -> String {
    if ace.way == Way::Unknown {
        return String::new();
    }
    let f = ace.flags & SHAPE;
    let w = e.kind_word();
    if f & IO != 0 && !passes(f) {
        return "Nowhere".into();
    }
    if e.obj.container { e.obj.scope_label(f) } else { format!("This {w}") }
}

fn says(e: &Editor, ace: &Ace) -> String {
    let w = e.kind_word();
    let who = who(e, ace);
    if ace.way == Way::Unknown {
        return "An entry of a type this editor doesn't know. KACS skips it when it checks access.".into();
    }
    let from = if ace.inherited() { format!(" It's inherited from {}.", e.from_word()) } else { String::new() };
    let down = if passes(ace.flags) { if ace.flags & IO != 0 { " It's only for new items inside." } else { " New items inside get it too." } } else { "" };
    match ace.way {
        Way::Label => {
            let pol: Vec<&str> = [(1, "change"), (2, "read"), (4, "run")].iter().filter(|(b, _)| ace.mask & b != 0).map(|(_, n)| *n).collect();
            format!("Labels this {w} {who}{}.{down}{from}", if pol.is_empty() { String::new() } else { format!(": programs below that can't {} it", pol.join(" or ")) })
        }
        Way::Trust => format!("Protects this {w}: programs less trusted than {who} may only use {}.{down}{from}", rights_text(&e.obj, ace.mask).to_lowercase()),
        Way::Claim => format!("Gives this {w} the claim {}: {}.{down}{from}", ace.claim.as_ref().map_or("(unnamed)", |c| if c.name.is_empty() { "(unnamed)" } else { c.name.as_str() }), what(e, ace)),
        Way::Policy => format!("Makes the central access policy {who} count for this {w}.{down}{from}"),
        _ => {
            let place = where_(e, ace);
            let nowhere = place == "Nowhere";
            let place = if nowhere { "what's inside, but it isn't passed down, so it applies nowhere".to_string() } else if e.obj.container { place.to_lowercase() } else { format!("this {w}") };
            let part = ace.object.map(|o| format!(", only for {}", e.obj.part(&o).map_or_else(|| format!("the part {}", guid_text(&o)), |p| p.name.clone()))).unwrap_or_default();
            let kind = ace.inherited_object.map(|k| format!(", passed only to {}", e.obj.kind_name(&k).map_or_else(|| format!("items of type {}", guid_text(&k)), str::to_lowercase))).unwrap_or_default();
            let when = if ace.cond.is_some() { ", while its condition holds" } else { "" };
            let r = rights_text(&e.obj, ace.mask);
            let rec = recorded(ace);
            let rec = if rec.is_empty() { "nothing".to_string() } else { rec };
            let say = match ace.way {
                Way::Allow => format!("Gives {who} {r}"),
                Way::Deny => format!("Refuses {who} {r}"),
                Way::Audit => format!("Records {rec} when {who} asks for {r}"),
                _ => format!("Records every use of {r} by {who} while it's open ({rec})"),
            };
            format!("{say} {} {place}{part}{kind}{when}.{from}", if nowhere { "for" } else { "on" })
        }
    }
}

fn badges(ace: &Ace, kept: Option<&String>, out_of_order: bool) -> String {
    let mut b = String::new();
    if ace.inherited() {
        b.push_str("<span class=\"xb\">Inherited</span>");
    }
    if let Some(why) = kept {
        let (cls, text) = if ace.way == Way::Unknown {
            ("kept", "Skipped by KACS")
        } else if why.contains("ignores") {
            ("warn", "Ignored")
        } else if why.contains("never applies") || why.contains("does nothing") || why.contains("neither") {
            ("warn", "Does Nothing")
        } else {
            ("kept", "Advanced Only")
        };
        b.push_str(&format!("<span class=\"xb {cls}\" title=\"{}\">{text}</span>", h(why)));
    }
    if out_of_order {
        b.push_str("<span class=\"xb warn\">Out of Order</span>");
    }
    b
}

/// The ids of the entries out of the standard order.
fn out_of_order(aces: &[Ace]) -> Vec<u32> {
    let known: Vec<&Ace> = aces.iter().filter(|a| matches!(a.way, Way::Allow | Way::Deny)).collect();
    known.iter().enumerate().filter(|(j, x)| known[..*j].iter().any(|y| edit::rank(y) > edit::rank(x))).map(|(_, x)| x.id).collect()
}

// ---- the lists

pub fn list(e: &Editor, which: List) -> String {
    let w = e.kind_word();
    if which == List::Sacl && !e.shows_sacl() {
        if e.read_label {
            return format!("{}{}", wrapped_note("Only the integrity label of the SACL was read: the rest takes SeSecurityPrivilege, which the program that opened this doesn't have."), label_only(e));
        }
        return "<p class=\"note fixed\">The SACL isn't shown. Reading it takes SeSecurityPrivilege, which the program that opened this doesn't have.</p>".into();
    }
    let may = may_list(e, which);
    let off = if may { "" } else { " disabled" };
    let protected = e.sd.control & if which == List::Dacl { PD } else { PS } != 0;
    let ctl = format!(
        "<div class=\"xctl\">{}<label class=\"chk\">{} Protected: don't take entries from {} <code class=\"guid\">{}</code></label></div>",
        if which == List::Dacl { format!("<label class=\"chk\">{} No access list at all</label>", e.checkbox("x.null", e.sd.dacl.is_none(), off)) } else { String::new() },
        e.checkbox(if which == List::Dacl { "x.prot.dacl" } else { "x.prot.sacl" }, protected, off),
        h(&e.from_word()),
        if which == List::Dacl { "PD" } else { "PS" }
    );
    let Some(acl) = acl(e, which) else {
        if which == List::Dacl {
            return format!("{ctl}{}", banner(true, &format!("<b>There's no access list,</b> so anyone can do anything with this {}. Untick \"No access list at all\" to start one.", h(&w)), ""));
        }
        return format!("{ctl}{}{}", wrapped_note("There's no SACL."), if may { "<div class=\"under\"><button type=\"button\" fx-click=\"x-add\">+ Add Entry</button></div>" } else { "" });
    };
    let kept = kept_in(&e.obj, &acl.aces, which);
    let disorder = if which == List::Dacl { out_of_order(&acl.aces) } else { vec![] };
    let order = if disorder.is_empty() {
        String::new()
    } else {
        banner(
            true,
            &format!("<b>{} out of the standard order.</b> KACS reads the list from the top, and the first entry to decide a right wins.", if disorder.len() == 1 { "1 entry is".into() } else { format!("{} entries are", disorder.len()) }),
            &if may { link("x-order", &[], "Put in Order") } else { String::new() },
        )
    };
    let sel = selected(e, which);
    let rows: String = acl
        .aces
        .iter()
        .enumerate()
        .map(|(i, ace)| {
            let why = kept.iter().find(|(id, _)| *id == ace.id).map(|(_, w)| w);
            format!(
                "<li{inh} id=\"x{id}\"{drag}><button type=\"button\" class=\"xrow\" role=\"option\" aria-selected=\"{on}\" fx-click=\"x-sel\" fx-value-id=\"{id}\"><span class=\"xn\">{n}</span><span class=\"xc {cls}\">{code}</span><span class=\"xw\">{who}</span><span class=\"xr\">{what}</span><span class=\"xs\">{place}</span><span class=\"xbs\">{badges}</span></button></li>",
                inh = if ace.inherited() { " class=\"inh\"" } else { "" },
                drag = if may { format!(" fx-drag fx-value-id=\"{}\"", ace.id) } else { String::new() },
                id = ace.id,
                on = sel == Some(ace.id),
                n = i + 1,
                cls = way_class(ace.way),
                code = h(&code(ace)),
                who = h(&who(e, ace)),
                what = h(&what(e, ace)),
                place = h(&where_(e, ace)),
                badges = badges(ace, why, disorder.contains(&ace.id)),
            )
        })
        .collect();
    let empty = if which == List::Dacl { "The list is empty, so nobody but the owner can do anything." } else { "The SACL is empty." };
    let editor = sel.and_then(|id| acl.aces.iter().find(|a| a.id == id)).map(|ace| entry_editor(e, ace, which, &kept)).unwrap_or_default();
    format!(
        "{ctl}{order}<div class=\"xtable\"><div class=\"xcols\" aria-hidden=\"true\"><span>#</span><span>Type</span><span>{}</span><span>{}</span><span>Applies To</span><span></span></div>\
         <ol class=\"xlist\" role=\"listbox\" aria-label=\"{}\"{}>{}</ol></div>{}{editor}{}",
        if which == List::Dacl { "Who" } else { "Who or What" },
        if which == List::Dacl { "Rights" } else { "Says" },
        if which == List::Dacl { "Access list entries" } else { "SACL entries" },
        if may { " fx-reorder=\"x-moved\"" } else { "" },
        if rows.is_empty() { format!("<li class=\"xnone\">{empty}</li>") } else { rows },
        if may { "<div class=\"under\"><button type=\"button\" fx-click=\"x-add\">+ Add Entry</button></div>" } else { "" },
        wrapped_note(&format!(
            "{}{}",
            if which == List::Dacl {
                "KACS checks the integrity label and process trust first, then the owner's own rights, then this list from the top."
            } else {
                "Order in the SACL changes nothing, so the simple view writes it back in the standard order: label, trust, auditing, claims, policies, then anything else."
            },
            if acl.aces.is_empty() || !may { "" } else { " Drag an entry to move it, or press Alt with ↑ or ↓ to move the picked one." }
        ))
    )
}

/// The label alone, where that is all of the SACL that was read.
fn label_only(e: &Editor) -> String {
    let Some(acl) = &e.sd.sacl else { return wrapped_note("It has no integrity label: it counts as Medium.") };
    let kept = kept_in(&e.obj, &acl.aces, List::Sacl);
    acl.aces.iter().filter(|a| a.way == Way::Label).map(|a| entry_editor(e, a, List::Sacl, &kept)).collect()
}

fn way_class(w: Way) -> &'static str {
    match w {
        Way::Allow => "allow",
        Way::Deny => "deny",
        Way::Audit => "audit",
        Way::Alarm => "alarm",
        Way::Label => "label",
        Way::Trust => "trust",
        Way::Claim => "claim",
        Way::Policy => "policy",
        Way::Unknown => "unknown",
    }
}

fn bit_boxes(e: &Editor, name: &str, bits: &[(String, u32, String, bool)], value: u32, fixed: bool) -> String {
    let boxes: String = bits
        .iter()
        .map(|(label, mask, code, locked)| {
            let off = if *locked || fixed { " disabled" } else { "" };
            format!("<label class=\"chk\">{} <span>{}</span><code>{}</code></label>", e.checkbox(&format!("{name}.{mask}"), value & mask == *mask && *mask != 0, off), h(label), h(code))
        })
        .collect();
    format!("<div class=\"bits\">{boxes}</div>")
}

fn entry_editor(e: &Editor, ace: &Ace, which: List, kept: &[(u32, String)]) -> String {
    let aces = &acl(e, which).expect("a list with the entry").aces;
    let i = aces.iter().position(|a| a.id == ace.id).unwrap_or(0);
    let may = may_entry(e, ace, which);
    let fixed = !may || ace.inherited();
    let w = e.kind_word();
    let moves = if may_list(e, which) || may {
        format!(
            "<div class=\"xmoves\"><button type=\"button\" class=\"small\" fx-click=\"x-move\" fx-value-v=\"up\"{} aria-label=\"Move up\">↑</button><button type=\"button\" class=\"small\" fx-click=\"x-move\" fx-value-v=\"down\"{} aria-label=\"Move down\">↓</button><button type=\"button\" class=\"small\" fx-click=\"x-dup\"{}>Duplicate</button><button type=\"button\" class=\"small remove-rule\" fx-click=\"x-del\"{}>Remove</button></div>",
            if i == 0 { " disabled" } else { "" },
            if i + 1 == aces.len() { " disabled" } else { "" },
            if may_list(e, which) { "" } else { " disabled" },
            if may { "" } else { " disabled" }
        )
    } else {
        String::new()
    };
    let why = kept.iter().find(|(id, _)| *id == ace.id).map(|(_, w)| w);
    let mut notes = String::new();
    if let Some(why) = why {
        notes.push_str(&banner(true, &format!("<b>The simple view can't show this.</b> {}", h(why)), ""));
    }
    if ace.inherited() {
        notes.push_str(&banner(
            false,
            &format!("Inherited from <b>{f}</b>. KACS replaces it whenever {f} passes its entries down again, so change it there, or make it this {}'s own.", h(&w), f = h(&e.from_word())),
            &if may { link("x-own", &[], &format!("Make It This {}'s Own", title_case(&w))) } else { String::new() },
        ));
    }
    let body = if ace.way == Way::Unknown {
        format!(
            "<div class=\"fld\"><span>Its Bytes</span><code class=\"expr\">{}</code></div>{}",
            h(&ace.bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")),
            wrapped_note("This editor can't read it, so it can only be moved or removed. It goes back exactly as it came.")
        )
    } else {
        fields(e, ace, which, fixed)
    };
    let kind = ace.kind().map_or_else(|| format!("{} · 0x{:02x}", unacted(ace.byte).unwrap_or("Unknown type"), ace.byte), |t| format!("{} · 0x{:02x}", t.name, t.byte));
    format!(
        "<section class=\"xed\" aria-label=\"Entry {n}\"><div class=\"xhead\"><span class=\"xc {cls}\">{code}</span><b>Entry {n}</b><span class=\"guid\">{kind}</span><span class=\"grow\"></span>{moves}</div>\
         <p class=\"said\">{said}</p>{notes}{body}<div class=\"fld\"><span>As SDDL</span><code class=\"expr\">{sddl}</code></div></section>",
        n = i + 1,
        cls = way_class(ace.way),
        code = h(&code(ace)),
        kind = h(&kind),
        said = h(&says(e, ace)),
        sddl = h(&ace_text(ace)),
    )
}

fn fields(e: &Editor, ace: &Ace, which: List, fixed: bool) -> String {
    let id = ace.id;
    let off = if fixed { " disabled" } else { "" };
    let f = |k: &str| format!("x.{id}.{k}");
    let wrong = |k: &str| e.wrong.get(&f(k)).map(|w| format!("<span class=\"wrong\">{}</span>", h(w))).unwrap_or_default();
    let invalid = |k: &str| if e.wrong.contains_key(&f(k)) { " aria-invalid=\"true\"" } else { "" };
    let ways: Vec<(String, String, bool)> = match which {
        List::Dacl => vec![("allow".into(), "Allow".into(), false), ("deny".into(), "Deny".into(), false)],
        List::Sacl => [("audit", "Auditing"), ("alarm", "Continuous Auditing"), ("label", "Integrity Label"), ("trust", "Process Trust Label"), ("claim", "Resource Claim"), ("policy", "Central Access Policy")]
            .iter()
            .map(|(k, l)| (k.to_string(), l.to_string(), *k != "label" && !e.may_sacl()))
            .collect(),
    };
    let mut out = vec![format!("<label class=\"fld\"><span>Kind of Entry</span>{}</label>", e.select(&f("way"), &ways, way_class(ace.way), off))];
    match ace.way {
        w if w.accessy() => {
            let shown = ace.sid.map_or_else(String::new, |s| if e.names.named(&s) { e.name(&s) } else { s.to_string() });
            out.push(format!(
                "<label class=\"fld\"><span>Who</span>{}<small class=\"guid\">{}</small>{}</label>",
                e.text_field(&f("sid"), &shown, &format!(" placeholder=\"Name or SID, such as Everyone\"{off}{}", invalid("sid"))),
                h(&ace.sid.map(|s| s.to_string()).unwrap_or_default()),
                wrong("sid")
            ));
        }
        Way::Label => {
            let level = ace.sid.and_then(|s| sid_level(&s));
            let opts: Vec<(String, String, bool)> = INTEGRITY
                .iter()
                .map(|(k, n)| {
                    let above = !e.caller.may_label(*n) && Some(*n) != level;
                    (n.to_string(), if above { format!("{k} ({n}) — Needs SeRelabelPrivilege") } else { format!("{k} ({n})") }, above)
                })
                .collect();
            out.push(format!(
                "<label class=\"fld\"><span>Level</span>{}<small class=\"guid\">{}</small></label>",
                e.select(&f("level"), &opts, &level.map(|l| l.to_string()).unwrap_or_default(), off),
                h(&ace.sid.map(|s| s.to_string()).unwrap_or_default())
            ));
        }
        Way::Trust => {
            let (t, l) = ace.sid.and_then(|s| sid_trust(&s)).unwrap_or((512, 0));
            let types = vec![("0".to_string(), "None (0)".to_string(), false), ("512".into(), "Protected (512)".into(), false), ("1024".into(), "Isolated (1024)".into(), false)];
            out.push(format!(
                "<div class=\"fld\"><span>Trust</span><div class=\"pair\">{}{}</div><small class=\"guid\">{}</small>{}</div>",
                e.select(&f("ttype"), &types, &t.to_string(), &format!("{off} aria-label=\"Type\"")),
                e.text_field(&f("tlevel"), &l.to_string(), &format!(" inputmode=\"numeric\" aria-label=\"Trust level\"{off}{}", invalid("tlevel"))),
                h(&ace.sid.map(|s| s.to_string()).unwrap_or_default()),
                wrong("tlevel")
            ));
        }
        Way::Policy => {
            out.push(format!(
                "<label class=\"fld\"><span>Policy</span>{}{}</label>",
                e.text_field(&f("policy"), &ace.sid.map(|s| s.to_string()).unwrap_or_default(), &format!(" class=\"mono\" placeholder=\"S-1-17-…\"{off}{}", invalid("policy"))),
                wrong("policy")
            ));
        }
        Way::Claim => {
            let c = ace.claim.clone().unwrap_or(Claim { name: String::new(), kind: ClaimType::Text, flags: 0, values: vec![] });
            let types: Vec<(String, String, bool)> = ClaimType::ALL.iter().map(|t| (t.key().to_string(), format!("{} ({})", t.label(), t.sddl()), false)).collect();
            let flags = [("Not passed down", 0x1u32, false), ("Match case", 0x2, false), ("Only for refusals", 0x4, false), ("Off by default", 0x8, false), ("Off", 0x10, false), ("Locked (needs SeTcbPrivilege)", 0x20, !e.caller.tcb)];
            let bits: Vec<(String, u32, String, bool)> = flags.iter().map(|(n, m, l)| (n.to_string(), *m, format!("0x{m:x}"), *l)).collect();
            out.push(format!("<label class=\"fld\"><span>Claim</span>{}</label>", e.text_field(&f("aname"), &c.name, &format!(" placeholder=\"Such as Classification\"{off}"))));
            out.push(format!("<label class=\"fld\"><span>Kind</span>{}</label>", e.select(&f("atype"), &types, c.kind.key(), off)));
            out.push(format!(
                "<label class=\"fld\"><span>{}</span>{}{}</label>",
                if c.kind == ClaimType::Sid { "Users or Groups" } else { "Values" },
                e.text_field(&f("avals"), &c.values.join(", "), &format!(" placeholder=\"One or more, with commas\"{off}")),
                if e.checked { c.problem().map(|w| format!("<span class=\"wrong\">{}</span>", h(&w))).unwrap_or_default() } else { String::new() }
            ));
            out.push(format!("<div class=\"fld wide\"><span>Claim Flags <code class=\"guid\">0x{:x}</code></span>{}</div>", c.flags, bit_boxes(e, &f("aflag"), &bits, c.flags, fixed)));
        }
        _ => {}
    }
    if !matches!(ace.way, Way::Claim | Way::Policy) {
        let label = ace.way == Way::Label;
        let std = [("Read or change auditing", ACCESS_SYSTEM_SECURITY), ("Maximum allowed", MAXIMUM_ALLOWED)];
        let generics = [("Generic all", GENERIC_ALL, "GA"), ("Generic read", GENERIC_READ, "GR"), ("Generic write", GENERIC_WRITE, "GW"), ("Generic execute", GENERIC_EXECUTE, "GX")];
        let extra = std.iter().map(|(_, m)| m).chain(generics.iter().map(|(_, m, _)| m)).fold(0, |a, m| a | m);
        let has = ace.mask & extra != 0;
        let more = has || e.adv.as_ref().is_some_and(|a| a.more);
        let mut groups: Vec<(String, Vec<(String, u32, String, bool)>)> = Vec::new();
        if label {
            groups.push((String::new(), [("No write up", 1u32, "NW"), ("No read up", 2, "NR"), ("No execute up", 4, "NX")].iter().map(|(n, m, c)| (n.to_string(), *m, c.to_string(), false)).collect()));
        } else {
            let mut own: Vec<(String, u32, String, bool)> = e.obj.specific.iter().map(|r| (r.name.clone(), r.mask, format!("0x{:x}", r.mask), false)).collect();
            own.push(("Synchronize".into(), SYNCHRONIZE, "0x100000".into(), false));
            groups.push((format!("This {}'s Rights", title_case(&e.kind_word())), own));
            if more {
                groups.push(("Rarely Needed".into(), std.iter().map(|(n, m)| (n.to_string(), *m, format!("0x{m:x}"), false)).collect()));
                groups.push(("Generic".into(), generics.iter().map(|(n, m, c)| (n.to_string(), *m, c.to_string(), false)).collect()));
            }
        }
        let fold = if label || has {
            String::new()
        } else {
            format!(
                "<button type=\"button\" class=\"link small\" fx-click=\"x-more\" aria-expanded=\"{more}\">{}</button>",
                if more { "Hide the Rarely Needed Rights" } else { "Show Auditing, Maximum Allowed and Generic Rights" }
            )
        };
        let known = groups.iter().flat_map(|(_, b)| b.iter().map(|x| x.1)).fold(if label { 0 } else { extra }, |a, m| a | m);
        let other = ace.mask & !known;
        let title = if label { "Policy" } else if ace.way == Way::Trust { "What Less Trusted Programs May Do" } else { "Rights" };
        out.push(format!(
            "<div class=\"fld wide\"><div class=\"fhead\"><span>{title}</span>{}</div>{}{}{fold}{}</div>",
            e.text_field(&f("mask"), &format!("0x{:x}", ace.mask), &format!(" class=\"hex\" aria-label=\"As hex\"{off}{}", invalid("mask"))),
            wrong("mask"),
            groups.iter().map(|(t, bits)| format!("{}{}", if t.is_empty() { String::new() } else { format!("<span class=\"sub\">{}</span>", h(t)) }, bit_boxes(e, &f("bit"), bits, ace.mask, fixed))).collect::<String>(),
            if other != 0 { wrapped_note(&format!("Also bits this {} doesn't name: 0x{other:x}.", e.kind_word())) } else { String::new() }
        ));
    }
    let folder = e.obj.kind.eq_ignore_ascii_case("folder");
    let mut flag_bits: Vec<(String, u32, String, bool)> = vec![
        ((if folder { "Passed to files" } else { "Passed to items that aren't containers" }).into(), OI as u32, "OI".into(), false),
        ((if folder { "Passed to subfolders" } else { "Passed to containers" }).into(), CI as u32, "CI".into(), false),
        ("Passed one level only".into(), NP as u32, "NP".into(), false),
        ("Not for this item itself".into(), IO as u32, "IO".into(), false),
        ("Inherited".into(), ID as u32, "ID".into(), true),
    ];
    if matches!(ace.way, Way::Audit | Way::Alarm) || ace.flags & (SA | FA) != 0 {
        flag_bits.push(("Record successes".into(), SA as u32, "SA".into(), false));
        flag_bits.push(("Record failures".into(), FA as u32, "FA".into(), false));
    }
    out.push(format!(
        "<div class=\"fld wide\"><span>Flags <code class=\"guid\">{}</code></span>{}</div>",
        h(&if flags_text(ace.flags).is_empty() { "none".into() } else { flags_text(ace.flags) }),
        bit_boxes(e, &f("flag"), &flag_bits, ace.flags as u32, fixed)
    ));
    if ace.way.accessy() {
        let guid_field = |k: &str, label: &str, value: Option<Guid>, opts: Vec<(Guid, String)>, none: &str| {
            let list = format!("dl-{id}-{k}");
            let named = value.map_or_else(|| none.to_string(), |g| opts.iter().find(|(o, _)| *o == g).map_or_else(|| "Not one the program that opened this names".to_string(), |(_, n)| n.clone()));
            format!(
                "<label class=\"fld\"><span>{label}</span>{}<datalist id=\"{list}\">{}</datalist><small class=\"guid\">{}</small>{}</label>",
                e.text_field(&f(k), &value.map(|g| guid_text(&g)).unwrap_or_default(), &format!(" class=\"mono\" list=\"{list}\" placeholder=\"None\"{off}{}", invalid(k))),
                opts.iter().map(|(g, n)| format!("<option value=\"{}\" label=\"{}\">", guid_text(g), h(n))).collect::<String>(),
                h(&named),
                wrong(k)
            )
        };
        out.push(guid_field("obj", "Object Type", ace.object, e.obj.parts.iter().map(|p| (p.guid, p.name.clone())).collect(), "None: covers all of it"));
        out.push(guid_field("kind", "Inherited Object Type", ace.inherited_object, e.obj.kinds.clone(), "None: passed to every kind of item"));
        let cond = match &ace.cond {
            None if fixed => wrapped_note("None."),
            None => "<button type=\"button\" class=\"small\" fx-click=\"x-cond-add\">+ Add a Condition</button>".into(),
            Some(Cond::Tree(node)) => format!(
                "{}{}{}",
                e.cond_editor(node, CondOf::Entry(id), fixed),
                if e.checked { cond::tree_problem(node).map(|w| format!("<span class=\"wrong\">Its condition isn't finished: {}</span>", h(&w))).unwrap_or_default() } else { String::new() },
                if fixed { String::new() } else { "<button type=\"button\" class=\"small\" fx-click=\"x-cond-del\">Remove the Condition</button>".into() }
            ),
            Some(c @ Cond::Opaque(_)) => format!(
                "<code class=\"expr\">{}</code>{}{}",
                h(&c.text()),
                wrapped_note("The editor can't show this condition as tests, so it's kept exactly as it came."),
                if fixed { String::new() } else { "<button type=\"button\" class=\"small\" fx-click=\"x-cond-del\">Remove the Condition</button>".into() }
            ),
        };
        out.push(format!("<div class=\"fld wide\"><span>Condition</span>{cond}</div>"));
    }
    format!("<div class=\"xgrid\">{}</div>", out.concat())
}

/// The Descriptor tab: the owner, the primary group, the control flags, and
/// the whole descriptor as SDDL.
pub fn desc(e: &Editor) -> String {
    let editing = e.adv.as_ref().and_then(|a| a.text.as_ref());
    let off = if e.may_owner() && editing.is_none() { "" } else { " disabled" };
    let sid_field = |k: &str, label: &str, v: Option<Sid>, hint: &str| {
        let name = format!("x.{k}");
        let shown = v.map_or_else(String::new, |s| if e.names.named(&s) { e.name(&s) } else { s.to_string() });
        let why = e.wrong.get(&name).cloned().or_else(|| if k == "owner" && e.can.owner { v.and_then(|s| e.owner_problem(&s)) } else { None });
        format!(
            "<label class=\"fld\"><span>{label}</span>{}<small class=\"guid\">{}</small>{}</label>",
            e.text_field(&name, &shown, &format!("{}{off}{}", if k == "owner" { " list=\"may-own\"" } else { "" }, if why.is_some() { " aria-invalid=\"true\"" } else { "" })),
            h(&v.map(|s| s.to_string()).unwrap_or_default()),
            match why {
                Some(w) => format!("<span class=\"wrong\">{}</span>", h(&w)),
                None if !hint.is_empty() => format!("<span class=\"hint\">{}</span>", h(hint)),
                None => String::new(),
            }
        )
    };
    let may_own: Vec<String> = e.caller.may_own().iter().map(|s| e.name(s)).collect();
    let own_hint = if e.caller.restore { "Anyone: this program has SeRestorePrivilege.".to_string() } else if may_own.is_empty() { String::new() } else { format!("You can make {} the owner.", may_own.join(" or ")) };
    let c = e.sd.control_bits();
    let flags = [
        ("SR", "Self-relative", SR),
        ("DP", "Access list present", DP),
        ("PD", "Access list protected", PD),
        ("DI", "Access list auto-inherited", DI),
        ("SP", "SACL present", SP),
        ("PS", "SACL protected", PS),
        ("SI", "SACL auto-inherited", SI),
    ];
    let chips: String = flags.iter().map(|(code, n, bit)| {
        let on = c & bit != 0;
        format!("<span class=\"xb{}\" title=\"{}{}\">{} {code} · {}</span>", if on { " on" } else { "" }, h(n), if on { "" } else { " (off)" }, if on { "✓" } else { "–" }, h(n))
    }).collect();
    let whole = sd_text(&e.sd);
    let sddl = match editing {
        Some(draft) => {
            let rows = draft.lines().count().clamp(6, 18) + 1;
            let wrong = e.wrong.get("x.sddl").map(|w| format!("<span class=\"wrong\">{}</span>", h(w))).unwrap_or_default();
            format!(
                "<textarea class=\"sddl\" {} rows=\"{rows}\" spellcheck=\"false\" autocomplete=\"off\"{}>{}</textarea>{wrong}\
                 <span class=\"hint\">Entries you leave as they are go back exactly as they came. A comment marked # stands for an entry SDDL can't say: leave it where it should be, or take it out to remove the entry.</span>\
                 <div class=\"row\"><button type=\"button\" class=\"small primary\" fx-click=\"x-text-use\" fx-key=\"Ctrl+Enter\">Use This Text</button><button type=\"button\" class=\"small\" fx-click=\"x-text-cancel\">Cancel</button></div>",
                e.field("x.sddl", draft),
                if wrong.is_empty() { "" } else { " aria-invalid=\"true\"" },
                h(draft)
            )
        }
        None => format!(
            "<pre class=\"sddl\">{}</pre>{}",
            h(&whole),
            if may_text(e) { "<div class=\"row\"><button type=\"button\" class=\"small\" fx-click=\"x-text\">Edit as Text</button></div>" } else { "" }
        ),
    };
    format!(
        "<div class=\"xgrid\">{}{}</div><datalist id=\"may-own\">{}</datalist>{}\
         <div class=\"fld\"><span>Control Flags</span><div class=\"ctlflags\">{chips}</div>{}</div>\
         <div class=\"fld\"><span>The Whole Descriptor, as SDDL</span>{sddl}</div>{}",
        sid_field("owner", "Owner", e.sd.owner, &own_hint),
        sid_field("group", "Primary Group", e.sd.group, ""),
        may_own.iter().map(|n| format!("<option value=\"{}\">", h(n))).collect::<String>(),
        if e.can.owner { String::new() } else { format!("<p class=\"note fixed\">{}</p>", h(e.can.why.as_deref().unwrap_or("The program that opened this can't change the owner."))) },
        wrapped_note("Presence and protection are set on each list's tab; the others are kept as found."),
        if editing.is_some() { String::new() } else { wrapped_note("SDDL has no code for some entries, such as a type KACS doesn't act on, so they show as a comment. The editor hands the descriptor back as bytes (PSPU §8.5), so they still go back exactly as they came.") }
    )
}

/// Whether anything the text says can be changed.
fn may_text(e: &Editor) -> bool {
    e.may_owner() || e.may_dacl() || e.may_sacl() || e.may_label()
}

/// Why the descriptor the text says can't be taken, if it can't: it changes
/// a part this program can't, or the SACL beyond the label where only the
/// label can be.
fn text_refused(e: &Editor, new: &Descriptor) -> Option<String> {
    let same = |a: &Option<Acl>, b: &Option<Acl>, keep: &dyn Fn(&Ace) -> bool| match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => {
            let (a, b): (Vec<&Ace>, Vec<&Ace>) = (a.aces.iter().filter(|x| keep(x)).collect(), b.aces.iter().filter(|x| keep(x)).collect());
            a.len() == b.len() && a.iter().zip(&b).all(|(x, y)| x.same(y))
        }
        _ => false,
    };
    let all = |_: &Ace| true;
    let differs = |bits: u16| (new.control ^ e.sd.control) & bits != 0;
    if (new.owner != e.sd.owner || new.group != e.sd.group) && !e.may_owner() {
        return Some("The text changes the owner or group, which can't be changed here.".into());
    }
    if (!same(&new.dacl, &e.sd.dacl, &all) || differs(PD | DI | DR)) && !e.may_dacl() {
        return Some("The text changes the access list, which can't be changed here.".into());
    }
    if e.may_sacl() || (same(&new.sacl, &e.sd.sacl, &all) && !differs(PS | SI | SR_REQ)) {
        return None;
    }
    if e.may_label() && same(&new.sacl, &e.sd.sacl, &|a| a.way != Way::Label) && !differs(PS | SI | SR_REQ) {
        return None;
    }
    Some(if e.may_label() { "The text changes the SACL beyond its integrity label, and only the label can be changed here." } else { "The text changes the SACL, which can't be changed here." }.into())
}

/// Takes the descriptor the text says, if it can be.
fn use_text(e: &mut Editor) {
    let Some(draft) = e.adv.as_ref().and_then(|a| a.text.clone()) else { return };
    let taken = from_text(&draft, &e.sd, &mut e.ids).and_then(|new| text_refused(e, &new).map_or(Ok(new), Err));
    match taken {
        Err(why) => {
            e.wrong.insert("x.sddl".into(), why);
        }
        Ok(new) => {
            e.wrong.remove("x.sddl");
            let changed = new != e.sd;
            for sid in new.owner.iter().chain(&new.group).chain(new.dacl.iter().chain(&new.sacl).flat_map(|a| &a.aces).filter_map(|a| a.sid.as_ref())) {
                e.names.learn(sid);
            }
            e.sd = new;
            let first = |acl: &Option<Acl>| acl.as_ref().and_then(|a| a.aces.first()).map(|a| a.id);
            let (dacl, sacl) = (first(&e.sd.dacl), first(&e.sd.sacl));
            let keep = |id: Option<u32>, acl: &Option<Acl>| id.filter(|id| acl.iter().flat_map(|a| &a.aces).any(|a| a.id == *id));
            let (was_dacl, was_sacl) = e.adv.as_ref().map_or((None, None), |a| (a.dacl, a.sacl));
            let (dacl, sacl) = (keep(was_dacl, &e.sd.dacl).or(dacl), keep(was_sacl, &e.sd.sacl).or(sacl));
            if let Some(a) = &mut e.adv {
                a.text = None;
                a.stash = None;
                a.dacl = dacl;
                a.sacl = sacl;
            }
            e.status = if changed { "The descriptor now says what the text says.".into() } else { "The text says what the descriptor already did.".into() };
        }
    }
}

/// The keys Advanced mode's lists answer to.
pub fn keys(e: &Editor) -> String {
    match current(e) {
        Some(l) if may_list(e, l) => "<button type=\"button\" fx-key=\"Alt+ArrowUp\" fx-click=\"x-move\" fx-value-v=\"up\"></button><button type=\"button\" fx-key=\"Alt+ArrowDown\" fx-click=\"x-move\" fx-value-v=\"down\"></button>".into(),
        _ => String::new(),
    }
}

// ---- what Apply refuses

/// What stops the entries being written, if anything: only what can't be
/// written, or would do nothing at all, of what has changed.
pub fn fault(e: &Editor) -> Option<(String, Place)> {
    if let Some(draft) = e.adv.as_ref().and_then(|a| a.text.as_ref())
        && *draft != sd_text(&e.sd)
    {
        return Some(("The text has changes not used yet. Use This Text, or Cancel them.".into(), Place::Descriptor));
    }
    let changed_owner = e.sd.owner != e.applied.owner;
    match e.sd.owner {
        None => return Some(("Nobody owns it. Name an owner.".into(), Place::Descriptor)),
        Some(o) if changed_owner && e.can.owner => {
            if let Some(why) = e.owner_problem(&o) {
                return Some((why, Place::Descriptor));
            }
        }
        _ => {}
    }
    for (which, acl) in [(List::Dacl, &e.sd.dacl), (List::Sacl, &e.sd.sacl)] {
        let Some(acl) = acl else { continue };
        for (i, ace) in acl.aces.iter().enumerate() {
            // What came as it is goes back as it came.
            if e.found.ace(ace.id).is_some_and(|was| was.same(ace)) {
                continue;
            }
            let at = |why: String| Some((format!("Entry {} in the {}: {why}", i + 1, if which == List::Dacl { "access list" } else { "SACL" }), Place::Entry(which, ace.id)));
            if ace.way.accessy() && ace.sid.is_none() {
                return at("Name who it's for.".into());
            }
            if ace.way.accessy() && ace.mask == 0 && e.adv.is_some() {
                return at("It covers no rights. Tick at least one, or remove it.".into());
            }
            if ace.way == Way::Trust && ace.sid.and_then(|s| sid_trust(&s)).is_none() {
                return at("The trust level is a whole number, such as 1024.".into());
            }
            if ace.way == Way::Label
                && let Some(level) = ace.sid.and_then(|s| sid_level(&s))
                && !e.caller.may_label(level)
                && e.found.ace(ace.id).and_then(|a| a.sid) != ace.sid
            {
                return at("That level is above your own, which takes SeRelabelPrivilege.".into());
            }
            if let Some(Cond::Tree(node)) = &ace.cond
                && let Some(why) = cond::tree_problem(node)
            {
                return at(format!("Its condition isn't finished: {why}"));
            }
            if let Some(c) = &ace.claim
                && let Some(why) = c.problem()
            {
                return at(why);
            }
        }
    }
    None
}

// ---- inheriting again

/// Takes the access list's inherited entries back from the parent's.
pub fn reinherit_dacl(e: &mut Editor, parent: &[u8]) {
    reinherit(e, parent, List::Dacl);
}

/// Takes the SACL's inherited entries back from the parent's.
pub fn reinherit_sacl(e: &mut Editor, parent: &[u8]) {
    reinherit(e, parent, List::Sacl);
}

/// Unprotects `list` and takes its inherited entries back from `parent`'s,
/// as KACS gives them to an object it creates (PCDS §5.6, re-propagation,
/// which libpeios does): this object's own stay as they are, and the
/// parent's come after them.
fn reinherit(e: &mut Editor, parent: &[u8], list: List) {
    let (bit, auto, info) = match list {
        List::Dacl => (PD, DI, SecInfo::DACL),
        List::Sacl => (PS, SI, SecInfo::SACL),
    };
    let was = e.sd.control;
    e.sd.control &= !bit;
    let child = match e.sd.build(&e.found) {
        Ok(b) => b,
        Err(why) => {
            e.trouble = Some(why);
            e.sd.control = was;
            return;
        }
    };
    let g = e.obj.generic;
    let mapping = GenericMapping::new(g.read, g.write, g.execute, g.all);
    let result = match peios::security::reinherit_with(parent, &child, e.obj.container, Some(&mapping), info) {
        Ok(sd) => sd,
        Err(why) => {
            e.trouble = Some(format!("What {} passes down could not be worked out: {why}.", e.from_word()));
            e.sd.control = was;
            return;
        }
    };
    let mut found = Found::default();
    let Ok(got) = Descriptor::parse(result.as_bytes(), &mut e.ids, &mut found) else { return };
    let (theirs, mine) = match list {
        List::Dacl => (got.dacl, &mut e.sd.dacl),
        List::Sacl => (got.sacl, &mut e.sd.sacl),
    };
    let inherited: Vec<Ace> = theirs.map(|l| l.aces.into_iter().filter(Ace::inherited).collect()).unwrap_or_default();
    if mine.is_none() && !inherited.is_empty() {
        *mine = Some(Acl { revision: 2, aces: vec![] });
    }
    if let Some(l) = mine {
        l.aces.retain(|a| !a.inherited());
        l.aces.extend(inherited);
    }
    e.sd.control |= auto;
}

// ---- what the controls do

pub fn event(e: &mut Editor, name: &str, value: &Value, _fields: &mut Fields) {
    let v = |k: &str| value[k].as_str().unwrap_or("").to_string();
    if name == "x-more" {
        if let Some(a) = &mut e.adv {
            a.more = !a.more;
        }
        return;
    }
    match name {
        "x-text" if may_text(e) => {
            let whole = sd_text(&e.sd);
            if let Some(a) = &mut e.adv {
                a.text = Some(whole);
            }
            return;
        }
        "x-text-use" => return use_text(e),
        "x-text-cancel" => {
            if let Some(a) = &mut e.adv {
                a.text = None;
            }
            e.wrong.remove("x.sddl");
            return;
        }
        _ => {}
    }
    let Some(which) = current(e) else { return };
    if name == "x-sel" {
        if let Ok(id) = v("id").parse() {
            select(e, which, Some(id));
        }
        return;
    }
    if name == "x-add" {
        if !may_list(e, which) {
            return;
        }
        let read = e.obj.general.iter().find(|r| r.name.eq_ignore_ascii_case("Read")).map_or(e.obj.generic.read, |r| r.mask);
        let write = e.obj.general.iter().find(|r| r.name.eq_ignore_ascii_case("Write")).map_or(e.obj.generic.write, |r| r.mask);
        let id = e.ids.next();
        let home = e.obj.home();
        let ace = match which {
            List::Dacl => Ace { sid: None, ..Ace::new(id, Way::Allow, home, read, everyone()) },
            List::Sacl => Ace::new(id, Way::Audit, home | FA, write, everyone()),
        };
        let list = match which {
            List::Dacl => e.sd.dacl.get_or_insert(Acl { revision: 2, aces: vec![] }),
            List::Sacl => e.sd.sacl.get_or_insert(Acl { revision: 2, aces: vec![] }),
        };
        // A new entry goes before what is inherited.
        let at = if which == List::Dacl { list.aces.iter().position(Ace::inherited).unwrap_or(list.aces.len()) } else { list.aces.len() };
        list.aces.insert(at, ace);
        select(e, which, Some(id));
        return;
    }
    if name == "x-moved" {
        // Dropped somewhere else among the entries: `to` is where it now is.
        let (Ok(id), Ok(to)) = (v("id").parse::<u32>(), v("to").parse::<usize>()) else { return };
        if !may_list(e, which) {
            return;
        }
        let Some(acl) = acl_mut(e, which) else { return };
        let Some(from) = acl.aces.iter().position(|a| a.id == id) else { return };
        let ace = acl.aces.remove(from);
        acl.aces.insert(to.min(acl.aces.len()), ace);
        select(e, which, Some(id));
        return;
    }
    if name == "x-order" {
        if !may_list(e, which) {
            return;
        }
        if let Some(acl) = acl_mut(e, which) {
            acl.aces = edit::in_order(std::mem::take(&mut acl.aces));
            e.status = "Put in the standard order.".into();
        }
        return;
    }
    let Some(id) = selected(e, which) else { return };
    let Some((ace, _)) = e.entry(id) else { return };
    let ace = ace.clone();
    let may = may_entry(e, &ace, which);
    match name {
        "x-move" if may_list(e, which) || may => {
            let Some(acl) = acl_mut(e, which) else { return };
            let Some(i) = acl.aces.iter().position(|a| a.id == id) else { return };
            let j = if v("v") == "up" { i.checked_sub(1) } else { Some(i + 1).filter(|j| *j < acl.aces.len()) };
            if let Some(j) = j {
                acl.aces.swap(i, j);
            }
        }
        "x-dup" if may_list(e, which) => {
            let new = e.ids.next();
            let Some(acl) = acl_mut(e, which) else { return };
            let Some(i) = acl.aces.iter().position(|a| a.id == id) else { return };
            acl.aces.insert(i + 1, Ace { id: new, ..ace });
            select(e, which, Some(new));
        }
        "x-del" if may => {
            let Some(acl) = acl_mut(e, which) else { return };
            let Some(i) = acl.aces.iter().position(|a| a.id == id) else { return };
            acl.aces.remove(i);
            let next = acl.aces.get(i).or(i.checked_sub(1).and_then(|j| acl.aces.get(j))).map(|a| a.id);
            e.wrong.retain(|k, _| !k.starts_with(&format!("x.{id}.")));
            select(e, which, next);
        }
        "x-own" if may => {
            if let Some(a) = e.entry_mut(id) {
                a.flags &= !ID;
            }
        }
        "x-cond-add" if may && !ace.inherited() && ace.way.accessy() => {
            if let Some(a) = e.entry_mut(id) {
                a.cond = Some(Cond::Tree(Node::fresh()));
            }
        }
        "x-cond-del" if may && !ace.inherited() => {
            if let Some(a) = e.entry_mut(id) {
                a.cond = None;
            }
        }
        _ => {}
    }
}

/// Changing what kind of SACL entry it is starts its fields afresh.
fn retype(e: &Editor, ace: &mut Ace, way: Way) {
    let was = ace.way;
    ace.way = way;
    let read = e.obj.general.iter().find(|r| r.name.eq_ignore_ascii_case("Read")).map_or(e.obj.generic.read, |r| r.mask);
    if way.accessy() {
        if !was.accessy() {
            ace.sid = Some(everyone());
            ace.mask = read;
            ace.claim = None;
        }
        if matches!(way, Way::Audit | Way::Alarm) && ace.flags & (SA | FA) == 0 {
            ace.flags |= FA;
        }
        if matches!(way, Way::Allow | Way::Deny) {
            ace.flags &= !(SA | FA);
        }
        return;
    }
    ace.object = None;
    ace.inherited_object = None;
    ace.cond = None;
    ace.claim = None;
    ace.flags &= !(SA | FA);
    match way {
        Way::Label => {
            ace.sid = Some(level_sid(8192.min(e.caller.integrity.max(4096))));
            ace.mask = 1;
        }
        Way::Trust => {
            ace.sid = trust_sid(512, 1024);
            ace.mask = read;
        }
        Way::Claim => {
            ace.sid = Some(everyone());
            ace.mask = 0;
            ace.claim = Some(Claim { name: String::new(), kind: ClaimType::Text, flags: 0, values: vec![] });
        }
        Way::Policy => {
            ace.sid = "S-1-17-0".parse().ok();
            ace.mask = 0;
        }
        _ => {}
    }
}

pub fn input(e: &mut Editor, name: &str, value: &str) {
    if name == "advmode" {
        e.status.clear();
        e.trouble = None;
        if value.is_empty() { leave(e) } else { enter(e) }
        return;
    }
    let parts: Vec<&str> = name.split('.').collect();
    match parts.as_slice() {
        ["x", "sddl"] => {
            if let Some(a) = &mut e.adv
                && a.text.is_some()
            {
                a.text = Some(value.to_string());
            }
        }
        ["x", "owner" | "group"] => {
            if !e.may_owner() {
                return;
            }
            e.typed.insert(name.to_string(), value.to_string());
            match e.names.find(value) {
                Ok(sid) => {
                    e.wrong.remove(name);
                    if parts[1] == "owner" { e.sd.owner = Some(sid) } else { e.sd.group = Some(sid) }
                }
                Err(why) if value.trim().is_empty() && parts[1] == "group" => {
                    let _ = why;
                    e.wrong.remove(name);
                    e.sd.group = None;
                }
                Err(why) => {
                    e.wrong.insert(name.to_string(), why);
                }
            }
        }
        ["x", "null"] => {
            if !e.may_dacl() {
                return;
            }
            let stash = if value.is_empty() { e.adv.as_mut().and_then(|a| a.stash.take()).or(Some(Acl { revision: 2, aces: vec![] })) } else { None };
            if !value.is_empty() {
                let gone = e.sd.dacl.take();
                if let Some(a) = &mut e.adv {
                    a.stash = gone;
                }
            } else {
                e.sd.dacl = stash;
            }
        }
        ["x", "prot", which] => {
            let (list, bit) = if *which == "dacl" { (List::Dacl, PD) } else { (List::Sacl, PS) };
            if !may_list(e, list) {
                return;
            }
            if value.is_empty() { e.sd.control &= !bit } else { e.sd.control |= bit }
        }
        ["x", id, what, rest @ ..] => {
            let Ok(id) = id.parse::<u32>() else { return };
            let Some((ace, list)) = e.entry(id) else { return };
            if !may_entry(e, ace, list) || ace.inherited() {
                return;
            }
            let mut ace = ace.clone();
            let bit: u32 = rest.first().and_then(|b| b.parse().ok()).unwrap_or(0);
            let on = !value.is_empty();
            let mut wrong: Option<String> = None;
            match *what {
                "way" => {
                    let way = match value {
                        "allow" => Way::Allow,
                        "deny" => Way::Deny,
                        "audit" => Way::Audit,
                        "alarm" => Way::Alarm,
                        "label" => Way::Label,
                        "trust" => Way::Trust,
                        "claim" => Way::Claim,
                        "policy" => Way::Policy,
                        _ => return,
                    };
                    if list == List::Sacl && way != Way::Label && !e.may_sacl() {
                        return;
                    }
                    retype(e, &mut ace, way);
                }
                "sid" => {
                    e.typed.insert(name.to_string(), value.to_string());
                    match e.names.find(value) {
                        Ok(sid) => ace.sid = Some(sid),
                        Err(why) => wrong = Some(if value.trim().is_empty() { "Name who it's for.".into() } else { why }),
                    }
                }
                "mask" => {
                    e.typed.insert(name.to_string(), value.to_string());
                    let v = value.trim();
                    let n = v.strip_prefix("0x").or_else(|| v.strip_prefix("0X")).map_or_else(|| v.parse::<u32>().ok(), |hex| u32::from_str_radix(hex, 16).ok());
                    match n {
                        Some(n) => ace.mask = n,
                        None => wrong = Some("Write the rights in hex, such as 0x1200a9.".into()),
                    }
                }
                "bit" => ace.mask = if on { ace.mask | bit } else { ace.mask & !bit },
                "flag" => ace.flags = if on { ace.flags | bit as u8 } else { ace.flags & !(bit as u8) },
                "obj" | "kind" => {
                    e.typed.insert(name.to_string(), value.to_string());
                    let g = if value.trim().is_empty() { Some(None) } else { guid_parse(value).map(Some) };
                    match g {
                        Some(g) => {
                            if *what == "obj" { ace.object = g } else { ace.inherited_object = g }
                        }
                        None => wrong = Some("A GUID is written like bf967aba-0de6-11d0-a285-00aa003049e2.".into()),
                    }
                }
                "level" => {
                    let Ok(n) = value.parse::<u32>() else { return };
                    if !e.caller.may_label(n) {
                        return;
                    }
                    ace.sid = Some(level_sid(n));
                }
                "ttype" | "tlevel" => {
                    if *what == "tlevel" {
                        e.typed.insert(name.to_string(), value.to_string());
                    }
                    let (t, l) = ace.sid.and_then(|s| sid_trust(&s)).unwrap_or((512, 0));
                    let t = if *what == "ttype" { value.parse().unwrap_or(t) } else { t };
                    match if *what == "tlevel" { value.trim().parse::<u32>().ok() } else { Some(l) } {
                        Some(l) => ace.sid = trust_sid(t, l),
                        None => wrong = Some("The trust level is a whole number, such as 1024.".into()),
                    }
                }
                "policy" => {
                    e.typed.insert(name.to_string(), value.to_string());
                    match value.trim().parse::<Sid>() {
                        Ok(s) if value.trim().starts_with("S-1-17-") => ace.sid = Some(s),
                        _ => wrong = Some("A central access policy is named by its SID, such as S-1-17-….".into()),
                    }
                }
                "aname" | "atype" | "avals" | "aflag" => {
                    let c = ace.claim.get_or_insert(Claim { name: String::new(), kind: ClaimType::Text, flags: 0, values: vec![] });
                    match *what {
                        "aname" => c.name = value.to_string(),
                        "atype" => {
                            if let Some(t) = ClaimType::from_key(value) {
                                c.kind = t;
                                if t != ClaimType::Text {
                                    c.flags &= !claim::CASE_SENSITIVE;
                                }
                            }
                        }
                        "avals" => {
                            e.typed.insert(name.to_string(), value.to_string());
                            let sid = c.kind == ClaimType::Sid;
                            let vals: Vec<String> = value.split(',').map(str::trim).filter(|v| !v.is_empty()).map(String::from).collect();
                            c.values = if sid { vals.iter().map(|v| e.names.find(v).map_or_else(|_| v.clone(), |s| s.to_string())).collect() } else { vals };
                        }
                        _ => {
                            if bit == claim::MANDATORY && !e.caller.tcb {
                                return;
                            }
                            c.flags = if on { c.flags | bit } else { c.flags & !bit };
                        }
                    }
                }
                _ => return,
            }
            match wrong {
                Some(w) => {
                    e.wrong.insert(name.to_string(), w);
                }
                None => {
                    e.wrong.remove(name);
                    if let Some(a) = e.entry_mut(id) {
                        *a = ace;
                    }
                }
            }
        }
        _ => {}
    }
}

