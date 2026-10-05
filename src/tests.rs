//! The dialog, driven as a person would drive it: what it shows, and what
//! pressing and typing does to the descriptor it sends.

use gxwi_sd_editor::{Can, Generic, Object, Request, Right};
use libgxwi::{Facts, Fields, Live};
use peios::security::sddl;
use serde_json::json;

use super::*;

const DOM: &str = "S-1-5-21-1-2-3-";

fn folder_rights() -> Vec<Right> {
    let g = |name: &str, mask| Right { name: name.into(), mask, general: true };
    let s = |name: &str, mask| Right { name: name.into(), mask, general: false };
    vec![
        g("Full control", 0x1f01ff),
        g("Modify", 0x1301bf),
        g("Read & execute", 0x1200a9),
        g("Read", 0x120089),
        g("Write", 0x100116),
        s("Traverse folder / run file", 0x20),
        s("List folder / read data", 0x1),
        s("Read attributes", 0x80),
        s("Read extended attributes", 0x8),
        s("Create files / write data", 0x2),
        s("Create folders / append data", 0x4),
        s("Write attributes", 0x100),
        s("Write extended attributes", 0x10),
        s("Delete subfolders and files", 0x40),
        s("Delete", 0x10000),
        s("Read permissions", 0x20000),
        s("Change permissions", 0x40000),
        s("Take ownership", 0x80000),
    ]
}

/// The editor open on a folder with `text` as its descriptor, as a program
/// that can do what `can` says asked for it, by a caller who is an elevated
/// administrator.
pub fn editor(text: &str, can: Can) -> Editor {
    let sd = sddl::parse(text).unwrap();
    let request = Request {
        object: Object { name: "finance".into(), kind: "Folder".into(), container: true, parent: Some(gxwi_sd_editor::Parent { name: "/srv".into(), sd: None }), ..Object::default() },
        sd: sd.as_bytes().to_vec(),
        rights: folder_rights(),
        generic: Generic { read: 0x120089, write: 0x100116, execute: 0x1200a0, all: 0x1f01ff },
        can,
        ..Request::default()
    };
    let caller = Caller {
        user: Some(format!("{DOM}1000").parse().unwrap()),
        owner_groups: vec!["S-1-5-32-544".parse().unwrap()],
        sids: vec![],
        restore: false,
        relabel: false,
        tcb: false,
        take_ownership: false,
        integrity: 12288,
        pip_type: 512,
        pip_trust: 2048,
    };
    Editor::new(request, Names::offline(), caller, Learned::default()).unwrap()
}

pub fn all() -> Can {
    Can { dacl: true, owner: true, audit: true, label: true, propagate: true, why: None }
}

pub fn shown(e: &Editor) -> String {
    e.render(&Facts { views: 1, fields: &Fields::default() })
}

pub fn press(e: &mut Editor, name: &str, value: serde_json::Value) {
    let mut fields = Fields::default();
    e.event(name, &value, &mut fields);
}

pub fn type_in(e: &mut Editor, name: &str, value: &str) {
    let mut fields = Fields::default();
    fields.set(name, value);
    e.input(name, &mut fields);
}

/// The descriptor as the editor writes SDDL, on one line. libpeios'
/// formatter refuses a whole descriptor holding a type it has no code for.
pub fn sddl_of(e: &Editor) -> String {
    e.sd.build(&e.found).expect("it can be written");
    text::sd_text(&e.sd).replace("\n  ", "").replace('\n', "")
}

fn sid(rid: u32) -> String {
    format!("{DOM}{rid}")
}

#[test]
fn a_folder_opens_on_who_it_names_and_ticking_changes_the_list() {
    let mut e = editor(&format!("O:{o}G:{o}D:(D;OICI;0x10156;;;{c})(A;OICI;0x1301bf;;;{f})(A;OICIID;FA;;;SY)", o = sid(1001), c = sid(1106), f = sid(1105)), all());
    let html = shown(&e);
    assert!(html.contains("Users and Groups") && html.contains("Access &amp; Auditing"), "{html}");
    assert_eq!(e.listed.len(), 3);
    // Finance's Modify; tick Full control.
    press(&mut e, "pick", json!({ "sid": sid(1105) }));
    press(&mut e, "tick", json!({ "mask": "2032127", "way": "allow" }));
    assert!(sddl_of(&e).contains(&format!("(A;OICI;FA;;;{})", sid(1105))), "{}", sddl_of(&e));
    assert_eq!(e.changed(), [Part::Dacl]);
    // Untick it again: nothing has changed.
    press(&mut e, "tick", json!({ "mask": "2032127", "way": "allow" }));
    press(&mut e, "tick", json!({ "mask": "1245631", "way": "allow" }));
    assert_eq!(e.changed(), [] as [Part; 0], "{}", sddl_of(&e));
}

/// The finance folder of the mock: a refusal, Finance's Modify, a
/// conditional rule for Auditors, a folder-only rule, Creator Owner, and
/// what comes from /srv; a label, auditing and two claims.
fn finance() -> String {
    format!(
        "O:{dana}G:{fin}D:(D;OICI;0x10156;;;{con})(A;OICI;0x1301bf;;;{fin})(XA;OICI;0x1200a9;;;{aud};(@Device.Compliance == \"Compliant\" || Device_Member_of_Any {{SID({lab})}}))(A;;0x1200a9;;;AU)(A;OICIIO;GA;;;CO)(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)\
         S:(AU;OICIFA;0x10156;;;WD)(AU;OICISAFA;0x120089;;;{con})(RA;OICI;;;;WD;(\"Classification\",TS,0x0,\"Confidential\"))",
        dana = sid(1001),
        fin = sid(1105),
        con = sid(1106),
        aud = sid(1107),
        lab = sid(2002)
    )
}

#[test]
fn the_mock_finance_folder_reads_as_the_mock_showed_it() {
    let mut e = editor(&finance(), all());
    // Contractors' refusal opens straight into the advanced rights.
    press(&mut e, "pick", json!({ "sid": sid(1106) }));
    assert!(e.advanced);
    // Auditors' rule is in Conditionals, as a tree.
    press(&mut e, "pick", json!({ "sid": sid(1107) }));
    press(&mut e, "tab", json!({ "v": "cond" }));
    let html = shown(&e);
    assert!(html.contains("@Device.Compliance == &quot;Compliant&quot; || Device_Member_of_Any {SID(S-1-5-21-1-2-3-2002)}"), "{html}");
    assert!(html.contains("If their device&#39;s Compliance isn&#39;t known, this rule gives nothing.") || html.contains("If their device's Compliance isn't known, this rule gives nothing."), "{html}");
    // Authenticated Users' rule is for the folder only.
    press(&mut e, "pick", json!({ "sid": "S-1-5-11" }));
    assert_eq!(e.scope, 0);
    // Nothing has changed, so nothing is to be sent.
    assert!(e.changed().is_empty());
    assert_eq!(e.simple().claims.len(), 1);
}

#[test]
fn a_conditional_rule_is_made_finished_and_compared_with_another_claim() {
    let mut e = editor(&finance(), all());
    press(&mut e, "pick", json!({ "sid": sid(1105) }));
    press(&mut e, "tab", json!({ "v": "cond" }));
    press(&mut e, "c-new", json!({}));
    let card = e.simple().cards(&sid(1105).parse().unwrap())[0].key;
    // Unfinished, Apply refuses it and says why.
    press(&mut e, "apply", json!({}));
    assert_eq!(e.trouble.as_deref(), Some("A condition for S-1-5-21-1-2-3-1105 isn't finished: Name the claim to test."));
    type_in(&mut e, &format!("c.d{card}.0.name"), "Department");
    type_in(&mut e, &format!("c.d{card}.0.vsrc"), "Resource");
    press(&mut e, "apply", json!({}));
    assert_eq!(e.trouble.as_deref(), Some("A condition for S-1-5-21-1-2-3-1105 isn't finished: Name the claim to compare it with."));
    type_in(&mut e, &format!("c.d{card}.0.val"), "Department");
    let node = e.cond_of(CondOf::Card(card)).unwrap();
    assert_eq!(cond::expr(&node), "@User.Department == @Resource.Department");
    assert!(e.fault().is_none(), "{:?}", e.fault().map(|f| f.0));
    assert!(sddl_of(&e).contains("(XA;OICI;0x120089;;;S-1-5-21-1-2-3-1105;(@User.Department == @Resource.Department))"), "{}", sddl_of(&e));
    // A group inside, and taking its only test away takes it away.
    press(&mut e, "c-add", json!({ "k": format!("d{card}"), "p": "r", "v": "group" }));
    assert!(matches!(e.cond_of(CondOf::Card(card)), Some(Node::Group(_, items)) if items.len() == 2));
    press(&mut e, "c-del-node", json!({ "k": format!("d{card}"), "p": "1" }));
    press(&mut e, "c-del-node", json!({ "k": format!("d{card}"), "p": "0" }));
    assert!(e.simple().cards(&sid(1105).parse().unwrap()).is_empty(), "with no test left it's an ordinary rule");
}

#[test]
fn the_owner_can_be_given_only_where_kacs_allows() {
    let mut e = editor(&finance(), all());
    press(&mut e, "change-owner", json!({}));
    assert!(shown(&e).contains("You can make S-1-5-21-1-2-3-1000 or BUILTIN\\Administrators the owner."), "{}", shown(&e));
    let mut fields = Fields::default();
    for (k, v) in [("own.owner", "S-1-5-21-1-2-3-1004"), ("own.group", "S-1-5-21-1-2-3-1105"), ("own.level", ""), ("own.trust", "")] {
        fields.set(k, v);
    }
    e.event("owners", &json!({}), &mut fields);
    assert!(e.wrong.get("owner").is_some_and(|w| w.contains("SeRestorePrivilege")), "{:?}", e.wrong);
    assert_eq!(e.sd.owner, Some(sid(1001).parse().unwrap()));
    press(&mut e, "own-me", json!({}));
    assert_eq!(e.draft("owner"), sid(1000));
    fields.set("own.owner", &sid(1000));
    e.event("owners", &json!({}), &mut fields);
    assert!(e.wrong.is_empty() && e.asking.is_none());
    assert_eq!(e.sd.owner, Some(sid(1000).parse().unwrap()));
    assert_eq!(e.changed(), [Part::Owner]);
    // With SeRestorePrivilege, anyone.
    let mut e = editor(&finance(), all());
    e.caller.restore = true;
    press(&mut e, "change-owner", json!({}));
    fields.set("own.owner", &sid(1004));
    e.event("owners", &json!({}), &mut fields);
    assert!(e.wrong.is_empty(), "{:?}", e.wrong);
}

#[test]
fn a_label_alone_is_sent_as_the_label_and_a_level_above_is_refused() {
    let mut e = editor(&finance(), all());
    press(&mut e, "change-owner", json!({}));
    let mut fields = Fields::default();
    for (k, v) in [("own.owner", sid(1001)), ("own.group", sid(1105)), ("own.level", "8192".into()), ("own.nw", "on".into()), ("own.nr", "on".into()), ("own.trust", String::new())] {
        fields.set(k, &v);
    }
    e.event("owners", &json!({}), &mut fields);
    assert_eq!(e.simple().label.map(|l| (l.level, l.policy)), Some((8192, 3)));
    assert_eq!(e.changed(), [Part::Label]);
    // A program that can't apply a label alone sends the SACL.
    e.can.label = false;
    assert_eq!(e.changed(), [Part::Sacl]);
    // Above the caller's own High, without SeRelabel, nothing changes.
    let mut e = editor(&finance(), all());
    press(&mut e, "change-owner", json!({}));
    fields.set("own.level", "16384");
    e.event("owners", &json!({}), &mut fields);
    assert!(e.simple().label.is_none());
}

#[test]
fn only_the_misplaced_rule_for_a_part_is_kept_and_moving_it_frees_it() {
    let sd = format!(
        "O:BAG:BAD:(A;CI;0x20094;;;AU)(OD;CIIO;0x100;00299570-246d-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;{con})(OA;CIIO;0x100;00299570-246d-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;{rowan})(A;CIID;0xf01ff;;;BA)",
        con = sid(1106),
        rowan = sid(1000)
    );
    let mut e = editor(&sd, all());
    e.obj.children = gxwi_sd_editor::Children::Containers;
    e.obj.parts = vec![PartDef { guid: sd::guid_parse("00299570-246d-11d0-a768-00aa006e0529").unwrap(), name: "Reset password".into(), kind: gxwi_sd_editor::PartKind::Right, set: None }];
    e.obj.kinds = vec![(sd::guid_parse("bf967aba-0de6-11d0-a285-00aa003049e2").unwrap(), "Accounts".into())];
    let s = e.simple();
    assert_eq!(s.parts.len(), 1, "rowan's rule is in Specific Rights");
    assert_eq!(s.entries().iter().filter(|x| x.kept.is_some()).count(), 1, "Contractors' refusal is Advanced only");
    assert!(shown(&e).contains("1 entry can only be shown in Advanced mode"));
    // In Advanced mode, move it up above the allow: it's then in place.
    press(&mut e, "adv-open", json!({}));
    let id = e.adv.as_ref().unwrap().dacl.unwrap();
    assert_eq!(e.entry(id).unwrap().0.sid, Some(sid(1106).parse().unwrap()));
    press(&mut e, "x-move", json!({ "v": "up" }));
    type_in(&mut e, "advmode", "");
    assert_eq!(e.simple().parts.len(), 2);
    assert!(e.simple().entries().iter().all(|x| x.kept.is_none()));
}

#[test]
fn an_entry_dragged_is_where_it_was_dropped() {
    let mut e = editor(&finance(), all());
    type_in(&mut e, "advmode", "on");
    let ids: Vec<u32> = e.sd.dacl.as_ref().unwrap().aces.iter().map(|a| a.id).collect();
    let html = shown(&e);
    assert!(html.contains("fx-reorder=\"x-moved\"") && html.contains(&format!("id=\"x{}\" fx-drag fx-value-id=\"{}\"", ids[3], ids[3])), "{html}");
    press(&mut e, "x-moved", json!({ "id": ids[3].to_string(), "to": "0" }));
    let now: Vec<u32> = e.sd.dacl.as_ref().unwrap().aces.iter().map(|a| a.id).collect();
    assert_eq!(now[..4], [ids[3], ids[0], ids[1], ids[2]]);
    assert_eq!(e.adv.as_ref().unwrap().dacl, Some(ids[3]));
    // Past the end, it goes last.
    press(&mut e, "x-moved", json!({ "id": ids[3].to_string(), "to": "99" }));
    assert_eq!(e.sd.dacl.as_ref().unwrap().aces.last().unwrap().id, ids[3]);
    // A list the program can't change can't be dragged.
    let mut e = editor(&finance(), Can { dacl: false, ..all() });
    type_in(&mut e, "advmode", "on");
    assert!(!shown(&e).contains("fx-drag"));
    press(&mut e, "x-moved", json!({ "id": ids[3].to_string(), "to": "0" }));
    assert_eq!(e.sd.dacl.as_ref().unwrap().aces[3].id, ids[3]);
}

#[test]
fn the_descriptor_is_edited_as_text_within_what_the_program_can_change() {
    let mut e = editor(&finance(), all());
    type_in(&mut e, "advmode", "on");
    press(&mut e, "top", json!({ "v": "desc" }));
    press(&mut e, "x-text", json!({}));
    let text = e.adv.as_ref().unwrap().text.clone().unwrap();
    assert!(shown(&e).contains("Use This Text"));
    // Unused changes hold Apply back.
    let refuse = text.replace("(A;;0x1200a9;;;AU)", "(D;;0x1200a9;;;AU)");
    type_in(&mut e, "x.sddl", &refuse);
    assert!(e.fault().is_some_and(|f| f.0.contains("not used yet")));
    press(&mut e, "x-text-use", json!({}));
    assert!(e.adv.as_ref().unwrap().text.is_none(), "{:?}", e.wrong);
    assert!(sddl_of(&e).contains("(D;;0x1200a9;;;AU)"));
    assert_eq!(e.changed(), [Part::Dacl]);
    // Wrong text is said, and stays to be put right.
    press(&mut e, "x-text", json!({}));
    type_in(&mut e, "x.sddl", &text.replace("(A;;0x1200a9;;;AU)", "(A;;0x1200a9;;;AU"));
    press(&mut e, "x-text-use", json!({}));
    assert!(e.wrong.get("x.sddl").is_some_and(|w| w.contains("bracket")));
    press(&mut e, "escape", json!({}));
    assert!(e.adv.as_ref().unwrap().text.is_none() && e.closer.is_none());
    // A program that can't change the SACL can't have it changed by text.
    let mut e = editor(&finance(), Can { audit: false, label: false, ..all() });
    type_in(&mut e, "advmode", "on");
    press(&mut e, "x-text", json!({}));
    let text = e.adv.as_ref().unwrap().text.clone().unwrap();
    type_in(&mut e, "x.sddl", &text.replace("(AU;OICIFA;", "(AU;OICISAFA;"));
    press(&mut e, "x-text-use", json!({}));
    assert_eq!(e.wrong.get("x.sddl").map(String::as_str), Some("The text changes the SACL, which can't be changed here."));
    assert!(e.changed().is_empty());
}

#[test]
fn advanced_mode_changes_entries_and_the_simple_view_follows() {
    let mut e = editor(&finance(), all());
    type_in(&mut e, "advmode", "on");
    // Finance's entry, to Read.
    let fin = e.sd.dacl.as_ref().unwrap().aces[1].id;
    press(&mut e, "x-sel", json!({ "id": fin.to_string() }));
    type_in(&mut e, &format!("x.{fin}.mask"), "0x120089");
    assert!(shown(&e).contains("Gives S-1-5-21-1-2-3-1105 Read on this folder, subfolders and files."), "{}", shown(&e));
    type_in(&mut e, &format!("x.{fin}.mask"), "nonsense");
    assert_eq!(e.wrong.get(&format!("x.{fin}.mask")).map(String::as_str), Some("Write the rights in hex, such as 0x1200a9."));
    type_in(&mut e, "advmode", "");
    let shown = e.simple().shown(&e.obj, &sid(1105).parse().unwrap(), sd::OI | sd::CI, &[0x120089, 0x1301bf]);
    assert_eq!(shown, [(edit::Tick::Yes, edit::Tick::No), (edit::Tick::No, edit::Tick::No)]);
    // An entry with nobody in it is refused at Apply, and shown.
    type_in(&mut e, "advmode", "on");
    press(&mut e, "x-add", json!({}));
    press(&mut e, "apply", json!({}));
    assert!(e.trouble.as_deref().is_some_and(|t| t.ends_with("Name who it's for.")), "{:?}", e.trouble);
    // Inherited entries wait for "Make it this folder's own".
    let sys = e.sd.dacl.as_ref().unwrap().aces.iter().find(|a| a.inherited()).unwrap().id;
    press(&mut e, "x-sel", json!({ "id": sys.to_string() }));
    type_in(&mut e, &format!("x.{sys}.mask"), "0x1");
    assert_ne!(e.entry(sys).unwrap().0.mask, 1);
    press(&mut e, "x-own", json!({}));
    type_in(&mut e, &format!("x.{sys}.mask"), "0x1");
    assert_eq!(e.entry(sys).unwrap().0.mask, 1);
}

#[test]
fn every_kind_of_sacl_entry_can_be_made() {
    let mut e = editor(&finance(), all());
    type_in(&mut e, "advmode", "on");
    press(&mut e, "top", json!({ "v": "sacl" }));
    press(&mut e, "x-add", json!({}));
    let id = e.adv.as_ref().unwrap().sacl.unwrap();
    for (way, code) in [("alarm", "AL"), ("label", "ML"), ("trust", "TL"), ("claim", "RA"), ("policy", "SP"), ("audit", "AU")] {
        type_in(&mut e, &format!("x.{id}.way"), way);
        assert_eq!(text::code(e.entry(id).unwrap().0), code);
    }
    type_in(&mut e, &format!("x.{id}.way"), "claim");
    press(&mut e, "apply", json!({}));
    assert!(e.trouble.as_deref().is_some_and(|t| t.contains("Name the claim.")), "{:?}", e.trouble);
    type_in(&mut e, &format!("x.{id}.aname"), "Project");
    type_in(&mut e, &format!("x.{id}.avals"), "Atlas, Kestrel");
    type_in(&mut e, "advmode", "");
    assert!(e.simple().claims.iter().any(|c| c.claim.name == "Project" && c.claim.values == ["Atlas", "Kestrel"]));
    assert_eq!(e.changed(), [Part::Sacl]);
}

#[test]
fn claims_are_added_in_the_claims_tab() {
    let mut e = editor(&finance(), all());
    press(&mut e, "top", json!({ "v": "claims" }));
    press(&mut e, "cl-new", json!({}));
    let id = e.simple().claims.last().unwrap().id;
    type_in(&mut e, &format!("cl.{id}.name"), "Budget");
    type_in(&mut e, &format!("cl.{id}.kind"), "unumber");
    type_in(&mut e, &format!("cl.{id}.vals"), "250000,");
    assert_eq!(e.simple().claims.last().unwrap().claim.values, ["250000"]);
    assert!(e.fault().is_none());
    assert!(sddl_of(&e).contains("(\"Budget\",TU,0x0,250000)"), "{}", sddl_of(&e));
}

#[test]
fn claims_the_machine_defines_are_suggested_before_those_used() {
    let mut e = editor(&finance(), all());
    e.known.0.insert("User.Clearance".into(), known::Defined { kind: Some(claim::ClaimType::UInt), values: vec!["3".into(), "2".into()], description: "How secret they may see".into() });
    e.known.0.insert("Resource.Budget".into(), known::Defined { kind: Some(claim::ClaimType::UInt), ..Default::default() });
    e.learned.learn("User.Department", &["Finance".into()]);
    e.learned.learn("User.Clearance", &["2".into()]);
    press(&mut e, "pick", json!({ "sid": sid(1105) }));
    press(&mut e, "tab", json!({ "v": "cond" }));
    press(&mut e, "c-new", json!({}));
    let html = shown(&e);
    let clearance = html.find("<option value=\"Clearance\" label=\"Defined on this machine: How secret they may see · used once\">").expect("Clearance is defined");
    let department = html.find("<option value=\"Department\" label=\"Used once\">").expect("Department was used");
    assert!(clearance < department, "{html}");
    let card = e.simple().cards(&sid(1105).parse().unwrap())[0].key;
    type_in(&mut e, &format!("c.d{card}.0.name"), "Clearance");
    let html = shown(&e);
    let three = html.find("<option value=\"3\" label=\"Defined on this machine\">").expect("3 is defined");
    let two = html.find("<option value=\"2\" label=\"Defined on this machine · used once\">").expect("2 is defined and used");
    assert!(three < two, "the machine's order: {html}");
    // A resource claim it defines is made as the kind it says.
    press(&mut e, "top", json!({ "v": "claims" }));
    press(&mut e, "cl-new", json!({}));
    let id = e.simple().claims.last().unwrap().id;
    type_in(&mut e, &format!("cl.{id}.name"), "Budget");
    assert_eq!(e.simple().claims.last().unwrap().claim.kind, claim::ClaimType::UInt);
}

#[test]
fn stopping_inheritance_keeps_or_removes_and_protects() {
    let mut e = editor(&finance(), all());
    press(&mut e, "inherit-stop", json!({ "v": "access" }));
    assert!(shown(&e).contains("Stop taking access from <b>/srv</b>?"));
    press(&mut e, "inherit-drop", json!({ "v": "access" }));
    assert!(e.sd.control & sd::PD != 0);
    assert!(e.sd.dacl.as_ref().unwrap().aces.iter().all(|a| !a.inherited()));
    assert!(!e.listed.contains(&"S-1-5-18".parse().unwrap()));
    // Without the parent's descriptor, inheriting again can't be offered.
    assert!(shown(&e).contains("Inheriting again needs what /srv passes down"), "{}", shown(&e));
}

#[test]
fn inheriting_again_takes_back_what_the_parent_passes_down() {
    let mut e = editor(&finance().replace("D:(", "D:P(").replace("(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)", ""), all());
    e.parent = Some(sddl::parse("O:SYG:SYD:(A;OICI;FA;;;SY)(A;CI;0x1;;;WD)(A;;0x2;;;AU)S:(AU;OICIFA;0x1;;;WD)").unwrap().as_bytes().to_vec());
    press(&mut e, "inherit-on", json!({ "v": "access" }));
    let text = sddl_of(&e);
    assert!(text.contains("(A;OICIID;FA;;;SY)") && text.contains("(A;CIID;0x1;;;WD)") && !text.contains("0x2;;;AU"), "{text}");
    assert_eq!(e.sd.control & sd::PD, 0);
}

#[test]
fn putting_in_order_and_making_a_list() {
    let mut e = editor(&format!("O:SYG:SYD:(A;OICI;0x1301bf;;;{f})(D;OICI;0x10156;;;{c})", f = sid(1105), c = sid(1106)), all());
    assert!(shown(&e).contains("isn&#39;t in the standard order") || shown(&e).contains("isn't in the standard order"));
    press(&mut e, "put-in-order", json!({}));
    assert!(sddl_of(&e).find("(D;").unwrap() < sddl_of(&e).find("(A;").unwrap());
    let mut e = editor("O:SYG:SY", all());
    assert!(shown(&e).contains("There&#39;s no access list") || shown(&e).contains("There's no access list"));
    press(&mut e, "make-list", json!({}));
    assert!(sddl_of(&e).contains("D:(A;OICI;FA;;;WD)"), "{}", sddl_of(&e));
}

#[test]
fn auditing_rules_are_made_and_ticked() {
    let mut e = editor(&finance(), all());
    press(&mut e, "pick", json!({ "sid": sid(1105) }));
    press(&mut e, "tab", json!({ "v": "audit" }));
    press(&mut e, "a-new", json!({}));
    let key = e.simple().audits.iter().find(|a| a.sid == sid(1105).parse::<Sid>().unwrap()).unwrap().ids[0];
    press(&mut e, "a-tick", json!({ "k": key.to_string(), "mask": "1179785", "way": "ok" }));
    type_in(&mut e, &format!("a.{key}.every"), "on");
    let text = sddl_of(&e);
    assert!(text.contains(&format!("(AL;OICISA;0x120089;;;{})", sid(1105))) && text.contains(&format!("(AL;OICIFA;0x100116;;;{})", sid(1105))), "{text}");
    assert_eq!(e.changed(), [Part::Sacl]);
}

#[test]
fn changing_what_is_passed_down_asks_whether_to_update_what_is_inside() {
    let mut e = editor(&format!("O:{o}G:{o}D:(A;OICI;0x1301bf;;;{f})(A;;FA;;;{o})", o = sid(1001), f = sid(1105)), all());
    // A rule for the folder alone passes nothing down: no question.
    press(&mut e, "pick", json!({ "sid": sid(1001) }));
    press(&mut e, "tick", json!({ "mask": "2032127", "way": "allow" }));
    press(&mut e, "tick", json!({ "mask": "1179785", "way": "deny" }));
    assert!(!e.passes_changed(&e.changed()));
    // One that passes down does.
    let mut e = editor(&format!("O:{o}G:{o}D:(A;OICI;0x1301bf;;;{f})", o = sid(1001), f = sid(1105)), all());
    press(&mut e, "pick", json!({ "sid": sid(1105) }));
    press(&mut e, "tick", json!({ "mask": "2032127", "way": "allow" }));
    press(&mut e, "ok", json!({}));
    assert_eq!(e.asking, Some(Asking::Push { then_close: true }));
    let html = shown(&e);
    assert!(html.contains("Update what&#39;s already inside this folder too?") || html.contains("Update what's already inside this folder too?"), "{html}");
    press(&mut e, "push", json!({ "v": "all" }));
    assert_eq!(e.pushing, Some(Pushing::default()));
    assert_eq!(e.push_parts, [Part::Dacl]);
    // How far it has got, and how it went.
    assert!(!e.answered(ToEditor::Progress { done: 1204, at: "/srv/finance/q3".into() }));
    assert!(shown(&e).contains("1,204 items done"));
    let failed = vec![gxwi_sd_editor::Failure { name: "/srv/finance/locked".into(), why: "permission denied".into() }];
    assert!(!e.answered(ToEditor::Applied { done: 1210, failed, stopped: false }), "it stays open to say what could not be done");
    let html = shown(&e);
    assert!(html.contains("1,210 items inside updated; 1 item couldn") && html.contains("/srv/finance/locked") && html.contains("Try Again"), "{html}");
    assert!(e.changed().is_empty());
    // Only this folder: sent without pushing, and closed on OK.
    let mut e = editor(&format!("O:{o}G:{o}D:(A;OICI;0x1301bf;;;{f})", o = sid(1001), f = sid(1105)), all());
    press(&mut e, "pick", json!({ "sid": sid(1105) }));
    press(&mut e, "tick", json!({ "mask": "2032127", "way": "allow" }));
    press(&mut e, "ok", json!({}));
    press(&mut e, "push", json!({ "v": "here" }));
    assert!(e.pushing.is_none());
    assert!(e.answered(ToEditor::applied()));
}

#[test]
fn a_program_that_can_change_nothing_gets_only_close() {
    let mut e = editor("O:SYG:SYD:(A;OICI;FA;;;SY)", Can { dacl: false, owner: false, audit: false, label: false, propagate: false, why: Some("You may not change it here.".into()) });
    let html = shown(&e);
    assert!(html.contains("You may not change it here.") && html.contains(">Close</button>") && !html.contains(">Apply<"), "{html}");
    press(&mut e, "tick", json!({ "mask": "1179785", "way": "deny" }));
    assert!(e.changed().is_empty());
}
