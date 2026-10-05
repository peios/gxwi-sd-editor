//! The dialog as a person sees it: the owner and labels, the tabs, who is
//! listed and what each can do, conditions, rules for parts, auditing,
//! claims, central policies and Effective Access; and what each control
//! does. Advanced mode is `adv`'s.

use std::fmt::Write as _;

use gxwi_sd_editor::{PartKind, Right};
use libgxwi::{Fields, Value, escape as h};
use peios::security::Sid;

use crate::claim::{self, ClaimType};
use crate::cond::{self, Cond, MemberOp, Mode, Node, Op, Src, Val};
use crate::edit::{self, Card, CondOf, Tick};
use crate::sd::*;
use crate::text::*;
use crate::view::*;
use crate::{Adv, AdvTab, Asking, Editor, Side, Tab, Top, adv, eff, people};

pub const LOCK: &str = "<svg viewBox=\"0 0 24 24\" aria-hidden=\"true\"><rect x=\"5\" y=\"11\" width=\"14\" height=\"10\" rx=\"2\"/><path d=\"M8 11V8a4 4 0 0 1 8 0v3\"/></svg>";
pub const INFO: &str = "<svg viewBox=\"0 0 24 24\" aria-hidden=\"true\"><circle cx=\"12\" cy=\"12\" r=\"9\"/><path d=\"M12 11v5M12 8h.01\"/></svg>";
pub const WARN: &str = "<svg viewBox=\"0 0 24 24\" aria-hidden=\"true\"><path d=\"M12 3 2 20h20z\"/><path d=\"M12 10v4M12 17h.01\"/></svg>";
const CHEVRON: &str = "<svg viewBox=\"0 0 24 24\" aria-hidden=\"true\"><path d=\"m6 9 6 6 6-6\"/></svg>";

/// The avatars, by the kind of principal.
fn avatar(kind: &str) -> &'static str {
    match kind {
        "group" => "<circle cx=\"9\" cy=\"8\" r=\"3.5\"/><path d=\"M2.5 20a6.5 6.5 0 0 1 13 0\"/><path d=\"M16 4.5a3.5 3.5 0 0 1 0 7M18 14a6.5 6.5 0 0 1 3.5 6\"/>",
        "special" => "<circle cx=\"12\" cy=\"12\" r=\"9\"/><path d=\"M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18\"/>",
        "system" => "<rect x=\"4\" y=\"5\" width=\"14\" height=\"11\" rx=\"2\"/><path d=\"M9 20h6M12 16v4\"/>",
        _ => "<circle cx=\"12\" cy=\"8\" r=\"4\"/><path d=\"M4 21a8 8 0 0 1 16 0\"/>",
    }
}

/// What kind of principal a SID is, and what to say under its name.
fn kind_of(e: &Editor, sid: &Sid) -> (&'static str, &'static str) {
    match sid.to_string().as_str() {
        "S-1-1-0" => ("special", "Anyone, signed in or not"),
        "S-1-5-11" => ("special", "Anyone signed in"),
        "S-1-3-0" => ("special", "Whoever creates each item"),
        "S-1-3-1" => ("special", "The group of whoever creates each item"),
        "S-1-3-4" => ("special", "The owner"),
        "S-1-5-10" => ("special", "The account itself"),
        "S-1-5-18" | "S-1-5-19" | "S-1-5-20" => ("system", "Built in · used by services"),
        s if s.starts_with("S-1-5-32-") => ("group", "Built-in group"),
        _ if e.names.is_group(sid) => ("group", "Group"),
        _ if e.names.named(sid) => ("user", "User"),
        _ => ("user", "Unknown"),
    }
}

pub fn wrapped_note(text: &str) -> String {
    format!("<p class=\"note\">{}</p>", h(text))
}

/// A banner: an icon, what is said, and what can be done about it.
pub fn banner(warn: bool, said: &str, links: &str) -> String {
    format!(
        "<div class=\"inherit{}\">{}<div class=\"grow\"><p>{said}</p></div>{}</div>",
        if warn { " warn" } else { "" },
        if warn { WARN } else { INFO },
        if links.is_empty() { String::new() } else { format!("<div class=\"links\">{links}</div>") }
    )
}

pub fn link(event: &str, values: &[(&str, &str)], label: &str) -> String {
    let attrs: String = values.iter().map(|(k, v)| format!(" fx-value-{k}=\"{}\"", h(v))).collect();
    format!("<button type=\"button\" class=\"link\" fx-click=\"{event}\"{attrs}>{}</button>", h(label))
}

/// Where a fault is, to be taken to.
pub enum Place {
    Person(Sid, Tab),
    Claims,
    Entry(List, u32),
    Descriptor,
}

impl Editor {
    /// What the object is, as a noun in a sentence: "folder", "registry
    /// key". A program may say where it is in `kind` too ("Registry key
    /// Machine\Software\X"), which is left off, with what leads up to it.
    pub fn kind_word(&self) -> String {
        let mut words: Vec<&str> = self.obj.kind.split_whitespace().take_while(|w| !w.contains(['\\', '/'])).collect();
        while words.len() > 1 && matches!(words.last(), Some(&("of" | "in" | "at" | "on"))) {
            words.pop();
        }
        words.join(" ").to_lowercase()
    }

    pub fn from_word(&self) -> String {
        self.obj.from.clone().unwrap_or_else(|| "the parent".into())
    }

    pub fn name(&self, sid: &Sid) -> String {
        self.names.of(sid)
    }

    /// A select, as a field.
    pub fn select(&self, name: &str, options: &[(String, String, bool)], current: &str, attrs: &str) -> String {
        let mut opts = String::new();
        let mut any = false;
        for (value, label, disabled) in options {
            let on = value == current;
            any |= on;
            let _ = write!(opts, "<option value=\"{}\"{}{}>{}</option>", h(value), if on { " selected" } else { "" }, if *disabled && !on { " disabled" } else { "" }, h(label));
        }
        if !any && !current.is_empty() {
            let _ = write!(opts, "<option value=\"{}\" selected>{}</option>", h(current), h(current));
        }
        format!("<select {}{attrs}>{opts}</select>", self.field(name, current))
    }

    pub fn checkbox(&self, name: &str, on: bool, attrs: &str) -> String {
        format!("<input type=\"checkbox\" {}{}{attrs}>", self.field(name, if on { "on" } else { "" }), if on { " checked" } else { "" })
    }

    pub fn text_field(&self, name: &str, value: &str, attrs: &str) -> String {
        let shown = self.shown_text(name, value);
        format!("<input {} value=\"{}\" autocomplete=\"off\" spellcheck=\"false\"{attrs}>", self.field(name, &shown), h(&shown))
    }

    // ---- the whole dialog

    pub fn html(&self) -> String {
        let changeable = self.can.dacl || self.can.owner || self.can.audit || self.can.label;
        let owner = self.sd.owner.map_or_else(|| "Nobody".into(), |o| self.name(&o));
        let open = self.asking == Some(Asking::Owner);
        let change = format!(
            "<button type=\"button\" class=\"ownerbtn\" fx-click=\"change-owner\" aria-expanded=\"{open}\" aria-haspopup=\"dialog\"><span class=\"k\">Owner</span><b>{}</b>{CHEVRON}</button>",
            h(&owner)
        );
        let owning = if open { self.owners() } else { String::new() };
        let body = match &self.adv {
            Some(adv) => {
                let fixed = self.fixed_note();
                match adv.tab {
                    AdvTab::Effective => self.eff_tab(),
                    AdvTab::Desc => adv::desc(self),
                    AdvTab::Dacl => format!("{fixed}{}", adv::list(self, List::Dacl)),
                    AdvTab::Sacl => adv::list(self, List::Sacl),
                }
            }
            None => match self.top {
                Top::Claims => self.claims_tab(),
                Top::Policy => self.cap_tab(),
                Top::Effective => self.eff_tab(),
                Top::Access => format!(
                    "{}{}<div class=\"split\"><section class=\"people\"><h2 id=\"people\">Users and Groups</h2><ul class=\"listed\" role=\"listbox\" aria-labelledby=\"people\">{}</ul>{}{}</section><section class=\"boxes\">{}</section></div>",
                    self.fixed_note(),
                    self.banners(),
                    self.listed.iter().map(|s| self.row(s)).collect::<String>(),
                    if self.asking == Some(Asking::Add) { self.adding() } else { String::new() },
                    self.under(),
                    self.right_pane()
                ),
            },
        };
        let trouble = self.trouble.as_ref().map(|t| format!("<p class=\"trouble\" role=\"alert\">{}</p>", h(t))).unwrap_or_default();
        // Pushing into what is inside is asked about, followed and reported
        // in the footer, which stays in sight however far down the page is.
        let push = self.push_html();
        // Applying, or asking whether to update what is inside first.
        let busy = self.sending != crate::Sending::No || matches!(self.asking, Some(Asking::Push { .. }));
        let unchanged = self.changed().is_empty();
        let footer = if changeable {
            format!(
                "<button type=\"button\" class=\"primary\" fx-click=\"ok\"{b}>OK</button><button type=\"button\" fx-click=\"cancel\">Cancel</button><button type=\"button\" fx-click=\"apply\"{a}>Apply</button>",
                b = if busy { " disabled" } else { "" },
                a = if busy || unchanged { " disabled" } else { "" }
            )
        } else {
            "<button type=\"button\" class=\"primary\" fx-click=\"cancel\">Close</button>".into()
        };
        format!(
            "<div hidden><button type=\"button\" fx-key=\"Escape\" fx-click=\"escape\"></button>{keys}</div>\
             <div class=\"fit\" fx-fit><div class=\"editor\">\
             <header class=\"head\"><div class=\"grow\"><h1>{name}</h1><p>{kind}</p></div>{change}{owning}</header>\
             {top}{body}{trouble}\
             <footer>{push}<span class=\"status\" role=\"status\">{status}</span>{footer}</footer></div></div>",
            keys = adv::keys(self),
            name = h(&self.obj.name),
            kind = h(&self.obj.kind),
            top = self.topbar(),
            status = h(&self.status),
        )
    }

    /// Pushing into what is inside: whether to, how far it has got, and
    /// how it went where not all of it was done.
    fn push_html(&self) -> String {
        let what = self.kind_word();
        if let Some(Asking::Push { .. }) = self.asking {
            return format!(
                "<div class=\"inherit push\" role=\"group\" aria-labelledby=\"pushq\">{INFO}<div class=\"grow\"><p id=\"pushq\"><b>Update what's already inside this {w} too?</b> What this {w} passes down has changed. New items get the change on their own, but items already inside keep what they were given unless they're updated now. Items that don't inherit are left as they are.</p>\
                 <div class=\"ask\"><button type=\"button\" class=\"primary\" fx-click=\"push\" fx-value-v=\"all\" fx-autofocus>Update Them Too</button><button type=\"button\" fx-click=\"push\" fx-value-v=\"here\">Only This {W}</button><button type=\"button\" fx-click=\"keep\">Cancel</button></div></div></div>",
                w = h(&what),
                W = h(&title_case(&what)),
            );
        }
        if let Some(p) = &self.pushing {
            let said = if p.stopping {
                format!("<b>Stopping after the item in hand…</b> {} updated so far.", crate::items(p.done))
            } else if p.done == 0 {
                format!("<b>Applying, then updating what's inside this {}…</b>", h(&what))
            } else {
                format!("<b>Updating what's inside…</b> {} done<span class=\"at\">{}</span>", crate::items(p.done), h(&p.at))
            };
            return format!(
                "<div class=\"inherit push\" role=\"status\">{INFO}<div class=\"grow\"><p>{said}</p><progress aria-label=\"Updating what's inside\"></progress></div><div class=\"links\"><button type=\"button\" fx-click=\"stop-push\"{}>Stop</button></div></div>",
                if p.stopping { " disabled" } else { "" }
            );
        }
        let Some(w) = &self.pushed else { return String::new() };
        if w.failed.is_empty() && !w.stopped {
            return String::new();
        }
        let mut said = if w.stopped {
            format!("<b>Stopped after {}.</b> The rest still have what this {} passed down before.", crate::items(w.done), h(&what))
        } else {
            format!("<b>{} inside updated; {} couldn't be.</b>", crate::items(w.done), crate::items(w.failed.len() as u64))
        };
        if !w.failed.is_empty() {
            const SHOWN: usize = 8;
            let list: String = w.failed.iter().take(SHOWN).map(|f| format!("<li><span class=\"guid\">{}</span> — {}</li>", h(&f.name), h(&f.why))).collect();
            let more = if w.failed.len() > SHOWN { format!("<li>and {} more</li>", w.failed.len() - SHOWN) } else { String::new() };
            if w.stopped {
                said.push_str(&format!(" {} couldn't be:", crate::items(w.failed.len() as u64)));
            }
            said.push_str(&format!("</p><ul class=\"failed\">{list}{more}</ul><p>"));
        }
        banner(
            true,
            &said,
            &format!("{}{}", link("push-again", &[], if w.stopped { "Update the Rest" } else { "Try Again" }), link("push-done", &[], "Dismiss")),
        )
    }

    fn topbar(&self) -> String {
        let s = self.simple();
        let tops: Vec<(&str, &str, usize, bool)> = match &self.adv {
            Some(adv) => vec![
                ("dacl", "Access List (DACL)", self.sd.dacl.as_ref().map_or(0, |a| a.aces.len()), adv.tab == AdvTab::Dacl),
                ("sacl", "Auditing & Labels (SACL)", if self.shows_sacl() { self.sd.sacl.as_ref().map_or(0, |a| a.aces.len()) } else { 0 }, adv.tab == AdvTab::Sacl),
                ("desc", "Descriptor", 0, adv.tab == AdvTab::Desc),
                ("eff", "Effective Access", 0, adv.tab == AdvTab::Effective),
            ],
            None => vec![
                ("access", "Access & Auditing", 0, self.top == Top::Access),
                ("claims", "Claims", if self.shows_sacl() { s.claims.len() } else { 0 }, self.top == Top::Claims),
                ("cap", "Central Access Policy", if self.shows_sacl() { s.policies.len() } else { 0 }, self.top == Top::Policy),
                ("eff", "Effective Access", 0, self.top == Top::Effective),
            ],
        };
        let tabs: String = tops
            .iter()
            .map(|(k, l, n, on)| {
                let count = if *n > 0 { format!("<span class=\"count\">{n}</span>") } else { String::new() };
                format!("<button type=\"button\" role=\"tab\" aria-selected=\"{on}\" fx-click=\"top\" fx-value-v=\"{k}\">{}{count}</button>", h(l))
            })
            .collect();
        let on = self.adv.is_some();
        format!(
            "<div class=\"toptabs\"><div class=\"tabrow\" role=\"tablist\">{tabs}</div>\
             <label class=\"advswitch\" title=\"Edit the access list and SACL entry by entry\"><input type=\"checkbox\" role=\"switch\" {}{}> Advanced Mode</label></div>",
            self.field("advmode", if on { "on" } else { "" }),
            if on { " checked" } else { "" }
        )
    }

    /// Why the access list cannot be changed, said once above it.
    fn fixed_note(&self) -> String {
        if self.can.dacl {
            return String::new();
        }
        let why = self.can.why.as_deref().unwrap_or("The program that opened this can't change who may do what with it.");
        format!("<p class=\"note fixed\">{}</p>", h(why))
    }

    // ---- the owner, the primary group, the label and process trust

    pub fn draft(&self, key: &str) -> String {
        self.typed.get(&format!("own.{key}")).cloned().unwrap_or_default()
    }

    /// Fills the dropdown's fields from the descriptor, as it opens.
    pub fn open_owners(&mut self) {
        let s = self.simple();
        let mut set = |k: &str, v: String| {
            self.typed.insert(format!("own.{k}"), v);
        };
        set("owner", self.sd.owner.map(|o| self.names.of(&o)).unwrap_or_default());
        set("group", self.sd.group.map(|g| self.names.of(&g)).unwrap_or_default());
        let label = s.label.clone();
        set("level", label.as_ref().map(|l| l.level.to_string()).unwrap_or_default());
        let flag = |b: bool| if b { "on".to_string() } else { String::new() };
        set("nw", flag(label.as_ref().is_none_or(|l| l.policy & 1 != 0)));
        set("nr", flag(label.as_ref().is_some_and(|l| l.policy & 2 != 0)));
        set("nx", flag(label.as_ref().is_some_and(|l| l.policy & 4 != 0)));
        set("linh", flag(label.as_ref().is_some_and(|l| l.inherit)));
        let trust = s.trust.clone();
        let preset = match &trust {
            None => String::new(),
            Some(t) if t.pip_type == 512 && (t.trust == 2048 || t.trust == 8192) => format!("512-{}", t.trust),
            Some(_) => "custom".into(),
        };
        set("trust", preset);
        set("ttype", trust.as_ref().map_or("512".into(), |t| t.pip_type.to_string()));
        set("tlevel", trust.as_ref().map_or("1024".into(), |t| t.trust.to_string()));
        let read = self.obj.general.iter().find(|r| r.name.eq_ignore_ascii_case("Read")).map_or(self.obj.generic.read, |r| r.mask);
        set("keep", trust.as_ref().map_or(read, |t| t.mask).to_string());
        set("tinh", flag(trust.as_ref().is_some_and(|t| t.inherit)));
    }

    fn owners(&self) -> String {
        let s = self.simple();
        let d = |k: &str| self.draft(k);
        let wrong = |k: &str| self.wrong.get(k).map(|w| format!("<span class=\"wrong\" id=\"wrong-{k}\">{}</span>", h(w))).unwrap_or_default();
        let invalid = |k: &str| if self.wrong.contains_key(k) { format!(" aria-invalid=\"true\" aria-describedby=\"wrong-{k}\"") } else { String::new() };
        let own_off = if self.may_owner() { "" } else { " disabled" };
        let field = |k: &str, attrs: &str| {
            let v = d(k);
            format!("<input {} value=\"{}\" autocomplete=\"off\" spellcheck=\"false\"{attrs}>", self.field(&format!("own.{k}"), &v), h(&v))
        };
        let check = |k: &str, label: &str, on: bool| {
            let v = d(k);
            format!("<label class=\"chk\"><input type=\"checkbox\" {}{}{}> {label}</label>", self.field(&format!("own.{k}"), &v), if v.is_empty() { "" } else { " checked" }, if on { "" } else { " disabled" })
        };
        let me = self.caller.user.map(|u| self.name(&u));
        let may_own: Vec<String> = self.caller.may_own().iter().map(|s| self.name(s)).collect();
        let hint = if self.caller.restore {
            "Anyone: this program has SeRestorePrivilege.".to_string()
        } else if may_own.is_empty() {
            "Only the owner it has can stay: this program can't tell who it runs as.".into()
        } else {
            format!("You can make {} the owner.", may_own.join(" or "))
        };
        let me_button = match &me {
            Some(me) if self.may_owner() && d("owner") != *me => "<button type=\"button\" class=\"link small\" fx-click=\"own-me\">Make Me the Owner</button>".to_string(),
            _ => String::new(),
        };
        let owner_field = format!(
            "<label class=\"fld\"><span>Owner</span>{}{}<span class=\"hint\">{}{me_button}</span></label><datalist id=\"may-own\">{}</datalist>",
            field("owner", &format!(" list=\"may-own\"{own_off}{}", invalid("owner"))),
            wrong("owner"),
            if self.wrong.contains_key("owner") { String::new() } else { format!("{} ", h(&hint)) },
            may_own.iter().map(|n| format!("<option value=\"{}\">", h(n))).collect::<String>()
        );
        let group_field = format!("<label class=\"fld\"><span>Primary Group</span>{}{}</label>", field("group", &format!("{own_off}{}", invalid("group"))), wrong("group"));
        // A label: changing it takes the right to change the owner, or the
        // SACL; above the caller's own integrity, SeRelabelPrivilege.
        let linh = s.label.as_ref().is_some_and(|l| l.inherited);
        let may_label = self.may_label() && !linh;
        let level = d("level");
        let mut levels = vec![(String::new(), "No Label (Counts as Medium)".to_string(), false)];
        for (k, n) in INTEGRITY {
            let above = !self.caller.may_label(*n) && Some(*n) != s.label.as_ref().map(|l| l.level);
            levels.push((n.to_string(), if above { format!("{k} — Needs SeRelabelPrivilege") } else { k.to_string() }, above));
        }
        let labelled = !level.is_empty();
        let label_part = if self.read_label {
            format!(
                "<label class=\"fld\"><span>Integrity</span>{}</label><div class=\"checks\"><span>Lower programs can't</span>{}{}{}</div>{}{}",
                self.select("own.level", &levels, &level, if may_label { "" } else { " disabled" }),
                check("nw", "change", labelled && may_label),
                check("nr", "read", labelled && may_label),
                check("nx", "run", labelled && may_label),
                if self.obj.container { format!("<div class=\"checks\">{}</div>", check("linh", "Pass the label to new items inside", labelled && may_label)) } else { String::new() },
                if linh { wrapped_note(&format!("The integrity label is inherited from {}. Change it there, or in Advanced mode.", self.from_word())) } else { String::new() },
            )
        } else {
            wrapped_note("The integrity label isn't shown: the program that opened this didn't read it.")
        };
        let tinh = s.trust.as_ref().is_some_and(|t| t.inherited);
        let may_trust = self.may_sacl() && !tinh;
        let trust_part = if self.shows_sacl() {
            let trust = d("trust");
            let presets = [("", "Not Protected", 0, 0), ("512-2048", "Protected · Peios Apps (2048)", 512, 2048), ("512-8192", "Protected · Peios TCB (8192)", 512, 8192), ("custom", "Custom…", 0, 0)];
            let options: Vec<(String, String, bool)> = presets
                .iter()
                .map(|(k, l, t, n)| {
                    let above = *t != 0 && !self.caller.dominates(*t, *n);
                    (k.to_string(), if above { format!("{l} — Above This App's Own") } else { l.to_string() }, above)
                })
                .collect();
            let custom = if trust == "custom" {
                format!(
                    "<div class=\"pip-custom\"><label class=\"fld\"><span>Type</span>{}</label><label class=\"fld\"><span>Trust Level</span>{}</label></div>{}",
                    self.select("own.ttype", &[("512".into(), "Protected (512)".into(), false), ("1024".into(), "Isolated (1024)".into(), false)], &d("ttype"), if may_trust { "" } else { " disabled" }),
                    field("tlevel", &format!(" inputmode=\"numeric\"{}{}", if may_trust { "" } else { " disabled" }, invalid("trust"))),
                    wrong("trust")
                )
            } else {
                String::new()
            };
            let keeps: Vec<(String, String, bool)> = std::iter::once(("0".to_string(), "Nothing".to_string(), false))
                .chain(self.obj.general.iter().skip(1).map(|r| (r.mask.to_string(), r.name.clone(), false)))
                .collect();
            let keep = if trust.is_empty() {
                String::new()
            } else {
                format!("<label class=\"fld inline\"><span>Less trusted programs may</span>{}</label>", self.select("own.keep", &keeps, &d("keep"), if may_trust { "" } else { " disabled" }))
            };
            let tinh_box = if !trust.is_empty() && self.obj.container { format!("<div class=\"checks\">{}</div>", check("tinh", "Pass the protection to new items inside", may_trust)) } else { String::new() };
            format!(
                "<label class=\"fld\"><span>Process Trust</span>{}</label>{}{custom}{keep}{tinh_box}",
                self.select("own.trust", &options, &trust, if may_trust { "" } else { " disabled" }),
                if tinh { wrapped_note(&format!("The process trust label is inherited from {}. Change it there, or in Advanced mode.", self.from_word())) } else { String::new() }
            )
        } else {
            wrapped_note("Process trust isn't shown: it's in the SACL, which the program that opened this can't read.")
        };
        let acts = if self.may_owner() || may_label || may_trust {
            "<div class=\"acts\"><button type=\"button\" fx-click=\"keep\">Cancel</button><button type=\"submit\" class=\"primary\">Done</button></div>".to_string()
        } else {
            format!("<p class=\"note\">{}</p><div class=\"acts\"><button type=\"button\" fx-click=\"keep\">Close</button></div>", h(self.can.why.as_deref().unwrap_or("The program that opened this can't change these.")))
        };
        format!("<form class=\"owners\" fx-submit=\"owners\" role=\"dialog\" aria-label=\"Owner and labels\">{owner_field}{group_field}{label_part}{trust_part}{acts}</form>")
    }

    /// The owner rule (KACS set-security, Ownership): the owner it has can
    /// stay; otherwise the caller, or a group they may own things as, unless
    /// they have SeRestorePrivilege.
    pub fn owner_problem(&self, sid: &Sid) -> Option<String> {
        if Some(*sid) == self.applied.owner || self.caller.restore || self.caller.may_own().contains(sid) {
            return None;
        }
        let who: Vec<String> = self.caller.may_own().iter().map(|s| self.name(s)).collect();
        Some(if who.is_empty() {
            format!("Giving it to {} takes SeRestorePrivilege.", self.name(sid))
        } else {
            format!("Only {} can be made the owner here. Giving it to {} takes SeRestorePrivilege.", who.join(" or "), self.name(sid))
        })
    }

    fn owners_done(&mut self) {
        if self.asking != Some(Asking::Owner) {
            return;
        }
        self.wrong.clear();
        let d = |e: &Editor, k: &str| e.draft(k);
        let owner_typed = d(self, "owner");
        let group_typed = d(self, "group");
        let owner = if self.may_owner() { self.names.find(&owner_typed).map(Some) } else { Ok(self.sd.owner) };
        let group = if self.may_owner() { if group_typed.trim().is_empty() && self.sd.group.is_none() { Ok(None) } else { self.names.find(&group_typed).map(Some) } } else { Ok(self.sd.group) };
        match &owner {
            Err(why) => {
                self.wrong.insert("owner".into(), why.clone());
            }
            Ok(Some(sid)) if self.may_owner() => {
                if let Some(why) = self.owner_problem(sid) {
                    self.wrong.insert("owner".into(), why);
                }
            }
            _ => {}
        }
        if let Err(why) = &group {
            self.wrong.insert("group".into(), why.clone());
        }
        let trust_choice = d(self, "trust");
        let keep: u32 = d(self, "keep").parse().unwrap_or(0);
        let mut trust = None;
        if trust_choice == "custom" {
            let ty: u32 = d(self, "ttype").parse().unwrap_or(512);
            match d(self, "tlevel").trim().parse::<u32>() {
                Err(_) => {
                    self.wrong.insert("trust".into(), "The trust level is a whole number, such as 1024.".into());
                }
                Ok(level) if !self.caller.dominates(ty, level) => {
                    self.wrong.insert("trust".into(), format!("That's above this app's own trust ({}, {}), so it would lock itself out.", pip_type_name(self.caller.pip_type), self.caller.pip_trust));
                }
                Ok(level) => trust = Some((ty, level)),
            }
        } else if let Some((t, n)) = trust_choice.split_once('-').and_then(|(t, n)| Some((t.parse().ok()?, n.parse().ok()?))) {
            trust = Some((t, n));
        }
        if !self.wrong.is_empty() {
            return;
        }
        if self.may_owner() {
            self.sd.owner = owner.ok().flatten();
            self.sd.group = group.ok().flatten();
        }
        let level = d(self, "level");
        let flag = |k: &str| !d(self, k).is_empty();
        let label = level.parse::<u32>().ok().map(|n| (n, (flag("nw") as u32) | (flag("nr") as u32) << 1 | (flag("nx") as u32) << 2, flag("linh")));
        let may_label = self.may_label();
        let may_trust = self.may_sacl();
        let tinh = flag("tinh");
        let caller = self.caller.clone();
        self.edit(|s, _, ids, _| {
            if may_label && !s.label.as_ref().is_some_and(|l| l.inherited) {
                s.label = match label {
                    Some((n, policy, inherit)) if caller.may_label(n) || s.label.as_ref().is_some_and(|l| l.level == n) => {
                        let id = s.label.as_ref().map_or_else(|| ids.next(), |l| l.id);
                        Some(Label { id, level: n, policy, inherit, inherited: false })
                    }
                    Some(_) => s.label.clone(),
                    None => None,
                };
                s.sacl |= s.label.is_some();
            }
            if may_trust && !s.trust.as_ref().is_some_and(|t| t.inherited) {
                s.trust = trust.map(|(pip_type, level)| Trust { id: s.trust.as_ref().map_or_else(|| ids.next(), |t| t.id), pip_type, trust: level, mask: keep, inherit: tinh, inherited: false });
                s.sacl |= s.trust.is_some();
            }
        });
        self.asking = None;
        self.typed.retain(|k, _| !k.starts_with("own."));
    }

    // ---- banners above the list

    fn banners(&self) -> String {
        let s = self.simple();
        let what = self.kind_word();
        let mut out = String::new();
        match &self.sd.dacl {
            None => out.push_str(&banner(
                true,
                &format!("<b>There's no access list,</b> so anyone can do anything with this {}. That's not the same as an empty list, which lets nobody but its owner do anything.", h(&what)),
                &if self.may_dacl() { link("make-list", &[], "Make an Access List") } else { String::new() },
            )),
            Some(d) if d.aces.is_empty() => out.push_str(&banner(false, &format!("<b>The access list is empty,</b> so nobody can do anything with this {} except its owner, who can still change who may.", h(&what)), "")),
            _ => {}
        }
        if let Some((first, later)) = self.sd.dacl.as_ref().and_then(|d| edit::disorder(&d.aces)) {
            let (f, l) = (first.sid.map(|s| self.name(&s)).unwrap_or_default(), later.sid.map(|s| self.name(&s)).unwrap_or_default());
            let why = if later.way == Way::Deny && first.way == Way::Allow {
                format!("{} refusal comes after {} allow, so anyone covered by both gets what the allow gives first.", poss(&l), poss(&f))
            } else {
                format!("This {what}'s own rule for {l} comes after an inherited one for {f}, so the inherited rule decides first.")
            };
            out.push_str(&banner(true, &format!("<b>The access list isn't in the standard order.</b> {}", h(&why)), &if self.may_dacl() { link("put-in-order", &[], "Put in Order") } else { String::new() }));
        }
        let kept = s.entries().iter().filter(|e| e.kept.is_some()).count() + if self.shows_sacl() { s.skept.len() } else { 0 };
        if kept > 0 {
            out.push_str(&banner(
                false,
                &format!("<b>{} can only be shown in Advanced mode.</b> {} kept as found.", if kept == 1 { "1 entry".into() } else { format!("{kept} entries") }, if kept == 1 { "It's" } else { "They're" }),
                &link("adv-open", &[], "Show in Advanced Mode"),
            ));
        }
        out.push_str(&self.inheritance(&s));
        out
    }

    /// Inheritance, in one banner: what comes from the parent, and stopping
    /// or restarting it. Access and the SACL are protected apart.
    fn inheritance(&self, s: &Simple) -> String {
        let from = self.from_word();
        let what = self.kind_word();
        if let Some(Asking::Stop(side)) = self.asking {
            let noun = if side == Side::Access { "access" } else { "auditing & labels" };
            let v = if side == Side::Access { "access" } else { "sacl" };
            return format!(
                "<div class=\"inherit\">{INFO}<div class=\"grow\"><p>Stop taking {noun} from <b>{f}</b>? Changes there will no longer reach this {w}. What should happen to what it gives now?</p>\
                 <div class=\"ask\"><button type=\"button\" class=\"primary\" fx-click=\"inherit-copy\" fx-value-v=\"{v}\">Keep It as This {W}'s Own</button><button type=\"button\" fx-click=\"inherit-drop\" fx-value-v=\"{v}\">Remove It</button><button type=\"button\" fx-click=\"keep\">Cancel</button></div></div></div>",
                f = h(&from),
                w = h(&what),
                W = h(&title_case(&what)),
            );
        }
        let access = self.sd.dacl.is_some();
        let inherited: Vec<Sid> = {
            let mut v: Vec<Sid> = Vec::new();
            for e in s.entries().iter().filter(|e| e.ace.inherited()) {
                if let Some(sid) = e.ace.sid
                    && !v.contains(&sid)
                {
                    v.push(sid);
                }
            }
            v
        };
        let n = inherited.len();
        let protected = self.sd.control & PD != 0;
        let sprotected = self.sd.control & PS != 0;
        let sacl_bits = if self.shows_sacl() && !sprotected { s.sacl_inherited() } else { vec![] };
        let mut got = Vec::new();
        if access && !protected && n > 0 {
            got.push(format!("access for {}", if n == 1 { "1 user or group".into() } else { format!("{n} users and groups") }));
        }
        got.extend(sacl_bits);
        let mut off = Vec::new();
        if access && protected {
            off.push("access".to_string());
        }
        if self.shows_sacl() && sprotected {
            off.push("auditing & labels".to_string());
        }
        if got.is_empty() && off.is_empty() {
            return String::new();
        }
        let mut links = String::new();
        if access && self.may_dacl() {
            if protected {
                links.push_str(&link("inherit-on", &[("v", "access")], "Inherit Access Again"));
            } else if n > 0 {
                links.push_str(&link("inherit-stop", &[("v", "access")], "Stop Inheriting Access"));
            }
        }
        if self.may_sacl() {
            if sprotected {
                links.push_str(&link("inherit-on", &[("v", "sacl")], "Inherit Auditing & Labels Again"));
            } else if !s.sacl_inherited().is_empty() {
                links.push_str(&link("inherit-stop", &[("v", "sacl")], "Stop Inheriting Auditing & Labels"));
            }
        }
        let mut said = Vec::new();
        if !got.is_empty() {
            let it = if got.len() == 1 && (got[0].starts_with("the ") || got[0].starts_with("1 ")) { "it" } else { "them" };
            said.push(format!(
                "Inherited from <b>{}</b>: {}. Change {it} there{}.",
                h(&from),
                h(&and_list(&got)),
                if links.contains("inherit-stop") { ", or stop inheriting" } else { "" }
            ));
        }
        if !off.is_empty() {
            said.push(format!("This {} doesn't take {} from <b>{}</b>.", h(&what), h(&and_list(&off)), h(&from)));
        }
        if (protected || sprotected) && self.parent.is_none() && (self.may_dacl() || self.may_sacl()) {
            said.push(format!("Inheriting again needs what {} passes down, which the program that opened this didn't send.", h(&from)));
            links = links.replace("fx-click=\"inherit-on\"", "fx-click=\"inherit-on\" disabled");
        }
        banner(false, &said.join(" "), &links)
    }

    // ---- who is listed

    fn row(&self, sid: &Sid) -> String {
        let s = self.simple();
        let theirs: Vec<&Entry> = s.entries().iter().filter(|e| e.ace.sid.as_ref() == Some(sid)).collect();
        let inherited = !theirs.is_empty() && theirs.iter().all(|e| e.ace.inherited());
        let (kind, what) = kind_of(self, sid);
        let sub = if self.names.named(sid) { format!("{} · <span class=\"sid\">{}</span>", h(what), h(&sid.to_string())) } else { h(what) };
        let adv_only = !theirs.is_empty() && theirs.iter().all(|e| e.kept.is_some()) && !s.parts.iter().any(|r| r.sid == *sid);
        let audited_only = self.shows_sacl() && s.audits.iter().any(|a| a.sid == *sid) && theirs.is_empty() && !s.parts.iter().any(|r| r.sid == *sid);
        let right = if adv_only {
            "<span class=\"from\">Advanced Only</span>".to_string()
        } else if inherited {
            format!("<span class=\"from\" title=\"From {}\">↳ Inherited</span><span class=\"lvl\">{LOCK}{}</span>", h(&self.from_word()), h(&self.inherited_level(&s, sid)))
        } else if audited_only {
            "<span class=\"from\">Audited Only</span>".into()
        } else {
            String::new()
        };
        format!(
            "<li{inh}><button type=\"button\" class=\"who\" fx-click=\"pick\" fx-value-sid=\"{sidt}\" role=\"option\" aria-selected=\"{sel}\"><span class=\"av k-{kind}\"><svg viewBox=\"0 0 24 24\" aria-hidden=\"true\">{av}</svg></span><span class=\"txt\"><span class=\"name\">{name}</span><small>{sub}</small></span>{right}</button></li>",
            inh = if inherited { " class=\"inh\"" } else { "" },
            sidt = h(&sid.to_string()),
            sel = self.picked == Some(*sid),
            av = avatar(kind),
            name = h(&self.name(sid)),
        )
    }

    fn inherited_level(&self, s: &Simple, sid: &Sid) -> String {
        let es: Vec<&Entry> = s.entries().iter().filter(|e| e.ace.sid.as_ref() == Some(sid) && e.ace.inherited() && e.ace.applies() && e.kept.is_none()).collect();
        let allow = es.iter().filter(|e| e.ace.way == Way::Allow).fold(0, |a, e| a | self.obj.mapped(e.ace.mask));
        let deny = es.iter().filter(|e| e.ace.way == Way::Deny).fold(0, |a, e| a | e.ace.mask);
        match self.obj.general.iter().find(|r| core(allow) & core(r.mask) == core(r.mask)) {
            Some(r) => r.name.clone(),
            None if deny != 0 => "Denied".into(),
            None if !es.is_empty() => "Advanced".into(),
            None => "For What's Inside".into(),
        }
    }

    fn adding(&self) -> String {
        let wrong = self.wrong.get("who").map(|w| format!("<p class=\"wrong\" id=\"wrong-who\">{}</p>", h(w))).unwrap_or_default();
        format!(
            "<form class=\"naming\" fx-submit=\"added\"><input name=\"who\" fx-autofocus autocomplete=\"off\" spellcheck=\"false\" aria-label=\"The name of a user or group to add\" placeholder=\"Name, such as Everyone or jack\"{}>\
             <button type=\"submit\">Add</button><button type=\"button\" fx-click=\"keep\">Cancel</button>{wrong}</form>",
            if wrong.is_empty() { "" } else { " aria-describedby=\"wrong-who\" aria-invalid=\"true\"" }
        )
    }

    fn under(&self) -> String {
        if !self.can.dacl {
            return String::new();
        }
        let s = self.simple();
        let removable = self.picked.is_some_and(|p| {
            s.entries().iter().any(|e| e.ace.sid == Some(p) && !e.ace.inherited()) || s.parts.iter().any(|r| r.sid == p) || (self.may_sacl() && s.audits.iter().any(|a| a.sid == p && !a.inherited)) || !s.principals(true).contains(&p)
        });
        format!(
            "<div class=\"under\"><button type=\"button\" fx-click=\"add\"{}>Add…</button><button type=\"button\" fx-click=\"remove\"{}>Remove</button></div>",
            if self.asking == Some(Asking::Add) || !self.may_dacl() { " disabled" } else { "" },
            if removable && self.may_dacl() { "" } else { " disabled" }
        )
    }

    // ---- what the one picked can do

    fn right_pane(&self) -> String {
        let Some(sid) = self.picked else {
            return format!("<p class=\"none\">Nobody is picked. Pick someone{}.</p>", if self.can.dacl { ", or add someone" } else { "" });
        };
        let s = self.simple();
        let conds = s.cards(&sid).len();
        let parts = s.parts.iter().filter(|r| r.sid == sid).count();
        let audits = if self.shows_sacl() { s.audits.iter().filter(|a| a.sid == sid).count() } else { 0 };
        let tabs = [(Tab::Access, "access", "Access", 0), (Tab::Cond, "cond", "Conditionals", conds), (Tab::Specific, "specific", "Specific Rights", parts), (Tab::Audit, "audit", "Auditing", audits)];
        let bar: String = tabs
            .iter()
            .map(|(t, k, l, n)| {
                let count = if *n > 0 { format!("<span class=\"count\">{n}</span>") } else { String::new() };
                format!("<button type=\"button\" role=\"tab\" aria-selected=\"{}\" fx-click=\"tab\" fx-value-v=\"{k}\">{l}{count}</button>", self.tab == *t)
            })
            .collect();
        let body = if self.sd.dacl.is_none() && self.tab != Tab::Audit {
            "<p class=\"note fixed\">There's no access list, so there are no rules: everyone can do everything. Make an access list to start one.</p>".to_string()
        } else {
            match self.tab {
                Tab::Access => self.access(&s, &sid),
                Tab::Cond => self.conditionals(&s, &sid),
                Tab::Specific => self.specific(&s, &sid),
                Tab::Audit => self.auditing(&s, &sid),
            }
        };
        format!("<div class=\"caption\">What {} can do</div><div class=\"tabs\" role=\"tablist\">{bar}</div><div class=\"pane\">{body}</div>", h(&self.name(&sid)))
    }

    /// "Applies to", with "One level down" beside it, on a container.
    fn scope_widget(&self, name: &str, flags: u8, fixed: bool, has: &[u8]) -> String {
        if !self.obj.container {
            return String::new();
        }
        let base = flags & !NP;
        let opts: Vec<(String, String, bool)> = self.obj.scopes().into_iter().map(|(f, l)| (f.to_string(), if has.iter().any(|h| h & !NP == f) { format!("{l} •") } else { l }, false)).collect();
        let off = if fixed { " disabled" } else { "" };
        let np_off = if fixed || !passes(base) { " disabled" } else { "" };
        format!(
            "<div class=\"scope\"><span>Applies to</span>{}<label class=\"chk np\" title=\"Pass it to the items directly inside, but not further\">{} One level down</label></div>",
            self.select(name, &opts, &base.to_string(), off),
            self.checkbox(&format!("{name}.np"), flags & NP != 0, np_off)
        )
    }

    fn access(&self, s: &Simple, sid: &Sid) -> String {
        let has: Vec<u8> = {
            let mut v: Vec<u8> = s.entries().iter().filter(|e| edit::plain(e) && e.ace.sid.as_ref() == Some(sid)).map(|e| e.ace.flags & SHAPE).collect();
            v.dedup();
            v
        };
        let fixed = !self.may_dacl();
        let scope = self.scope_widget("scope", self.scope, fixed, &has);
        let also = if self.obj.container {
            let others: Vec<u8> = {
                let mut o: Vec<u8> = has.iter().copied().filter(|f| *f != self.scope).collect();
                o.sort();
                o.dedup();
                o
            };
            if others.is_empty() {
                String::new()
            } else {
                format!(
                    "<p class=\"note\">{} also has rules for {}.</p>",
                    h(&self.name(sid)),
                    others.iter().map(|f| format!("<button type=\"button\" class=\"link small\" fx-click=\"scope\" fx-value-v=\"{f}\">{}</button>", h(&self.obj.scope_label(*f).to_lowercase()))).collect::<Vec<_>>().join(", ")
                )
            }
        } else {
            String::new()
        };
        let fits = s.simple_for(&self.obj, sid, self.scope);
        let toggle = if self.advanced {
            format!(
                "<div class=\"advtoggle\"><button type=\"button\" class=\"link small\" fx-click=\"adv\" fx-value-v=\"0\"{}>Show Simple Rights</button>{}</div>",
                if fits { "" } else { " disabled" },
                if fits { "" } else { "<span class=\"note\">These rules can't be shown as the simple rights.</span>" }
            )
        } else {
            "<div class=\"advtoggle\"><button type=\"button\" class=\"link small\" fx-click=\"adv\" fx-value-v=\"1\">Show Advanced Rights</button></div>".into()
        };
        let mine: Vec<&Entry> = s.entries().iter().filter(|e| edit::plain(e) && e.ace.sid.as_ref() == Some(sid) && (!self.obj.container || e.ace.flags & SHAPE == self.scope)).collect();
        let mut notes = String::new();
        if let Some(g) = mine.iter().find(|e| e.ace.mask & GENERIC != 0) {
            let name = generic_name(g.ace.mask & GENERIC);
            notes.push_str(&wrapped_note(&format!(
                "Written with the generic right {name}, which here means {}. It's kept as {name} unless changed.",
                self.obj.level_name(g.ace.mask).unwrap_or("the rights ticked")
            )));
        }
        let audit_bit = mine.iter().any(|e| e.ace.mask & ACCESS_SYSTEM_SECURITY != 0);
        if audit_bit {
            notes.push_str(&wrapped_note("This rule includes the right to read and change auditing. In an access list that does nothing: only SeSecurityPrivilege grants it."));
        }
        let mut rights: Vec<Right> = if self.advanced { self.obj.specific.clone() } else { self.obj.general.clone() };
        if self.advanced && audit_bit {
            rights.push(Right { name: "Read or change auditing (no effect here)".into(), mask: ACCESS_SYSTEM_SECURITY, general: false });
        }
        let kept = s.entries().iter().filter(|e| e.ace.sid.as_ref() == Some(sid) && e.kept.is_some()).count();
        let adv_only = if kept > 0 {
            banner(false, &format!("{} has {} only Advanced mode can show.", h(&self.name(sid)), if kept == 1 { "an entry".into() } else { format!("{kept} entries") }), &link("adv-open", &[("sid", &sid.to_string())], if kept == 1 { "Show It" } else { "Show Them" }))
        } else {
            String::new()
        };
        let shown = s.shown(&self.obj, sid, self.scope, &rights.iter().map(|r| r.mask).collect::<Vec<_>>());
        let rows: String = rights
            .iter()
            .zip(&shown)
            .enumerate()
            .map(|(i, (r, (a, d)))| {
                // Which right of the list it is, as well as its mask, for
                // whatever finds a box by its place.
                let row = |t: Tick, way: &str| tick_box(t, "tick", r.mask, way, &r.name, fixed, "").replace(" fx-value-way=", &format!(" fx-value-right=\"{i}\" fx-value-way="));
                format!("<tr><th scope=\"row\">{}</th>{}{}</tr>", h(&r.name), row(*a, "allow"), row(*d, "deny"))
            })
            .collect();
        let greyed = if shown.iter().any(|(a, d)| *a == Tick::Inherited || *d == Tick::Inherited) { wrapped_note("Greyed ticks are inherited from what this is in, and are changed there.") } else { String::new() };
        format!("{adv_only}{scope}<table class=\"rights\"><thead><tr><th></th><th scope=\"col\">Allow</th><th scope=\"col\">Deny</th></tr></thead><tbody>{rows}</tbody></table>{greyed}{toggle}{notes}{also}")
    }

    // ---- conditions

    fn conditionals(&self, s: &Simple, sid: &Sid) -> String {
        let ro = !self.may_dacl();
        let cards: String = s
            .cards(sid)
            .iter()
            .map(|c| {
                let fixed = ro || c.inherited;
                let of = CondOf::Card(c.key);
                format!(
                    "<div class=\"rule{inh}\"><div class=\"rule-top\"><span class=\"when\">Only When</span>{from}</div>{editor}{unknown}<div class=\"when\">Then</div>{scope}{table}{remove}</div>",
                    inh = if c.inherited { " inh" } else { "" },
                    from = if c.inherited { format!("<span class=\"from\">↳ From {}</span>", h(&self.from_word())) } else { String::new() },
                    editor = self.cond_editor(&c.node, of, fixed),
                    unknown = wrapped_note(&cond_unknown(&c.node, core(c.allow_mask) != 0 && c.allow.is_some(), core(c.deny_mask) != 0 && c.deny.is_some())),
                    scope = self.scope_widget(&format!("card.{}", c.key), c.flags, fixed, &[]),
                    table = self.card_table(c, fixed),
                    remove = if fixed { String::new() } else { format!("<button type=\"button\" class=\"small remove-rule\" fx-click=\"c-del\" fx-value-k=\"{}\">Remove Rule</button>", c.key) },
                )
            })
            .collect();
        let none = if cards.is_empty() { wrapped_note(&format!("{} has no rules that depend on a condition.", self.name(sid))) } else { String::new() };
        let add = if ro { String::new() } else { "<button type=\"button\" fx-click=\"c-new\">+ Add a Conditional Rule</button>".into() };
        let forget = if !self.learned.used.is_empty() && self.learned.writable { " <button type=\"button\" class=\"link small\" fx-click=\"forget\">Forget What's Been Used</button>" } else { "" };
        format!(
            "{none}{cards}{add}{}<p class=\"note\">Suggestions are the claims this machine defines, then those used in rules applied here, most used first.{forget}</p>",
            wrapped_note(&format!("A conditional rule applies only while its condition holds. Conditions test claims (the person's, their device's, this {}'s, or the program's) and group membership, and combine them in groups.", self.kind_word()))
        )
    }

    fn card_table(&self, c: &Card, fixed: bool) -> String {
        let fits = self.obj.fits_general(c.allow_mask) && self.obj.fits_general(c.deny_mask);
        let advanced = !fits || self.shows_advanced.contains(&c.key);
        let rights = if advanced { &self.obj.specific } else { &self.obj.general };
        let has = |m: u32, r: &Right| core(self.obj.mapped(m)) & core(r.mask) == core(r.mask);
        let k = c.key.to_string();
        let rows: String = rights
            .iter()
            .map(|r| {
                let a = if c.allow.is_some() && has(c.allow_mask, r) { Tick::Yes } else { Tick::No };
                let d = if c.deny.is_some() && has(c.deny_mask, r) { Tick::Yes } else { Tick::No };
                format!("<tr><th scope=\"row\">{}</th>{}{}</tr>", h(&r.name), tick_box(a, "ctick", r.mask, "allow", &r.name, fixed, &k), tick_box(d, "ctick", r.mask, "deny", &r.name, fixed, &k))
            })
            .collect();
        format!("<table class=\"rights\"><thead><tr><th></th><th scope=\"col\">Allow</th><th scope=\"col\">Deny</th></tr></thead><tbody>{rows}</tbody></table>{}", adv_toggle("cadv", c.key, advanced, fits, "This rule"))
    }

    /// The condition editor: a tree, shown as nested groups, and the
    /// expression it makes.
    pub fn cond_editor(&self, node: &Node, of: CondOf, fixed: bool) -> String {
        format!("{}<code class=\"expr\">{}</code>", self.group_html(node, of, &[], fixed, 0), h(&cond::expr(node)))
    }

    fn cname(of: CondOf, path: &[usize], f: &str) -> String {
        let p = if path.is_empty() { "r".to_string() } else { path.iter().map(usize::to_string).collect::<Vec<_>>().join("-") };
        format!("c.{}.{p}.{f}", of.key())
    }

    fn at(of: CondOf, path: &[usize]) -> String {
        let p = if path.is_empty() { "r".to_string() } else { path.iter().map(usize::to_string).collect::<Vec<_>>().join("-") };
        format!(" fx-value-k=\"{}\" fx-value-p=\"{p}\"", of.key())
    }

    fn group_html(&self, node: &Node, of: CondOf, path: &[usize], fixed: bool, depth: usize) -> String {
        let Node::Group(mode, items) = node else { return String::new() };
        let off = if fixed { " disabled" } else { "" };
        let join = if mode.and() { "and" } else { "or" };
        let mut inner = String::new();
        for (i, n) in items.iter().enumerate() {
            let mut p = path.to_vec();
            p.push(i);
            if i > 0 {
                let _ = write!(inner, "<div class=\"and\">{join}</div>");
            }
            inner.push_str(&match n {
                Node::Group(..) => self.group_html(n, of, &p, fixed, depth + 1),
                Node::Member { .. } => self.member_html(n, of, &p, fixed),
                Node::Claim { .. } => self.claim_html(n, of, &p, fixed),
            });
        }
        let modes: Vec<(String, String, bool)> = Mode::ALL.iter().map(|m| (m.key().to_string(), mode_label(*m).to_string(), false)).collect();
        let del = if depth > 0 && !fixed { format!("<button type=\"button\" class=\"icon\" fx-click=\"c-del-node\"{} aria-label=\"Remove this group\">×</button>", Self::at(of, path)) } else { String::new() };
        let bad = if self.checked { cond::problem(node).map(|(_, w)| format!("<span class=\"wrong\">{}</span>", h(&w))).unwrap_or_default() } else { String::new() };
        let adds = if fixed {
            String::new()
        } else {
            let at = Self::at(of, path);
            format!(
                "<div class=\"cg-add\"><button type=\"button\" class=\"small\" fx-click=\"c-add\" fx-value-v=\"claim\"{at}>+ Claim</button><button type=\"button\" class=\"small\" fx-click=\"c-add\" fx-value-v=\"member\"{at}>+ Membership</button>{}</div>",
                if depth < 2 { format!("<button type=\"button\" class=\"small\" fx-click=\"c-add\" fx-value-v=\"group\"{at}>+ Group</button>") } else { String::new() }
            )
        };
        format!(
            "<div class=\"cgroup{}\"><div class=\"cg-head\">{}{del}</div>{inner}{bad}{adds}</div>",
            if depth > 0 { " nested" } else { "" },
            self.select(&Self::cname(of, path, "mode"), &modes, mode.key(), &format!("{off} aria-label=\"How these combine\""))
        )
    }

    fn claim_html(&self, node: &Node, of: CondOf, path: &[usize], fixed: bool) -> String {
        let Node::Claim { src, name, op, val } = node else { return String::new() };
        let off = if fixed { " disabled" } else { "" };
        let bad = cond::problem(node).filter(|(_, w)| self.checked || w.starts_with("A claim's") || w.starts_with("A value"));
        let id = Self::cname(of, path, "w").replace('.', "-");
        let invalid = |f: &str| if bad.as_ref().is_some_and(|(bf, _)| *bf == f) { format!(" aria-invalid=\"true\" aria-describedby=\"{id}\"") } else { String::new() };
        let sources: Vec<(String, String, bool)> = Src::ALL.iter().map(|s| (s.word().to_string(), src_label(*s).to_string(), false)).collect();
        let tests: Vec<(String, String, bool)> = Op::ALL.iter().map(|o| (o.key().to_string(), op_label(*o).to_string(), false)).collect();
        let list = format!("{id}-n");
        let names = self.name_suggestions(*src);
        let value = if op.valued() { self.value_cell(*src, name, *op, val, of, path, off, &invalid("val")) } else { "<span></span>".into() };
        format!(
            "<div class=\"cond\">{}{}<datalist id=\"{list}\">{}</datalist><span></span>{}{value}{}{}</div>",
            self.select(&Self::cname(of, path, "src"), &sources, src.word(), &format!("{off} aria-label=\"Where the claim comes from\"")),
            self.text_field(&Self::cname(of, path, "name"), name, &format!(" list=\"{list}\" placeholder=\"Claim, such as Department\" aria-label=\"Claim\"{off}{}", invalid("name"))),
            names.iter().map(|(n, why)| format!("<option value=\"{}\" label=\"{}\">", h(n), h(why))).collect::<String>(),
            self.select(&Self::cname(of, path, "op"), &tests, op.key(), &format!("{off} aria-label=\"Test\"")),
            if fixed { "<span></span>".to_string() } else { format!("<button type=\"button\" class=\"icon\" fx-click=\"c-del-node\"{} aria-label=\"Remove this test\">×</button>", Self::at(of, path)) },
            bad.map(|(_, w)| format!("<span class=\"wrong cw\" id=\"{id}\">{}</span>", h(&w))).unwrap_or_default()
        )
    }

    /// What a claim is tested against: a value, or another claim.
    #[allow(clippy::too_many_arguments)]
    fn value_cell(&self, src: Src, name: &str, op: Op, val: &Val, of: CondOf, path: &[usize], off: &str, invalid: &str) -> String {
        let against: Vec<(String, String, bool)> =
            [("", "a value"), ("User", "their account's"), ("Device", "their device's"), ("Resource", "this item's"), ("Local", "the program's")].iter().map(|(k, l)| (k.to_string(), l.to_string(), false)).collect();
        let (current, text, list) = match val {
            Val::Claim(other, n) => (other.word().to_string(), n.clone(), self.name_suggestions(*other)),
            Val::Value(v) => (String::new(), v.clone(), self.value_suggestions(&format!("{}.{}", src.word(), name.trim()))),
        };
        let id = Self::cname(of, path, "v").replace('.', "-");
        let placeholder = match val {
            Val::Claim(..) => "Claim, such as Department",
            Val::Value(_) if op.several() => "Values, with commas",
            Val::Value(_) => "Value",
        };
        format!(
            "<div class=\"cval\">{}{}<datalist id=\"{id}\">{}</datalist></div>",
            self.select(&Self::cname(of, path, "vsrc"), &against, &current, &format!("{off} aria-label=\"Compare with\"")),
            self.text_field(&Self::cname(of, path, "val"), &text, &format!(" list=\"{id}\" placeholder=\"{placeholder}\" aria-label=\"Value\"{off}{invalid}")),
            list.iter().map(|(v, why)| format!("<option value=\"{}\" label=\"{}\">", h(v), h(why))).collect::<String>()
        )
    }

    fn member_html(&self, node: &Node, of: CondOf, path: &[usize], fixed: bool) -> String {
        let Node::Member { device, op, sids } = node else { return String::new() };
        let off = if fixed { " disabled" } else { "" };
        let whose = vec![("0".to_string(), "They're".to_string(), false), ("1".to_string(), "Their device is".to_string(), false)];
        let ops: Vec<(String, String, bool)> = MemberOp::ALL.iter().map(|o| (o.key().to_string(), member_label(*o).to_string(), false)).collect();
        let at = Self::at(of, path);
        let chips: String = sids
            .iter()
            .map(|s| {
                let n = self.name(s);
                format!(
                    "<span class=\"chip\">{}{}</span>",
                    h(&n),
                    if fixed { String::new() } else { format!("<button type=\"button\" fx-click=\"m-delsid\"{at} fx-value-v=\"{}\" aria-label=\"Remove {}\">×</button>", h(&s.to_string()), h(&n)) }
                )
            })
            .collect();
        let bad = if self.checked { cond::problem(node).map(|(_, w)| format!("<span class=\"wrong cw\">{}</span>", h(&w))).unwrap_or_default() } else { String::new() };
        let add = if fixed {
            String::new()
        } else {
            format!(
                "<form class=\"addsid\" fx-submit=\"m-addsid\"{at}><input name=\"{}\" placeholder=\"+ Add a group by name\" autocomplete=\"off\" spellcheck=\"false\" aria-label=\"Add a group\"></form>",
                h(&Self::cname(of, path, "add"))
            )
        };
        format!(
            "<div class=\"cond member\">{}{}{}<div class=\"chips\">{chips}{add}</div>{}{bad}</div>",
            self.select(&Self::cname(of, path, "dev"), &whose, if *device { "1" } else { "0" }, &format!("{off} aria-label=\"Whose membership\"")),
            self.select(&Self::cname(of, path, "mop"), &ops, op.key(), &format!("{off} aria-label=\"Test\"")),
            if fixed { "<span></span>".to_string() } else { format!("<button type=\"button\" class=\"icon\" fx-click=\"c-del-node\"{at} aria-label=\"Remove this test\">×</button>") },
            self.wrong.get(&Self::cname(of, path, "add")).map(|w| format!("<span class=\"wrong cw\">{}</span>", h(w))).unwrap_or_default()
        )
    }

    /// The claims of `src` the machine defines, then those used before, most
    /// used first.
    fn name_suggestions(&self, src: Src) -> Vec<(String, String)> {
        let used = self.learned.names(src.word());
        let count = |n: &str| used.iter().find(|(u, _)| u == n).map_or(0, |(_, t)| *t);
        let mut defined = self.known.names(src.word());
        defined.sort_by(|a, b| count(&b.0).cmp(&count(&a.0)).then(a.0.cmp(&b.0)));
        let mut out: Vec<(String, String)> = defined.iter().map(|(n, d)| (n.clone(), defined_label(&d.description, count(n)))).collect();
        let rest: Vec<(String, String)> = used.into_iter().filter(|(n, _)| !out.iter().any(|(o, _)| o == n)).map(|(n, t)| (n, times(t))).collect();
        out.extend(rest);
        out
    }

    /// The values the machine defines for `claim`, in its order, then those
    /// used before.
    fn value_suggestions(&self, claim: &str) -> Vec<(String, String)> {
        let used = self.learned.values(claim);
        let count = |v: &str| used.iter().find(|(u, _)| u == v).map_or(0, |(_, t)| *t);
        let mut out: Vec<(String, String)> = self.known.get(claim).map(|d| d.values.iter().map(|v| (v.clone(), defined_label("", count(v)))).collect()).unwrap_or_default();
        let rest: Vec<(String, String)> = used.into_iter().filter(|(v, _)| !out.iter().any(|(o, _)| o == v)).map(|(v, t)| (v, times(t))).collect();
        out.extend(rest);
        out
    }

    // ---- rules for parts

    fn specific(&self, s: &Simple, sid: &Sid) -> String {
        let ro = !self.may_dacl();
        let rules: Vec<&PartRule> = s.parts.iter().filter(|r| r.sid == *sid).collect();
        if self.obj.parts.is_empty() && rules.is_empty() {
            return format!(
                "{}{}",
                wrapped_note(&format!("A {} has no parts with rules of their own, so there's nothing to set here.", self.kind_word())),
                wrapped_note("Objects with parts, such as an account's sign-in details or group membership, list them here.")
            );
        }
        let cards: String = rules
            .iter()
            .map(|r| {
                let key = r.ids[0];
                let of = CondOf::Rule(key);
                let cond = match &r.cond {
                    Some(Cond::Tree(node)) => format!("<div class=\"when\">Only When</div>{}{}", self.cond_editor(node, of, ro), wrapped_note(&cond_unknown(node, r.allow != 0, r.deny != 0))),
                    Some(Cond::Opaque(_)) => String::new(),
                    None if ro => String::new(),
                    None => format!("<button type=\"button\" class=\"small\" fx-click=\"r-cond\" fx-value-r=\"{key}\">+ Only When…</button>"),
                };
                format!(
                    "<div class=\"rule\"><div class=\"when\">Parts</div>{}{cond}<div class=\"when\">Then</div>{}{}{}{}</div>",
                    self.part_chips("r", key, &r.parts, ro),
                    self.scope_widget(&format!("r.{key}.scope"), r.flags & SHAPE, ro, &[]),
                    self.kind_widget("r", key, r.kind, r.flags, ro),
                    self.parts_table(r, ro),
                    if ro { String::new() } else { format!("<button type=\"button\" class=\"small remove-rule\" fx-click=\"r-del\" fx-value-r=\"{key}\">Remove Rule</button>") }
                )
            })
            .collect();
        let none = if cards.is_empty() { wrapped_note(&format!("{} has no rules for particular parts.", self.name(sid))) } else { String::new() };
        let add = if ro || self.obj.parts.is_empty() { String::new() } else { "<button type=\"button\" fx-click=\"r-new\">+ Add a Rule for Particular Parts</button>".into() };
        format!("{none}{cards}{add}{}", wrapped_note(&format!("A rule here covers only the parts it names, such as a property or an action. Rules in Access cover all of the {}.", self.kind_word())))
    }

    fn part_chips(&self, p: &str, key: u32, parts: &[Guid], fixed: bool) -> String {
        let chips: String = parts
            .iter()
            .map(|g| {
                let def = self.obj.part(g);
                let name = def.map_or_else(|| "Unknown Part".to_string(), |d| d.name.clone());
                let title = match def {
                    None => format!("A part the program that opened this doesn't name ({}). It's kept as it is.", guid_text(g)),
                    Some(d) if d.kind == PartKind::Set => {
                        let covers: Vec<String> = self.obj.parts.iter().filter(|x| x.set == Some(d.guid)).map(|x| x.name.clone()).collect();
                        format!("{}: covers {}. {}", d.name, if covers.is_empty() { "its properties".into() } else { covers.join(", ") }, guid_text(g))
                    }
                    Some(d) if d.kind == PartKind::Right => format!("{}: an action. {}", d.name, guid_text(g)),
                    Some(d) => format!("{}. {}", d.name, guid_text(g)),
                };
                let last = parts.len() == 1;
                format!(
                    "<span class=\"chip{}\" title=\"{}\">{}{}</span>",
                    if def.is_some_and(|d| d.kind == PartKind::Right) { " act" } else { "" },
                    h(&title),
                    h(&name),
                    if fixed || last { String::new() } else { format!("<button type=\"button\" fx-click=\"{p}-delpart\" fx-value-r=\"{key}\" fx-value-v=\"{}\" aria-label=\"Remove {}\">×</button>", guid_text(g), h(&name)) }
                )
            })
            .collect();
        let left: Vec<&PartDef> = self.obj.parts.iter().filter(|x| !parts.contains(&x.guid)).collect();
        let add = if fixed || left.is_empty() {
            String::new()
        } else {
            let mut opts = vec![(String::new(), "+ Add Part…".to_string(), false)];
            opts.extend(left.iter().map(|x| (guid_text(&x.guid), format!("{}{}{}", if x.set.is_some() { "  " } else { "" }, x.name, if x.kind == PartKind::Right { " (action)" } else { "" }), false)));
            self.select(&format!("{p}.{key}.add"), &opts, "", " class=\"addpart\" aria-label=\"Add a part\"")
        };
        let covered: Vec<String> = parts.iter().filter_map(|g| self.obj.part(g)).filter(|d| d.kind == PartKind::Set).flat_map(|d| self.obj.parts.iter().filter(move |x| x.set == Some(d.guid)).map(|x| x.name.clone())).collect();
        format!("<div class=\"chips\">{chips}{add}</div>{}", if covered.is_empty() { String::new() } else { wrapped_note(&format!("The sets named also cover {}.", covered.join(", "))) })
    }

    /// For a container of typed things: which kind of child a rule is
    /// passed down to.
    fn kind_widget(&self, p: &str, key: u32, kind: Option<Guid>, flags: u8, fixed: bool) -> String {
        if self.obj.kinds.is_empty() {
            return String::new();
        }
        let mut opts = vec![(String::new(), "Every kind of item".to_string(), false)];
        opts.extend(self.obj.kinds.iter().map(|(g, n)| (guid_text(g), format!("{n} only"), false)));
        let off = if fixed || !passes(flags) { " disabled" } else { "" };
        format!("<label class=\"scope\"><span>Passed to</span>{}</label>", self.select(&format!("{p}.{key}.kind"), &opts, &kind.map(|g| guid_text(&g)).unwrap_or_default(), off))
    }

    fn parts_table(&self, r: &PartRule, fixed: bool) -> String {
        let fits = [r.allow, r.deny].iter().all(|m| m & !0x130 == 0);
        let key = r.ids[0];
        let advanced = !fits || self.shows_advanced.contains(&key);
        let simple = [("Read", 0x10), ("Write", 0x20), ("Use (actions)", 0x100)];
        let rights: Vec<(String, u32)> = if advanced { self.obj.specific.iter().map(|x| (x.name.clone(), x.mask)).collect() } else { simple.iter().map(|(n, m)| (n.to_string(), *m)).collect() };
        let k = key.to_string();
        let rows: String = rights
            .iter()
            .map(|(n, m)| {
                let a = if r.allow & m == *m { Tick::Yes } else { Tick::No };
                let d = if r.deny & m == *m { Tick::Yes } else { Tick::No };
                format!("<tr><th scope=\"row\">{}</th>{}{}</tr>", h(n), tick_box(a, "r-tick", *m, "allow", n, fixed, &k), tick_box(d, "r-tick", *m, "deny", n, fixed, &k))
            })
            .collect();
        format!("<table class=\"rights\"><thead><tr><th></th><th scope=\"col\">Allow</th><th scope=\"col\">Deny</th></tr></thead><tbody>{rows}</tbody></table>{}", adv_toggle("r-adv", key, advanced, fits, "This rule"))
    }

    // ---- auditing

    fn auditing(&self, s: &Simple, sid: &Sid) -> String {
        if !self.shows_sacl() {
            return "<p class=\"note fixed\">Auditing isn't shown. Reading it takes the right to read the SACL (SeSecurityPrivilege), which the program that opened this doesn't have.</p>".into();
        }
        let ro = !self.may_sacl();
        let cards: String = s
            .audits
            .iter()
            .filter(|a| a.sid == *sid)
            .map(|a| {
                let key = a.ids[0];
                let fixed = ro || a.inherited;
                let off = if fixed { " disabled" } else { "" };
                let cover = if self.obj.parts.is_empty() {
                    String::new()
                } else {
                    let opts = vec![("all".to_string(), format!("All of the {}", self.kind_word()), false), ("parts".to_string(), "Particular parts".to_string(), false)];
                    format!(
                        "<label class=\"scope\"><span>Covers</span>{}</label>{}",
                        self.select(&format!("a.{key}.cover"), &opts, if a.parts.is_some() { "parts" } else { "all" }, off),
                        a.parts.as_ref().map(|p| self.part_chips("a", key, p, fixed)).unwrap_or_default()
                    )
                };
                let when = match &a.cond {
                    Some(Cond::Tree(node)) => format!("<div class=\"when\">Only When</div>{}{}", self.cond_editor(node, CondOf::Audit(key), fixed), wrapped_note("If a fact it tests isn't known, it's recorded anyway.")),
                    Some(Cond::Opaque(_)) => String::new(),
                    None if fixed => String::new(),
                    None => format!("<button type=\"button\" class=\"small\" fx-click=\"a-cond\" fx-value-r=\"{key}\">+ Only When…</button>"),
                };
                format!(
                    "<div class=\"rule{}\">{}{cover}{}{}{when}<div class=\"when\">Record</div>{}<label class=\"chk every\">{} Record every use while it's open, not just the opening</label>{}</div>",
                    if a.inherited { " inh" } else { "" },
                    if a.inherited { format!("<div class=\"rule-top\"><span class=\"when\">Inherited</span><span class=\"from\">↳ From {}</span></div>", h(&self.from_word())) } else { String::new() },
                    self.scope_widget(&format!("a.{key}.scope"), a.flags, fixed, &[]),
                    if a.parts.is_some() { self.kind_widget("a", key, a.kind, a.flags, fixed) } else { String::new() },
                    self.audit_table(a, fixed),
                    self.checkbox(&format!("a.{key}.every"), a.every, off),
                    if fixed { String::new() } else { format!("<button type=\"button\" class=\"small remove-rule\" fx-click=\"a-del\" fx-value-r=\"{key}\">Remove Rule</button>") }
                )
            })
            .collect();
        let none = if cards.is_empty() { wrapped_note(&format!("Nothing is recorded about {}.", self.name(sid))) } else { String::new() };
        let add = if ro { String::new() } else { "<button type=\"button\" fx-click=\"a-new\">+ Add an Auditing Rule</button>".into() };
        let fixed_note = if ro && !self.can.audit { "<p class=\"note fixed\">The program that opened this can read auditing but not change it.</p>" } else { "" };
        format!("{fixed_note}{none}{cards}{add}{}", wrapped_note("Successes record use that was allowed; failures record attempts that were refused. Records go to the event log."))
    }

    fn audit_table(&self, a: &Audit, fixed: bool) -> String {
        let key = a.ids[0];
        let fits = if a.parts.is_some() { [a.ok, a.fail].iter().all(|m| m & !0x130 == 0) } else { [a.ok, a.fail].iter().all(|m| self.obj.fits_general(*m)) };
        let advanced = !fits || self.shows_advanced.contains(&key);
        let mut rights: Vec<(String, u32)> = if advanced {
            self.obj.specific.iter().map(|x| (x.name.clone(), x.mask)).chain([("Read or change auditing".to_string(), ACCESS_SYSTEM_SECURITY)]).collect()
        } else if a.parts.is_some() {
            [("Read", 0x10), ("Write", 0x20), ("Use (actions)", 0x100)].iter().map(|(n, m)| (n.to_string(), *m)).collect()
        } else {
            self.obj.general.iter().map(|x| (x.name.clone(), x.mask)).collect()
        };
        rights.retain(|(_, m)| core(*m) != 0);
        let has = |m: u32, x: u32| core(self.obj.mapped(m)) & core(x) == core(x);
        let k = key.to_string();
        let rows: String = rights
            .iter()
            .map(|(n, m)| {
                let ok = if has(a.ok, *m) { Tick::Yes } else { Tick::No };
                let fail = if has(a.fail, *m) { Tick::Yes } else { Tick::No };
                format!("<tr><th scope=\"row\">{}</th>{}{}</tr>", h(n), tick_box(ok, "a-tick", *m, "ok", n, fixed, &k), tick_box(fail, "a-tick", *m, "fail", n, fixed, &k))
            })
            .collect();
        format!("<table class=\"rights\"><thead><tr><th></th><th scope=\"col\">Successes</th><th scope=\"col\">Failures</th></tr></thead><tbody>{rows}</tbody></table>{}", adv_toggle("a-adv", key, advanced, fits, "This rule"))
    }

    // ---- claims

    fn claims_tab(&self) -> String {
        let what = self.kind_word();
        if !self.shows_sacl() {
            return format!("<p class=\"note fixed\">This {}'s claims aren't shown. They're kept in its SACL, and reading that takes a right the program that opened this doesn't have.</p>", h(&what));
        }
        let s = self.simple();
        let names = self.name_suggestions(Src::Resource);
        let cards: String = s
            .claims
            .iter()
            .map(|c| {
                let id = c.id;
                let mandatory = c.claim.flags & claim::MANDATORY != 0;
                let locked = (mandatory && !self.caller.tcb) || c.inherited;
                let fixed = locked || !self.may_sacl();
                let off = if fixed { " disabled" } else { "" };
                let bad = c.claim.problem().filter(|w| self.checked || !(w.starts_with("Name") || w.starts_with("Give")));
                let types: Vec<(String, String, bool)> = ClaimType::ALL.iter().map(|t| (t.key().to_string(), t.label().to_string(), false)).collect();
                let shown_vals: Vec<String> = c.claim.values.iter().map(|v| if c.claim.kind == ClaimType::Sid { v.parse::<Sid>().map(|s| self.name(&s)).unwrap_or_else(|_| v.clone()) } else { v.clone() }).collect();
                let flag = |k: &str, bit: u32, label: &str, title: &str| format!("<label class=\"chk\" title=\"{}\">{} {label}</label>", h(title), self.checkbox(&format!("cl.{id}.{k}"), c.claim.flags & bit != 0, off));
                let top = if c.inherited {
                    format!("<div class=\"rule-top\"><span class=\"when\">Inherited</span><span class=\"from\">↳ From {}</span></div>", h(&self.from_word()))
                } else if mandatory {
                    format!("<div class=\"rule-top\"><span class=\"when\">Locked</span><span class=\"from\">{} Only something with SeTcbPrivilege can change or remove it</span></div>", LOCK.replace("<svg", "<svg class=\"lk\""))
                } else {
                    String::new()
                };
                let vals = self.value_suggestions(&format!("Resource.{}", c.claim.name.trim()));
                format!(
                    "<div class=\"rule claim{}\">{top}<div class=\"claim-row\"><label class=\"fld\"><span>Claim</span>{}<datalist id=\"cln-{id}\">{}</datalist></label><label class=\"fld\"><span>Kind</span>{}</label></div>\
                     <label class=\"fld\"><span>{}</span>{}<datalist id=\"clv-{id}\">{}</datalist></label>{}<div class=\"flags\">{}{}{}{}</div>\
                     <div class=\"claim-foot\"><code class=\"expr\">@Resource.{}</code>{}</div></div>",
                    if c.claim.flags & claim::DISABLED != 0 { " off" } else { "" },
                    self.text_field(&format!("cl.{id}.name"), &c.claim.name, &format!(" list=\"cln-{id}\" placeholder=\"Such as Classification\"{off}")),
                    names.iter().map(|(n, w)| format!("<option value=\"{}\" label=\"{}\">", h(n), h(w))).collect::<String>(),
                    self.select(&format!("cl.{id}.kind"), &types, c.claim.kind.key(), off),
                    if c.claim.kind == ClaimType::Sid { "Users or Groups" } else { "Values" },
                    self.text_field(&format!("cl.{id}.vals"), &shown_vals.join(", "), &format!(" list=\"clv-{id}\" placeholder=\"{}\"{off}", if c.claim.kind == ClaimType::Sid { "Names, with commas" } else if c.claim.kind == ClaimType::Bytes { "Hex, such as 9f86d0" } else { "One or more, with commas" })),
                    vals.iter().map(|(v, w)| format!("<option value=\"{}\" label=\"{}\">", h(v), h(w))).collect::<String>(),
                    bad.map(|w| format!("<span class=\"wrong\">{}</span>", h(&w))).unwrap_or_default(),
                    if c.claim.kind == ClaimType::Text { flag("cs", claim::CASE_SENSITIVE, "Match case", "Tests compare it with case") } else { String::new() },
                    flag("deny", claim::DENY_ONLY, "Only for refusals", "Allow rules can't see it; refusals can"),
                    flag("off", claim::DISABLED, "Off", "Kept, but no condition can see it"),
                    if self.obj.container { format!("<label class=\"chk\" title=\"New items inside get this claim too\">{} Pass to new items inside</label>", self.checkbox(&format!("cl.{id}.inherit"), c.inherit, off)) } else { String::new() },
                    h(if c.claim.name.trim().is_empty() { "?" } else { c.claim.name.trim() }),
                    if fixed { String::new() } else { format!("<button type=\"button\" class=\"small remove-rule\" fx-click=\"cl-del\" fx-value-r=\"{id}\">Remove Claim</button>") }
                )
            })
            .collect();
        format!(
            "{}{}{}",
            wrapped_note(&format!("Claims describe this {what}. Conditions here and in central access policies test them as @Resource.Name, so labelling something Confidential can change who may use it without touching anyone's rules.")),
            if cards.is_empty() { wrapped_note(&format!("This {what} has no claims.")) } else { cards },
            if self.may_sacl() { "<button type=\"button\" fx-click=\"cl-new\">+ Add a Claim</button>".to_string() } else { String::new() }
        )
    }

    // ---- central access policies

    fn cap_tab(&self) -> String {
        let what = self.kind_word();
        if !self.shows_sacl() {
            return "<p class=\"note fixed\">Which central access policies apply isn't shown. That's kept in the SACL, and reading it takes a right the program that opened this doesn't have.</p>".into();
        }
        let s = self.simple();
        let rows: String = s
            .policies
            .iter()
            .map(|p| {
                let fixed = p.inherited || !self.may_sacl();
                let off = if fixed { " disabled" } else { "" };
                format!(
                    "<div class=\"rule cap on\"><div class=\"cap-h\"><b class=\"guid\">{}</b>{}</div><span class=\"pill\">Not defined on this machine: KACS applies its recovery policy</span>\
                     <span class=\"note\">Until it's defined, only Administrators, Local System and the owner keep their access to this {}. Everyone else is refused whatever the access list gives.</span>{}{}</div>",
                    h(&p.sid.to_string()),
                    if p.inherited { format!("<span class=\"from\">↳ From {}</span>", h(&self.from_word())) } else { String::new() },
                    h(&what),
                    if self.obj.container { format!("<label class=\"chk\">{} Pass to new items inside</label>", self.checkbox(&format!("cap.{}.inherit", p.id), p.inherit, off)) } else { String::new() },
                    if fixed { String::new() } else { format!("<button type=\"button\" class=\"small remove-rule\" fx-click=\"cap-del\" fx-value-r=\"{}\">Stop Naming It</button>", p.id) }
                )
            })
            .collect();
        format!(
            "{}{}{}",
            wrapped_note(&format!("A central access policy is set for the whole machine. Naming one here makes it count for this {what} too, whenever its claims match. It can only take access away: someone gets what both the access list and the policy allow.")),
            if rows.is_empty() { wrapped_note(&format!("This {what} names no central access policies.")) } else { rows },
            wrapped_note("This machine defines no central access policies yet: authd hands them to KACS, which is still to come. A policy can be named by its SID in Advanced mode.")
        )
    }

    // ---- effective access

    pub fn eff_tab(&self) -> String {
        let users: Vec<Sid> = {
            let mut v: Vec<Sid> = self.caller.user.into_iter().collect();
            for s in &self.listed {
                if !v.contains(s) && kind_of(self, s).0 == "user" && self.names.named(s) {
                    v.push(*s);
                }
            }
            if let Some(w) = self.eff_who
                && !v.contains(&w)
            {
                v.push(w);
            }
            v
        };
        let who = self.eff_who.or(self.caller.user).or(users.first().copied());
        let mut opts: Vec<(String, String, bool)> = users.iter().map(|s| (s.to_string(), if Some(*s) == self.caller.user { format!("{} (you)", self.name(s)) } else { self.name(s) }, false)).collect();
        if opts.is_empty() {
            opts.push((String::new(), "Nobody to check".into(), true));
        }
        let parts = if self.obj.parts.is_empty() {
            String::new()
        } else {
            let mut p = vec![(String::new(), format!("All of the {}", self.kind_word()), false)];
            p.extend(self.obj.parts.iter().map(|d| (guid_text(&d.guid), format!("{}{}", if d.set.is_some() { "  " } else { "" }, d.name), false)));
            format!("<label class=\"scope\"><span>For</span>{}</label>", self.select("eff.part", &p, &self.eff_part.map(|g| guid_text(&g)).unwrap_or_default(), ""))
        };
        let find = format!(
            "<form class=\"naming eff-find\" fx-submit=\"eff-find\"><input name=\"eff.name\" autocomplete=\"off\" spellcheck=\"false\" placeholder=\"Someone else, by name\" aria-label=\"Check someone else\"{}><button type=\"submit\">Check</button>{}</form>",
            if self.wrong.contains_key("eff") { " aria-invalid=\"true\"" } else { "" },
            self.wrong.get("eff").map(|w| format!("<p class=\"wrong\">{}</p>", h(w))).unwrap_or_default()
        );
        let head = format!(
            "<div class=\"effhead\"><label class=\"scope\"><span>Check</span>{}</label>{parts}</div>{find}",
            self.select("eff.who", &opts, &who.map(|s| s.to_string()).unwrap_or_default(), "")
        );
        let Some(who) = who else { return head };
        let person = match self.people.get(&who) {
            Some(Ok(p)) => p.clone(),
            Some(Err(why)) => return format!("{head}<p class=\"note fixed\">{}</p>", h(why)),
            None => return format!("{head}<p class=\"note\">Finding out what {} belongs to…</p>", h(&self.name(&who))),
        };
        let s = self.simple();
        let (dacl, _) = s.write(&self.obj, &mut self.ids.clone());
        let name = |sid: &Sid| self.name(sid);
        let facts = eff::Facts { obj: &self.obj, simple: &s, dacl: dacl.as_deref(), owner: self.sd.owner, sacl: self.shows_sacl(), name: &name };
        let res = eff::effective(&facts, &person, self.eff_part);
        let general: String = self
            .obj
            .general
            .iter()
            .map(|r| {
                let m = core(r.mask);
                let (cls, mark, title) = if res.granted & m == m {
                    ("yes", "✓", "Has all of it")
                } else if res.granted & m != 0 {
                    ("part", "~", "Has some of it")
                } else {
                    ("no", "✗", "Has none of it")
                };
                format!("<span class=\"cap {cls}\" title=\"{title}\">{mark} {}</span>", h(&r.name))
            })
            .collect();
        let rows: String = self
            .obj
            .specific
            .iter()
            .map(|r| {
                let ok = res.granted & r.mask != 0;
                let why = res.by.get(&r.mask).map_or("Nothing gives it", |(_, w)| w.as_str());
                format!("<tr><th scope=\"row\">{}</th><td class=\"mk {}\">{}</td><td class=\"why\">{}</td></tr>", h(&r.name), if ok { "y" } else { "n" }, if ok { "✓" } else { "✗" }, h(why))
            })
            .collect();
        let mark = |m: eff::Mark| match m {
            eff::Mark::Yes => "<span class=\"mk y\">✓</span>",
            eff::Mark::No => "<span class=\"mk n\">✗</span>",
            eff::Mark::Skip => "<span class=\"mk s\">·</span>",
        };
        let trace: String = res
            .steps
            .iter()
            .map(|st| format!("<div class=\"tr\"><div class=\"g\">{}</div><div class=\"w\">{}</div></div>", st.stage, st.lines.iter().map(|(m, t)| format!("<div>{}<span>{}</span></div>", mark(*m), h(t))).collect::<String>()))
            .collect();
        format!(
            "{head}<p class=\"note\">As if {} opened it with an ordinary program, at Medium integrity, signed in with the groups and claims authd gives them. Device claims aren't known here.{}</p>\
             <div class=\"capchips\">{general}</div><div class=\"effgrid\"><table class=\"rights eff\"><thead><tr><th>Right</th><th></th><th>Decided By</th></tr></thead><tbody>{rows}</tbody></table>\
             <details class=\"how\" open><summary>How This Was Decided</summary><div class=\"trace\">{trace}</div></details></div>",
            h(&person.name),
            if self.shows_sacl() { "" } else { " Process trust, claims and central policy are in the SACL, which this program can't read, so they aren't counted." }
        )
    }

    /// Finds out about the one Effective Access is for, if it has not yet.
    pub fn look_up(&mut self) {
        let who = self.eff_who.or(self.caller.user).or_else(|| self.listed.iter().find(|s| kind_of(self, s).0 == "user" && self.names.named(s)).copied());
        if let Some(who) = who
            && !self.people.contains_key(&who)
        {
            let name = self.name(&who);
            self.people.insert(who, people::person(&who, name));
        }
    }

    // ---- Apply: what is unfinished, and where

    pub fn fault(&self) -> Option<(String, Place)> {
        if self.adv.is_some() {
            return adv::fault(self);
        }
        let s = self.simple();
        let name = |sid: &Sid| self.name(sid);
        for e in s.entries().iter().filter(|e| e.kept.is_none() && !e.ace.inherited()) {
            let Some(sid) = e.ace.sid else { continue };
            if let Some(Cond::Tree(node)) = &e.ace.cond
                && let Some(why) = cond::tree_problem(node)
            {
                return Some((format!("A condition for {} isn't finished: {why}", name(&sid)), Place::Person(sid, Tab::Cond)));
            }
        }
        for sid in s.principals(true) {
            for c in s.cards(&sid).iter().filter(|c| !c.inherited) {
                if core(c.allow_mask) == 0 && core(c.deny_mask) == 0 {
                    return Some((format!("A conditional rule for {} neither allows nor denies anything. Tick a right, or remove the rule.", name(&sid)), Place::Person(sid, Tab::Cond)));
                }
            }
        }
        for r in &s.parts {
            if let Some(Cond::Tree(node)) = &r.cond
                && let Some(why) = cond::tree_problem(node)
            {
                return Some((format!("A condition for {} isn't finished: {why}", name(&r.sid)), Place::Person(r.sid, Tab::Specific)));
            }
            if r.allow == 0 && r.deny == 0 {
                return Some((format!("A rule for {} in Specific Rights neither allows nor denies anything. Tick a right, or remove the rule.", name(&r.sid)), Place::Person(r.sid, Tab::Specific)));
            }
        }
        if let Some(c) = s.claims.iter().find(|c| c.claim.problem().is_some()) {
            return Some((format!("A claim isn't finished: {}", c.claim.problem().unwrap_or_default()), Place::Claims));
        }
        for a in s.audits.iter().filter(|a| !a.inherited) {
            if let Some(Cond::Tree(node)) = &a.cond
                && let Some(why) = cond::tree_problem(node)
            {
                return Some((format!("A condition in {} auditing isn't finished: {why}", poss(&name(&a.sid))), Place::Person(a.sid, Tab::Audit)));
            }
            if a.parts.as_ref().is_some_and(|p| p.is_empty()) {
                return Some((format!("An auditing rule for {} covers particular parts but names none. Add a part, or cover all of it.", name(&a.sid)), Place::Person(a.sid, Tab::Audit)));
            }
            if core(a.ok) == 0 && core(a.fail) == 0 {
                return Some((format!("An auditing rule for {} records nothing. Tick something to record, or remove the rule.", name(&a.sid)), Place::Person(a.sid, Tab::Audit)));
            }
        }
        adv::fault(self)
    }

    pub fn go(&mut self, place: Place) {
        match place {
            Place::Person(sid, tab) => {
                self.adv = None;
                self.top = Top::Access;
                if !self.listed.contains(&sid) {
                    self.listed.push(sid);
                }
                self.pick(Some(sid));
                self.tab = tab;
            }
            Place::Claims => {
                self.adv = None;
                self.top = Top::Claims;
            }
            Place::Entry(list, id) => {
                let adv = self.adv.get_or_insert(Adv { tab: AdvTab::Dacl, dacl: None, sacl: None, more: false, stash: None, text: None });
                match list {
                    List::Dacl => {
                        adv.tab = AdvTab::Dacl;
                        adv.dacl = Some(id);
                    }
                    List::Sacl => {
                        adv.tab = AdvTab::Sacl;
                        adv.sacl = Some(id);
                    }
                }
            }
            Place::Descriptor => {
                let adv = self.adv.get_or_insert(Adv { tab: AdvTab::Desc, dacl: None, sacl: None, more: false, stash: None, text: None });
                adv.tab = AdvTab::Desc;
            }
        }
    }
}

/// One box of a rights table.
fn tick_box(t: Tick, event: &str, mask: u32, way: &str, name: &str, fixed: bool, key: &str) -> String {
    let (checked, disabled, class) = match t {
        Tick::No => ("false", fixed, ""),
        Tick::Yes => ("true", fixed, ""),
        Tick::Inherited => ("true", true, " class=\"inherited\""),
    };
    let word = match way {
        "allow" => "Allow",
        "deny" => "Deny",
        "ok" => "Record successes:",
        _ => "Record failures:",
    };
    format!(
        "<td><button type=\"button\" role=\"checkbox\" aria-checked=\"{checked}\"{class}{} fx-click=\"{event}\" fx-value-mask=\"{mask}\" fx-value-way=\"{way}\"{} aria-label=\"{word} {}\"></button></td>",
        if disabled { " disabled" } else { "" },
        if key.is_empty() { String::new() } else { format!(" fx-value-k=\"{key}\"") },
        h(name)
    )
}

/// "Show advanced rights", and back, for one rule.
fn adv_toggle(event: &str, key: u32, advanced: bool, fits: bool, what: &str) -> String {
    if advanced {
        format!(
            "<div class=\"advtoggle\"><button type=\"button\" class=\"link small\" fx-click=\"{event}\" fx-value-k=\"{key}\" fx-value-v=\"0\"{}>Show Simple Rights</button>{}</div>",
            if fits { "" } else { " disabled" },
            if fits { String::new() } else { format!("<span class=\"note\">{what} can't be shown as the simple rights.</span>") }
        )
    } else {
        format!("<div class=\"advtoggle\"><button type=\"button\" class=\"link small\" fx-click=\"{event}\" fx-value-k=\"{key}\" fx-value-v=\"1\">Show Advanced Rights</button></div>")
    }
}

fn times(n: u32) -> String {
    if n == 1 { "Used once".into() } else { format!("Used {n} times") }
}

/// A suggestion the machine defines: what it is for, if it says, and how
/// often it has been used.
fn defined_label(description: &str, used: u32) -> String {
    let mut out = "Defined on this machine".to_string();
    if !description.trim().is_empty() {
        out = format!("{out}: {}", description.trim());
    }
    if used > 0 {
        out = format!("{out} · {}", times(used).to_lowercase());
    }
    out
}

pub fn title_case(s: &str) -> String {
    let mut c = s.chars();
    c.next().map_or_else(String::new, |f| f.to_uppercase().collect::<String>() + c.as_str())
}

fn mode_label(m: Mode) -> &'static str {
    match m {
        Mode::All => "All of these",
        Mode::Any => "Any of these",
        Mode::None => "None of these",
        Mode::NotAll => "Not all of these",
    }
}

fn src_label(s: Src) -> &'static str {
    match s {
        Src::User => "Their account",
        Src::Device => "Their device",
        Src::Resource => "This item's claims",
        Src::Local => "From the program",
    }
}

fn src_owner(s: Src) -> &'static str {
    match s {
        Src::User => "their account",
        Src::Device => "their device",
        Src::Resource => "this item",
        Src::Local => "the program",
    }
}

fn op_label(o: Op) -> &'static str {
    match o {
        Op::Eq => "is",
        Op::Ne => "isn't",
        Op::AnyOf => "is one of",
        Op::Contains => "includes",
        Op::Ge => "is at least",
        Op::Gt => "is more than",
        Op::Le => "is at most",
        Op::Lt => "is less than",
        Op::Exists => "is set",
        Op::NotExists => "isn't set",
    }
}

fn member_label(o: MemberOp) -> &'static str {
    match o {
        MemberOp::Of => "in all of",
        MemberOp::OfAny => "in any of",
        MemberOp::NotOf => "not in all of",
        MemberOp::NotOfAny => "in none of",
    }
}

/// What happens when a fact a condition tests is not known.
fn cond_unknown(node: &Node, allow: bool, deny: bool) -> String {
    let mut facts: Vec<String> = Vec::new();
    for c in node.claims() {
        if let Node::Claim { src, name, op, val } = c {
            if *op == Op::NotExists {
                continue;
            }
            let f = format!("{}'s {}", src_owner(*src), if name.trim().is_empty() { "claim" } else { name.trim() });
            if !facts.contains(&f) {
                facts.push(f);
            }
            if let Val::Claim(other, n) = val {
                let f = format!("{}'s {}", src_owner(*other), if n.trim().is_empty() { "claim" } else { n.trim() });
                if !facts.contains(&f) {
                    facts.push(f);
                }
            }
        }
    }
    if facts.is_empty() {
        return String::new();
    }
    let which = match facts.as_slice() {
        [one] => one.clone(),
        [rest @ .., last] => format!("{} or {last}", rest.join(", ")),
        [] => String::new(),
    };
    if allow && deny {
        format!("If {which} isn't known, what this allows isn't given, and what it denies is still denied.")
    } else if deny {
        format!("If {which} isn't known, this rule still denies.")
    } else {
        format!("If {which} isn't known, this rule gives nothing.")
    }
}

/// A path in a field name or value: "r" is the root, "0-1" the second item
/// of the first.
pub fn parse_path(p: &str) -> Option<Vec<usize>> {
    if p == "r" || p.is_empty() {
        return Some(vec![]);
    }
    p.split('-').map(|i| i.parse().ok()).collect()
}

// ---- what the controls do

pub fn event(e: &mut Editor, name: &str, value: &Value, fields: &mut Fields) {
    let v = |k: &str| value[k].as_str().unwrap_or("").to_string();
    let num = |k: &str| v(k).parse::<u32>().ok();
    let list = e.may_dacl() && e.sd.dacl.is_some();
    let sacl = e.may_sacl();
    match name {
        "pick" => {
            if let Ok(sid) = v("sid").parse::<Sid>()
                && e.listed.contains(&sid)
            {
                e.pick(Some(sid));
            }
        }
        "tab" => {
            e.tab = match v("v").as_str() {
                "cond" => Tab::Cond,
                "specific" => Tab::Specific,
                "audit" => Tab::Audit,
                _ => Tab::Access,
            }
        }
        "scope" => {
            if let Some(f) = num("v") {
                e.scope = f as u8;
                if let Some(p) = e.picked {
                    e.advanced = !e.simple().simple_for(&e.obj, &p, e.scope);
                }
            }
        }
        "adv" => e.advanced = v("v") == "1",
        "cadv" | "r-adv" | "a-adv" => {
            if let Some(k) = num("k") {
                if v("v") == "1" {
                    e.shows_advanced.insert(k);
                } else {
                    e.shows_advanced.remove(&k);
                }
            }
        }
        "adv-open" => {
            // Advanced mode, on the first entry only it can show.
            let s = e.simple();
            let sid = v("sid").parse::<Sid>().ok();
            let first = s.entries().iter().find(|x| x.kept.is_some() && (sid.is_none() || x.ace.sid == sid)).map(|x| (List::Dacl, x.ace.id));
            let first = first.or_else(|| if sid.is_none() && e.shows_sacl() { s.skept.first().map(|x| (List::Sacl, x.ace.id)) } else { None });
            adv::enter(e);
            if let Some((l, id)) = first {
                e.go(Place::Entry(l, id));
            }
        }
        "make-list" if e.may_dacl() && e.sd.dacl.is_none() => {
            let everyone = everyone();
            let full = e.obj.general.first().map_or(e.obj.generic.all, |r| r.mask);
            let id = e.ids.next();
            let flags = e.obj.home();
            e.sd.dacl = Some(Acl { revision: 2, aces: vec![Ace::new(id, Way::Allow, flags, full, everyone)] });
            if !e.listed.contains(&everyone) {
                e.listed.insert(0, everyone);
            }
            e.pick(Some(everyone));
        }
        "put-in-order" if list => {
            e.edit(|s, _, _, _| s.put_in_order());
            e.status = "Put in the standard order.".into();
        }
        "tick" if list => {
            let (Some(sid), Some(mask)) = (e.picked, num("mask")) else { return };
            let way = if v("way") == "deny" { Way::Deny } else { Way::Allow };
            let now = e.simple().shown(&e.obj, &sid, e.scope, &[mask])[0];
            let on = (if way == Way::Allow { now.0 } else { now.1 }) != Tick::Yes;
            let scope = e.scope;
            let found = e.found.clone();
            let was = move |id: u32| found.ace(id).map(|a| a.mask);
            e.edit(|s, obj, ids, _| s.tick(obj, ids, &was, sid, scope, mask, way, on));
        }
        "c-new" if list => {
            if let Some(sid) = e.picked {
                e.edit(|s, obj, ids, _| s.new_card(obj, ids, sid));
            }
        }
        "c-del" if list => {
            if let Some(k) = num("k") {
                e.edit(|s, _, _, _| s.remove_card(k));
            }
        }
        "ctick" if list => {
            let (Some(k), Some(mask)) = (num("k"), num("mask")) else { return };
            let way = if v("way") == "deny" { Way::Deny } else { Way::Allow };
            let Some(card) = e.simple().card(k) else { return };
            let (id, m) = if way == Way::Allow { (card.allow, card.allow_mask) } else { (card.deny, card.deny_mask) };
            let on = !(id.is_some() && core(e.obj.mapped(m)) & core(mask) == core(mask));
            e.edit(|s, obj, ids, _| s.card_tick(obj, ids, k, mask, way, on));
        }
        "c-add" | "c-del-node" | "m-delsid" => {
            let (Some(of), Some(path)) = (cond_key(&v("k")), parse_path(&v("p"))) else { return };
            if !e.may_cond(of) {
                return;
            }
            let what = v("v");
            match name {
                "c-add" => e.change_cond(of, |root| {
                    if let Some(Node::Group(_, items)) = root.at_mut(&path) {
                        items.push(match what.as_str() {
                            "member" => Node::Member { device: false, op: MemberOp::Of, sids: vec![] },
                            "group" => Node::Group(Mode::All, vec![Node::blank_claim()]),
                            _ => Node::blank_claim(),
                        });
                    }
                }),
                "c-del-node" => {
                    let Some((last, parent)) = path.split_last() else { return };
                    let last = *last;
                    e.change_cond(of, |root| {
                        if let Some(Node::Group(_, items)) = root.at_mut(parent)
                            && last < items.len()
                        {
                            items.remove(last);
                        }
                    });
                }
                _ => {
                    let Ok(gone) = what.parse::<Sid>() else { return };
                    e.change_cond(of, |root| {
                        if let Some(Node::Member { sids, .. }) = root.at_mut(&path) {
                            sids.retain(|s| *s != gone);
                        }
                    });
                }
            }
        }
        "m-addsid" => {
            let (Some(of), Some(path)) = (cond_key(&v("k")), parse_path(&v("p"))) else { return };
            if !e.may_cond(of) {
                return;
            }
            let field = Editor::cname(of, &path, "add");
            match e.names.find(fields.get(&field)) {
                Ok(sid) => {
                    e.wrong.remove(&field);
                    e.change_cond(of, |root| {
                        if let Some(Node::Member { sids, .. }) = root.at_mut(&path)
                            && !sids.contains(&sid)
                        {
                            sids.push(sid);
                        }
                    });
                    fields.set(&field, "");
                }
                Err(why) => {
                    e.wrong.insert(field, why);
                }
            }
        }
        "forget" => {
            let _ = e.learned.forget();
        }
        "r-new" if list => {
            if let Some(sid) = e.picked {
                e.edit(|s, obj, ids, _| s.new_rule(obj, ids, sid));
            }
        }
        "r-del" if list => {
            if let Some(k) = num("r") {
                e.edit(|s, _, _, _| s.parts.retain(|r| r.ids.first() != Some(&k)));
            }
        }
        "r-delpart" if list => {
            let (Some(k), Some(g)) = (num("r"), guid_parse(&v("v"))) else { return };
            e.edit(|s, _, _, _| {
                if let Some(r) = s.rule_mut(k)
                    && r.parts.len() > 1
                {
                    r.parts.retain(|p| *p != g);
                }
            });
        }
        "r-cond" if list => {
            if let Some(k) = num("r") {
                e.edit(|s, _, _, _| {
                    if let Some(r) = s.rule_mut(k) {
                        r.cond = Some(Cond::Tree(Node::fresh()));
                    }
                });
            }
        }
        "r-tick" if list => {
            let (Some(k), Some(mask)) = (num("k"), num("mask")) else { return };
            let deny = v("way") == "deny";
            e.edit(|s, _, _, _| {
                if let Some(r) = s.rule_mut(k) {
                    let (mine, other) = if deny { (&mut r.deny, &mut r.allow) } else { (&mut r.allow, &mut r.deny) };
                    if *mine & mask == mask {
                        *mine &= !mask;
                    } else {
                        *mine |= mask;
                        *other &= !mask;
                    }
                }
            });
        }
        "a-new" if sacl => {
            if let Some(sid) = e.picked {
                e.edit(|s, obj, ids, _| s.new_audit(obj, ids, sid));
                if !e.listed.contains(&sid) {
                    e.listed.push(sid);
                }
            }
        }
        "a-del" if sacl => {
            if let Some(k) = num("r") {
                e.edit(|s, _, _, _| s.audits.retain(|a| a.ids.first() != Some(&k) || a.inherited));
            }
        }
        "a-cond" if sacl => {
            if let Some(k) = num("r") {
                e.edit(|s, _, _, _| {
                    if let Some(a) = s.audit_mut(k) {
                        a.cond = Some(Cond::Tree(Node::fresh()));
                    }
                });
            }
        }
        "a-delpart" if sacl => {
            let (Some(k), Some(g)) = (num("r"), guid_parse(&v("v"))) else { return };
            e.edit(|s, _, _, _| {
                if let Some(a) = s.audit_mut(k)
                    && let Some(p) = &mut a.parts
                    && p.len() > 1
                {
                    p.retain(|x| *x != g);
                }
            });
        }
        "a-tick" if sacl => {
            let (Some(k), Some(mask)) = (num("k"), num("mask")) else { return };
            let ok = v("way") == "ok";
            let obj = e.obj.clone();
            e.edit(|s, _, _, _| {
                if let Some(a) = s.audit_mut(k) {
                    let side = if ok { &mut a.ok } else { &mut a.fail };
                    let m = obj.mapped(*side);
                    *side = if core(m) & core(mask) == core(mask) { m & !core(mask) } else { m | mask };
                    if core(*side) == 0 {
                        *side = 0;
                    }
                }
            });
        }
        "cl-new" if sacl => {
            e.edit(|s, obj, ids, _| s.new_claim(obj, ids));
        }
        "cl-del" if sacl => {
            if let Some(k) = num("r") {
                let tcb = e.caller.tcb;
                e.edit(|s, _, _, _| s.claims.retain(|c| c.id != k || c.inherited || (c.claim.flags & claim::MANDATORY != 0 && !tcb)));
            }
        }
        "cap-del" if sacl => {
            if let Some(k) = num("r") {
                e.edit(|s, _, _, _| s.policies.retain(|p| p.id != k || p.inherited));
            }
        }
        "add" if e.may_dacl() => {
            fields.set("who", "");
            e.wrong.clear();
            e.asking = Some(Asking::Add);
        }
        "added" if e.asking == Some(Asking::Add) => match e.names.find(fields.get("who")) {
            Ok(sid) => {
                e.asking = None;
                e.wrong.clear();
                if !e.listed.contains(&sid) {
                    e.listed.push(sid);
                    e.added.push(sid);
                }
                e.pick(Some(sid));
            }
            Err(why) => {
                e.wrong.insert("who".into(), why);
            }
        },
        "change-owner" => {
            if let Some(adv) = &mut e.adv {
                adv.tab = AdvTab::Desc;
                return;
            }
            e.wrong.clear();
            if e.asking == Some(Asking::Owner) {
                e.asking = None;
            } else {
                e.asking = Some(Asking::Owner);
                e.open_owners();
            }
        }
        "own-me" => {
            if let Some(me) = e.caller.user {
                let name = e.name(&me);
                e.typed.insert("own.owner".into(), name);
                e.wrong.remove("owner");
            }
        }
        "owners" => {
            // The dropdown's fields are what was typed: keep them through
            // the event that reads them.
            for k in ["owner", "group", "level", "nw", "nr", "nx", "linh", "trust", "ttype", "tlevel", "keep", "tinh"] {
                let f = format!("own.{k}");
                let got = fields.get(&f).to_string();
                e.typed.insert(f, got);
            }
            e.owners_done();
        }
        "remove" if e.may_dacl() => {
            let Some(sid) = e.picked else { return };
            let sacl = e.may_sacl();
            e.edit(|s, _, _, _| s.remove(&sid, sacl));
            e.added.retain(|s| *s != sid);
            if !e.simple().principals(e.read_sacl).contains(&sid) {
                let at = e.listed.iter().position(|s| *s == sid).unwrap_or(0);
                e.listed.retain(|s| *s != sid);
                let next = e.listed.get(at.min(e.listed.len().saturating_sub(1))).copied();
                e.pick(next);
            }
        }
        "inherit-stop" => {
            e.asking = Some(Asking::Stop(if v("v") == "sacl" { Side::Sacl } else { Side::Access }));
        }
        "inherit-copy" | "inherit-drop" => {
            let keep = name == "inherit-copy";
            if v("v") == "sacl" {
                if !sacl {
                    return;
                }
                e.edit(|s, _, _, _| s.stop_sacl(keep));
                e.sd.control |= PS;
            } else {
                if !list {
                    return;
                }
                e.edit(|s, _, _, _| s.stop_access(keep));
                e.sd.control |= PD;
            }
            e.asking = None;
            e.relist();
        }
        "inherit-on" => {
            let Some(parent) = e.parent.clone() else { return };
            if v("v") == "sacl" {
                if sacl {
                    adv::reinherit_sacl(e, &parent);
                }
            } else if list {
                adv::reinherit_dacl(e, &parent);
            }
            e.relist();
        }
        "eff-find" => match e.names.find(fields.get("eff.name")) {
            Ok(sid) => {
                e.wrong.remove("eff");
                e.eff_who = Some(sid);
                fields.set("eff.name", "");
                e.look_up();
            }
            Err(why) => {
                e.wrong.insert("eff".into(), why);
            }
        },
        _ => {}
    }
    if e.top == Top::Effective || e.adv.as_ref().is_some_and(|a| a.tab == AdvTab::Effective) {
        e.look_up();
    }
}

fn cond_key(k: &str) -> Option<CondOf> {
    CondOf::parse(k)
}

pub fn input(e: &mut Editor, name: &str, value: &str, _fields: &mut Fields) {
    let parts: Vec<&str> = name.split('.').collect();
    let on = !value.is_empty();
    let list = e.may_dacl() && e.sd.dacl.is_some();
    let sacl = e.may_sacl();
    // The owner dropdown's fields are a draft until Done.
    if parts[0] == "own" {
        e.typed.insert(name.to_string(), value.to_string());
        return;
    }
    match parts.as_slice() {
        ["scope"] => {
            if let Ok(f) = value.parse::<u8>() {
                e.scope = f | if passes(f) { e.scope & NP } else { 0 };
                if let Some(p) = e.picked {
                    e.advanced = !e.simple().simple_for(&e.obj, &p, e.scope);
                }
            }
        }
        ["scope", "np"] => {
            e.scope = (e.scope & !NP) | if on { NP } else { 0 };
            if let Some(p) = e.picked {
                e.advanced = !e.simple().simple_for(&e.obj, &p, e.scope);
            }
        }
        ["card", key, rest @ ..] if list => {
            let Ok(k) = key.parse::<u32>() else { return };
            let Some(card) = e.simple().card(k) else { return };
            if card.inherited {
                return;
            }
            let flags = new_scope(card.flags, rest, value);
            e.edit(|s, _, _, _| s.card_scope(k, flags));
        }
        ["r", key, what] if list => {
            let Ok(k) = key.parse::<u32>() else { return };
            e.edit(|s, obj, _, _| {
                let Some(r) = s.rule_mut(k) else { return };
                match *what {
                    "scope" | "np" => {
                        r.flags = new_scope(r.flags, if *what == "np" { &["np"] } else { &[] }, value);
                        if !passes(r.flags) {
                            r.kind = None;
                        }
                    }
                    "kind" => r.kind = guid_parse(value),
                    "add" => {
                        if let Some(g) = guid_parse(value).filter(|g| obj.part(g).is_some() && !r.parts.contains(g)) {
                            r.parts.push(g);
                        }
                    }
                    _ => {}
                }
            });
        }
        ["a", key, what] if sacl => {
            let Ok(k) = key.parse::<u32>() else { return };
            e.edit(|s, obj, _, _| {
                let Some(a) = s.audit_mut(k) else { return };
                if a.inherited {
                    return;
                }
                match *what {
                    "every" => a.every = on,
                    "cover" => {
                        a.parts = if value == "parts" { a.parts.clone().or_else(|| obj.parts.first().map(|p| vec![p.guid])) } else { None };
                        if a.parts.is_none() {
                            a.kind = None;
                        }
                    }
                    "scope" | "np" => {
                        a.flags = new_scope(a.flags, if *what == "np" { &["np"] } else { &[] }, value);
                        if !passes(a.flags) {
                            a.kind = None;
                        }
                    }
                    "kind" => a.kind = guid_parse(value),
                    "add" => {
                        if let (Some(g), Some(p)) = (guid_parse(value).filter(|g| obj.part(g).is_some()), &mut a.parts)
                            && !p.contains(&g)
                        {
                            p.push(g);
                        }
                    }
                    _ => {}
                }
            });
        }
        ["cl", id, what] if sacl => {
            let Ok(k) = id.parse::<u32>() else { return };
            let tcb = e.caller.tcb;
            if *what == "vals" {
                e.typed.insert(name.to_string(), value.to_string());
            }
            // Names in a users-or-groups claim are found as they are typed.
            let resolved: Vec<String> = value
                .split(',')
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(|v| v.to_string())
                .collect();
            let kind_now = e.simple().claims.iter().find(|c| c.id == k).map(|c| c.claim.kind);
            // A claim the machine defines comes as the kind it says.
            let defined_kind = if *what == "name" { e.known.get(&format!("Resource.{}", value.trim())).and_then(|d| d.kind) } else { None };
            let resolved: Vec<String> = if kind_now == Some(ClaimType::Sid) { resolved.iter().map(|v| e.names.find(v).map_or_else(|_| v.clone(), |s| s.to_string())).collect() } else { resolved };
            e.edit(|s, _, _, _| {
                let Some(c) = s.claims.iter_mut().find(|c| c.id == k) else { return };
                if c.inherited || (c.claim.flags & claim::MANDATORY != 0 && !tcb) {
                    return;
                }
                let bit = |f: &mut u32, b: u32| if on { *f |= b } else { *f &= !b };
                match *what {
                    "name" => {
                        c.claim.name = value.to_string();
                        if let Some(t) = defined_kind
                            && c.claim.values.is_empty()
                        {
                            c.claim.kind = t;
                            if t != ClaimType::Text {
                                c.claim.flags &= !claim::CASE_SENSITIVE;
                            }
                        }
                    }
                    "kind" => {
                        if let Some(t) = ClaimType::from_key(value) {
                            c.claim.kind = t;
                            if t != ClaimType::Text {
                                c.claim.flags &= !claim::CASE_SENSITIVE;
                            }
                        }
                    }
                    "vals" => c.claim.values = resolved,
                    "cs" => bit(&mut c.claim.flags, claim::CASE_SENSITIVE),
                    "deny" => bit(&mut c.claim.flags, claim::DENY_ONLY),
                    "off" => bit(&mut c.claim.flags, claim::DISABLED),
                    "inherit" => c.inherit = on,
                    _ => {}
                }
            });
        }
        ["cap", id, "inherit"] if sacl => {
            let Ok(k) = id.parse::<u32>() else { return };
            e.edit(|s, _, _, _| {
                if let Some(p) = s.policies.iter_mut().find(|p| p.id == k && !p.inherited) {
                    p.inherit = on;
                }
            });
        }
        ["eff", "who"] => {
            e.eff_who = value.parse().ok();
            e.look_up();
        }
        ["eff", "part"] => e.eff_part = guid_parse(value),
        ["c", key, path, what] => {
            let (Some(of), Some(path)) = (CondOf::parse(key), parse_path(path)) else { return };
            if !e.may_cond(of) || *what == "add" {
                return;
            }
            let value = value.to_string();
            let what = what.to_string();
            e.change_cond(of, |root| {
                let Some(n) = root.at_mut(&path) else { return };
                match (n, what.as_str()) {
                    (Node::Group(mode, _), "mode") => {
                        if let Some(m) = Mode::from_key(&value) {
                            *mode = m;
                        }
                    }
                    (Node::Claim { src, .. }, "src") => {
                        if let Some(s) = Src::from_word(&value) {
                            *src = s;
                        }
                    }
                    (Node::Claim { name, .. }, "name") => *name = value.clone(),
                    (Node::Claim { op, .. }, "op") => {
                        if let Some(o) = Op::from_key(&value) {
                            *op = o;
                        }
                    }
                    (Node::Claim { val, .. }, "val") => match val {
                        Val::Claim(_, n) => *n = value.clone(),
                        Val::Value(v) => *v = value.clone(),
                    },
                    (Node::Claim { val, .. }, "vsrc") => {
                        *val = match Src::from_word(&value) {
                            Some(s) => Val::Claim(s, if let Val::Claim(_, n) = val { n.clone() } else { String::new() }),
                            None => Val::Value(String::new()),
                        }
                    }
                    (Node::Member { device, sids, .. }, "dev") => {
                        let d = value == "1";
                        if *device != d {
                            *device = d;
                            sids.clear();
                        }
                    }
                    (Node::Member { op, .. }, "mop") => {
                        if let Some(o) = MemberOp::from_key(&value) {
                            *op = o;
                        }
                    }
                    _ => {}
                }
            });
        }
        _ => {}
    }
}

/// Where a scope picker leaves a rule: the place chosen, keeping "one
/// level down" where the place still passes things on; or that box.
fn new_scope(old: u8, rest: &[&str], value: &str) -> u8 {
    if rest.first() == Some(&"np") {
        return (old & !NP) | if value.is_empty() { 0 } else { NP };
    }
    match value.parse::<u8>() {
        Ok(f) => f | if passes(f) { old & NP } else { 0 },
        Err(_) => old,
    }
}
