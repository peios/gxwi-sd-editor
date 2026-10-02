//! gxwi-sd-editor — a security descriptor editor for GXWI desktops: a dialog
//! of its own, opened by a program that wants a descriptor edited, which
//! says what the object is and applies what comes back (the library, and
//! PSPU, set out how the two speak).
//!
//! The dialog shows the object's owner, and everyone its access list names.
//! For whoever is picked it has a box for each of the general rights the
//! program named, allowed and denied (`model`). What is inherited is shown
//! greyed. Add puts someone else in the list, by name, and Remove takes away
//! what was made here for whoever is picked. Apply sends the program the
//! descriptor as it stands, OK does that and closes once it has been applied,
//! and Cancel, or closing the dialog, sends nothing more.

use std::io::{BufRead, Write};
use std::sync::Arc;

use gxwi_sd_editor::{Can, FromEditor, Object, Request, ToEditor, line};
use libgxwi::{App, Closer, Facts, Fields, Live, Value, escape};
use peios::security::Sid;

mod model;
mod names;

use model::{Descriptor, Rules, Tick, Way};
use names::Names;

// What this program looks like on its dialog's strip. The icon itself is
// `gxwi-sd-editor.svg`, installed as the base theme's.
libgxwi::icon!(b"dev.peios.gxwi-sd-editor");

/// What is being asked of the person before anything more is done.
#[derive(Clone, Copy, PartialEq)]
enum Asking {
    /// Whom to add, typed.
    Add,
    /// Who the owner is to be, typed.
    Owner,
}

/// Where the descriptor is with the program.
#[derive(Clone, Copy, PartialEq)]
enum Sending {
    /// Nothing is waiting on the program.
    No,
    /// Sent, and waiting to hear that it was applied, and then to close or
    /// not.
    Yes { then_close: bool },
}

struct Editor {
    object: Object,
    rules: Rules,
    can: Can,
    descriptor: Descriptor,
    names: Names,
    /// Who is listed: everyone the access list names, and whoever has been
    /// added since, until they are removed.
    listed: Vec<Sid>,
    picked: Option<Sid>,
    asking: Option<Asking>,
    /// What has changed since the program last applied it: the owner, the
    /// access list.
    changed: (bool, bool),
    sending: Sending,
    /// What went wrong with the last thing asked, for the person to read.
    trouble: Option<String>,
    /// What went wrong with what was typed, said by the field.
    wrong: Option<String>,
    /// What lets the dialog go, once it is on the desktop.
    closer: Option<Closer>,
}

impl Editor {
    fn new(request: Request, mut names: Names) -> Result<Editor, String> {
        let descriptor = Descriptor::parse(&request.sd)?;
        let listed = descriptor.principals();
        for sid in listed.iter().chain(&descriptor.owner) {
            names.learn(sid);
        }
        let general = request.rights.into_iter().filter(|right| right.general).collect();
        Ok(Editor {
            object: request.object.clone(),
            rules: Rules { general, generic: request.generic, container: request.object.container },
            can: request.can,
            picked: listed.first().copied(),
            listed,
            descriptor,
            names,
            asking: None,
            changed: (false, false),
            sending: Sending::No,
            trouble: None,
            wrong: None,
            closer: None,
        })
    }

    /// Sends the program the descriptor as it stands, if anything changed.
    /// Whether anything was sent.
    fn send(&mut self, then_close: bool) -> bool {
        if self.sending != Sending::No || self.changed == (false, false) {
            return false;
        }
        let sd = match self.descriptor.build() {
            Ok(sd) => sd,
            Err(why) => {
                self.trouble = Some(why);
                return false;
            }
        };
        let said = line(&FromEditor::Apply { sd, parts: model::parts(self.changed.0, self.changed.1) });
        let mut out = std::io::stdout().lock();
        if out.write_all(said.as_bytes()).and_then(|()| out.flush()).is_err() {
            self.trouble = Some("The program that opened this has gone, and nothing can be applied.".into());
            return false;
        }
        self.sending = Sending::Yes { then_close };
        true
    }

    /// What the program answered. Whether the dialog is done with.
    fn answered(&mut self, answer: ToEditor) -> bool {
        let Sending::Yes { then_close } = std::mem::replace(&mut self.sending, Sending::No) else { return false };
        match answer {
            ToEditor::Applied => {
                self.changed = (false, false);
                self.trouble = None;
                then_close
            }
            ToEditor::Failed { why } => {
                self.trouble = Some(format!("This could not be applied: {why}"));
                false
            }
        }
    }

    fn close(&self) {
        if let Some(closer) = &self.closer {
            closer.close();
        }
    }

    fn row(&self, sid: &Sid) -> String {
        let name = self.names.of(sid);
        // Under the name, the SID it stands for, and whether everything
        // they have is inherited, with nothing made here.
        let theirs: Vec<_> = self.descriptor.dacl.iter().flatten().filter(|entry| entry.sid == *sid).collect();
        let mut note = Vec::new();
        if self.names.named(sid) {
            note.push(sid.to_string());
        }
        if !theirs.is_empty() && theirs.iter().all(|entry| entry.inherited()) {
            note.push("inherited".into());
        }
        format!(
            "<li><button type=\"button\" class=\"who\" fx-click=\"pick\" fx-value-sid=\"{sid}\" role=\"option\" aria-selected=\"{picked}\">\
             <span class=\"name\">{name}</span><small>{note}</small></button></li>",
            note = escape(&note.join(" · ")),
            sid = escape(&sid.to_string()),
            picked = self.picked == Some(*sid),
            name = escape(&name),
        )
    }

    fn boxes(&self) -> String {
        let Some(sid) = self.picked else {
            return "<p class=\"none\">Nobody is picked. Pick someone above, or add someone.</p>".into();
        };
        let shown = self.rules.shown(&self.descriptor, &sid);
        let tick = |tick: Tick, which: usize, way: &str, name: &str| {
            let (checked, disabled, class) = match tick {
                Tick::No => ("false", "", ""),
                Tick::Yes => ("true", "", ""),
                Tick::Inherited => ("true", " disabled", " class=\"inherited\""),
            };
            format!(
                "<td><button type=\"button\" role=\"checkbox\" aria-checked=\"{checked}\"{class}{disabled} fx-click=\"tick\" fx-value-right=\"{which}\" fx-value-way=\"{way}\" \
                 aria-label=\"{way_word} {name}\"></button></td>",
                way_word = if way == "allow" { "Allow" } else { "Deny" },
            )
        };
        let rows: String = self
            .rules
            .general
            .iter()
            .zip(&shown.rights)
            .enumerate()
            .map(|(which, (right, (allowed, denied)))| {
                let name = escape(&right.name);
                format!("<tr><th scope=\"row\">{name}</th>{}{}</tr>", tick(*allowed, which, "allow", &name), tick(*denied, which, "deny", &name))
            })
            .collect();
        let special = if shown.special != (false, false) {
            let mark = |on: bool| format!("<td><span role=\"checkbox\" aria-checked=\"{on}\" aria-disabled=\"true\" class=\"special\"></span></td>");
            format!("<tr class=\"special\"><th scope=\"row\">Special</th>{}{}</tr>", mark(shown.special.0), mark(shown.special.1))
        } else {
            String::new()
        };
        let greyed = if shown.rights.iter().any(|(allowed, denied)| *allowed == Tick::Inherited || *denied == Tick::Inherited) {
            "<p class=\"note\">Greyed ticks are inherited from the folder this is in, and are changed there.</p>"
        } else {
            ""
        };
        let special_note = if shown.special != (false, false) {
            "<p class=\"note\">Special is more than these boxes say, and is kept as it is.</p>"
        } else {
            ""
        };
        format!(
            "<table class=\"rights\"><caption>What {name} can do</caption>\
             <thead><tr><th></th><th scope=\"col\">Allow</th><th scope=\"col\">Deny</th></tr></thead>\
             <tbody>{rows}{special}</tbody></table>{greyed}{special_note}",
            name = escape(&self.names.of(&sid)),
        )
    }

    /// A field for a name, where it is asked for.
    fn field(&self, asking: Asking) -> String {
        let (event, label, button) = match asking {
            Asking::Add => ("added", "The name of a user or group to add", "Add"),
            Asking::Owner => ("owned", "The name of the new owner", "Change"),
        };
        let wrong = self.wrong.as_ref().map(|why| format!("<p class=\"wrong\" id=\"wrong\">{}</p>", escape(why))).unwrap_or_default();
        format!(
            "<form class=\"naming\" fx-submit=\"{event}\"><input name=\"who\" fx-autofocus autocomplete=\"off\" spellcheck=\"false\" \
             aria-label=\"{label}\" placeholder=\"Name, such as Everyone or jack\"{described}>\
             <button type=\"submit\">{button}</button><button type=\"button\" fx-click=\"keep\">Cancel</button>{wrong}</form>",
            described = if wrong.is_empty() { "" } else { " aria-describedby=\"wrong\" aria-invalid=\"true\"" },
        )
    }
}

impl Live for Editor {
    fn render(&self, _: &Facts) -> String {
        let busy = self.sending != Sending::No;
        let owner = match self.descriptor.owner {
            Some(owner) => escape(&self.names.of(&owner)),
            None => "nobody".into(),
        };
        let change = if self.can.owner && self.asking != Some(Asking::Owner) {
            "<button type=\"button\" fx-click=\"change-owner\">Change…</button>"
        } else {
            ""
        };
        let owning = if self.asking == Some(Asking::Owner) { self.field(Asking::Owner) } else { String::new() };
        let listed: String = self.listed.iter().map(|sid| self.row(sid)).collect();
        let empty = match &self.descriptor.dacl {
            None => "<p class=\"note\">There is no access list, so anyone can do anything with this. Ticking a box makes one.</p>",
            Some(entries) if entries.is_empty() && self.listed.is_empty() => "<p class=\"note\">The access list is empty, so nobody but its owner can change who can use this.</p>",
            _ => "",
        };
        let adding = if self.asking == Some(Asking::Add) { self.field(Asking::Add) } else { String::new() };
        let removable = self.picked.is_some_and(|sid| self.descriptor.dacl.iter().flatten().any(|entry| entry.sid == sid && !entry.inherited()) || !self.descriptor.principals().contains(&sid));
        let trouble = self.trouble.as_ref().map(|why| format!("<p class=\"trouble\" role=\"alert\">{}</p>", escape(why))).unwrap_or_default();
        let status = if busy { "<span class=\"status\" role=\"status\">Applying…</span>" } else { "<span class=\"status\" role=\"status\"></span>" };
        let unchanged = self.changed == (false, false);
        // The keys for answering what is asked, while something is.
        let keys = if self.asking.is_some() {
            "<button type=\"button\" fx-key=\"Escape\" fx-click=\"keep\"></button>"
        } else {
            "<button type=\"button\" fx-key=\"Escape\" fx-click=\"cancel\"></button>"
        };
        format!(
            "<div hidden>{keys}</div>\
             <div class=\"editor\" fx-fit>\
             <header><h1>{name}</h1><p>{kind}</p></header>\
             <section class=\"owner\"><span>Owner</span><strong>{owner}</strong>{change}</section>{owning}\
             <section class=\"people\"><h2 id=\"people\">Users and groups</h2>\
             <ul class=\"listed\" role=\"listbox\" aria-labelledby=\"people\">{listed}</ul>{empty}{adding}\
             <div class=\"under\"><button type=\"button\" fx-click=\"add\"{adding_now}>Add…</button>\
             <button type=\"button\" fx-click=\"remove\"{unremovable}>Remove</button></div></section>\
             <section class=\"boxes\">{boxes}</section>\
             {trouble}\
             <footer>{status}\
             <button type=\"button\" class=\"primary\" fx-click=\"ok\"{busy_attr}>OK</button>\
             <button type=\"button\" fx-click=\"cancel\">Cancel</button>\
             <button type=\"button\" fx-click=\"apply\"{apply_off}>Apply</button></footer>\
             </div>",
            name = escape(&self.object.name),
            kind = escape(&self.object.kind),
            adding_now = if self.asking == Some(Asking::Add) { " disabled" } else { "" },
            unremovable = if removable { "" } else { " disabled" },
            boxes = self.boxes(),
            busy_attr = if busy { " disabled" } else { "" },
            apply_off = if busy || unchanged { " disabled" } else { "" },
        )
    }

    fn event(&mut self, name: &str, value: &Value, fields: &mut Fields) {
        if !matches!(name, "pick") {
            self.trouble = None;
        }
        // While the program has the descriptor, it is as it was sent.
        let busy = self.sending != Sending::No;
        match name {
            "pick" => {
                if let Some(sid) = value["sid"].as_str().and_then(|sid| sid.parse::<Sid>().ok()).filter(|sid| self.listed.contains(sid)) {
                    self.picked = Some(sid);
                }
            }
            "tick" if !busy => {
                let (Some(sid), Some(which)) = (self.picked, value["right"].as_str().and_then(|which| which.parse::<usize>().ok())) else { return };
                let way = if value["way"].as_str() == Some("deny") { Way::Deny } else { Way::Allow };
                let shown = self.rules.shown(&self.descriptor, &sid);
                let Some(&(allowed, denied)) = shown.rights.get(which) else { return };
                let now = if way == Way::Allow { allowed } else { denied };
                if self.rules.tick(&mut self.descriptor, &sid, which, way, now != Tick::Yes) {
                    self.changed.1 = true;
                }
            }
            "add" => {
                fields.set("who", "");
                self.wrong = None;
                self.asking = Some(Asking::Add);
            }
            "change-owner" if self.can.owner => {
                fields.set("who", "");
                self.wrong = None;
                self.asking = Some(Asking::Owner);
            }
            "added" | "owned" if !busy => {
                let wanted = if name == "added" { Asking::Add } else { Asking::Owner };
                if self.asking != Some(wanted) {
                    return;
                }
                match self.names.find(fields.get("who")) {
                    Ok(sid) => {
                        self.asking = None;
                        self.wrong = None;
                        if wanted == Asking::Add {
                            if !self.listed.contains(&sid) {
                                self.listed.push(sid);
                            }
                            self.picked = Some(sid);
                        } else if self.descriptor.owner != Some(sid) {
                            self.descriptor.owner = Some(sid);
                            self.changed.0 = true;
                        }
                    }
                    Err(why) => self.wrong = Some(why),
                }
            }
            "keep" => {
                self.asking = None;
                self.wrong = None;
            }
            "remove" if !busy => {
                let Some(sid) = self.picked else { return };
                if self.rules.remove(&mut self.descriptor, &sid) {
                    self.changed.1 = true;
                }
                // Someone who still inherits something stays listed.
                if !self.descriptor.principals().contains(&sid) {
                    let at = self.listed.iter().position(|listed| *listed == sid).unwrap_or(0);
                    self.listed.retain(|listed| *listed != sid);
                    self.picked = self.listed.get(at.min(self.listed.len().saturating_sub(1))).copied();
                }
            }
            "apply" => {
                self.send(false);
            }
            "ok" => {
                if !busy && !self.send(true) && self.changed == (false, false) && self.trouble.is_none() {
                    self.close();
                }
            }
            "cancel" => self.close(),
            _ => {}
        }
    }
}

/// The request, from the first line of the input.
fn request() -> Result<Request, String> {
    let mut first = String::new();
    std::io::stdin().lock().read_line(&mut first).map_err(|e| format!("the request could not be read: {e}"))?;
    if first.trim().is_empty() {
        return Err("no request: it is opened by a program, which says what to edit on its first line (see gxwi-sd-editor(1))".into());
    }
    serde_json::from_str(&first).map_err(|e| format!("the request is not one: {e}"))
}

fn main() {
    // Gone with whatever opened it, however that went.
    // SAFETY: prctl with these arguments only sets a signal for later.
    unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) };
    if unsafe { libc::getppid() } == 1 {
        std::process::exit(0);
    }
    let request = request().unwrap_or_else(|why| die(&why));
    let title = format!("Permissions for {}", request.object.name);
    let editor = Editor::new(request, Names::new()).unwrap_or_else(|why| die(&why));
    let mut app = App::connect().unwrap_or_else(|e| die(&format!("no desktop to open on: {e}")));
    app.stylesheet("/editor.css", include_str!("editor.css"));
    let dialog = app.dialog(&title, editor);
    let closer = dialog.closer();
    dialog.update(|editor, _| editor.closer = Some(closer));
    // The program's answers, and its going.
    let heard = Arc::clone(&dialog);
    std::thread::spawn(move || {
        for said in std::io::stdin().lock().lines() {
            let Ok(said) = said else { break };
            let Ok(answer) = serde_json::from_str::<ToEditor>(&said) else { continue };
            let mut done = false;
            heard.update(|editor, _| done = editor.answered(answer));
            if done {
                heard.close();
            }
        }
        // Whoever opened it has gone: so does the dialog.
        std::process::exit(0);
    });
    if let Err(e) = app.run() {
        die(&e.to_string());
    }
}

fn die(why: &str) -> ! {
    eprintln!("gxwi-sd-editor: {why}");
    std::process::exit(1);
}
