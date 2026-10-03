//! gxwi-sd-editor: a security descriptor editor for GXWI desktops, and what a
//! program needs in order to open it.
//!
//! The editor is a program of its own, which a program that wants a
//! descriptor edited starts as a child of its own. The two speak over the
//! child's standard input and output, one JSON object a line. The editor
//! draws a dialog on the desktop the program is on, which it finds as any app
//! does, and edits a copy. The program does everything else: it reads the
//! descriptor, says what the object is called and what its rights are
//! called, and applies what comes back. It holds the object and the right to
//! change it, and the editor holds neither, so the editor serves files,
//! registry keys and services alike.
//!
//!   program → editor   the first line: a [`Request`]
//!   editor → program   { "type": "apply", "sd", "parts" }   on Apply or OK
//!   program → editor   { "type": "applied" }
//!                   or { "type": "failed", "why" }
//!
//! `sd` is a self-relative security descriptor's bytes, in base64, whichever
//! way it goes. What the editor sends is the whole of what it shows, and
//! `parts` are the parts of it that changed, which are the ones to apply:
//! the rest is as it was read. A descriptor is sent whole and only when the
//! person says so, never as they change it: one applied half way through can
//! take away the access needed to finish. A failure is shown in the dialog,
//! which stays open to be put right.
//!
//! The editor ends when the person closes it, and after OK once what it sent
//! has been applied, and its output closing is how the program knows. It
//! ends when its input closes as well, so it goes when the program does,
//! however the program ends.
//!
//! [`edit`] starts it and speaks for the program. This library has nothing of
//! GXWI's in it: with `default-features = false` it is the protocol alone.

use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};

use serde::{Deserialize, Serialize};

#[cfg(feature = "names")]
pub mod names;
#[cfg(feature = "registry")]
pub mod registry;

/// `edited`'s `parts`, and the rest of `current`: what applying only the
/// parts the person changed comes to, where a program keeps a descriptor
/// whole, as a registry value, rather than handing each part to whatever
/// keeps it. Why not, for the person to read.
#[cfg(feature = "splice")]
pub fn splice(current: &[u8], edited: &[u8], parts: &[Part]) -> Result<Vec<u8>, String> {
    use peios::security::{Control, SdBuilder, SdView};
    let current = SdView::parse(current).map_err(|e| format!("what it is now could not be read ({e})"))?;
    let edited = SdView::parse(edited).map_err(|e| format!("it is not a security descriptor ({e})"))?;
    let from = |part: Part| if parts.contains(&part) { &edited } else { &current };
    let mut sd = SdBuilder::new();
    if let Some(owner) = from(Part::Owner).owner() {
        sd.owner(owner);
    }
    if let Some(group) = from(Part::Group).group() {
        sd.group(group);
    }
    match from(Part::Dacl).dacl() {
        Some(dacl) => sd.dacl(&dacl.to_acl().map_err(|e| format!("its access list could not be made ({e})"))?),
        None => sd.dacl_grant_all(),
    };
    if let Some(sacl) = from(Part::Sacl).sacl() {
        sd.sacl(&sacl.to_acl().map_err(|e| format!("its audit list could not be made ({e})"))?);
    }
    let kept = (from(Part::Dacl).control() & (Control::DACL_PROTECTED | Control::DACL_AUTO_INHERITED))
        | (from(Part::Sacl).control() & (Control::SACL_PROTECTED | Control::SACL_AUTO_INHERITED));
    sd.control(kept, Control::empty());
    let sd = sd.build().map_err(|e| format!("it could not be made ({e})"))?;
    Ok(sd.as_bytes().to_vec())
}

/// Where the editor is installed.
pub const PROGRAM: &str = "/usr/bin/gxwi-sd-editor";

/// What the program tells the editor, as the first line of its input.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Request {
    pub object: Object,
    /// The descriptor as it is now: the owner, the group and the access list,
    /// and the rest if the program could read it.
    #[serde(with = "base64_bytes")]
    pub sd: Vec<u8>,
    /// What the object's rights are called. The `general` ones are what the
    /// person is shown and ticks, from the most to the least: "Full
    /// control", "Read". A mask that is more than they can say is shown as
    /// special.
    pub rights: Vec<Right>,
    /// What the generic rights are of this kind of object, for an entry
    /// that grants them.
    pub generic: Generic,
    /// What the program can change.
    #[serde(default)]
    pub can: Can,
}

/// The object whose descriptor it is.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Object {
    /// What it is called where the person found it: `notes.txt`.
    pub name: String,
    /// What kind of thing it is, for the person: "File", "Folder", "Service".
    pub kind: String,
    /// Whether things inside it inherit from it, as a folder's do. What is
    /// ticked for it then applies to it and everything in it.
    #[serde(default)]
    pub container: bool,
    /// What a container holds, which is what what is ticked for it is
    /// passed on to.
    #[serde(default, skip_serializing_if = "Children::is_all")]
    pub children: Children,
}

/// What a container holds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Children {
    /// Containers and other objects, as a folder holds folders and files.
    #[default]
    All,
    /// Containers alone, as a registry key holds keys and nothing else.
    Containers,
}

impl Children {
    fn is_all(&self) -> bool {
        *self == Children::All
    }
}

/// A right of the object's, by what it is called.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Right {
    pub name: String,
    pub mask: u32,
    #[serde(default)]
    pub general: bool,
}

/// The rights the generic ones stand for, on this kind of object.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Generic {
    pub read: u32,
    pub write: u32,
    pub execute: u32,
    pub all: u32,
}

/// Which parts of the descriptor the program can change. What it cannot is
/// shown all the same, and not offered to be changed.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Can {
    /// The access list. Left out, it can: a program could always change
    /// that, before it could say it could not.
    #[serde(default = "yes")]
    pub dacl: bool,
    #[serde(default)]
    pub owner: bool,
    #[serde(default)]
    pub audit: bool,
    /// Why it cannot change what it cannot, for the person to read: "You
    /// may not change this service's definition."
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

impl Default for Can {
    fn default() -> Can {
        Can { dacl: true, owner: false, audit: false, why: None }
    }
}

fn yes() -> bool {
    true
}

/// A part of a descriptor, as the program applies it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Part {
    Owner,
    Group,
    Dacl,
    Sacl,
}

/// What the editor tells the program.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FromEditor {
    Apply {
        #[serde(with = "base64_bytes")]
        sd: Vec<u8>,
        parts: Vec<Part>,
    },
}

/// What the program answers an `apply` with.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ToEditor {
    Applied,
    /// Why it could not be applied, for the person to read.
    Failed { why: String },
}

/// One line of the protocol: `message` as JSON, and the newline.
pub fn line(message: &impl Serialize) -> String {
    let mut line = serde_json::to_string(message).expect("the protocol's messages are all JSON");
    line.push('\n');
    line
}

/// Opens the editor at [`PROGRAM`] on `request`, which is [`edit_with`].
pub fn edit(
    request: &Request,
    apply: impl FnMut(&[u8], &[Part]) -> Result<(), String> + Send + 'static,
    done: impl FnOnce() + Send + 'static,
) -> io::Result<()> {
    edit_with(Path::new(PROGRAM), request, apply, done)
}

/// Starts `program` as the editor on `request`, and speaks for the caller on
/// a thread of its own: `apply` is given each descriptor the person applies
/// and the parts of it that changed, and what it returns is the editor's
/// answer, an `Err` saying why it could not be. `done` is called once, when
/// the editor has gone, however it went. The editor is the caller's child,
/// and goes when the caller does.
pub fn edit_with(
    program: &Path,
    request: &Request,
    mut apply: impl FnMut(&[u8], &[Part]) -> Result<(), String> + Send + 'static,
    done: impl FnOnce() + Send + 'static,
) -> io::Result<()> {
    let mut child = Command::new(program).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn()?;
    let (Some(mut input), Some(output)) = (child.stdin.take(), child.stdout.take()) else {
        return Err(io::Error::other("the editor was started without its input and output"));
    };
    if let Err(e) = input.write_all(line(request).as_bytes()).and_then(|()| input.flush()) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(e);
    }
    std::thread::spawn(move || {
        for said in BufReader::new(output).lines() {
            let Ok(said) = said else { break };
            // A line this does not know is not answered: a newer editor may
            // say more than this knows of.
            let Ok(FromEditor::Apply { sd, parts }) = serde_json::from_str(&said) else { continue };
            let answer = match apply(&sd, &parts) {
                Ok(()) => ToEditor::Applied,
                Err(why) => ToEditor::Failed { why },
            };
            if input.write_all(line(&answer).as_bytes()).and_then(|()| input.flush()).is_err() {
                break;
            }
        }
        drop(input);
        let _ = child.wait();
        done();
    });
    Ok(())
}

/// Bytes as base64 text, which is how a descriptor crosses in JSON.
mod base64_bytes {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], to: S) -> Result<S::Ok, S::Error> {
        to.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(from: D) -> Result<Vec<u8>, D::Error> {
        STANDARD.decode(String::deserialize(from)?).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "splice")]
    #[test]
    fn only_the_parts_changed_are_put_in() {
        use peios::security::{Control, SdView, sddl};
        let bytes = |text: &str| sddl::parse(text).unwrap().as_bytes().to_vec();
        let now = bytes("O:SYG:BAD:P(A;;0xf;;;SY)");
        let edited = bytes("O:BAG:SYD:(A;;0xf;;;SY)(A;;0x1;;;WD)");
        let applied = splice(&now, &edited, &[Part::Dacl]).unwrap();
        let view = SdView::parse(&applied).unwrap();
        assert_eq!(view.owner().unwrap().to_sid().to_string(), "S-1-5-18");
        assert_eq!(view.group().unwrap().to_sid().to_string(), "S-1-5-32-544");
        assert_eq!(view.dacl().unwrap().len(), 2);
        assert!(!view.control().contains(Control::DACL_PROTECTED), "protection goes with the access list it was on");
        assert_eq!(splice(&now, &edited, &[]).unwrap(), splice(&now, &now, &[Part::Dacl, Part::Owner]).unwrap());
        assert!(splice(&now, b"nonsense", &[Part::Dacl]).is_err());
    }

    fn request() -> Request {
        Request {
            object: Object { name: "notes.txt".into(), kind: "File".into(), container: false, children: Children::All },
            sd: vec![1, 0, 4, 128],
            rights: vec![Right { name: "Read".into(), mask: 0x0012_0089, general: true }],
            generic: Generic { read: 1, write: 2, execute: 4, all: 8 },
            can: Can { owner: true, ..Can::default() },
        }
    }

    #[test]
    fn a_request_crosses_as_one_line_and_comes_back_the_same() {
        let said = line(&request());
        assert!(said.ends_with('\n') && said.matches('\n').count() == 1);
        assert!(said.contains("\"sd\":\"AQAEgA==\""));
        assert_eq!(serde_json::from_str::<Request>(&said).unwrap(), request());
        // A program that leaves `can` out can change the access list and
        // nothing else, as before it could say otherwise.
        let bare = r#"{"object":{"name":"k","kind":"Key"},"sd":"","rights":[],"generic":{"read":0,"write":0,"execute":0,"all":0}}"#;
        let bare: Request = serde_json::from_str(bare).unwrap();
        assert_eq!((bare.object.container, &bare.can), (false, &Can { dacl: true, owner: false, audit: false, why: None }));
        assert!(!said.contains("children"), "a container of everything is the default, and goes unsaid");
        let key: Object = serde_json::from_str(r#"{"name":"sshd","kind":"Registry key","container":true,"children":"containers"}"#).unwrap();
        assert_eq!(key.children, Children::Containers);
        let older: Request = serde_json::from_str(&said.replace("\"can\":{", "\"can\":{\"x\":1,").replace("\"dacl\":true,", "")).unwrap();
        assert!(older.can.dacl && older.can.owner);
        // One that may only look says so, and why.
        let looking = Can { dacl: false, why: Some("You may not change it.".into()), ..Can::default() };
        assert_eq!(line(&looking), "{\"dacl\":false,\"owner\":false,\"audit\":false,\"why\":\"You may not change it.\"}\n");
        assert!(!line(&Can::default()).contains("why"));
    }

    #[test]
    fn the_answers_are_as_the_protocol_says() {
        let apply = FromEditor::Apply { sd: vec![0xff], parts: vec![Part::Owner, Part::Dacl] };
        assert_eq!(line(&apply), "{\"type\":\"apply\",\"sd\":\"/w==\",\"parts\":[\"owner\",\"dacl\"]}\n");
        assert_eq!(line(&ToEditor::Applied), "{\"type\":\"applied\"}\n");
        assert_eq!(line(&ToEditor::Failed { why: "no".into() }), "{\"type\":\"failed\",\"why\":\"no\"}\n");
        assert!(serde_json::from_str::<FromEditor>(r#"{"type":"apply","sd":"not base64!","parts":[]}"#).is_err());
    }

    #[test]
    fn edit_speaks_for_the_program_until_the_editor_goes() {
        // An editor that applies twice, says what it was answered, and goes.
        let dir = std::env::temp_dir().join(format!("gxwi-sd-editor-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let editor = dir.join("editor.sh");
        let heard = dir.join("heard");
        std::fs::write(
            &editor,
            format!(
                "#!/bin/sh\nread request\necho \"$request\" > {heard}\n\
                 echo '{{\"type\":\"apply\",\"sd\":\"AQI=\",\"parts\":[\"dacl\"]}}'\nread answer\necho \"$answer\" >> {heard}\n\
                 echo 'a line it does not know'\n\
                 echo '{{\"type\":\"apply\",\"sd\":\"AQI=\",\"parts\":[\"owner\"]}}'\nread answer\necho \"$answer\" >> {heard}\n",
                heard = heard.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&editor, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        let (tell, gone) = std::sync::mpsc::channel();
        let applied = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = applied.clone();
        edit_with(
            &editor,
            &request(),
            move |sd, parts| {
                seen.lock().unwrap().push((sd.to_vec(), parts.to_vec()));
                if parts == [Part::Owner] { Err("you are not allowed to".into()) } else { Ok(()) }
            },
            move || tell.send(()).unwrap(),
        )
        .unwrap();
        gone.recv_timeout(std::time::Duration::from_secs(10)).expect("done when the editor has gone");
        assert_eq!(*applied.lock().unwrap(), [(vec![1, 2], vec![Part::Dacl]), (vec![1, 2], vec![Part::Owner])]);
        let heard = std::fs::read_to_string(&heard).unwrap();
        let heard: Vec<&str> = heard.lines().collect();
        assert_eq!(serde_json::from_str::<Request>(heard[0]).unwrap(), request());
        assert_eq!(&heard[1..], ["{\"type\":\"applied\"}", "{\"type\":\"failed\",\"why\":\"you are not allowed to\"}"]);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
