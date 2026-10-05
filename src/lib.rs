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
//! the rest is as it was read. The integrity label is a part of its own,
//! sent only to a program that said it can apply one (`can.label`), and
//! never with the SACL, which carries the label when it is sent. A descriptor is sent whole and only when the
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
    if parts.contains(&Part::Label) && !parts.contains(&Part::Sacl) {
        // The label from what was edited, and the rest of the SACL as it is.
        use peios::security::{Ace, AceType, AclBuilder};
        let mut acl = AclBuilder::new();
        let label = |ace: &peios::security::AceView<'_>| ace.ace_type() == AceType::SystemMandatoryLabel;
        let mut any = false;
        for (sacl, keep_labels) in [(current.sacl(), false), (edited.sacl(), true)] {
            for ace in sacl.iter().flat_map(|sacl| sacl.iter().collect::<Vec<_>>()) {
                if label(&ace) != keep_labels {
                    continue;
                }
                let sid = ace.sid().ok_or("its audit list has an entry with nobody in it")?;
                acl.add(&Ace {
                    ace_type: ace.ace_type(),
                    flags: ace.flags(),
                    mask: ace.mask(),
                    sid,
                    object_type: ace.object_type(),
                    inherited_object_type: ace.inherited_object_type(),
                    app_data: ace.app_data(),
                });
                any = true;
            }
        }
        if any || current.sacl().is_some() {
            sd.sacl(&acl.build().map_err(|e| format!("its audit list could not be made ({e})"))?);
        }
    } else if let Some(sacl) = from(Part::Sacl).sacl() {
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
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Request {
    pub object: Object,
    /// The descriptor as it is now: the owner, the group and the access list,
    /// and the rest if the program could read it.
    #[serde(with = "base64_bytes")]
    pub sd: Vec<u8>,
    /// Which parts `sd` holds as they are: some of owner, group, dacl, sacl
    /// and label. A SACL that holds only the label, because that was all the
    /// program could read, is `label` without `sacl`. Left out, it is
    /// everything `sd` has.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read: Option<Vec<Part>>,
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
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
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
    /// What it is in, which is what its inherited entries come from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<Parent>,
    /// Its parts that rules can be made for one at a time, as an account's
    /// sign-in details are: object types (PCDS §5.4).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parts: Vec<ObjectPart>,
    /// On a container of typed things, the kinds of thing it holds, which a
    /// rule can be passed on to alone: inherited object types.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kinds: Vec<ChildKind>,
}

/// What an object is in.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Parent {
    /// What it is called where the person knows it: `/srv`.
    pub name: String,
    /// Its descriptor, if the program could read it: what is passed on from
    /// it is worked out from this when inheriting is turned back on, since
    /// that takes nothing back from it by itself.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "base64_option")]
    pub sd: Option<Vec<u8>>,
}

/// A part of an object, by its object type.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ObjectPart {
    /// The GUID, as it is written: `bf967aba-0de6-11d0-a285-00aa003049e2`.
    pub guid: String,
    pub name: String,
    pub kind: PartKind,
    /// The set it is in, by the set's GUID, for a property.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub set: Option<String>,
}

/// What a part is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PartKind {
    /// A set of properties, which a rule for it covers all of.
    Set,
    Property,
    /// An action, such as resetting a password.
    Right,
}

/// A kind of thing a container holds.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ChildKind {
    pub guid: String,
    pub name: String,
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
    /// Whether it can change the integrity label by itself, which takes the
    /// right to change the owner rather than the SACL's: it is then sent
    /// the `label` part. Left out, it cannot, and is never sent it.
    #[serde(default)]
    pub label: bool,
    /// Why it cannot change what it cannot, for the person to read: "You
    /// may not change this service's definition."
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

impl Default for Can {
    fn default() -> Can {
        Can { dacl: true, owner: false, audit: false, label: false, why: None }
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
    /// The integrity label alone, in the SACL, applied as KACS applies a
    /// label (LABEL_SECURITY_INFORMATION): the rest of the SACL stays.
    Label,
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

/// Bytes that may be left out, as base64 text.
mod base64_option {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Option<Vec<u8>>, to: S) -> Result<S::Ok, S::Error> {
        match bytes {
            Some(bytes) => super::base64_bytes::serialize(bytes, to),
            None => to.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(from: D) -> Result<Option<Vec<u8>>, D::Error> {
        use base64::Engine;
        match Option::<String>::deserialize(from)? {
            Some(text) => base64::engine::general_purpose::STANDARD.decode(text).map(Some).map_err(serde::de::Error::custom),
            None => Ok(None),
        }
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

    #[cfg(feature = "splice")]
    #[test]
    fn a_label_alone_takes_the_label_and_keeps_the_rest_of_the_sacl() {
        use peios::security::sddl;
        let bytes = |text: &str| sddl::parse(text).unwrap().as_bytes().to_vec();
        let now = bytes("O:SYG:SYD:(A;;0xf;;;SY)S:(ML;;NW;;;ME)(AU;FA;0x1;;;WD)");
        let edited = bytes("O:SYG:SYD:(A;;0xf;;;SY)S:(ML;;NWNR;;;LW)(AU;SA;0x2;;;WD)");
        let applied = sddl::format(&splice(&now, &edited, &[Part::Label]).unwrap()).unwrap();
        assert!(applied.contains("(AU;FA;0x1;;;WD)") && applied.contains("(ML;;NWNR;;;LW)"), "{applied}");
        assert!(!applied.contains("SA;0x2") && !applied.contains(";ME)"), "{applied}");
        // With the SACL as well, the SACL is what goes, label and all.
        let whole = sddl::format(&splice(&now, &edited, &[Part::Sacl, Part::Label]).unwrap()).unwrap();
        assert!(whole.contains("(AU;SA;0x2;;;WD)"), "{whole}");
    }

    fn request() -> Request {
        Request {
            object: Object { name: "notes.txt".into(), kind: "File".into(), ..Object::default() },
            sd: vec![1, 0, 4, 128],
            rights: vec![Right { name: "Read".into(), mask: 0x0012_0089, general: true }],
            generic: Generic { read: 1, write: 2, execute: 4, all: 8 },
            can: Can { owner: true, ..Can::default() },
            ..Request::default()
        }
    }

    #[test]
    fn what_the_redesign_adds_crosses_and_is_left_out_unsaid() {
        let mut full = request();
        full.read = Some(vec![Part::Owner, Part::Group, Part::Dacl, Part::Label]);
        full.can.label = true;
        full.object.parent = Some(Parent { name: "/srv".into(), sd: Some(vec![1, 2]) });
        full.object.parts = vec![ObjectPart { guid: "77b5b886-944a-11d1-aebd-0000f80367c1".into(), name: "Personal information".into(), kind: PartKind::Set, set: None }];
        full.object.kinds = vec![ChildKind { guid: "bf967aba-0de6-11d0-a285-00aa003049e2".into(), name: "Accounts".into() }];
        let said = line(&full);
        assert!(said.contains("\"parent\":{\"name\":\"/srv\",\"sd\":\"AQI=\"}") && said.contains("\"read\":[\"owner\",\"group\",\"dacl\",\"label\"]"), "{said}");
        assert_eq!(serde_json::from_str::<Request>(&said).unwrap(), full);
        let plain = line(&request());
        assert!(!plain.contains("parent") && !plain.contains("parts") && !plain.contains("kinds") && !plain.contains("\"read\":["), "{plain}");
        let bare: Object = serde_json::from_str(r#"{"name":"x","kind":"Folder","parent":{"name":"/"}}"#).unwrap();
        assert_eq!(bare.parent, Some(Parent { name: "/".into(), sd: None }));
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
        assert_eq!((bare.object.container, &bare.can), (false, &Can { dacl: true, owner: false, audit: false, label: false, why: None }));
        assert!(!said.contains("children"), "a container of everything is the default, and goes unsaid");
        let key: Object = serde_json::from_str(r#"{"name":"sshd","kind":"Registry key","container":true,"children":"containers"}"#).unwrap();
        assert_eq!(key.children, Children::Containers);
        let older: Request = serde_json::from_str(&said.replace("\"can\":{", "\"can\":{\"x\":1,").replace("\"dacl\":true,", "")).unwrap();
        assert!(older.can.dacl && older.can.owner);
        // One that may only look says so, and why.
        let looking = Can { dacl: false, why: Some("You may not change it.".into()), ..Can::default() };
        assert_eq!(line(&looking), "{\"dacl\":false,\"owner\":false,\"audit\":false,\"label\":false,\"why\":\"You may not change it.\"}\n");
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
