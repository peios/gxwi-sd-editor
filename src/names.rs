//! Who a SID is, and which SID a name is.
//!
//! The well-known principals by the names the documentation gives them, as
//! `ls -l` shows them (peiosutils' sid_render), and everyone else by asking
//! the authority, authd, on its identity socket, which is the only thing
//! that can say. A connection a question, as peiosutils does it: authd
//! closes one left idle, and the editor may be open for an hour.

use std::collections::HashMap;
use std::io;
use std::os::unix::net::UnixStream;
use std::time::Duration;

use libauthd::ident::{self, Fields, Key, Kind, Outcome};
use libauthd::transport::{recv_message, send_message};
use peios::security::{Sid, SidRef};

/// How long the authority is given to answer.
const TIMEOUT: Duration = Duration::from_secs(2);

/// The well-known principals: the SID, and what it is called.
const WELL_KNOWN: &[(&str, &str)] = &[
    ("S-1-0-0", "Nobody"),
    ("S-1-1-0", "Everyone"),
    ("S-1-2-0", "Local"),
    ("S-1-2-1", "Console Logon"),
    ("S-1-3-0", "Creator Owner"),
    ("S-1-3-1", "Creator Group"),
    ("S-1-3-4", "Owner Rights"),
    ("S-1-5-2", "Network"),
    ("S-1-5-4", "Interactive"),
    ("S-1-5-6", "Service"),
    ("S-1-5-7", "Anonymous"),
    ("S-1-5-10", "Self"),
    ("S-1-5-11", "Authenticated Users"),
    ("S-1-5-18", "Local System"),
    ("S-1-5-19", "Local Service"),
    ("S-1-5-20", "Network Service"),
    ("S-1-5-32-544", "BUILTIN\\Administrators"),
    ("S-1-5-32-545", "BUILTIN\\Users"),
    ("S-1-5-32-546", "BUILTIN\\Guests"),
    ("S-1-5-32-551", "BUILTIN\\Backup Operators"),
];

/// Other names the well-known principals go by where a person types one:
/// how `sd` takes them, and authd's spellings.
const ALSO: &[(&str, &str)] = &[
    ("World", "S-1-1-0"),
    ("System", "S-1-5-18"),
    ("LocalSystem", "S-1-5-18"),
    ("AuthenticatedUsers", "S-1-5-11"),
    ("Authenticated", "S-1-5-11"),
    ("LocalService", "S-1-5-19"),
    ("NetworkService", "S-1-5-20"),
];

/// The names known so far, so that a render never waits on the authority.
pub struct Names {
    known: HashMap<Sid, String>,
    /// Whom to ask about the rest. `None` asks nobody, for tests.
    ask: Option<fn(Key) -> io::Result<Option<(Sid, String)>>>,
}

impl Names {
    pub fn new() -> Names {
        Names { known: HashMap::new(), ask: Some(ask) }
    }

    #[cfg(test)]
    pub fn offline() -> Names {
        Names { known: HashMap::new(), ask: None }
    }

    /// Finds out what `sid` is called, to be said by [`Names::of`].
    pub fn learn(&mut self, sid: &SidRef) {
        let owned = sid.to_sid();
        if self.known.contains_key(&owned) {
            return;
        }
        let raw = sid.to_string();
        let name = match WELL_KNOWN.iter().find(|(known, _)| *known == raw) {
            Some((_, name)) => Some(name.to_string()),
            None => self.ask.and_then(|ask| ask(Key::Sid(sid.as_bytes().to_vec())).ok().flatten()).map(|(_, name)| name),
        };
        self.known.insert(owned, name.unwrap_or(raw));
    }

    /// What `sid` is called, as far as it has been learnt; its SID otherwise.
    pub fn of(&self, sid: &SidRef) -> String {
        self.known.get(&sid.to_sid()).cloned().unwrap_or_else(|| sid.to_string())
    }

    /// Whether `sid` has a name, and not just its SID to go by.
    pub fn named(&self, sid: &SidRef) -> bool {
        self.known.get(&sid.to_sid()).is_some_and(|name| *name != sid.to_string())
    }

    /// The principal `typed` names: a well-known one by any of its names,
    /// with or without `BUILTIN\`, a SID or one of SDDL's two letters, or
    /// whoever the authority says it is. Why not, for the person to read.
    pub fn find(&mut self, typed: &str) -> Result<Sid, String> {
        let typed = typed.trim();
        if typed.is_empty() {
            return Err("Type the name of a user or a group.".into());
        }
        let bare = |name: &str| name.strip_prefix("BUILTIN\\").unwrap_or(name).to_string();
        let well_known = WELL_KNOWN
            .iter()
            .map(|&(sid, name)| (name, sid))
            .chain(ALSO.iter().copied())
            .find(|(name, _)| name.eq_ignore_ascii_case(typed) || bare(name).eq_ignore_ascii_case(&bare(typed)))
            .map(|(_, sid)| sid);
        if let Some(sid) = well_known.and_then(|sid| sid.parse::<Sid>().ok()) {
            self.learn(&sid);
            return Ok(sid);
        }
        // A SID as it is written, or as SDDL abbreviates it.
        if typed.starts_with("S-") || (typed.len() == 2 && typed.chars().all(|c| c.is_ascii_uppercase())) {
            if let Ok(sid) = typed.parse::<Sid>() {
                self.learn(&sid);
                return Ok(sid);
            }
        }
        let Some(ask) = self.ask else { return Err(format!("There is nobody called {typed}.")) };
        match ask(Key::Name(typed.into())) {
            Ok(Some((sid, name))) => {
                self.known.insert(sid, name);
                Ok(sid)
            }
            Ok(None) => Err(format!("There is nobody called {typed}.")),
            Err(e) => Err(format!("Who {typed} is could not be found out: {e}.")),
        }
    }
}

/// One question to the authority. `Ok(None)` is its word that there is no
/// such principal.
fn ask(key: Key) -> io::Result<Option<(Sid, String)>> {
    let stream = UnixStream::connect(libauthd::IDENT_SOCKET_PATH)?;
    stream.set_read_timeout(Some(TIMEOUT))?;
    stream.set_write_timeout(Some(TIMEOUT))?;
    // The name and the SID are always answered: no more is asked, so that
    // nothing is withheld that was not needed.
    let request = ident::encode_lookup(&ident::Lookup { tag: 1, key, kind: Kind::Any, fields: Fields::empty() })
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    send_message(&stream, &request)?;
    let received = recv_message(&libauthd::wire::FRAMING, &stream)?;
    let reply = ident::decode_lookup_reply(received.expose()).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    match (reply.outcome, reply.record) {
        (Outcome::Found, Some(record)) => {
            let sid = SidRef::from_bytes(&record.sid).map(SidRef::to_sid).ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
            Ok(Some((sid, record.qualified_name)))
        }
        (Outcome::NotFound, _) => Ok(None),
        _ => Err(io::Error::other("the authority could not answer")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_well_known_are_known_by_any_of_their_names() {
        let mut names = Names::offline();
        for typed in ["Everyone", "everyone", "World", " Everyone ", "WD", "S-1-1-0"] {
            assert_eq!(names.find(typed).map(|sid| sid.to_string()), Ok("S-1-1-0".into()), "{typed}");
        }
        for typed in ["Administrators", "BUILTIN\\Administrators", "builtin\\administrators", "BA"] {
            assert_eq!(names.find(typed).map(|sid| sid.to_string()), Ok("S-1-5-32-544".into()), "{typed}");
        }
        assert_eq!(names.find("SYSTEM").map(|sid| sid.to_string()), Ok("S-1-5-18".into()));
        let admins: Sid = "S-1-5-32-544".parse().unwrap();
        assert_eq!(names.of(&admins), "BUILTIN\\Administrators");
        assert!(names.named(&admins));
    }

    #[test]
    fn what_cannot_be_found_is_said_and_a_sid_goes_by_its_number() {
        let mut names = Names::offline();
        assert_eq!(names.find("  "), Err("Type the name of a user or a group.".into()));
        assert_eq!(names.find("jack"), Err("There is nobody called jack.".into()));
        let someone: Sid = "S-1-5-21-1-2-3-1000".parse().unwrap();
        assert_eq!(names.find("S-1-5-21-1-2-3-1000"), Ok(someone));
        assert_eq!(names.of(&someone), "S-1-5-21-1-2-3-1000");
        assert!(!names.named(&someone));
    }
}
