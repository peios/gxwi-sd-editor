//! Someone, as Effective Access needs them: their groups and their claims,
//! asked of authd (`Fields::GROUPS | Fields::CLAIMS`), and the groups every
//! token signed in carries besides.

use std::collections::HashMap;
use std::time::Duration;

use libauthd::claim::Values;
use libauthd::ident::{Fields, Key, Kind, Value};
use libauthd_client::ident::Ident;
use peios::security::{Sid, SidRef};

use crate::eff::Person;

/// Who `sid` is, with what they belong to and what is claimed of them.
pub fn person(sid: &Sid, name: String) -> Result<Person, String> {
    let ident = Ident::new().with_timeout(Duration::from_secs(2));
    let record = ident
        .lookup(Key::Sid(sid.as_bytes().to_vec()), Kind::Any, Fields::GROUPS.union(Fields::CLAIMS))
        .map_err(|e| format!("What {name} belongs to could not be found out: {e}."))?
        .ok_or_else(|| format!("authd doesn't know {name}."))?;
    let mut sids: Vec<Sid> = vec![*sid];
    let mut claims = HashMap::new();
    for value in &record.values {
        match value {
            Value::Groups(groups) => sids.extend(groups.iter().filter_map(|g| SidRef::from_bytes(&g.sid).map(SidRef::to_sid))),
            Value::Claims(list) => {
                for c in list {
                    let values: Vec<String> = match &c.values {
                        Values::Int64(v) => v.iter().map(i64::to_string).collect(),
                        Values::Uint64(v) => v.iter().map(u64::to_string).collect(),
                        Values::Boolean(v) => v.iter().map(|b| if *b { "1".into() } else { "0".into() }).collect(),
                        Values::String(v) => v.clone(),
                        Values::Sid(v) => v.iter().filter_map(|s| SidRef::from_bytes(s).map(|s| s.to_string())).collect(),
                        Values::Octet(_) => continue,
                    };
                    claims.insert(format!("user.{}", c.name.to_lowercase()), values);
                }
            }
            _ => {}
        }
    }
    // What every signed-in token carries.
    for well_known in ["S-1-1-0", "S-1-5-11"] {
        let s: Sid = well_known.parse().expect("a well-known SID");
        if !sids.contains(&s) {
            sids.push(s);
        }
    }
    Ok(Person { sid: *sid, name, sids, device: vec![], claims, integrity: 8192 })
}
