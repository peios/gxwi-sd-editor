//! The claims this machine defines: what an administrator has said each
//! claim is, for suggestions before anything has been used.
//!
//! They live at `Machine\Common\SecurityDescriptorBuilder\KnownClaims`, a
//! key a claim, named as conditions name it, `Source.Name` (`User.Department`,
//! `Resource.Classification`). Each may hold `Type`, the SDDL code of its
//! kind (TS, TI, TU, TB, TD or TX); `Values`, the values it takes, most
//! likely first; and `Description`, what it is for. Common is for protocols
//! that are stable but not in the Peios specifications, so any program that
//! builds descriptors may read them; the man page says the format.

use std::collections::BTreeMap;

use peios::registry::{Key, KeyAccess, OpenFlags, ValueType};

use crate::claim::ClaimType;

pub const KEY: &str = "Machine\\Common\\SecurityDescriptorBuilder\\KnownClaims";

/// One claim the machine defines.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Defined {
    pub kind: Option<ClaimType>,
    pub values: Vec<String>,
    pub description: String,
}

/// Every claim the machine defines, by `Source.Name`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Known(pub BTreeMap<String, Defined>);

impl Known {
    /// What the machine defines, or nothing where it cannot be read. A
    /// claim whose key cannot be read is left out.
    pub fn read() -> Known {
        let Ok(top) = Key::open(None, KEY, KeyAccess::ENUMERATE_SUB_KEYS, OpenFlags::empty()) else { return Known::default() };
        let mut out = BTreeMap::new();
        for sub in top.subkeys(None).flatten() {
            let name = String::from_utf8_lossy(&sub.name).into_owned();
            let Ok(key) = Key::open(Some(&top), &name, KeyAccess::QUERY_VALUE, OpenFlags::empty()) else { continue };
            let read = |value: &str| key.query_value(value.as_bytes(), None).ok();
            let text = |value: &str| read(value).filter(|v| v.ty == ValueType::SZ).map(|v| strings(&v.data).into_iter().next().unwrap_or_default());
            let defined = Defined {
                kind: text("Type").and_then(|t| ClaimType::from_sddl(t.trim())),
                values: read("Values").filter(|v| v.ty == ValueType::MULTI_SZ).map(|v| strings(&v.data)).unwrap_or_default(),
                description: text("Description").unwrap_or_default(),
            };
            out.insert(name, defined);
        }
        Known(out)
    }

    /// The claims defined for `source`, by name.
    pub fn names(&self, source: &str) -> Vec<(String, &Defined)> {
        let prefix = format!("{source}.");
        self.0.iter().filter_map(|(k, d)| Some((k.strip_prefix(&prefix)?.to_string(), d))).collect()
    }

    pub fn get(&self, claim: &str) -> Option<&Defined> {
        self.0.get(claim.trim())
    }
}

/// The strings of a REG_SZ or REG_MULTI_SZ, each ended by a NUL.
fn strings(data: &[u8]) -> Vec<String> {
    data.split(|b| *b == 0).filter(|s| !s.is_empty()).map(|s| String::from_utf8_lossy(s).into_owned()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_end_at_each_nul() {
        assert_eq!(strings(b"Finance\0Ops\0\0"), ["Finance", "Ops"]);
        assert_eq!(strings(b"Text"), ["Text"]);
    }

    #[test]
    fn names_are_by_source() {
        let mut k = Known::default();
        k.0.insert("User.Department".into(), Defined { kind: Some(ClaimType::Text), ..Default::default() });
        k.0.insert("Resource.Classification".into(), Defined::default());
        assert_eq!(k.names("User").iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(), ["Department"]);
    }
}
