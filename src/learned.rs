//! The claims rules on this machine have tested, and the values they were
//! tested for, most used first: suggestions for the next rule.
//!
//! They are the machine's, as claims are, so they live in its registry, at
//! `Machine\Common\SecurityDescriptorBuilder`, value `UsedClaims`, where
//! any program that builds descriptors may share them. They are learnt when
//! rules are applied, from what was applied only, so a typo is never
//! learnt. Whoever may read the key is offered them, and only whoever may
//! write it teaches them (Administrators and SYSTEM, as the machine hive's
//! descriptor passes down). The key is made by the package that ships it,
//! never here.

use std::collections::BTreeMap;

use peios::registry::{Key, KeyAccess, OpenFlags, ValueType};

pub const KEY: &str = "Machine\\Common\\SecurityDescriptorBuilder";
const NAME: &str = "UsedClaims";

/// One claim, as `Source.Name`: how often it was used, and each value.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Use {
    pub times: u32,
    pub values: BTreeMap<String, u32>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Learned {
    pub used: BTreeMap<String, Use>,
    /// Whether this program may teach it, and so forget it.
    pub writable: bool,
}

impl Learned {
    /// What the machine has learnt, or nothing where it cannot be read.
    pub fn read() -> Learned {
        let writable = Key::open(None, KEY, KeyAccess::SET_VALUE, OpenFlags::empty()).is_ok();
        let Ok(value) = Key::open(None, KEY, KeyAccess::QUERY_VALUE, OpenFlags::empty()).and_then(|key| key.query_value(NAME.as_bytes(), None)) else { return Learned { writable, ..Learned::default() } };
        if value.ty != ValueType::MULTI_SZ {
            return Learned { writable, ..Learned::default() };
        }
        Learned { writable, ..Learned::parse(&String::from_utf8_lossy(&value.data)) }
    }

    /// One claim a line: its name, how often, then each value and how
    /// often, with tabs between.
    fn parse(text: &str) -> Learned {
        let mut out = BTreeMap::new();
        for line in text.split('\0').filter(|l| !l.is_empty()) {
            let mut fields = line.split('\t');
            let (Some(name), Some(times)) = (fields.next(), fields.next().and_then(|t| t.parse().ok())) else { continue };
            let values = fields.filter_map(|f| f.rsplit_once('=')).filter_map(|(v, n)| Some((v.to_string(), n.parse().ok()?))).collect();
            out.insert(name.to_string(), Use { times, values });
        }
        Learned { used: out, writable: false }
    }

    fn lines(&self) -> Vec<String> {
        self.used
            .iter()
            .map(|(name, u)| {
                let mut line = format!("{name}\t{}", u.times);
                for (v, n) in &u.values {
                    line.push_str(&format!("\t{v}={n}"));
                }
                line
            })
            .collect()
    }

    /// Counts a claim being used, with the values it was tested for.
    pub fn learn(&mut self, name: &str, values: &[String]) {
        let name = name.trim();
        if name.is_empty() || name.contains(['\t', '\0']) {
            return;
        }
        let u = self.used.entry(name.to_string()).or_default();
        u.times += 1;
        for v in values.iter().filter(|v| !v.contains(['\t', '\0', '='])) {
            *u.values.entry(v.clone()).or_default() += 1;
        }
    }

    /// The claim names used from `source`, most used first.
    pub fn names(&self, source: &str) -> Vec<(String, u32)> {
        let prefix = format!("{source}.");
        let mut out: Vec<(String, u32)> = self.used.iter().filter_map(|(k, u)| Some((k.strip_prefix(&prefix)?.to_string(), u.times))).collect();
        out.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        out
    }

    /// The values a claim was tested for, most used first.
    pub fn values(&self, claim: &str) -> Vec<(String, u32)> {
        let mut out: Vec<(String, u32)> = self.used.get(claim.trim()).map(|u| u.values.iter().map(|(v, n)| (v.clone(), *n)).collect()).unwrap_or_default();
        out.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        out
    }

    /// Saves what has been learnt. Why not, which is nothing the person
    /// needs to hear: suggestions are a help.
    pub fn write(&self) -> Result<(), String> {
        let own = Key::open(None, KEY, KeyAccess::SET_VALUE, OpenFlags::empty()).map_err(|e| e.to_string())?;
        let mut bytes = Vec::new();
        for line in self.lines() {
            bytes.extend_from_slice(line.as_bytes());
            bytes.push(0);
        }
        bytes.push(0);
        own.set_value(NAME.as_bytes(), ValueType::MULTI_SZ, &bytes).call().map_err(|e| e.to_string())
    }

    /// Forgets everything learnt.
    pub fn forget(&mut self) -> Result<(), String> {
        self.used.clear();
        self.write()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_is_learnt_comes_back_most_used_first() {
        let mut l = Learned::default();
        l.learn("User.Department", &["Finance".into()]);
        l.learn("User.Department", &["Finance".into(), "Ops".into()]);
        l.learn("User.Clearance", &["3".into()]);
        l.learn("Resource.Department", &[]);
        assert_eq!(l.names("User"), [("Department".to_string(), 2), ("Clearance".to_string(), 1)]);
        assert_eq!(l.values("User.Department"), [("Finance".to_string(), 2), ("Ops".to_string(), 1)]);
        let text = l.lines().join("\0");
        assert_eq!(Learned::parse(&text), l);
    }
}
