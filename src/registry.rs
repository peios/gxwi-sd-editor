//! A registry key's descriptor, for a program that opens the editor on one:
//! what a key's rights are called, what the generic rights stand for on a
//! key, and the request and the apply for a key's own descriptor.
//!
//! Registry Editor and Services Manager both open the editor on keys, and
//! say a key's rights the same way through this.

use peios::registry::{Key, KeyAccess, OpenFlags, SecInfo};
use peios::security::SecurityDescriptor;

use crate::{Can, Children, Generic, Object, Part, Request, Right};

const EACCES: i32 = 13;

/// What applies a descriptor the person applied, and why it could not be.
pub type Apply = Box<dyn FnMut(&[u8], &[Part]) -> Result<(), String> + Send>;

/// A key's rights, by what they are called, the general ones first and from
/// the most to the least.
pub fn key_rights() -> Vec<Right> {
    let general = |name: &str, mask: KeyAccess| Right { name: name.into(), mask: mask.bits(), general: true };
    let special = |name: &str, mask: KeyAccess| Right { name: name.into(), mask: mask.bits(), general: false };
    vec![
        general("Full control", KeyAccess::ALL_ACCESS),
        general("Read", KeyAccess::READ),
        general("Write", KeyAccess::WRITE),
        special("Read values", KeyAccess::QUERY_VALUE),
        special("Change values", KeyAccess::SET_VALUE),
        special("Create keys", KeyAccess::CREATE_SUB_KEY),
        special("List keys", KeyAccess::ENUMERATE_SUB_KEYS),
        special("Watch for changes", KeyAccess::NOTIFY),
        special("Create links", KeyAccess::CREATE_LINK),
        special("Delete", KeyAccess::DELETE),
        special("Read permissions", KeyAccess::READ_CONTROL),
        special("Change permissions", KeyAccess::WRITE_DAC),
        special("Take ownership", KeyAccess::WRITE_OWNER),
    ]
}

/// What the generic rights stand for on a key (LCS TRM §5.4.2). There is
/// nothing to execute on a key, so execute stands for nothing.
pub fn key_generic() -> Generic {
    Generic { read: KeyAccess::READ.bits(), write: KeyAccess::WRITE.bits(), execute: 0, all: KeyAccess::ALL_ACCESS.bits() }
}

/// The descriptor of the key at `path`, as the editor is to be asked to show
/// it, and what applies what it sends back. The key is opened for as much
/// of changing its descriptor as the person may do, which is what they are
/// offered; `cannot` says why, where they may not change who may use it.
/// `name` is what the key is called where the person found it.
pub fn key(path: &str, name: &str, cannot: &str) -> Result<(Request, Apply), String> {
    let mut opened = None;
    for (dacl, owner) in [(true, true), (true, false), (false, true), (false, false)] {
        let mut access = KeyAccess::READ_CONTROL;
        access.set(KeyAccess::WRITE_DAC, dacl);
        access.set(KeyAccess::WRITE_OWNER, owner);
        match Key::open(None, path, access, OpenFlags::empty()) {
            Ok(key) => {
                opened = Some((key, dacl, owner));
                break;
            }
            Err(e) if e.raw_os_error() == Some(EACCES) => continue,
            Err(e) => return Err(format!("it could not be read ({e})")),
        }
    }
    let Some((key, dacl, owner)) = opened else { return Err("you may not read who may use it".into()) };
    // The integrity label as well, where it can be read: it is changed with
    // the right to change the owner.
    let basic = SecInfo::OWNER | SecInfo::GROUP | SecInfo::DACL;
    let (descriptor, labelled) = match key.get_security(basic | SecInfo::LABEL) {
        Ok(descriptor) => (descriptor, true),
        Err(_) => (
            key.get_security(basic).map_err(|e| if e.raw_os_error() == Some(EACCES) { "you may not read who may use it".to_string() } else { format!("who may use it could not be read ({e})") })?,
            false,
        ),
    };
    let mut read = vec![Part::Owner, Part::Group, Part::Dacl];
    if labelled {
        read.push(Part::Label);
    }
    let request = Request {
        object: Object { name: name.into(), kind: format!("Registry key {path}"), container: true, children: Children::Containers, ..Object::default() },
        sd: descriptor.as_bytes().to_vec(),
        read: Some(read),
        rights: key_rights(),
        generic: key_generic(),
        can: Can { dacl, owner, label: owner && labelled, why: (!dacl).then(|| cannot.to_string()), ..Can::default() },
    };
    let apply = move |sd: &[u8], parts: &[Part]| {
        let mut secinfo = SecInfo::empty();
        for part in parts {
            secinfo |= match part {
                Part::Owner => SecInfo::OWNER,
                Part::Group => SecInfo::GROUP,
                Part::Dacl => SecInfo::DACL,
                Part::Sacl => SecInfo::SACL,
                Part::Label => SecInfo::LABEL,
            };
        }
        let sd = SecurityDescriptor::from_validated_bytes(sd.to_vec()).map_err(|e| format!("it is not a security descriptor ({e})"))?;
        // The registry takes the parts named, and keeps the rest as it is.
        key.set_security(secinfo, &sd, None).map_err(|e| if e.raw_os_error() == Some(EACCES) { "you are not allowed to".to_string() } else { e.to_string() })
    };
    Ok((request, Box::new(apply)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_general_rights_come_first_and_full_control_is_the_most() {
        let rights = key_rights();
        assert!(rights[..3].iter().all(|right| right.general));
        assert!(rights[3..].iter().all(|right| !right.general));
        assert_eq!(rights[0].mask, key_generic().all);
        // Every right named is within Full control.
        assert!(rights.iter().all(|right| right.mask & !rights[0].mask == 0));
    }

    #[test]
    fn execute_stands_for_nothing_on_a_key() {
        assert_eq!(key_generic().execute, 0);
        assert_eq!(key_generic().read, KeyAccess::READ.bits());
    }
}
