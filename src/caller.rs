//! Who is changing the descriptor, as KACS will judge what they apply.
//!
//! The editor runs on the token of the program that opened it, which is
//! the token that program applies with, so its own token says whom the
//! owner may be given to (KACS set-security §Ownership), how high a label
//! may go, and how far the process trust label may be raised. Privileges
//! are counted when they are present, enabled or not: a program may enable
//! one only around its own call.

use peios::process::Process;
use peios::security::{Privileges, Sid};
use peios::token::{Token, TokenAccess};

/// SE_GROUP_OWNER: a group the token may make the owner.
const GROUP_OWNER: u32 = 0x8;
/// SeTakeOwnershipPrivilege and SeRelabelPrivilege, which peios-rs has no
/// names for.
const TAKE_OWNERSHIP: u64 = 1 << 9;
const RELABEL: u64 = 1 << 32;

#[derive(Clone, Debug, PartialEq)]
pub struct Caller {
    pub user: Option<Sid>,
    /// The groups it may make the owner.
    pub owner_groups: Vec<Sid>,
    /// Every SID on it, for showing what it can do.
    pub sids: Vec<Sid>,
    /// SeRestorePrivilege: the owner may be anyone.
    pub restore: bool,
    /// SeRelabelPrivilege: the label may be any level.
    pub relabel: bool,
    /// SeTcbPrivilege: a locked claim may be changed.
    pub tcb: bool,
    pub take_ownership: bool,
    /// Its integrity level, by RID.
    pub integrity: u32,
    /// Its process trust: the type and the trust within it.
    pub pip_type: u32,
    pub pip_trust: u32,
}

impl Caller {
    /// This process's.
    pub fn own() -> Caller {
        let mut caller = Caller::unknown();
        if let Ok(token) = Token::open_self(false, TokenAccess::QUERY) {
            caller.user = token.user().ok();
            if let Ok(groups) = token.groups() {
                caller.owner_groups = groups.iter().filter(|(_, attrs)| attrs & GROUP_OWNER != 0).map(|(sid, _)| *sid).collect();
                caller.sids = groups.into_iter().map(|(sid, _)| sid).collect();
            }
            caller.sids.extend(caller.user);
            if let Ok(privileges) = token.privileges() {
                let present = privileges.present;
                caller.restore = present.contains(Privileges::RESTORE);
                caller.tcb = present.contains(Privileges::TCB);
                caller.relabel = present.bits() & RELABEL != 0;
                caller.take_ownership = present.bits() & TAKE_OWNERSHIP != 0;
            }
            if let Ok(level) = token.integrity() {
                caller.integrity = level.rid();
            }
        }
        if let Ok(psb) = Process::psb(None) {
            caller.pip_type = psb.pip_type;
            caller.pip_trust = psb.pip_trust;
        }
        caller
    }

    /// One that can be told nothing: Medium, unprotected, and no rights to
    /// give anything away.
    pub fn unknown() -> Caller {
        Caller {
            user: None,
            owner_groups: Vec::new(),
            sids: Vec::new(),
            restore: false,
            relabel: false,
            tcb: false,
            take_ownership: false,
            integrity: 8192,
            pip_type: 0,
            pip_trust: 0,
        }
    }

    /// Whom the owner may be given to, besides anyone with SeRestore: the
    /// caller, and the groups it may own things as.
    pub fn may_own(&self) -> Vec<Sid> {
        self.user.iter().chain(&self.owner_groups).copied().collect()
    }

    /// Whether a label at `level` is one it may set.
    pub fn may_label(&self, level: u32) -> bool {
        self.relabel || level <= self.integrity
    }

    /// Whether process trust of `pip_type` and `trust` is no more than its
    /// own, so it does not lock itself out.
    pub fn dominates(&self, pip_type: u32, trust: u32) -> bool {
        self.pip_type >= pip_type && self.pip_trust >= trust
    }
}
