//! Conditions: an entry's expression (PCDS §5.8), as the tree a person
//! edits, and as the `artx` bytecode KACS reads (PCDS §5.11).
//!
//! The tree is groups (all, any, none, not all of their items) holding
//! claim tests, membership tests and further groups. Bytecode is read into
//! the tree where the tree can say it; where it cannot, the condition is
//! kept as its bytes and shown as text. A tree is written as the SDDL text
//! `sd --if` takes, which libpeios turns into bytecode, so whatever this
//! editor writes is what the system's own tools write.

use peios::security::{Sid, SidRef, sddl};

/// Where a claim comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Src {
    User,
    Device,
    Resource,
    Local,
}

impl Src {
    pub const ALL: [Src; 4] = [Src::User, Src::Device, Src::Resource, Src::Local];

    pub fn word(self) -> &'static str {
        match self {
            Src::User => "User",
            Src::Device => "Device",
            Src::Resource => "Resource",
            Src::Local => "Local",
        }
    }

    pub fn from_word(word: &str) -> Option<Src> {
        Src::ALL.into_iter().find(|s| s.word() == word)
    }

    fn token(self) -> u8 {
        match self {
            Src::Local => 0xf8,
            Src::User => 0xf9,
            Src::Resource => 0xfa,
            Src::Device => 0xfb,
        }
    }

    fn from_token(t: u8) -> Option<Src> {
        Src::ALL.into_iter().find(|s| s.token() == t)
    }
}

/// How a group's items combine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    All,
    Any,
    None,
    NotAll,
}

impl Mode {
    pub const ALL: [Mode; 4] = [Mode::All, Mode::Any, Mode::None, Mode::NotAll];

    pub fn key(self) -> &'static str {
        match self {
            Mode::All => "all",
            Mode::Any => "any",
            Mode::None => "none",
            Mode::NotAll => "notall",
        }
    }

    pub fn from_key(key: &str) -> Option<Mode> {
        Mode::ALL.into_iter().find(|m| m.key() == key)
    }

    /// Whether its items are joined by and, rather than or.
    pub fn and(self) -> bool {
        matches!(self, Mode::All | Mode::NotAll)
    }
}

/// What a claim is tested for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    Eq,
    Ne,
    AnyOf,
    Contains,
    Ge,
    Gt,
    Le,
    Lt,
    Exists,
    NotExists,
}

impl Op {
    pub const ALL: [Op; 10] = [Op::Eq, Op::Ne, Op::AnyOf, Op::Contains, Op::Ge, Op::Gt, Op::Le, Op::Lt, Op::Exists, Op::NotExists];

    pub fn key(self) -> &'static str {
        match self {
            Op::Eq => "eq",
            Op::Ne => "ne",
            Op::AnyOf => "any",
            Op::Contains => "contains",
            Op::Ge => "ge",
            Op::Gt => "gt",
            Op::Le => "le",
            Op::Lt => "lt",
            Op::Exists => "exists",
            Op::NotExists => "notexists",
        }
    }

    pub fn from_key(key: &str) -> Option<Op> {
        Op::ALL.into_iter().find(|o| o.key() == key)
    }

    /// Whether it tests against a value, rather than only whether the claim
    /// is there.
    pub fn valued(self) -> bool {
        !matches!(self, Op::Exists | Op::NotExists)
    }

    /// Whether its value is several, with commas.
    pub fn several(self) -> bool {
        matches!(self, Op::AnyOf | Op::Contains)
    }

    fn sddl(self) -> &'static str {
        match self {
            Op::Eq => "==",
            Op::Ne => "!=",
            Op::AnyOf => "Any_of",
            Op::Contains => "Contains",
            Op::Ge => ">=",
            Op::Gt => ">",
            Op::Le => "<=",
            Op::Lt => "<",
            Op::Exists => "Exists",
            Op::NotExists => "Not_Exists",
        }
    }
}

/// A membership test.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemberOp {
    Of,
    OfAny,
    NotOf,
    NotOfAny,
}

impl MemberOp {
    pub const ALL: [MemberOp; 4] = [MemberOp::Of, MemberOp::OfAny, MemberOp::NotOf, MemberOp::NotOfAny];

    pub fn key(self) -> &'static str {
        match self {
            MemberOp::Of => "of",
            MemberOp::OfAny => "ofany",
            MemberOp::NotOf => "notof",
            MemberOp::NotOfAny => "notofany",
        }
    }

    pub fn from_key(key: &str) -> Option<MemberOp> {
        MemberOp::ALL.into_iter().find(|o| o.key() == key)
    }

    fn function(self, device: bool) -> String {
        let base = match self {
            MemberOp::Of => "Member_of",
            MemberOp::OfAny => "Member_of_Any",
            MemberOp::NotOf => "Not_Member_of",
            MemberOp::NotOfAny => "Not_Member_of_Any",
        };
        if device { base.replace("Member_of", "Device_Member_of") } else { base.into() }
    }
}

/// What a claim is compared with: a value as typed (several, with commas,
/// for the tests that take several), or another claim.
#[derive(Clone, Debug, PartialEq)]
pub enum Val {
    Value(String),
    Claim(Src, String),
}

#[derive(Clone, Debug, PartialEq)]
pub enum Node {
    Group(Mode, Vec<Node>),
    Claim { src: Src, name: String, op: Op, val: Val },
    Member { device: bool, op: MemberOp, sids: Vec<Sid> },
}

impl Node {
    /// A new condition: one test, to be filled in.
    pub fn fresh() -> Node {
        Node::Group(Mode::All, vec![Node::blank_claim()])
    }

    pub fn blank_claim() -> Node {
        Node::Claim { src: Src::User, name: String::new(), op: Op::Eq, val: Val::Value(String::new()) }
    }

    /// The node at `path`, counted from 0 down the groups: "" is this one.
    pub fn at(&self, path: &[usize]) -> Option<&Node> {
        match (path.split_first(), self) {
            (None, _) => Some(self),
            (Some((i, rest)), Node::Group(_, items)) => items.get(*i)?.at(rest),
            _ => None,
        }
    }

    pub fn at_mut(&mut self, path: &[usize]) -> Option<&mut Node> {
        match path.split_first() {
            None => Some(self),
            Some((i, rest)) => match self {
                Node::Group(_, items) => items.get_mut(*i)?.at_mut(rest),
                _ => None,
            },
        }
    }

    /// Every claim test in it.
    pub fn claims(&self) -> Vec<&Node> {
        match self {
            Node::Group(_, items) => items.iter().flat_map(Node::claims).collect(),
            Node::Claim { .. } => vec![self],
            Node::Member { .. } => vec![],
        }
    }
}

/// What a claim's name may be: what libpeios' SDDL can write
/// (`grammar/cond.rs`, `is_ident_continue`).
pub fn name_ok(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | ':' | '.'))
}

/// A test's values, as typed: split at commas where it takes several.
pub fn values(op: Op, val: &Val) -> Vec<String> {
    match val {
        Val::Claim(..) => vec![],
        Val::Value(text) if op.several() => text.split(',').map(str::trim).filter(|v| !v.is_empty()).map(String::from).collect(),
        Val::Value(text) => [text.trim()].into_iter().filter(|v| !v.is_empty()).map(String::from).collect(),
    }
}

/// What is wrong with a node itself, if anything, and in which of its
/// fields: "name", "val" or "sids".
pub fn problem(node: &Node) -> Option<(&'static str, String)> {
    match node {
        Node::Group(_, items) if items.is_empty() => Some(("", "This group has nothing in it.".into())),
        Node::Group(..) => None,
        Node::Member { sids, .. } if sids.is_empty() => Some(("sids", "Pick at least one group.".into())),
        Node::Member { .. } => None,
        Node::Claim { name, op, val, .. } => {
            let name = name.trim();
            if name.is_empty() {
                return Some(("name", "Name the claim to test.".into()));
            }
            if !name_ok(name) {
                return Some(("name", "A claim's name can use letters, digits, _, : and . only.".into()));
            }
            if !op.valued() {
                return None;
            }
            match val {
                Val::Claim(_, other) if other.trim().is_empty() => Some(("val", "Name the claim to compare it with.".into())),
                Val::Claim(_, other) if !name_ok(other.trim()) => Some(("val", "A claim's name can use letters, digits, _, : and . only.".into())),
                Val::Claim(..) => None,
                Val::Value(text) if text.contains('"') => Some(("val", "A value can't contain a double quote.".into())),
                Val::Value(_) if values(*op, val).is_empty() => Some(("val", "Give the value to test for.".into())),
                Val::Value(_) => None,
            }
        }
    }
}

/// The first thing wrong anywhere in a tree.
pub fn tree_problem(node: &Node) -> Option<String> {
    if let Some((_, why)) = problem(node) {
        return Some(why);
    }
    match node {
        Node::Group(_, items) => items.iter().find_map(tree_problem),
        _ => None,
    }
}

/// A value as SDDL writes it: a whole number bare, yes and no as 1 and 0,
/// text in quotes.
fn literal(value: &str) -> String {
    let v = value.trim();
    if !v.is_empty() && v.strip_prefix('-').unwrap_or(v).chars().all(|c| c.is_ascii_digit()) {
        v.into()
    } else if v.eq_ignore_ascii_case("true") {
        "1".into()
    } else if v.eq_ignore_ascii_case("false") {
        "0".into()
    } else {
        format!("\"{v}\"")
    }
}

/// The tree as `sd --if` would take it.
pub fn expr(node: &Node) -> String {
    write(node, true)
}

fn write(node: &Node, top: bool) -> String {
    match node {
        Node::Group(mode, items) => {
            let inner = items.iter().map(|n| write(n, false)).collect::<Vec<_>>().join(if mode.and() { " && " } else { " || " });
            let inner = if inner.is_empty() { "true".into() } else { inner };
            let negated = matches!(mode, Mode::None | Mode::NotAll);
            let wrapped = if items.len() > 1 || negated { format!("({inner})") } else { inner.clone() };
            if negated {
                format!("!{wrapped}")
            } else if top {
                inner
            } else {
                wrapped
            }
        }
        Node::Member { device, op, sids } => {
            format!("{} {{{}}}", op.function(*device), sids.iter().map(|s| format!("SID({s})")).collect::<Vec<_>>().join(", "))
        }
        Node::Claim { src, name, op, val } => {
            let name = name.trim();
            let at = format!("@{}.{}", src.word(), if name.is_empty() { "?" } else { name });
            if !op.valued() {
                return format!("{} {at}", op.sddl());
            }
            match val {
                Val::Claim(other, n) => format!("{at} {} @{}.{}", op.sddl(), other.word(), if n.trim().is_empty() { "?" } else { n.trim() }),
                Val::Value(_) if op.several() => {
                    format!("{at} {} {{{}}}", op.sddl(), values(*op, val).iter().map(|v| literal(v)).collect::<Vec<_>>().join(", "))
                }
                Val::Value(text) => format!("{at} {} {}", op.sddl(), literal(text)),
            }
        }
    }
}

/// An entry's condition.
#[derive(Clone, Debug, PartialEq)]
pub enum Cond {
    /// One the tree can say.
    Tree(Node),
    /// One it cannot, kept as its bytes.
    Opaque(Vec<u8>),
}

impl Cond {
    /// An entry's application data, as a condition.
    pub fn read(data: &[u8]) -> Cond {
        match decode(data).and_then(|e| group(&e)) {
            Some(node) => Cond::Tree(node),
            None => Cond::Opaque(data.to_vec()),
        }
    }

    /// As bytecode, to be written.
    pub fn bytes(&self) -> Result<Vec<u8>, String> {
        match self {
            Cond::Opaque(bytes) => Ok(bytes.clone()),
            Cond::Tree(node) => {
                if let Some(why) = tree_problem(node) {
                    return Err(format!("A condition isn't finished: {why}"));
                }
                sddl::parse_condition(&expr(node)).map_err(|e| format!("A condition could not be written ({e}): {}", expr(node)))
            }
        }
    }

    /// As text, to be read.
    pub fn text(&self) -> String {
        match self {
            Cond::Tree(node) => expr(node),
            Cond::Opaque(bytes) => sddl::format_condition(bytes).unwrap_or_else(|_| format!("a condition this editor can't read ({} bytes)", bytes.len())),
        }
    }

    pub fn tree(&self) -> Option<&Node> {
        match self {
            Cond::Tree(node) => Some(node),
            Cond::Opaque(_) => None,
        }
    }
}

/// The bytecode's expression, before it is a tree.
#[derive(Clone, Debug, PartialEq)]
enum E {
    Int(i64),
    Str(String),
    Sid(Sid),
    Composite(Vec<E>),
    Attr(Src, String),
    /// A relational operator, by its byte: left, right.
    Rel(u8, Box<E>, Box<E>),
    /// A unary one: Exists, Not_Exists, and the membership tests.
    Un(u8, Box<E>),
    And(Box<E>, Box<E>),
    Or(Box<E>, Box<E>),
    Not(Box<E>),
}

fn u32_at(b: &[u8], at: usize) -> Option<usize> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?) as usize)
}

fn utf16(b: &[u8]) -> Option<String> {
    if b.len() % 2 != 0 {
        return None;
    }
    String::from_utf16(&b.chunks(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect::<Vec<_>>()).ok()
}

/// One literal at `at`, and where the next token starts.
fn literal_at(b: &[u8], at: usize) -> Option<(E, usize)> {
    let t = *b.get(at)?;
    match t {
        0x01..=0x04 => {
            let raw = i64::from_le_bytes(b.get(at + 1..at + 9)?.try_into().ok()?);
            let sign = *b.get(at + 9)?;
            let v = if sign == 0x02 && raw > 0 { -raw } else { raw };
            Some((E::Int(v), at + 11))
        }
        0x10 => {
            let len = u32_at(b, at + 1)?;
            Some((E::Str(utf16(b.get(at + 5..at + 5 + len)?)?), at + 5 + len))
        }
        0x51 => {
            let len = u32_at(b, at + 1)?;
            let sid = SidRef::from_bytes(b.get(at + 5..at + 5 + len)?)?.to_sid();
            Some((E::Sid(sid), at + 5 + len))
        }
        0x50 => {
            let len = u32_at(b, at + 1)?;
            let end = at + 5 + len;
            let mut items = Vec::new();
            let mut i = at + 5;
            while i < end {
                let (item, next) = literal_at(b, i)?;
                items.push(item);
                i = next;
            }
            (i == end).then_some((E::Composite(items), end))
        }
        _ => None,
    }
}

/// The bytecode as an expression, if it is one this editor can read.
fn decode(data: &[u8]) -> Option<E> {
    let b = data.strip_prefix(b"artx")?;
    let mut stack: Vec<E> = Vec::new();
    let mut at = 0;
    while at < b.len() {
        let t = b[at];
        match t {
            // Padding, to the end.
            0x00 => {
                if b[at..].iter().any(|&x| x != 0) {
                    return None;
                }
                break;
            }
            0x01..=0x04 | 0x10 | 0x50 | 0x51 => {
                let (lit, next) = literal_at(b, at)?;
                stack.push(lit);
                at = next;
            }
            0x18 => return None,
            0xf8..=0xfb => {
                let len = u32_at(b, at + 1)?;
                let name = utf16(b.get(at + 5..at + 5 + len)?)?;
                stack.push(E::Attr(Src::from_token(t)?, name));
                at += 5 + len;
            }
            0x80..=0x86 | 0x88 | 0x8e | 0x8f => {
                let right = stack.pop()?;
                let left = stack.pop()?;
                stack.push(E::Rel(t, Box::new(left), Box::new(right)));
                at += 1;
            }
            0x87 | 0x89..=0x8d | 0x90..=0x93 => {
                let operand = stack.pop()?;
                stack.push(E::Un(t, Box::new(operand)));
                at += 1;
            }
            0xa0 | 0xa1 => {
                let right = stack.pop()?;
                let left = stack.pop()?;
                stack.push(if t == 0xa0 { E::And(Box::new(left), Box::new(right)) } else { E::Or(Box::new(left), Box::new(right)) });
                at += 1;
            }
            0xa2 => {
                let operand = stack.pop()?;
                stack.push(E::Not(Box::new(operand)));
                at += 1;
            }
            _ => return None,
        }
    }
    (stack.len() == 1).then(|| stack.pop()).flatten()
}

/// The terms of a chain of one operator, in order.
fn chain(e: &E, and: bool) -> Vec<&E> {
    match (e, and) {
        (E::And(l, r), true) | (E::Or(l, r), false) => {
            let mut out = chain(l, and);
            out.extend(chain(r, and));
            out
        }
        _ => vec![e],
    }
}

/// An expression as a group, the shape a condition's root always has.
fn group(e: &E) -> Option<Node> {
    match e {
        E::And(..) => Some(Node::Group(Mode::All, chain(e, true).into_iter().map(node).collect::<Option<_>>()?)),
        E::Or(..) => Some(Node::Group(Mode::Any, chain(e, false).into_iter().map(node).collect::<Option<_>>()?)),
        E::Not(inner) => match &**inner {
            E::Or(..) => Some(Node::Group(Mode::None, chain(inner, false).into_iter().map(node).collect::<Option<_>>()?)),
            E::And(..) => Some(Node::Group(Mode::NotAll, chain(inner, true).into_iter().map(node).collect::<Option<_>>()?)),
            other => Some(Node::Group(Mode::None, vec![node(other)?])),
        },
        _ => Some(Node::Group(Mode::All, vec![node(e)?])),
    }
}

/// A value the tree can hold as typed text: a number or text without
/// commas or quotes.
fn value_text(e: &E) -> Option<String> {
    match e {
        E::Int(v) => Some(v.to_string()),
        E::Str(s) if !s.contains(',') && !s.contains('"') && !s.trim().is_empty() && s.trim() == s => Some(s.clone()),
        _ => None,
    }
}

fn node(e: &E) -> Option<Node> {
    match e {
        E::And(..) | E::Or(..) | E::Not(..) => group(e),
        E::Un(t @ (0x87 | 0x8d), operand) => {
            let E::Attr(src, name) = &**operand else { return None };
            let op = if *t == 0x87 { Op::Exists } else { Op::NotExists };
            Some(Node::Claim { src: *src, name: name.clone(), op, val: Val::Value(String::new()) })
        }
        E::Un(t, operand) => {
            let (device, op) = match t {
                0x89 => (false, MemberOp::Of),
                0x8a => (true, MemberOp::Of),
                0x8b => (false, MemberOp::OfAny),
                0x8c => (true, MemberOp::OfAny),
                0x90 => (false, MemberOp::NotOf),
                0x91 => (true, MemberOp::NotOf),
                0x92 => (false, MemberOp::NotOfAny),
                0x93 => (true, MemberOp::NotOfAny),
                _ => return None,
            };
            let sids = match &**operand {
                E::Sid(s) => vec![*s],
                E::Composite(items) => items.iter().map(|i| if let E::Sid(s) = i { Some(*s) } else { None }).collect::<Option<_>>()?,
                _ => return None,
            };
            Some(Node::Member { device, op, sids })
        }
        E::Rel(t, left, right) => {
            let E::Attr(src, name) = &**left else { return None };
            // The negated set tests, as a group of one that is negated.
            let (op, negated) = match t {
                0x80 => (Op::Eq, false),
                0x81 => (Op::Ne, false),
                0x82 => (Op::Lt, false),
                0x83 => (Op::Le, false),
                0x84 => (Op::Gt, false),
                0x85 => (Op::Ge, false),
                0x86 => (Op::Contains, false),
                0x88 => (Op::AnyOf, false),
                0x8e => (Op::Contains, true),
                0x8f => (Op::AnyOf, true),
                _ => return None,
            };
            let val = match &**right {
                E::Attr(other, n) => Val::Claim(*other, n.clone()),
                E::Composite(items) if op.several() => Val::Value(items.iter().map(value_text).collect::<Option<Vec<_>>>()?.join(", ")),
                single if !matches!(single, E::Composite(_)) => Val::Value(value_text(single)?),
                _ => return None,
            };
            let claim = Node::Claim { src: *src, name: name.clone(), op, val };
            Some(if negated { Node::Group(Mode::None, vec![claim]) } else { claim })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round(text: &str) -> Node {
        let bytes = sddl::parse_condition(text).unwrap();
        match Cond::read(&bytes) {
            Cond::Tree(node) => {
                // What the tree writes is the same condition.
                assert_eq!(sddl::parse_condition(&expr(&node)).unwrap(), bytes, "{text} → {}", expr(&node));
                node
            }
            Cond::Opaque(_) => panic!("{text} was not read"),
        }
    }

    #[test]
    fn conditions_are_read_into_the_tree_and_written_back_the_same() {
        round("@User.Department == \"Finance\"");
        round("@Device.Compliance == \"Compliant\" || Device_Member_of_Any {SID(S-1-5-21-1-2-3-2002)}");
        round("@User.Department == @Resource.Department");
        round("@User.Clearance >= 3 && !(@User.Projects Any_of {\"Atlas\", \"Kestrel\"} || Exists @Device.Managed)");
        round("Member_of {SID(S-1-5-32-544), SID(S-1-5-11)} && Not_Exists @Local.X");
        let node = round("@User.Level == -4");
        assert_eq!(node, Node::Group(Mode::All, vec![Node::Claim { src: Src::User, name: "Level".into(), op: Op::Eq, val: Val::Value("-4".into()) }]));
    }

    #[test]
    fn what_the_tree_cannot_say_is_kept_as_it_came() {
        for text in ["@User.Name == \"a,b\"", "1 == @User.X", "@User.Blob == #0a0b"] {
            let bytes = sddl::parse_condition(text).unwrap();
            let cond = Cond::read(&bytes);
            assert_eq!(cond, Cond::Opaque(bytes.clone()), "{text}");
            assert_eq!(cond.bytes().unwrap(), bytes);
        }
        assert!(matches!(Cond::read(b"nope"), Cond::Opaque(_)));
    }

    #[test]
    fn an_unfinished_tree_says_what_is_missing() {
        assert_eq!(Cond::Tree(Node::fresh()).bytes().unwrap_err(), "A condition isn't finished: Name the claim to test.");
        let bad = Node::Claim { src: Src::User, name: "a b".into(), op: Op::Eq, val: Val::Value("x".into()) };
        assert_eq!(problem(&bad).unwrap().0, "name");
        let no_value = Node::Claim { src: Src::User, name: "X".into(), op: Op::AnyOf, val: Val::Value(" , ".into()) };
        assert_eq!(problem(&no_value).unwrap().1, "Give the value to test for.");
        assert_eq!(expr(&Node::Group(Mode::None, vec![bad])), "!(@User.a b == \"x\")");
    }
}
