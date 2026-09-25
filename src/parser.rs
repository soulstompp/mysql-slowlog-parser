//! The line and statement parsers a slow log is made of, and the pass that reads the author's
//! literals out of a parsed statement.
//!
//! What it reads: the header block, the `# Time:`, `# User@Host:` and `# Query_time:` lines, the
//! `USE` and `SET timestamp` commands, an administrator command, a `--` comment's key/value
//! pairs, and the statement's own bytes up to the `;` that ends it. [`parse_sql`] hands the text
//! to `sqlparser` and walks the tree once to record every literal, masking them on the way where
//! the caller asked for it.
//!
//! Each line grammar reads one whole line first and parses only that, so no line grammar reads
//! past the end of its own line.
//!
//! What it refuses: a line that does not match its shape, as a winnow backtrack; and text
//! `sqlparser` will not parse, which [`crate::codec`] files as an invalid statement with the
//! author's bytes intact.
//!
//! What it declines to interpret: the server version string, carried as the file spelled it,
//! because `-log`, `-MariaDB` and `-percona` are three grammars for one field; a comment's keys,
//! which are reported under the names the comment used rather than mapped onto names of this
//! crate's choosing; and the column a value in a tuple assignment or a row constructor belongs
//! to, which MySQL does not write down.

use crate::EntryMasking;
use bytes::{BufMut, Bytes, BytesMut};
use sqlparser::ast::{
    AssignmentTarget, BinaryOperator, Expr, ObjectName, SetExpr, Statement, Value, ValueWithSpan,
    VisitMut, VisitorMut,
};
use sqlparser::dialect::MySqlDialect;
use sqlparser::parser::{Parser as SQLParser, ParserError};
use sqlparser::tokenizer::{Token, Tokenizer, Whitespace};
use std::borrow::Cow;
use std::collections::HashMap;
use std::ops::ControlFlow;
use std::ops::Not;
use std::str;
use std::str::FromStr;
use winnow::ascii::{Caseless, alphanumeric1, digit1, float, multispace0, space0, space1};
use winnow::combinator::{alt, cut_err, eof, not, opt, peek, preceded, repeat, separated, trace};
use winnow::error::{ContextError, ErrMode, InputError, Needed};
// Aliased: `sqlparser` exports a `ParserError` of its own and both are used in this file.
use winnow::error::ParserError as WinnowError;
use winnow::stream::{AsBytes, AsChar, StreamIsPartial};
use winnow::token::{any, literal, rest, take, take_till, take_while};
use winnow::{ModalResult, Parser, Partial, seq};
use winnow_datetime::{Date, DateTime, Time};
use winnow_iso8601::datetime::datetime;

pub type Stream<'i> = Partial<&'i [u8]>;

/// The next line, without its line ending.
///
/// A partial stream holds a line only once its `\n` has arrived; at the end of a complete stream
/// the rest of the input is the last line. A `\r` before the `\n` belongs to the line ending.
pub(crate) fn line<'i>(i: &mut Stream<'i>) -> ModalResult<&'i [u8]> {
    trace("line", move |input: &mut Stream<'i>| {
        let l: &[u8] = take_till(0.., b'\n').parse_next(input)?;
        let _ = opt(literal("\n")).parse_next(input)?;
        Ok(l.strip_suffix(b"\r").unwrap_or(l))
    })
    .parse_next(i)
}

/// Decimal digits as a number, or `None` where they do not fit in `T`.
fn decimal<T: FromStr>(digits: &[u8]) -> Option<T> {
    str::from_utf8(digits).ok()?.parse().ok()
}

/// The bytes with surrounding whitespace removed, or `None` where nothing is left.
fn written(b: &[u8]) -> Option<Bytes> {
    let b = b.trim_ascii();
    b.is_empty().not().then(|| Bytes::copy_from_slice(b))
}

fn refused<T>() -> ModalResult<T> {
    Err(ErrMode::Backtrack(ContextError::new()))
}

/// A struct holding a `DateTime` parsed from the Time: line of the entry
/// ex: `# Time: 2018-02-05T02:46:43.015898Z`
#[derive(Clone)]
pub struct TimeLine {
    time: DateTime,
}

impl TimeLine {
    /// returns a clone of the DateTime parsed from the Time: line
    pub fn time(&self) -> DateTime {
        self.time.clone()
    }
}

/// Parses an entry's `# Time:` line into a `DateTime`.
///
/// Two spellings: the ISO 8601 form MySQL 5.7 and later write (`2018-02-05T02:46:43.015898Z`,
/// `2015-06-26T16:43:23+02:00`), and the `yymmdd h:mm:ss` form MySQL before 5.7 and MariaDB
/// write (`180205  2:46:47`). The second states no zone, so its offset is `None`, and its
/// two-digit year reads as 1969 to 2068.
pub fn parse_entry_time(i: &mut Stream) -> ModalResult<DateTime> {
    trace("parse_entry_time", move |input: &mut Stream| {
        let mut l = preceded(peek(literal("# Time:")), line).parse_next(input)?;

        seq!(
            _: literal("# Time:"),
            _: space1,
            alt((datetime, legacy_datetime)),
            _: space0,
            _: eof,
        )
        .map(|t| t.0)
        .parse_next(&mut l)
    })
    .parse_next(i)
}

/// `yymmdd h:mm:ss`, the hour padded with a space rather than a zero, and an optional fraction.
fn legacy_datetime(i: &mut &[u8]) -> ModalResult<DateTime> {
    let (yy, month, day, hour, minute, second, fraction): (i32, u32, u32, u32, u32, u32, _) = seq!(
        take_while(2, AsChar::is_dec_digit).verify_map(decimal),
        take_while(2, AsChar::is_dec_digit).verify_map(decimal),
        take_while(2, AsChar::is_dec_digit).verify_map(decimal),
        _: space1,
        take_while(1..=2, AsChar::is_dec_digit).verify_map(decimal),
        _: literal(":"),
        take_while(2, AsChar::is_dec_digit).verify_map(decimal),
        _: literal(":"),
        take_while(2, AsChar::is_dec_digit).verify_map(decimal),
        opt(preceded(literal("."), digit1)),
    )
    .parse_next(i)?;

    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return refused();
    }
    if hour > 23 || minute > 59 || second > 60 {
        return refused();
    }

    // Everything after the `.`, scaled to nanoseconds; digits past the ninth are dropped.
    let nanosecond = match fraction {
        Some(f) => {
            let f: &[u8] = &f[..f.len().min(9)];
            decimal::<u32>(f).unwrap_or(0) * 10u32.pow(9 - f.len() as u32)
        }
        None => 0,
    };

    Ok(DateTime {
        date: Date::YMD {
            year: if yy >= 69 { 1900 + yy } else { 2000 + yy },
            month,
            day,
        },
        time: Time {
            hour,
            minute,
            second,
            nanosecond,
            offset: None,
            time_zone: None,
            calendar: None,
        },
    })
}

/// The values of an entry's `# User@Host:` line.
///
/// ex. `# User@Host: msandbox[msandbox] @ localhost []  Id:     3`
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionLine {
    pub(crate) user: Bytes,
    pub(crate) sys_user: Bytes,
    pub(crate) host: Option<Bytes>,
    pub(crate) ip_address: Option<Bytes>,
    pub(crate) thread_id: Option<u32>,
}

impl SessionLine {
    /// The user name before the brackets: the account MySQL matched for privileges. Empty where
    /// the server wrote none, as for a replication applier thread.
    pub fn user(&self) -> Bytes {
        self.user.clone()
    }

    /// The user name inside the brackets: the name the client connected as.
    pub fn sys_user(&self) -> Bytes {
        self.sys_user.clone()
    }

    /// The client's host name, where the line carried one.
    pub fn host(&self) -> Option<Bytes> {
        self.host.clone()
    }

    /// The client's IP address as the server wrote it, IPv4 or IPv6, where the line carried one.
    pub fn ip_address(&self) -> Option<Bytes> {
        self.ip_address.clone()
    }

    /// The connection's thread id, the line's `Id:`. `None` where the server wrote no `Id:`, as
    /// MySQL 5.5 and MariaDB do.
    pub fn thread_id(&self) -> Option<u32> {
        self.thread_id
    }
}

/// The server a slow log's first line declares.
///
/// Every claim a reader makes about MySQL's *behaviour* — which statements block which, whether
/// a DDL takes readers down with it, whether a `GROUP BY` sorts — holds only for a given server
/// version, and this is the only place a log states one. The same statement text obeys different
/// rules under 5.7 and under 8.0.
#[derive(Debug, PartialEq, Default, Clone)]
pub struct HeaderLines {
    version: Bytes,
    tcp_port: Option<usize>,
    socket: Option<Bytes>,
    named_pipe: Option<Bytes>,
}

impl HeaderLines {
    /// The server version string exactly as the file spelled it, e.g.
    /// `5.7.20-log (MySQL Community Server (GPL)).`
    ///
    /// Unparsed on purpose: turning it into a `(major, minor, patch)` is a reading, and one that
    /// a distribution suffix (`-log`, `-MariaDB`, `-percona`) can break. Whoever needs a
    /// comparison makes it, on the bytes the server wrote.
    pub fn version(&self) -> &Bytes {
        &self.version
    }

    /// The TCP port the server was listening on, where the line carried one.
    pub fn tcp_port(&self) -> Option<usize> {
        self.tcp_port
    }

    /// The unix socket path, where the line carried one.
    pub fn socket(&self) -> Option<&Bytes> {
        self.socket.as_ref()
    }

    /// The Windows named pipe, where the line carried one. A server on Windows writes
    /// `TCP Port: 3306, Named Pipe: MySQL` where a unix server writes its socket.
    pub fn named_pipe(&self) -> Option<&Bytes> {
        self.named_pipe.as_ref()
    }
}

/// Parses one header block: the `<program>, Version: <version> started with:` line, the line
/// naming the port and the socket or named pipe, and the `Time  Id Command  Argument` column
/// line where it follows.
///
/// Refused as a backtrack where the first line is not a header's, and as a cut where it is and
/// the next line is not the listener line.
pub fn log_header(i: &mut Stream<'_>) -> ModalResult<HeaderLines> {
    trace("log_header", move |input: &mut Stream<'_>| {
        not(literal("#")).parse_next(input)?;
        let first = line
            .verify(|l: &[u8]| is_header_start(l))
            .parse_next(input)?;
        let version = header_version(first).unwrap_or_default();

        let mut listener = cut_err(line).parse_next(input)?;
        let (tcp_port, socket, named_pipe) = cut_err(listener_line).parse_next(&mut listener)?;

        let _ = opt(line.verify(|l: &[u8]| l.starts_with(b"Time"))).parse_next(input)?;

        Ok(HeaderLines {
            version,
            tcp_port,
            socket,
            named_pipe,
        })
    })
    .parse_next(i)
}

/// Whether `line` opens a header block: `<program>, Version: <version> started with:`.
pub(crate) fn is_header_start(line: &[u8]) -> bool {
    !line.starts_with(b"#") && header_version(line).is_some()
}

/// The version between `, Version: ` and a trailing ` started with:`, where both are there and
/// something is between them.
fn header_version(line: &[u8]) -> Option<Bytes> {
    const MARK: &[u8] = b", Version: ";
    let start = line.windows(MARK.len()).position(|w| w == MARK)? + MARK.len();
    let end = line.trim_ascii_end().strip_suffix(b" started with:")?.len();
    (start < end).then(|| Bytes::copy_from_slice(&line[start..end]))
}

/// `Tcp port: 12345  Unix socket: /tmp/mysql.sock`, or `TCP Port: 3306, Named Pipe: MySQL`.
#[allow(clippy::type_complexity)]
fn listener_line(i: &mut &[u8]) -> ModalResult<(Option<usize>, Option<Bytes>, Option<Bytes>)> {
    let port = preceded(
        (literal(Caseless("Tcp port:")), space0),
        opt(digit1.verify_map(decimal)),
    )
    .parse_next(i)?;

    alt((
        preceded((space1, literal("Unix socket:")), rest).map(|s: &[u8]| (written(s), None)),
        preceded((space0, literal(","), space0, literal("Named Pipe:")), rest)
            .map(|p: &[u8]| (None, written(p))),
    ))
    .map(|(socket, pipe)| (port, socket, pipe))
    .parse_next(i)
}

/// The statement's bytes, up to and including the `;` that ends it.
///
/// MySQL writes the text the client sent and then `;` and a line ending, whatever that text
/// ended in, so the terminator is not a SQL token: it can follow an open quote or sit inside a
/// `--` comment the client left unterminated, and a client's own trailing `;` makes it `;;`. The
/// rule is positional instead. A statement ends at a `;` that ends its line and whose next line
/// opens the next entry (`# Time:` or `# User@Host:`), opens a header block, or is the end of the
/// input; blank lines between the two are allowed. A `;` inside a line or at the end of a line in
/// a compound body (`BEGIN … END`) does not end it.
///
/// What the rule cannot frame is a statement whose own text holds a line ending in `;` followed
/// by a line beginning `# Time:` or `# User@Host:`, such as a slow log quoted with raw newlines
/// in a string or a comment. It ends there, and decoding resumes at the line after.
///
/// The bytes are already contiguous in the buffer the decoder handed over, so the scan decides a
/// length and `take` takes it in one copy.
///
/// The refusal is winnow's: an end not yet in the bytes is `Incomplete` on a partial stream and
/// a backtrack on a complete one, which is the distinction the decoder's loop turns into "read
/// more" against "stop".
pub fn sql_lines(i: &mut Stream<'_>) -> ModalResult<Bytes> {
    trace("sql_lines", move |input: &mut Stream<'_>| {
        let end = statement_end(input.as_bytes(), !input.is_partial());

        match end {
            Some(n) => Ok(Bytes::copy_from_slice(take(n).parse_next(input)?)),
            None if input.is_partial() => Err(WinnowError::incomplete(input, Needed::new(1))),
            None => Err(WinnowError::from_input(input)),
        }
    })
    .parse_next(i)
}

/// One past the `;` that ends the statement at the head of `bytes`, by the rule in
/// [`sql_lines`], or `None` where the bytes in hand do not settle it.
///
/// With `complete` the end of `bytes` is the end of the input. Without it, `None` means read
/// more: deciding needs the rest of the line after a `;`, and enough of the next line to say
/// whether it opens an entry.
pub(crate) fn statement_end(bytes: &[u8], complete: bool) -> Option<usize> {
    let mut from = 0;

    while let Some(at) = bytes[from..].iter().position(|&b| b == b';') {
        from += at + 1;

        let after = &bytes[from..];
        let blanks = after
            .iter()
            .take_while(|&&b| b == b' ' || b == b'\t')
            .count();
        let next = match &after[blanks..] {
            [] => return complete.then_some(from),
            [b'\n', ..] => blanks + 1,
            [b'\r', b'\n', ..] => blanks + 2,
            [b'\r'] => return complete.then_some(from),
            _ => continue,
        };

        match opens_entry(&after[next..], complete) {
            Some(true) => return Some(from),
            Some(false) => continue,
            None => return None,
        }
    }

    None
}

/// Whether the text after a line ending opens the next entry or a header block, or is the end
/// of the input; `None` where the bytes in hand are too few to say.
fn opens_entry(rest: &[u8], complete: bool) -> Option<bool> {
    const ENTRY: [&[u8]; 2] = [b"# Time:", b"# User@Host:"];

    let rest = rest.trim_ascii_start();
    if rest.is_empty() {
        return complete.then_some(true);
    }

    if rest[0] == b'#' {
        if ENTRY.iter().any(|p| rest.starts_with(p)) {
            return Some(true);
        }
        if !complete && ENTRY.iter().any(|p| p.starts_with(rest)) {
            return None;
        }
        return Some(false);
    }

    match rest.iter().position(|&b| b == b'\n') {
        Some(n) => Some(is_header_start(&rest[..n])),
        None if complete => Some(is_header_start(rest)),
        None => None,
    }
}

/// Parses an entry's `# User@Host:` line: `priv_user[user] @ host [ip]`, then `Id:` where the
/// server wrote one.
///
/// Every field is read as written up to the delimiter that ends it, so a name may hold `-`, `.`
/// or digits anywhere, the address may be IPv4 or IPv6, and any of them may be empty: a
/// replication applier writes `[SQL_SLAVE] @  []`. MySQL 5.5 and MariaDB write no `Id:`.
pub fn entry_user(i: &mut Stream) -> ModalResult<SessionLine> {
    trace("entry_user", move |input: &mut Stream<'_>| {
        let mut l = preceded(peek(literal("# User@Host:")), line).parse_next(input)?;

        let (user, sys_user, host, ip_address, thread_id) = seq!(
            _: literal("# User@Host:"),
            _: space0,
            take_till(0.., b'['),
            _: literal("["),
            take_till(0.., b']'),
            _: literal("]"),
            _: space0,
            _: literal("@"),
            _: space0,
            take_till(0.., (b' ', b'\t', b'[')),
            _: space0,
            _: literal("["),
            take_till(0.., b']'),
            _: literal("]"),
            opt(preceded((space1, literal("Id:"), space0), digit1.verify_map(decimal))),
            _: space0,
            _: eof,
        )
        .parse_next(&mut l)?;

        Ok(SessionLine {
            user: Bytes::copy_from_slice(user),
            sys_user: Bytes::copy_from_slice(sys_user),
            host: written(host),
            ip_address: written(ip_address),
            thread_id,
        })
    })
    .parse_next(i)
}

/// The key/value pairs parsed from the comment preceding a SQL statement.
///
/// The comment is a `--` line immediately before the statement, as in
/// `-- file: app.rb, line: 12`: a key is ASCII letters, digits and `_`, followed by `:` or `=`,
/// and pairs are separated by `,` or `;`.
///
/// Whatever the comment said, under the names it used. Applications annotate with whatever keys
/// they like, so a fixed set of fields would admit only those. Deciding that two logs' keys name
/// the same thing is a judgement that belongs to whoever is comparing them, and
/// [`crate::EntryCodecConfig::map_comment_context`] is where a caller says so.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SqlStatementContext {
    /// Every pair the comment carried, keys and values exactly as written.
    pub entries: HashMap<Bytes, Bytes>,
}

impl SqlStatementContext {
    /// Builds a context from the pairs a comment parsed into. `None` where there were none, so a
    /// context always carries at least one pair.
    pub fn new(entries: HashMap<Bytes, Bytes>) -> Option<Self> {
        if entries.is_empty() {
            None
        } else {
            Some(Self { entries })
        }
    }

    /// The value written under `key`, lossily decoded.
    pub fn get(&self, key: &str) -> Option<Cow<'_, str>> {
        self.entries
            .get(key.as_bytes())
            .map(|v| String::from_utf8_lossy(v.as_ref()))
    }

    /// The value written under `key`, as it arrived.
    pub fn get_bytes(&self, key: &str) -> Option<Bytes> {
        self.entries.get(key.as_bytes()).cloned()
    }

    /// The value under `key` parsed as `T`. `None` both where the key is absent and where it
    /// will not parse -- a caller that needs to tell those apart uses `get` and parses itself.
    pub fn get_parsed<T: FromStr>(&self, key: &str) -> Option<T> {
        self.get(key).and_then(|v| v.trim().parse().ok())
    }

    /// The keys the comment used, in no particular order.
    pub fn keys(&self) -> impl Iterator<Item = Cow<'_, str>> {
        self.entries
            .keys()
            .map(|k| String::from_utf8_lossy(k.as_ref()))
    }

    /// Whether the comment carried no pairs at all.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

pub fn details_comment(i: &mut Stream) -> ModalResult<HashMap<Bytes, Bytes>> {
    trace("details_comment", move |input: &mut Stream<'_>| {
        let mut name: Option<Bytes> = None;

        let mut res: HashMap<Bytes, BytesMut> = HashMap::new();

        let _ = literal("--").parse_next(input)?;

        loop {
            if name.is_none()
                && let Ok(n) = details_tag(input)
            {
                name.replace(n.clone());
                if res.insert(n, BytesMut::new()).is_some() {
                    // A key written twice is refused rather than overwritten.
                    return Err(ErrMode::Cut(ContextError::new()));
                }
            }

            if let Ok(c) = any::<Partial<&[u8]>, InputError<_>>(input) {
                let c = c as char;

                if c == '\n' || c == '\r' {
                    break;
                }

                if c == ';' || c == ',' {
                    name = None;
                    continue;
                }

                if let Some(k) = &name {
                    let v = &mut res.get_mut(k).ok_or(ErrMode::Cut(ContextError::new()))?;

                    v.put_bytes(c as u8, 1);
                } else {
                    // A value with no key before it is refused.
                    return Err(ErrMode::Cut(ContextError::new()));
                }

                continue;
            } else {
                break;
            }
        }

        Ok(res.into_iter().map(|(k, v)| (k, v.freeze())).collect())
    })
    .parse_next(i)
}

pub fn details_tag(i: &mut Stream) -> ModalResult<Bytes> {
    trace("details_tag", move |input: &mut Stream<'_>| {
        let name = seq!(
            _: multispace0,
            user_name,
            _: multispace0,
            _: alt((literal(":"), literal("="))),
            _: multispace0,
        )
        .parse_next(input)?;

        Ok(name.0)
    })
    .parse_next(i)
}

pub fn user_name(i: &mut Stream) -> ModalResult<Bytes> {
    trace("user_name", move |input: &mut Stream<'_>| {
        let parts: Vec<&[u8]> =
            repeat(1.., alt((alphanumeric1, literal("_")))).parse_next(input)?;

        let b = parts.iter().fold(BytesMut::new(), |mut acc, p| {
            acc.put_slice(p);
            acc
        });

        Ok(b.freeze())
    })
    .parse_next(i)
}

/// The values of an entry's `# Query_time:` line.
#[derive(Clone, Debug, PartialEq)]
pub struct StatsLine {
    /// how long the overall query took, in seconds
    pub(crate) query_time: f64,
    /// how long the query waited to acquire locks, in seconds
    pub(crate) lock_time: f64,
    /// how many rows were sent
    pub(crate) rows_sent: u64,
    /// how many rows were examined
    pub(crate) rows_examined: u64,
    /// the `Name: value` fields after `Rows_examined`, in the order written
    pub(crate) extra: Vec<(Bytes, Bytes)>,
}

impl StatsLine {
    /// how long the overall query took, in seconds
    pub fn query_time(&self) -> f64 {
        self.query_time
    }
    /// how long the query waited to acquire locks, in seconds
    pub fn lock_time(&self) -> f64 {
        self.lock_time
    }

    /// how many rows were sent
    pub fn rows_sent(&self) -> u64 {
        self.rows_sent
    }
    /// how many rows were examined
    pub fn rows_examined(&self) -> u64 {
        self.rows_examined
    }

    /// Every further `Name: value` field of the entry's comment lines, in the order written, names
    /// and values as the server spelled them.
    pub fn extra(&self) -> &[(Bytes, Bytes)] {
        &self.extra
    }
}

/// Parses an entry's `# Query_time:` line, and the `# Name: value` lines around it.
///
/// `Query_time`, `Lock_time`, `Rows_sent` and `Rows_examined` in that order, then any number of
/// further `Name: value` fields: MySQL 8.0 writes them under `log_slow_extra`, and Percona Server
/// writes `Rows_affected`. The row counts are 64-bit; one that does not fit is refused.
///
/// MariaDB and Percona Server also write whole lines of such fields before and after it, as in
/// `# Thread_id: 8  Schema: shop  QC_hit: No` and `# Rows_affected: 0  Bytes_sent: 60`. Their
/// fields join the line's own in [`StatsLine::extra`], in the order written. A comment line that
/// is not `Name: value` fields is refused, as is MariaDB's `# explain:` block.
pub fn parse_entry_stats(i: &mut Stream<'_>) -> ModalResult<StatsLine> {
    trace("parse_entry_stats", move |input: &mut Stream<'_>| {
        let mut extra = Vec::new();

        while opt(peek(literal("# Query_time:")))
            .parse_next(input)?
            .is_none()
        {
            extra.extend(field_line(input)?);
        }

        let mut l = line(input)?;
        let (query_time, lock_time, rows_sent, rows_examined, fields): (_, _, _, _, Vec<_>) = seq!(
            _: literal("#"),
            _: space1,
            _: literal("Query_time:"),
            _: space1,
            float,
            _: space1,
            _: literal("Lock_time:"),
            _: space1,
            float,
            _: space1,
            _: literal("Rows_sent:"),
            _: space1,
            digit1.verify_map(decimal),
            _: space1,
            _: literal("Rows_examined:"),
            _: space1,
            digit1.verify_map(decimal),
            repeat(0.., stats_field),
            _: space0,
            _: eof,
        )
        .parse_next(&mut l)?;
        extra.extend(fields);

        while let Some(fields) = opt(field_line).parse_next(input)? {
            extra.extend(fields);
        }

        Ok(StatsLine {
            query_time,
            lock_time,
            rows_sent,
            rows_examined,
            extra,
        })
    })
    .parse_next(i)
}

/// A comment line made only of `Name: value` fields, as MariaDB and Percona Server write around
/// the `# Query_time:` line. The lines that open an entry or a statement are not among them.
fn field_line(i: &mut Stream<'_>) -> ModalResult<Vec<(Bytes, Bytes)>> {
    not(alt((
        literal("# Time:"),
        literal("# User@Host:"),
        literal("# Query_time:"),
        literal("# administrator command:"),
    )))
    .parse_next(i)?;

    let mut l = preceded(peek(literal("#")), line).parse_next(i)?;
    seq!(_: literal("#"), repeat(1.., stats_field), _: space0, _: eof)
        .map(|t| t.0)
        .parse_next(&mut l)
}

/// One `Name: value` field of a comment line.
///
/// One space at most after the `:`, because a server writes an empty value as nothing: MariaDB's
/// `Schema:   QC_hit: No` is a `Schema` with no database followed by `QC_hit`.
fn stats_field(i: &mut &[u8]) -> ModalResult<(Bytes, Bytes)> {
    seq!(
        _: space1,
        take_while(1.., (AsChar::is_alphanum, b'_')),
        _: literal(":"),
        _: opt(literal(" ")),
        take_till(0.., (b' ', b'\t')),
    )
    .map(|(name, value): (&[u8], &[u8])| {
        (Bytes::copy_from_slice(name), Bytes::copy_from_slice(value))
    })
    .parse_next(i)
}

/// An administrator command, `# administrator command: Quit;`, logged in place of a statement.
#[derive(Clone, Debug, PartialEq)]
pub struct EntryAdminCommand {
    /// The command as the log spelled it, e.g. `Quit` or `Init DB`, without the `;`.
    pub command: Bytes,
}

/// parse "# administrator command: " entry line
pub fn admin_command(i: &mut Stream) -> ModalResult<EntryAdminCommand> {
    trace("admin_command", move |input: &mut Stream<'_>| {
        let command = seq!(
            _: literal("# administrator command:"),
            _: space1,
            // To the `;` and not one word, because many of MySQL's administrator commands carry
            // a space: `Init DB`, `Register Slave`, `Binlog Dump`, `Table Dump`, `Change user`,
            // `Close stmt`, `Reset stmt`, `Long Data`, `Set option`, `Field List`, `Create DB`,
            // `Drop DB`, `Process info`, `Connect Out`, `Delayed insert`. A parser that matched
            // one alphanumeric run would fail here, and the caller in `codec.rs` wraps this in
            // `opt` for that reason: winnow does not rewind a parser that failed after
            // consuming, so a mid-line failure would leave the rest of the line to be read as
            // the statement's SQL.
            take_till(1.., (b';', b'\r', b'\n')),
            _: literal(";"),
        )
        .parse_next(input)?;

        Ok(EntryAdminCommand {
            // `space1` ate the leading run; trailing spaces before the `;` are ours.
            command: command.0.trim_ascii_end().to_owned().into(),
        })
    })
    .parse_next(i)
}

/// Parses the `use <database>;` line that precedes an entry's `SET timestamp` where the
/// database changed.
///
/// MySQL writes the name as it is and unquoted, so everything between `use` and the `;` that
/// ends the line is the name, `-` and `.` included. A name wrapped in backticks is unquoted,
/// with a doubled backtick read as one.
pub fn use_database(i: &mut Stream) -> ModalResult<Bytes> {
    trace("use_database", move |input: &mut Stream<'_>| {
        let mut l = preceded(peek(literal(Caseless("use"))), line).parse_next(input)?;

        let after = preceded((literal(Caseless("use")), space1), rest).parse_next(&mut l)?;
        let Some(name) = after.trim_ascii_end().strip_suffix(b";") else {
            return refused();
        };
        let name = name.trim_ascii();

        let name = match name.strip_prefix(b"`").and_then(|n| n.strip_suffix(b"`")) {
            Some(quoted) => unquote_backticks(quoted),
            None => Bytes::copy_from_slice(name),
        };

        if name.is_empty() {
            return refused();
        }
        Ok(name)
    })
    .parse_next(i)
}

/// The inside of a backtick-quoted identifier, with each doubled backtick read as one.
fn unquote_backticks(quoted: &[u8]) -> Bytes {
    let mut out = Vec::with_capacity(quoted.len());
    let mut i = 0;
    while i < quoted.len() {
        out.push(quoted[i]);
        i += if quoted[i] == b'`' && quoted.get(i + 1) == Some(&b'`') {
            2
        } else {
            1
        };
    }
    Bytes::from(out)
}

/// The values of the `SET …;` line that precedes every statement.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(crate) struct SetLine {
    pub(crate) timestamp: u32,
    pub(crate) last_insert_id: Option<u64>,
    pub(crate) insert_id: Option<u64>,
}

/// Parses the `SET timestamp=<unix seconds>;` line that precedes every statement.
///
/// MySQL writes `last_insert_id=` and `insert_id=` in front of `timestamp=` where the statement
/// read `LAST_INSERT_ID()` or generated an auto-increment value, as in
/// `SET insert_id=7,timestamp=1517798807;`. Refused: a line with no `timestamp`, a name outside
/// those three or written twice, and a value that does not fit, the timestamp being a `u32`.
pub fn start_timestamp_command(i: &mut Stream) -> ModalResult<SetLine> {
    trace("start_timestamp_command", move |input: &mut Stream<'_>| {
        let mut l = preceded(peek(literal("SET ")), line).parse_next(input)?;

        let (assignments,): (Vec<(&[u8], u64)>,) = seq!(
            _: literal("SET"),
            _: space1,
            separated(
                1..,
                seq!(
                    take_while(1.., (AsChar::is_alpha, b'_')),
                    _: space0,
                    _: literal("="),
                    _: space0,
                    digit1.verify_map(decimal),
                ),
                (space0, literal(","), space0),
            ),
            _: space0,
            _: literal(";"),
            _: space0,
            _: eof,
        )
        .parse_next(&mut l)?;

        let mut timestamp = None;
        let mut set = SetLine::default();
        for (name, value) in assignments {
            let slot = match name {
                b"timestamp" if timestamp.is_none() => {
                    timestamp = u32::try_from(value).ok();
                    if timestamp.is_none() {
                        return refused();
                    }
                    continue;
                }
                b"last_insert_id" => &mut set.last_insert_id,
                b"insert_id" => &mut set.insert_id,
                _ => return refused(),
            };
            if slot.replace(value).is_some() {
                return refused();
            }
        }

        match timestamp {
            Some(t) => Ok(SetLine {
                timestamp: t,
                ..set
            }),
            None => refused(),
        }
    })
    .parse_next(i)
}

/// One literal value the author wrote.
///
/// `WHERE tenant_id = 42` is the author's claim about which rows the statement was about.
/// Masking replaces the value with `?`, which is a reader's assertion that two authors' subjects
/// are interchangeable; recording the literal here is what makes masking a grouping choice rather
/// than an edit to the document.
///
/// No source position: [`EntryLiteral::ordinal`] is the position, and it is exact because one
/// pass both records and masks, so the two cannot fall out of step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryLiteral {
    /// Position in the statement's own value order, counting from zero.
    ///
    /// Deterministic: the traversal is depth-first in field-declaration order, emitted by
    /// `sqlparser_derive`. It is stable within a `sqlparser` version, and nothing promises it
    /// across one.
    pub ordinal: u32,
    /// The literal rendered as SQL, quoting and all. The rendering is `sqlparser`'s, so escapes
    /// are normalised and `0x41` reads `X'41'`; the author's exact bytes are in
    /// [`crate::EntrySqlAttributes::sql_raw`].
    pub rendered: Bytes,
    /// The payload without its quoting -- what a reader groups by.
    pub value: Bytes,
    /// Which kind of literal it is.
    pub kind: LiteralKind,
    /// The column the author compared this value against, where the syntax names one. A value
    /// means something only in a domain, and the domain is a column of a relation: without it
    /// `42` the tenant and `42` the row limit are one value.
    ///
    /// `None` where the value sits in a position that names no column: a `CREATE TABLE` default,
    /// a `LIMIT`, a `SET` value and a function argument are literals the author wrote there, and
    /// they select no rows.
    ///
    /// Five syntactic shapes reach this, and they are not all the same claim. A comparison, an
    /// `IN` list and a `BETWEEN` bound name the column a value is *sought* in; `UPDATE … SET qty
    /// = 5` and `INSERT … (qty) VALUES (5)` name the column a value is *written* to, which is a
    /// key the statement creates or changes rather than one it looks up. [`Self::sought`] is what
    /// tells them apart, because a lock taken to find a row and a lock taken to write one are
    /// different locks. The value must be the shape's direct operand: one under a unary minus,
    /// in parentheses or behind a charset introducer is `None`, as is one written by
    /// `INSERT … SET` or `ON DUPLICATE KEY UPDATE`.
    pub column: Option<LiteralColumn>,
    /// Whether the author was **looking for** this value or **writing** it.
    ///
    /// A log may contain no predicate at all — a restore only ever writes — so a caller that
    /// reads only sought values can find nothing where the author bound a great many.
    ///
    /// `false` on an unbound literal, where it asserts nothing.
    pub sought: bool,
    /// The position in the row this value was written at, where the `INSERT` named no columns:
    /// the `n`-th value reaches the table's `n`-th column.
    ///
    /// A domain, and not the same one as [`Self::column`]. Which physical column `#n` is lives in
    /// a catalogue no slow log carries, so a positional domain and a named domain over one table
    /// are kept apart rather than fused on a guess.
    pub column_position: Option<u32>,
}

/// The column name an [`EntryLiteral`] was compared against, exactly as the author spelled it.
///
/// The written name and not a relation. `e1.dept_id` carries the qualifier the author used,
/// which is an alias far more often than a table — and an alias is scoped, so resolving it to a
/// relation is a second hop through the statement's own occurrences. That hop belongs to whoever
/// holds the scope tree, which this struct does not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiteralColumn {
    /// Everything before the last `.`, joined as written — an alias, a table, or a schema and a
    /// table. `None` where the author wrote a bare column name.
    ///
    /// A bare name fixes a relation only where the statement names exactly one.
    pub qualifier: Option<Bytes>,
    /// The column name itself.
    pub name: Bytes,
}

/// What kind of literal an [`EntryLiteral`] is.
///
/// A boolean, a `NULL` and a placeholder are not the author's subject and are never recorded.
///
/// [`Self::DoubleQuotedString`] is the ambiguous one. MySQL reads `"…"` as a string literal under
/// its default `sql_mode` and as an identifier under `ANSI_QUOTES`; `MySqlDialect` is fixed and
/// honours no mode, so this arm records the default reading. A slow log does not carry the mode,
/// so nothing here can decide it.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum LiteralKind {
    /// a numeric literal
    Number,
    /// `'...'`
    SingleQuotedString,
    /// `"..."`
    DoubleQuotedString,
    /// `N'...'`
    NationalString,
    /// `X'...'`
    HexString,
}

vocabulary!(LiteralKind {
    DoubleQuotedString => "double_quoted",
    HexString => "hex",
    NationalString => "national",
    Number => "number",
    SingleQuotedString => "single_quoted",
});

/// Parses one or more SQL statements and returns them with every literal the author wrote.
///
/// With `EntryMasking::PlaceHolder` the returned statements carry `?` in place of each literal;
/// the literals come back either way, so **the author's subject survives masking**.
pub fn parse_sql(
    sql: &str,
    mask: &EntryMasking,
) -> Result<(Vec<Statement>, Vec<EntryLiteral>), ParserError> {
    let mut tokenizer = Tokenizer::new(&MySqlDialect {}, sql);
    let tokens = tokenizer.tokenize()?;

    let mut parser = SQLParser::new(&MySqlDialect {}).with_tokens(tokens);
    let mut statements = parser.parse_statements()?;

    let mut pass = LiteralPass {
        literals: Vec::new(),
        mask: mask == &EntryMasking::PlaceHolder,
        binds: Vec::new(),
        targets: HashMap::new(),
        positional: HashMap::new(),
    };
    for s in statements.iter_mut() {
        let _ = s.visit(&mut pass);
    }

    Ok((statements, pass.literals))
}

/// Re-renders one statement's SQL text with a substitute in place of chosen literals, and returns
/// the rendering.
///
/// `replacements[i]` is the new payload for the `i`-th literal this crate records, in the same
/// traversal order and under the same arm filter -- so an ordinal from [`EntryLiteral`] indexes
/// this directly and the two cannot drift apart. `None` leaves a literal alone, and a short slice
/// leaves the tail alone.
///
/// The text must be the author's or an unmasked rendering of it. A masked rendering carries `?`
/// where the literals were, a placeholder is not a literal, and nothing is substituted.
///
/// The kind is taken from the original and never from the caller: a quoted string stays a quoted
/// string, with its quotes escaped. Swapping them changes the statement, because MySQL compares
/// an integer column against a string by coercing it and takes a different path through the
/// index. A number's or a hex literal's payload is written as given and not checked, so a caller
/// substituting one must supply digits.
///
/// Returns `None` where the text does not parse or is not exactly one statement. A caller with a
/// substitute to apply and nothing to apply it to has to withhold, and the `None` is what says
/// so; returning the original would hand back the author's values from a function that promises
/// it did not.
///
/// It re-parses rather than taking a tree, because a caller usually knows its substitutes only
/// once the whole log is read, and by then the trees are gone.
pub fn rewrite_literals(sql: &str, replacements: &[Option<String>]) -> Option<String> {
    let mut tokenizer = Tokenizer::new(&MySqlDialect {}, sql);
    let tokens = tokenizer.tokenize().ok()?;
    let mut parser = SQLParser::new(&MySqlDialect {}).with_tokens(tokens);
    let mut statements = parser.parse_statements().ok()?;
    if statements.len() != 1 {
        return None;
    }

    let mut pass = RewritePass {
        replacements,
        seen: 0,
    };
    let _ = statements[0].visit(&mut pass);
    Some(statements[0].to_string())
}

/// Whether `sql` carries a value the author supplied: `Some(true)` where its tokens include a
/// literal, `Some(false)` where they do not, and `None` where it cannot be tokenized.
///
/// For the statements this grammar refuses, and only those. A statement that parsed has literals
/// with a position — [`EntryLiteral::column`] says whether the author went for a row with one —
/// which is a sharper question than this. A statement with no parse has no positions, so the only
/// thing left to ask is whether there is a value in it at all.
///
/// It over-approximates, and the direction matters: `LIMIT 10` and `SET TIME_ZONE='+00:00'` both
/// answer `true` while naming nobody. A caller withholding on this answer withholds a little more
/// than it must, which costs fidelity and not confidentiality.
///
/// It reads inside MySQL version gates, `/*!40101 … */`, whatever their version, because the
/// server executes what is inside one.
///
/// A value written as an identifier is invisible here, and no token scan can see it: in
/// ``DEFINER=`msandbox`@`%` `` a username and a host are backtick identifiers. A caller must not
/// read a `false` as covering that case.
pub fn carries_a_value(sql: &str) -> Option<bool> {
    fn scan(sql: &str, depth: u32) -> Option<bool> {
        if depth > 4 {
            return Some(false);
        }
        let tokens = Tokenizer::new(&MySqlDialect {}, sql).tokenize().ok()?;
        for t in &tokens {
            match t {
                Token::Number(..)
                | Token::SingleQuotedString(_)
                | Token::DoubleQuotedString(_)
                | Token::NationalStringLiteral(_)
                | Token::HexStringLiteral(_)
                | Token::EscapedStringLiteral(_)
                | Token::SingleQuotedByteStringLiteral(_)
                | Token::DoubleQuotedByteStringLiteral(_) => return Some(true),
                Token::Whitespace(Whitespace::MultiLineComment(body)) => {
                    // `MySqlDialect` expands `/*!40101 … */` into tokens itself; what reaches
                    // here is a body that starts `!` only after whitespace.
                    if let Some(rest) = body.trim_start().strip_prefix('!') {
                        let inner = rest.trim_start_matches(|c: char| c.is_ascii_digit());
                        if scan(inner, depth + 1)? {
                            return Some(true);
                        }
                    }
                }
                _ => {}
            }
        }
        Some(false)
    }
    scan(sql, 0)
}

/// The substitution half of [`LiteralPass`], sharing its arm filter and therefore its ordinals.
struct RewritePass<'a> {
    replacements: &'a [Option<String>],
    seen: usize,
}

impl VisitorMut for RewritePass<'_> {
    type Break = ();

    /// The hook takes a `ValueWithSpan`, which carries the source span; the body shadows it to
    /// the inner `Value`, because every arm below is about what the author wrote and assigning
    /// through the inner value leaves the span alone.
    fn pre_visit_value(&mut self, value: &mut ValueWithSpan) -> ControlFlow<Self::Break> {
        let value = &mut value.value;
        // The same arms as `LiteralPass::pre_visit_value`, which is load-bearing: a boolean, a
        // NULL or a placeholder is recorded by neither, so neither advances its counter over one.
        // An ordinal that meant a different literal in the two passes would substitute into the
        // wrong slot.
        if !matches!(
            value,
            Value::Number(..)
                | Value::SingleQuotedString(_)
                | Value::DoubleQuotedString(_)
                | Value::NationalStringLiteral(_)
                | Value::HexStringLiteral(_)
        ) {
            return ControlFlow::Continue(());
        }
        let i = self.seen;
        self.seen += 1;
        let Some(Some(new)) = self.replacements.get(i) else {
            return ControlFlow::Continue(());
        };
        // Assigning through `&mut Value` leaves the `ValueWithSpan` wrapper alone, for the same
        // reason masking does.
        *value = match &*value {
            Value::Number(_, long) => Value::Number(new.clone(), *long),
            Value::SingleQuotedString(_) => Value::SingleQuotedString(new.clone()),
            Value::DoubleQuotedString(_) => Value::DoubleQuotedString(new.clone()),
            Value::NationalStringLiteral(_) => Value::NationalStringLiteral(new.clone()),
            Value::HexStringLiteral(_) => Value::HexStringLiteral(new.clone()),
            other => other.clone(),
        };
        ControlFlow::Continue(())
    }
}

/// Records every literal in a statement, and replaces it where asked, in one traversal.
///
/// After the parse and never before it. Replacing tokens first destroys well-formed statements,
/// because a number inside a type declaration is not a value and `CHAR(?)`, `DECIMAL(?,?)` and
/// `INT(?)` are not SQL. After the parse the ambiguity is gone: a type parameter is not a `Value`
/// and a literal is.
///
/// `pre_visit_value` and not `Expr::Value`: `Expr::TypedString` (`DATE '2020-01-01'`) and
/// `Expr::MatchAgainst` (MySQL's `AGAINST ('term')`) hold a `Value` without being one, so an
/// `Expr`-shaped pass would neither mask nor record them.
///
/// It reaches a few `Value`s that select no rows -- a `CEIL(x TO 2)` scale, a `TABLESAMPLE` seed.
/// Those are grammar rather than subject, and masking one is wrong in the same way masking a type
/// parameter would be, but it cannot break a parse: the tree already exists.
struct LiteralPass {
    literals: Vec<EntryLiteral>,
    mask: bool,
    /// One entry per enclosing `Expr`, saying what a value **directly beneath it** is compared
    /// against.
    ///
    /// The parent and only the parent. `pre_visit_value` fires inside the `Expr::Value` node, so
    /// the stack reads `[…, the comparison, Expr::Value]` and the binding is at `len - 2`.
    /// Searching further up would let `WHERE a = f(g(1))` bind `1` to `a`, which is a claim the
    /// author did not make: the value is an argument, not a key.
    binds: Vec<Option<LiteralColumn>>,
    /// Values reached through a node that is **not** an `Expr`, by the address of the value.
    ///
    /// An `Assignment` and an `INSERT` column list are not expressions, so no hook on this
    /// visitor sees the column beside the value and [`Self::binds`] cannot reach them at any
    /// depth. On a log that only ever wrote, these are the only bound literals there are.
    ///
    /// Keyed on the value's address and never on its payload: `INSERT INTO t (a, b) VALUES (5,
    /// 5)` writes one payload into two columns, and a payload-matched queue would hand both to
    /// whichever it met first. The address is taken in `pre_visit_statement`, which runs before
    /// the statement's children and therefore before anything is masked; masking assigns through
    /// `&mut Value` and moves no node, so the address still names the same slot when
    /// `pre_visit_value` reaches it. Nothing is ever dereferenced.
    targets: HashMap<usize, LiteralColumn>,
    /// Values written by an `INSERT` that named no columns, by address, with the position in the
    /// row they were written at.
    ///
    /// The column is recoverable positionally: an `INSERT` with no column list writes in the
    /// table's own column order, so the `n`-th value reaches the `n`-th column for every such
    /// statement against that table. Kept apart from [`Self::targets`] because a positional
    /// domain and a named one are not known to be the same domain; deciding that needs the
    /// catalogue.
    positional: HashMap<usize, u32>,
}

/// The column name an `ObjectName` spells, split into its qualifier and its last part.
fn column_of_name(n: &ObjectName) -> Option<LiteralColumn> {
    let mut parts: Vec<String> =
        n.0.iter()
            .filter_map(|p| p.as_ident().map(|i| i.value.clone()))
            .collect();
    let name = parts.pop()?;
    Some(LiteralColumn {
        qualifier: parts.is_empty().not().then(|| Bytes::from(parts.join("."))),
        name: Bytes::from(name),
    })
}

/// Records the address of every literal a **non-expression** node pairs with a column.
///
/// `UPDATE … SET (a, b) = (…)` -- `AssignmentTarget::Tuple` -- is deliberately not here. The
/// tuple's right-hand side is one `Expr` rather than a list, so which column each value inside it
/// goes to is a positional reading of a subquery or a row constructor, and MySQL does not write
/// it down.
fn statement_targets(
    s: &Statement,
    out: &mut HashMap<usize, LiteralColumn>,
    positional: &mut HashMap<usize, u32>,
) {
    let mut put = |col: Option<LiteralColumn>, e: &Expr| {
        if let (Some(c), Expr::Value(v)) = (col, e) {
            out.insert(std::ptr::from_ref(&v.value).addr(), c);
        }
    };
    match s {
        Statement::Update(u) => {
            for a in &u.assignments {
                if let AssignmentTarget::ColumnName(n) = &a.target {
                    put(column_of_name(n), &a.value);
                }
            }
        }
        Statement::Insert(i) => {
            let Some(q) = &i.source else { return };
            let SetExpr::Values(vs) = q.body.as_ref() else {
                return;
            };
            for row in &vs.rows {
                // An `INSERT` with no column list is still writing the author's data, so its
                // values must not be filed as naming no column at all -- the bucket a `LIMIT` and
                // a `CREATE TABLE` default sit in.
                if i.columns.is_empty() {
                    // The column is recoverable positionally: such an `INSERT` writes in the
                    // table's own column order, so the `n`-th value goes to the `n`-th column for
                    // every such statement against that table, which is what makes `(relation,
                    // #n)` a domain rather than a label.
                    //
                    // It is not the same domain as a named one and must not be fused with it.
                    // `INSERT INTO t (b, a) VALUES (1, 2)` puts `1` in `b`, and `INSERT INTO t
                    // VALUES (1, 2)` puts `1` in the table's first column, which the log does not
                    // say is `b`. Deciding they are one needs the catalogue.
                    for (n, e) in row.content.iter().enumerate() {
                        if let Expr::Value(v) = e {
                            positional.insert(std::ptr::from_ref(&v.value).addr(), n as u32);
                        }
                    }
                    continue;
                }
                // `Insert.columns` holds an `ObjectName` per column, because a column list entry
                // can be qualified in some dialects. MySQL's cannot, so the last part is the
                // column and `column_of_name` is what says so.
                for (col, e) in i.columns.iter().zip(&row.content) {
                    put(column_of_name(col), e);
                }
            }
        }
        _ => {}
    }
}

/// The column a value **directly beneath this expression** is sought in, where there is one.
///
/// Comparison operators only. `Expr::BinaryOp` covers `+` as well as `=`, so a rule that took any
/// binary operator would bind the `1` in `qty + 1` to `qty` — filing arithmetic as a key lookup,
/// in a field whose purpose is to say which rows a statement went for.
fn binding_of(e: &Expr) -> Option<LiteralColumn> {
    let is_value = |x: &Expr| matches!(x, Expr::Value(_));
    match e {
        Expr::BinaryOp { left, op, right } if is_comparison(op) => {
            if is_value(right) {
                column_of(left)
            } else if is_value(left) {
                column_of(right)
            } else {
                None
            }
        }
        // Every member of an `IN` list is sought in the same column, so one binding serves them
        // all — and they are direct children, which is what makes that exact.
        Expr::InList { expr, list, .. } if list.iter().any(is_value) => column_of(expr),
        // A range: the bound is a claim about a stretch of the index rather than about one row,
        // which is where InnoDB's next-key locking applies.
        Expr::Between {
            expr, low, high, ..
        } if is_value(low) || is_value(high) => column_of(expr),
        _ => None,
    }
}

/// Whether this operator makes its two sides a comparison rather than a computation.
fn is_comparison(op: &BinaryOperator) -> bool {
    use BinaryOperator as B;
    matches!(
        op,
        // `<=>` is MySQL's own NULL-safe equality and belongs here for the same reason `=` does:
        // it names rows.
        B::Eq | B::NotEq | B::Lt | B::LtEq | B::Gt | B::GtEq | B::Spaceship
    )
}

/// The written column name, where this expression is one.
fn column_of(e: &Expr) -> Option<LiteralColumn> {
    match e {
        Expr::Identifier(i) => Some(LiteralColumn {
            qualifier: None,
            name: Bytes::from(i.value.clone()),
        }),
        Expr::CompoundIdentifier(parts) => {
            let (last, rest) = parts.split_last()?;
            Some(LiteralColumn {
                qualifier: rest.is_empty().not().then(|| {
                    Bytes::from(
                        rest.iter()
                            .map(|p| p.value.clone())
                            .collect::<Vec<_>>()
                            .join("."),
                    )
                }),
                name: Bytes::from(last.value.clone()),
            })
        }
        _ => None,
    }
}

impl VisitorMut for LiteralPass {
    type Break = ();

    fn pre_visit_statement(&mut self, statement: &mut Statement) -> ControlFlow<Self::Break> {
        statement_targets(statement, &mut self.targets, &mut self.positional);
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, expr: &mut Expr) -> ControlFlow<Self::Break> {
        // Read before the value beneath is masked: `pre_visit_value` replaces the value with a
        // placeholder, and a binding computed afterwards would see `?` on both sides.
        self.binds.push(binding_of(expr));
        ControlFlow::Continue(())
    }

    fn post_visit_expr(&mut self, _expr: &mut Expr) -> ControlFlow<Self::Break> {
        self.binds.pop();
        ControlFlow::Continue(())
    }

    /// Shadowed to the inner `Value`, as in [`RewritePass::pre_visit_value`], so `addr` below is
    /// the inner `Value`'s — which is what `targets` and `positional` are keyed on.
    fn pre_visit_value(&mut self, value: &mut ValueWithSpan) -> ControlFlow<Self::Break> {
        let value = &mut value.value;
        let (kind, payload) = match value {
            Value::Number(n, _) => (LiteralKind::Number, n.clone()),
            Value::SingleQuotedString(v) => (LiteralKind::SingleQuotedString, v.clone()),
            Value::DoubleQuotedString(v) => (LiteralKind::DoubleQuotedString, v.clone()),
            Value::NationalStringLiteral(v) => (LiteralKind::NationalString, v.clone()),
            Value::HexStringLiteral(v) => (LiteralKind::HexString, v.clone()),
            // A boolean, a NULL and a placeholder are not the author's subject: `TRUE` names no
            // rows, and a `?` already in the text was never the author's value.
            _ => return ControlFlow::Continue(()),
        };

        // `len - 2` and never a search: see `LiteralPass::binds`. A value with no enclosing
        // expression at all -- which the traversal does reach -- binds to nothing.
        let sought = self
            .binds
            .len()
            .checked_sub(2)
            .and_then(|i| self.binds[i].clone());
        // The predicate first: a value can only be in one of the two positions, and where it is
        // in neither both are `None`.
        let addr = std::ptr::from_ref(&*value).addr();
        let written = self.targets.get(&addr).cloned();
        let column_position = self.positional.get(&addr).copied();

        self.literals.push(EntryLiteral {
            ordinal: self.literals.len() as u32,
            rendered: Bytes::from(value.to_string()),
            value: Bytes::from(payload),
            kind,
            sought: sought.is_some(),
            column_position,
            column: sought.or(written),
        });

        if self.mask {
            // The inner value and not the wrapper: `Expr::value(..)` would build a fresh
            // `ValueWithSpan` through `with_empty_span()` and discard the source span. Assigning
            // through `&mut Value` leaves the wrapper alone.
            *value = Value::Placeholder("?".to_string());
        }
        ControlFlow::Continue(())
    }
}

#[cfg(test)]
mod every_literal_kind {
    use super::*;

    fn kinds(sql: &str) -> Vec<(LiteralKind, String)> {
        parse_sql(sql, &EntryMasking::None)
            .unwrap_or_else(|e| panic!("{sql}: {e}"))
            .1
            .iter()
            .map(|l| (l.kind, String::from_utf8_lossy(&l.rendered).into_owned()))
            .collect()
    }

    /// EVERY ARM OF [`LiteralKind`] IS REACHED BY MYSQL TEXT, and `E'…'`, which is not MySQL, is
    /// refused.
    #[test]
    fn every_arm_that_a_mysql_literal_reaches_has_one() {
        use LiteralKind as K;
        let cases: &[(&str, K)] = &[
            ("SELECT 1 FROM t WHERE a = 42", K::Number),
            ("SELECT 1 FROM t WHERE a = 4.25", K::Number),
            ("SELECT 1 FROM t WHERE a = 'x'", K::SingleQuotedString),
            ("SELECT 1 FROM t WHERE a = \"x\"", K::DoubleQuotedString),
            ("SELECT 1 FROM t WHERE a = N'x'", K::NationalString),
            ("SELECT 1 FROM t WHERE a = X'41'", K::HexString),
        ];
        let mut seen: std::collections::BTreeSet<String> = Default::default();
        for (sql, want) in cases {
            let got = kinds(sql);
            assert!(
                got.iter().any(|(k, _)| k == want),
                "{sql}: wanted {want:?}, got {got:?}"
            );
            seen.insert(format!("{want:?}"));
        }
        // THE GUARD. Five arms, written out because the enum cannot be iterated.
        assert_eq!(
            seen.len(),
            5,
            "every LiteralKind arm needs text that reaches it; reached {seen:?}"
        );

        // MySQL has no `E'…'` literal and this grammar refuses the text, so there is nothing for
        // an arm to hold.
        assert!(
            parse_sql("SELECT 1 FROM t WHERE a = E'x'", &EntryMasking::None).is_err(),
            "E'…' is not MySQL and this parser does not accept it"
        );
    }

    /// `"x"` IS A LITERAL OR AN IDENTIFIER AND THE LOG DOES NOT SAY WHICH.
    ///
    /// This is not two dialects disagreeing — it is **MySQL disagreeing with itself** depending
    /// on a setting a slow log never records. By default `"x"` is a string literal; under
    /// `sql_mode = 'ANSI_QUOTES'` the same bytes are a quoted **identifier**, which is a column
    /// and not a subject at all. So this arm firing records a literal for text that may have
    /// been a column name.
    ///
    /// The parser is not wrong to pick one: `MySqlDialect` is fixed and honours no mode. What
    /// would be wrong is filing the reading without recording that a reading was made.
    #[test]
    fn a_double_quoted_string_is_the_one_literal_the_mode_can_reinterpret() {
        let got = kinds("SELECT \"name\" FROM person");
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].0, LiteralKind::DoubleQuotedString);
        assert_eq!(got[0].1, "\"name\"", "the author's own spelling is kept");

        // Under `ANSI_QUOTES` this same statement has NO literal and names a column — so the
        // count this crate files for it is 1 under one mode and 0 under the other.
        assert!(
            kinds("SELECT 'name' FROM person")
                .iter()
                .all(|(k, _)| *k == LiteralKind::SingleQuotedString),
            "the unambiguous spelling, for contrast"
        );
    }
}

/// THE SUBSTITUTION, WHICH IS WHAT LETS A STATEMENT SHIP WITHOUT ITS SUBJECT.
#[cfg(test)]
mod a_literal_can_be_replaced_by_its_surrogate {
    use super::*;

    fn lits(sql: &str) -> Vec<String> {
        parse_sql(sql, &EntryMasking::None)
            .unwrap()
            .1
            .iter()
            .map(|l| String::from_utf8_lossy(&l.value).into_owned())
            .collect()
    }

    /// THE ROUND TRIP, WHICH IS THE ONLY THING THAT SAYS THE ORDINALS LINE UP.
    ///
    /// Rewrite every literal to its own recorded value and the statement must come back
    /// unchanged. If [`RewritePass`] counted one arm differently from [`LiteralPass`] -- a
    /// `NULL`, a `TRUE`, a `?` -- every ordinal after it would be off by one and this is what
    /// catches it, on a statement built to contain exactly those.
    #[test]
    fn rewriting_each_literal_to_itself_changes_nothing() {
        let sql = "SELECT a FROM t WHERE id = 42 AND ok = TRUE AND note IS NULL \
                   AND name = 'kay' AND tag = X'41' AND n = N'x' LIMIT 10";
        let rendered = parse_sql(sql, &EntryMasking::None).unwrap().0[0].to_string();
        let same: Vec<Option<String>> = lits(&rendered).into_iter().map(Some).collect();
        assert_eq!(same.len(), 5, "TRUE and NULL are not the author's subject");
        assert_eq!(
            rewrite_literals(&rendered, &same).as_deref(),
            Some(&*rendered)
        );
    }

    /// AND THE SUBSTITUTION LANDS WHERE THE ORDINAL SAYS, not one literal over.
    #[test]
    fn a_surrogate_replaces_the_literal_its_ordinal_names() {
        let sql = "SELECT a FROM t WHERE ok = TRUE AND id = 42 AND other = 99";
        let rendered = parse_sql(sql, &EntryMasking::None).unwrap().0[0].to_string();
        assert_eq!(lits(&rendered), vec!["42", "99"]);
        let out = rewrite_literals(&rendered, &[Some("7".into()), None]).unwrap();
        assert!(out.contains("id = 7"), "{out}");
        assert!(out.contains("other = 99"), "{out}");
    }

    /// THE KIND IS THE ORIGINAL'S AND THE CALLER CANNOT SAY OTHERWISE.
    ///
    /// A number that came back quoted would be a different statement: MySQL coerces the
    /// comparison and takes a different route through the index, so a replay of it contends
    /// somewhere else. The caller supplies a payload and never a type.
    #[test]
    fn a_surrogate_keeps_the_type_the_author_wrote() {
        let n = rewrite_literals("SELECT a FROM t WHERE id = 42", &[Some("7".into())]).unwrap();
        assert!(n.contains("id = 7") && !n.contains("'7'"), "{n}");

        let q = rewrite_literals("SELECT a FROM t WHERE k = '42'", &[Some("7".into())]).unwrap();
        assert!(q.contains("k = '7'"), "{q}");

        // And the mapped statement is still SQL, which is the whole difference between this
        // and a `?` nobody recorded a bind for.
        for out in [n, q] {
            assert!(parse_sql(&out, &EntryMasking::None).is_ok(), "{out}");
        }
    }

    /// TEXT WITH NO PARSE GETS `None` AND NEVER ITS OWN BYTES BACK.
    ///
    /// A caller holding a surrogate and no tree to apply it to must **withhold**. Handing back
    /// the original would return the author's values from a call whose name promises it did not.
    #[test]
    fn text_that_does_not_parse_is_refused_rather_than_returned() {
        assert_eq!(
            rewrite_literals("ALTER TABLE t DISABLE KEYS", &[Some("1".into())]),
            None
        );
        assert_eq!(
            rewrite_literals("LOCK TABLES shop.invoice WRITE", &[]),
            None
        );
        // And two statements are refused as well: the ordinals would span them and a caller
        // asking for one statement's literal would reach another's.
        assert_eq!(
            rewrite_literals("SELECT 1; SELECT 2", &[Some("9".into())]),
            None
        );
    }

    /// A short slice leaves the tail alone rather than panicking.
    #[test]
    fn a_literal_with_no_surrogate_is_left_as_the_author_wrote_it() {
        let out = rewrite_literals("SELECT a FROM t WHERE id = 42 LIMIT 10", &[]).unwrap();
        assert!(out.contains("42") && out.contains("10"), "{out}");
    }

    /// AN INSERT WITH NO COLUMN LIST IS WRITING DATA, NOT WRITING NOTHING.
    ///
    /// `INSERT INTO t VALUES (1, 'kay')` puts a row in a table. Filing those values as "no
    /// column is named here" — the bucket a `LIMIT` and a `CREATE TABLE` default live in —
    /// would make them look like grammar, and a rule keyed on the bucket would publish them in
    /// the clear.
    ///
    /// The column's name is unrecoverable: it is the table's `n`-th, and which one that is lives
    /// in a catalogue no slow log carries. Its position is not.
    #[test]
    fn an_insert_with_no_column_list_writes_to_a_column_it_can_name_by_position() {
        let ls = parse_sql("INSERT INTO t VALUES (1, 'kay')", &EntryMasking::None)
            .unwrap()
            .1;
        assert_eq!(ls.len(), 2);
        // AND THE COLUMN IS RECOVERABLE POSITIONALLY: the `n`-th value reaches the table's
        // `n`-th column, for every such statement against that table.
        assert_eq!(
            ls.iter().map(|l| l.column_position).collect::<Vec<_>>(),
            vec![Some(0), Some(1)]
        );
        assert!(ls.iter().all(|l| l.column.is_none()), "and it is not NAMED");

        // A column list names them, so they are named and NOT positional -- the two are
        // exclusive, and the same statement one clause different proves it.
        let named = parse_sql(
            "INSERT INTO t (a, b) VALUES (1, 'kay')",
            &EntryMasking::None,
        )
        .unwrap()
        .1;
        assert!(named.iter().all(|l| l.column_position.is_none()));
        assert!(named.iter().all(|l| l.column.is_some()));

        // And a literal that names nobody is in neither: a `LIMIT` is grammar.
        let limit = parse_sql("SELECT a FROM t LIMIT 10", &EntryMasking::None)
            .unwrap()
            .1;
        assert_eq!(limit.len(), 1);
        assert!(limit[0].column_position.is_none() && limit[0].column.is_none());

        // EVERY ROW OF A MULTI-ROW INSERT COUNTS FROM ZERO AGAIN. A counter that ran on
        // across rows would file the second row's first value in the table's third column.
        let rows = parse_sql("INSERT INTO t VALUES (1, 2), (3, 4)", &EntryMasking::None)
            .unwrap()
            .1;
        assert_eq!(
            rows.iter().map(|l| l.column_position).collect::<Vec<_>>(),
            vec![Some(0), Some(1), Some(0), Some(1)]
        );
    }

    /// THE VERSION GATE IS THE WHOLE DIFFICULTY.
    ///
    /// MySQL executes `/*!40101 ... */`. A scan that read the gate as a comment would answer
    /// `false` on a statement that sets a value.
    #[test]
    fn a_value_inside_a_version_gate_is_still_a_value() {
        assert_eq!(
            carries_a_value("/*!40103 SET TIME_ZONE='+00:00' */;"),
            Some(true)
        );
        assert_eq!(
            carries_a_value("/*!40014 SET UNIQUE_CHECKS=0 */;"),
            Some(true)
        );
        // And a gate with no value in it stays false, so reading inside a gate is not a
        // blanket `true` on every gated statement.
        assert_eq!(
            carries_a_value("/*!40101 SET character_set_client = utf8 */;"),
            Some(false)
        );
    }

    /// Statements this grammar refuses and that carry nothing.
    #[test]
    fn a_statement_with_no_value_carries_none() {
        for sql in [
            "ALTER TABLE `film` DISABLE KEYS",
            "ANALYZE TABLE actor, address, category",
            "UNLOCK TABLES",
            "LOCK TABLES shop.invoice WRITE",
        ] {
            assert_eq!(carries_a_value(sql), Some(false), "{sql}");
        }
        for sql in [
            "LOAD DATA INFILE '/tmp/load_data_test.24252' INTO TABLE percona_test.load_data",
            "SELECT a FROM t LIMIT 10",
        ] {
            assert_eq!(carries_a_value(sql), Some(true), "{sql}");
        }
    }

    /// AND A VALUE WRITTEN AS AN IDENTIFIER IS INVISIBLE, which is stated rather than
    /// implied. ``DEFINER=`msandbox`@`%` `` is a username and a host, and no scan for literals
    /// can see them.
    #[test]
    fn a_value_written_as_an_identifier_is_not_seen() {
        assert_eq!(
            carries_a_value(
                "/*!50003 CREATE*/ /*!50017 DEFINER=`msandbox`@`%`*/ /*!50003 \
                             TRIGGER rental_date BEFORE INSERT ON rental FOR EACH ROW \
                             SET NEW.rental_date = NOW() */;"
            ),
            Some(false)
        );
    }
}

/// THE DOMAIN A VALUE LIVES IN.
///
/// Without `tenant_id`, `42` the tenant and `42` the row limit sit in one pool with nothing
/// separating them. A value means nothing outside a domain, and for a lock the domain is a
/// column of a relation.
#[cfg(test)]
mod every_literal_binding {
    use super::*;

    /// `(rendered, qualifier.name or "-", sought)` for each literal, in ordinal order.
    fn bound(sql: &str, mask: &EntryMasking) -> Vec<(String, String, bool)> {
        parse_sql(sql, mask)
            .unwrap_or_else(|e| panic!("{sql}: {e}"))
            .1
            .iter()
            .map(|l| {
                let col = match &l.column {
                    Some(c) => match &c.qualifier {
                        Some(q) => format!(
                            "{}.{}",
                            String::from_utf8_lossy(q),
                            String::from_utf8_lossy(&c.name)
                        ),
                        None => String::from_utf8_lossy(&c.name).into_owned(),
                    },
                    None => "-".to_string(),
                };
                (
                    String::from_utf8_lossy(&l.rendered).into_owned(),
                    col,
                    l.sought,
                )
            })
            .collect()
    }

    /// Every syntactic shape that names the column a value is **sought** in.
    #[test]
    fn a_literal_carries_the_column_the_author_looked_for_it_in() {
        assert_eq!(
            bound("SELECT id FROM t WHERE tenant_id = 42", &EntryMasking::None),
            [("42".into(), "tenant_id".into(), true)]
        );
        // Written either way round: a predicate is a comparison, not an assignment.
        assert_eq!(
            bound("SELECT id FROM t WHERE 42 = tenant_id", &EntryMasking::None),
            [("42".into(), "tenant_id".into(), true)]
        );
        // The qualifier the author wrote, which is an alias far more often than a table.
        assert_eq!(
            bound(
                "SELECT id FROM t e1 WHERE e1.dept_id = 4",
                &EntryMasking::None
            ),
            [("4".into(), "e1.dept_id".into(), true)]
        );
        // An `IN` list: every member is sought in the same column.
        assert_eq!(
            bound(
                "SELECT id FROM t WHERE id IN (1, 2, 3)",
                &EntryMasking::None
            ),
            [
                ("1".into(), "id".into(), true),
                ("2".into(), "id".into(), true),
                ("3".into(), "id".into(), true)
            ]
        );
        // A range, which is where InnoDB's next-key locking actually lives.
        assert_eq!(
            bound(
                "SELECT id FROM t WHERE id BETWEEN 5 AND 9",
                &EntryMasking::None
            ),
            [
                ("5".into(), "id".into(), true),
                ("9".into(), "id".into(), true)
            ]
        );
    }

    /// ARITHMETIC IS NOT A KEY LOOKUP.
    ///
    /// `Expr::BinaryOp` covers `+` as well as `=`. A rule taking any binary operator binds the
    /// `1` in `qty - 1` to `qty` and files a computation as a row the statement went for.
    #[test]
    fn arithmetic_is_not_a_key_lookup() {
        // Neither literal is bound: `1` sits under `-`, and `0`'s other side is a
        // computation rather than a column.
        assert_eq!(
            bound("SELECT id FROM t WHERE qty - 1 > 0", &EntryMasking::None),
            [
                ("1".into(), "-".into(), false),
                ("0".into(), "-".into(), false)
            ]
        );
        // And the same column with a comparison **is** bound, so the rule is about the
        // operator and not about the shape.
        assert_eq!(
            bound("SELECT id FROM t WHERE qty > 0", &EntryMasking::None),
            [("0".into(), "qty".into(), true)]
        );
    }

    /// A VALUE SOUGHT AND A VALUE WRITTEN ARE DIFFERENT CLAIMS, and one statement makes both.
    ///
    /// A lock taken to find a row and a lock taken to change one are different locks, so the
    /// column alone would fuse them.
    #[test]
    fn a_written_value_and_a_sought_value_are_not_the_same_claim() {
        assert_eq!(
            bound("UPDATE t SET qty = 5 WHERE id = 7", &EntryMasking::None),
            [
                ("5".into(), "qty".into(), false),
                ("7".into(), "id".into(), true)
            ]
        );
    }

    /// ONE PAYLOAD WRITTEN TO TWO COLUMNS, which is what rules out matching on the payload.
    ///
    /// `Assignment` and an insert column list are not expressions, so the binding is taken by
    /// the value's **address** in `pre_visit_statement`. A queue keyed on `5` would hand both
    /// columns to whichever it met first and the two would be indistinguishable.
    #[test]
    fn one_payload_written_to_two_columns_keeps_them_apart() {
        assert_eq!(
            bound("INSERT INTO t (a, b) VALUES (5, 5)", &EntryMasking::None),
            [
                ("5".into(), "a".into(), false),
                ("5".into(), "b".into(), false)
            ]
        );
    }

    /// AN INSERT NAMES A DOMAIN WHERE NO PREDICATE DOES, which a predicate-only rule would read
    /// as silence.
    ///
    /// A `mysqldump` restore seeks nothing and writes everything. A log that only ever wrote is
    /// a different thing from a log with no domains in it.
    #[test]
    fn an_insert_names_a_domain_even_where_no_predicate_does() {
        assert_eq!(
            bound(
                "INSERT INTO checksums (db_tbl, checksum) VALUES ('sakila.actor', 188518946)",
                &EntryMasking::None
            ),
            [
                ("'sakila.actor'".into(), "db_tbl".into(), false),
                ("188518946".into(), "checksum".into(), false)
            ]
        );
    }

    /// MASKING MOVES THE RENDER AND NOT THE DOMAIN.
    ///
    /// The binding is read in `pre_visit_statement` and `pre_visit_expr`, both of which run
    /// before the value beneath is replaced. A binding computed afterwards would see `?` on
    /// both sides of every comparison and bind nothing at all.
    #[test]
    fn masking_does_not_move_a_literal_out_of_its_domain() {
        let sql = "UPDATE t SET qty = 5 WHERE e1.dept_id BETWEEN 2 AND 8";
        let plain = bound(sql, &EntryMasking::None);
        let masked = bound(sql, &EntryMasking::PlaceHolder);
        assert_eq!(
            plain.iter().map(|(_, c, s)| (c, s)).collect::<Vec<_>>(),
            masked.iter().map(|(_, c, s)| (c, s)).collect::<Vec<_>>(),
            "the domain is the author's and masking is the reader's"
        );
        // `rendered` stays the author's under both settings, which is the whole point of
        // filing literals through masking. What masking moves is the statement, so that is
        // where the placeholder is checked.
        assert!(
            plain.iter().all(|(r, _, _)| r != "?"),
            "the author's spelling is recorded either way: {plain:?}"
        );
        let rendered = parse_sql(sql, &EntryMasking::PlaceHolder).unwrap().0[0].to_string();
        assert!(
            rendered.contains("qty = ?") && rendered.contains("BETWEEN ? AND ?"),
            "and the statement really is masked: {rendered}"
        );
    }
}

#[cfg(test)]
mod tests {
    use crate::EntryMasking;
    use crate::parser::{
        EntryAdminCommand, HeaderLines, SessionLine, SetLine, StatsLine, Stream, admin_command,
        details_comment, entry_user, log_header, parse_entry_stats, parse_entry_time, parse_sql,
        sql_lines, start_timestamp_command, use_database,
    };
    use bytes::Bytes;
    use std::assert_eq;
    use std::collections::HashMap;
    use winnow::combinator::opt;
    use winnow::error::ErrMode;
    use winnow::stream::{AsBytes, StreamIsPartial};
    use winnow::{ModalResult, Parser};
    use winnow_datetime::{Date, DateTime, Offset, Time};

    /// A finished slice: the end of these bytes is the end of the input.
    fn complete(s: &str) -> Stream<'_> {
        let mut i = Stream::new(s.as_bytes());
        let _ = i.complete();
        i
    }

    /// A refusal and never `Incomplete`: the line is all there, so there is nothing to wait for.
    fn refused<T: std::fmt::Debug>(r: ModalResult<T>) -> bool {
        matches!(r, Err(ErrMode::Backtrack(_) | ErrMode::Cut(_)))
    }

    /// THE MICROSECONDS A SLOW LOG WRITES ARE KEPT.
    ///
    /// `# Time:` carries six fractional digits, and a `Time` that held milliseconds would
    /// read `.015898` as `15` and fold instants a microsecond apart onto one. Requires
    /// winnow_datetime 0.4, whose `Time` carries nanoseconds.
    #[test]
    fn a_time_line_keeps_its_microseconds() {
        let mut i = Stream::new("# Time: 2018-02-05T02:46:43.015898Z\n".as_bytes());
        let dt = parse_entry_time(&mut i).unwrap();

        assert_eq!(dt.time.second, 43);
        assert_eq!(dt.time.nanosecond, 15_898_000, ".015898 is 15_898_000ns");

        // and two instants a microsecond apart stay two instants
        let mut a = Stream::new("# Time: 2018-02-05T02:46:43.015898Z\n".as_bytes());
        let mut b = Stream::new("# Time: 2018-02-05T02:46:43.015899Z\n".as_bytes());
        assert_ne!(
            parse_entry_time(&mut a).unwrap().time.nanosecond,
            parse_entry_time(&mut b).unwrap().time.nanosecond,
        );
    }

    #[test]
    fn parses_time_line() {
        let i = "# Time: 2015-06-26T16:43:23+0200\n";

        let expected = DateTime {
            date: Date::YMD {
                year: 2015,
                month: 6,
                day: 26,
            },
            time: Time {
                hour: 16,
                minute: 43,
                second: 23,
                nanosecond: 0,
                offset: Some(Offset::Fixed {
                    hours: 2,
                    minutes: 0,
                    critical: false,
                }),
                time_zone: None,
                calendar: None,
            },
        };

        let mut s = Stream::new(i.as_bytes());

        let dt = parse_entry_time(&mut s).unwrap();
        assert_eq!(expected, dt);
        assert!(s.as_bytes().is_empty(), "the line and its line ending");
    }

    /// MySQL before 5.7 and MariaDB write `yymmdd h:mm:ss`, the hour padded with a space.
    #[test]
    fn parses_the_pre_5_7_time_line() {
        let at = |s: &str| parse_entry_time(&mut Stream::new(s.as_bytes())).unwrap();

        let dt = at("# Time: 180205  2:46:47\n");
        assert_eq!(
            dt.date,
            Date::YMD {
                year: 2018,
                month: 2,
                day: 5
            }
        );
        assert_eq!((dt.time.hour, dt.time.minute, dt.time.second), (2, 46, 47));
        assert_eq!(dt.time.offset, None, "the line states no zone");

        assert_eq!(at("# Time: 180205 12:46:47\n").time.hour, 12);
        assert_eq!(
            at("# Time: 130601  8:01:06.058915\n").time.nanosecond,
            58_915_000
        );
        assert_eq!(
            at("# Time: 991231 23:59:59\n").date,
            Date::YMD {
                year: 1999,
                month: 12,
                day: 31
            }
        );

        for bad in [
            "# Time: 181305  2:46:47\n",
            "# Time: 180205 24:46:47\n",
            "# Time: 18020  2:46:47\n",
            "# Time: yesterday\n",
        ] {
            assert!(
                refused(parse_entry_time(&mut Stream::new(bad.as_bytes()))),
                "{bad}"
            );
        }
    }

    /// Every shape of the `# User@Host:` line: `priv_user[user] @ host [ip]`, then `Id:` where
    /// the server wrote one. Each field is read to the delimiter that ends it.
    #[test]
    fn parses_every_session_line() {
        type Want = (
            &'static str,
            &'static str,
            Option<&'static str>,
            Option<&'static str>,
        );
        let cases: &[(&str, Want, Option<u32>)] = &[
            (
                "# User@Host: msandbox[msandbox] @ localhost []  Id:     3",
                ("msandbox", "msandbox", Some("localhost"), None),
                Some(3),
            ),
            (
                "# User@Host: lobster[lobster] @ [192.168.56.1]  Id:   190",
                ("lobster", "lobster", None, Some("192.168.56.1")),
                Some(190),
            ),
            (
                "# User@Host: root[root] @ local.tests.rs [127.0.0.2]  Id: 7",
                ("root", "root", Some("local.tests.rs"), Some("127.0.0.2")),
                Some(7),
            ),
            (
                "# User@Host: app-rw[app-rw] @ db-01.example.com []  Id:     3",
                ("app-rw", "app-rw", Some("db-01.example.com"), None),
                Some(3),
            ),
            (
                "# User@Host: svc.batch[svc.batch] @ ip-10-0-0-5.ec2.internal [10.0.0.5]  Id: 9",
                (
                    "svc.batch",
                    "svc.batch",
                    Some("ip-10-0-0-5.ec2.internal"),
                    Some("10.0.0.5"),
                ),
                Some(9),
            ),
            (
                "# User@Host: app[app] @ node1.cluster01 []  Id:     3",
                ("app", "app", Some("node1.cluster01"), None),
                Some(3),
            ),
            (
                "# User@Host: app[app] @ localhost [::1]  Id:     3",
                ("app", "app", Some("localhost"), Some("::1")),
                Some(3),
            ),
            (
                "# User@Host: app[app] @  [::ffff:10.0.0.7]  Id:     3",
                ("app", "app", None, Some("::ffff:10.0.0.7")),
                Some(3),
            ),
            // A replication applier: no account, no host, no address.
            (
                "# User@Host: [SQL_SLAVE] @  []  Id:     1",
                ("", "SQL_SLAVE", None, None),
                Some(1),
            ),
            // MySQL 5.5 and MariaDB write no `Id:`, which is not an `Id:` of zero.
            (
                "# User@Host: root[root] @ localhost []",
                ("root", "root", Some("localhost"), None),
                None,
            ),
        ];

        for (line, (user, sys_user, host, ip), id) in cases {
            let text = format!("{line}\n");
            let mut s = Stream::new(text.as_bytes());
            let got = entry_user(&mut s).unwrap_or_else(|e| panic!("{line}: {e:?}"));

            assert_eq!(
                got,
                SessionLine {
                    user: Bytes::from(*user),
                    sys_user: Bytes::from(*sys_user),
                    host: host.map(Bytes::from),
                    ip_address: ip.map(Bytes::from),
                    thread_id: *id,
                },
                "{line}"
            );
            assert!(s.as_bytes().is_empty(), "{line}");
        }
    }

    /// A thread id past `u32` and a line of another shape are refusals, never a panic.
    #[test]
    fn a_session_line_that_does_not_fit_is_refused() {
        for bad in [
            "# User@Host: root[root] @ localhost []  Id: 99999999999\n",
            "# User@Host: root[root] localhost []  Id: 3\n",
            "# User@Host: root[root] @ localhost []  Id: 3 extra\n",
        ] {
            assert!(
                refused(entry_user(&mut Stream::new(bad.as_bytes()))),
                "{bad}"
            );
        }
    }

    #[test]
    fn parses_stats_line() {
        let i = "# Query_time: 1.000016  Lock_time: 2.000000 Rows_sent: 3  Rows_examined: 4\n";

        let expected = StatsLine {
            query_time: 1.000016,
            lock_time: 2.0,
            rows_sent: 3,
            rows_examined: 4,
            extra: vec![],
        };

        let mut s = complete(i);
        let res = parse_entry_stats(&mut s).unwrap();
        assert_eq!(expected, res);
        assert!(s.as_bytes().is_empty());
    }

    /// Row counts are 64-bit: a scan past four billion rows is a number a server writes.
    #[test]
    fn row_counts_are_64_bit_and_one_past_that_is_refused() {
        let i =
            "# Query_time: 1.0  Lock_time: 0.0 Rows_sent: 4294967296  Rows_examined: 5000000000\n";
        let res = parse_entry_stats(&mut complete(i)).unwrap();
        assert_eq!(
            (res.rows_sent, res.rows_examined),
            (4_294_967_296, 5_000_000_000)
        );

        let i =
            "# Query_time: 1.0  Lock_time: 0.0 Rows_sent: 0  Rows_examined: 99999999999999999999\n";
        assert!(refused(parse_entry_stats(&mut complete(i))));
    }

    /// `log_slow_extra` appends fields to the line, and every one of them is carried, in order.
    #[test]
    fn a_log_slow_extra_line_is_read_whole() {
        let i = "# Query_time: 0.000352  Lock_time: 0.000100 Rows_sent: 1  Rows_examined: 2 \
                 Thread_id: 10 Errno: 0 Killed: 0 Bytes_received: 27 Bytes_sent: 60 \
                 Read_first: 0 Read_last: 0 Read_key: 1 Read_next: 0 Read_prev: 0 Read_rnd: 0 \
                 Read_rnd_next: 3 Sort_merge_passes: 0 Sort_range_count: 0 Sort_rows: 0 \
                 Sort_scan_count: 0 Created_tmp_disk_tables: 0 Created_tmp_tables: 0 \
                 Count_hit_tmp_table_size: 0 Start: 2019-01-01T12:00:00.000000Z \
                 End: 2019-01-01T12:00:00.000352Z\n";
        let res = parse_entry_stats(&mut complete(i)).unwrap();

        assert_eq!((res.rows_sent, res.rows_examined), (1, 2));
        let names: Vec<&[u8]> = res.extra.iter().map(|(n, _)| n.as_ref()).collect();
        assert_eq!(names.len(), 21);
        assert_eq!(names[0], b"Thread_id");
        assert_eq!(names[20], b"End");
        assert_eq!(
            res.extra[19],
            (
                Bytes::from("Start"),
                Bytes::from("2019-01-01T12:00:00.000000Z")
            )
        );
        assert_eq!(
            res.extra[3],
            (Bytes::from("Bytes_received"), Bytes::from("27"))
        );

        // Percona Server's one further field, after two spaces.
        let i =
            "# Query_time: 0.1  Lock_time: 0.0  Rows_sent: 1  Rows_examined: 1  Rows_affected: 0\n";
        let res = parse_entry_stats(&mut complete(i)).unwrap();
        assert_eq!(
            res.extra,
            vec![(Bytes::from("Rows_affected"), Bytes::from("0"))]
        );
    }

    /// MariaDB and Percona Server write whole lines of fields around the `# Query_time:` line,
    /// and their fields join the line's own, in the order written.
    #[test]
    fn the_field_lines_around_the_stats_line_join_its_fields() {
        let mariadb = "# Thread_id: 36  Schema:   QC_hit: No
# Query_time: 0.000094  Lock_time: 0.000028  Rows_sent: 1  Rows_examined: 1
# Rows_affected: 0  Bytes_sent: 57
SET timestamp=1680698153;\n";
        let mut s = Stream::new(mariadb.as_bytes());
        let res = parse_entry_stats(&mut s).unwrap();

        assert_eq!((res.rows_sent, res.rows_examined), (1, 1));
        let fields: Vec<(&[u8], &[u8])> = res
            .extra
            .iter()
            .map(|(n, v)| (n.as_ref(), v.as_ref()))
            .collect();
        assert_eq!(
            fields,
            [
                (&b"Thread_id"[..], &b"36"[..]),
                (b"Schema", b""),
                (b"QC_hit", b"No"),
                (b"Rows_affected", b"0"),
                (b"Bytes_sent", b"57"),
            ]
        );
        assert_eq!(s.as_bytes(), b"SET timestamp=1680698153;\n");

        let percona = "# Schema: test  Last_errno: 0  Killed: 0
# Query_time: 0.000291  Lock_time: 0.000127  Rows_sent: 1  Rows_examined: 1  Rows_affected: 0
# Bytes_sent: 106  Tmp_tables: 0  Tmp_disk_tables: 0  Tmp_table_sizes: 0
# InnoDB_trx_id: 0
#   InnoDB_IO_r_ops: 0  InnoDB_IO_r_bytes: 0  InnoDB_IO_r_wait: 0.000000
SET timestamp=1547113018;\n";
        let res = parse_entry_stats(&mut Stream::new(percona.as_bytes())).unwrap();
        assert_eq!(res.extra.len(), 12);
        assert_eq!(
            res.extra[3],
            (Bytes::from("Rows_affected"), Bytes::from("0"))
        );
        assert_eq!(
            res.extra[11],
            (Bytes::from("InnoDB_IO_r_wait"), Bytes::from("0.000000"))
        );

        // A comment line of another shape is refused, and so is a stats line that never comes.
        for bad in [
            "# No InnoDB statistics available for this query\n# Query_time: 1.0  Lock_time: 0.0 Rows_sent: 0  Rows_examined: 0\n",
            "# Thread_id: 1\n# Time: 2018-02-05T02:46:43Z\n",
        ] {
            assert!(
                refused(parse_entry_stats(&mut Stream::new(bad.as_bytes()))),
                "{bad}"
            );
        }
    }

    #[test]
    fn parses_admin_command_line() {
        let i = "# administrator command: Quit;\n";

        let expected = EntryAdminCommand {
            command: "Quit".into(),
        };

        let mut s = Stream::new(i.as_bytes());
        let res = admin_command(&mut s).unwrap();
        assert_eq!(expected, res);
    }

    #[test]
    fn parses_use_database() {
        let i = "use mysql;\n";
        let mut s = Stream::new(i.as_bytes());

        let res = use_database(&mut s).unwrap();
        assert_eq!(res, Bytes::from("mysql"));
        assert!(s.as_bytes().is_empty());
    }

    /// MySQL writes the name unquoted and as it is, so the name is everything up to the `;` that
    /// ends the line.
    #[test]
    fn a_database_name_is_everything_up_to_the_semicolon() {
        for (line, name) in [
            ("use my-app;\n", "my-app"),
            ("use shop.v2;\n", "shop.v2"),
            ("use 2024_archive;\n", "2024_archive"),
            ("USE mysql;\n", "mysql"),
            ("use a;b;\n", "a;b"),
            ("use `my-app`;\n", "my-app"),
            ("use `we``ird`;\n", "we`ird"),
            ("use mysql;\r\n", "mysql"),
        ] {
            let got = use_database(&mut Stream::new(line.as_bytes()))
                .unwrap_or_else(|e| panic!("{line}: {e:?}"));
            assert_eq!(got, Bytes::from(name), "{line}");
        }

        for bad in ["use ;\n", "use mysql\n", "SET timestamp=1;\n"] {
            let mut s = Stream::new(bad.as_bytes());
            assert_eq!(opt(use_database).parse_next(&mut s).unwrap(), None, "{bad}");
            assert_eq!(s.as_bytes(), bad.as_bytes(), "a refusal consumes nothing");
        }
    }

    #[test]
    fn parses_start_timestamp() {
        let l = "SET timestamp=1517798807;\n";
        let mut s = Stream::new(l.as_bytes());
        let res = start_timestamp_command(&mut s).unwrap();

        assert_eq!(
            res,
            SetLine {
                timestamp: 1517798807,
                last_insert_id: None,
                insert_id: None
            }
        );
        assert!(s.as_bytes().is_empty());
    }

    /// MySQL writes `last_insert_id=` and `insert_id=` in front of `timestamp=` on the same line.
    #[test]
    fn a_set_line_carries_the_insert_ids() {
        let l = "SET last_insert_id=5,insert_id=6,timestamp=1517798807;\n";
        assert_eq!(
            start_timestamp_command(&mut Stream::new(l.as_bytes())).unwrap(),
            SetLine {
                timestamp: 1517798807,
                last_insert_id: Some(5),
                insert_id: Some(6)
            }
        );

        for bad in [
            "SET timestamp=4294967296;\n",
            "SET timestamp=99999999999999999999999;\n",
            "SET insert_id=6;\n",
            "SET names=1,timestamp=2;\n",
            "SET timestamp=1,timestamp=2;\n",
            "SET NAMES utf8;\n",
        ] {
            assert!(
                refused(start_timestamp_command(&mut Stream::new(bad.as_bytes()))),
                "{bad}"
            );
        }
    }

    #[test]
    fn parses_details_comment() {
        let s0 = "-- Id: 123; long: some kind of details here; caller: hello_world()\n";
        let s1 = "-- Id: 123, long: some kind of details here, caller : hello_world()\n";
        let s2 = "-- Id= 123, long = some kind of details here, caller= hello_world()\n";

        let expected = (
            Stream::new("".as_bytes()),
            HashMap::from([
                ("Id".into(), "123".into()),
                ("long".into(), "some kind of details here".into()),
                ("caller".into(), "hello_world()".into()),
            ]),
        );

        let mut s = Stream::new(s0.as_bytes());
        let res = details_comment(&mut s).unwrap();
        //TODO: Stream ToString and ToStr
        assert_eq!((s, res), expected);

        let mut s = Stream::new(s1.as_bytes());
        let res = details_comment(&mut s).unwrap();
        assert_eq!((s, res), expected);

        let mut s = Stream::new(s2.as_bytes());
        let res = details_comment(&mut s).unwrap();

        assert_eq!((s, res), expected);
    }

    #[test]
    fn parses_details_comment_trailing_key() {
        let i = "-- Id: 123, long: some kind of details here, caller: hello_world():52\n";
        let mut s = Stream::new(i.as_bytes());

        let res = details_comment(&mut s).unwrap();

        let expected = (
            Stream::new("".as_bytes()),
            HashMap::from([
                ("Id".into(), "123".into()),
                ("long".into(), "some kind of details here".into()),
                ("caller".into(), "hello_world():52".into()),
            ]),
        );

        assert_eq!((s, res), expected);

        let i = "-- Id: 123, long: some kind of details here, caller: hello_world(): 52\n";
        let mut s = Stream::new(i.as_bytes());

        let res = details_comment(&mut s).unwrap();
        let expected = (
            Stream::new("".as_bytes()),
            HashMap::from([
                ("Id".into(), "123".into()),
                ("long".into(), "some kind of details here".into()),
                ("caller".into(), "hello_world(): 52".into()),
            ]),
        );

        assert_eq!((s, res), expected);
    }

    #[test]
    fn parses_masked_selects() {
        let sql0 = "SELECT a, b, 123, 'abcd', myfunc(b) \
           FROM table_1 \
           WHERE a > b AND b < 100 \
           ORDER BY a DESC, b";

        let sql1 = "SELECT a, b, 456, 'efg', myfunc(b) \
           FROM table_1 \
           WHERE a > b AND b < 1000 \
           ORDER BY a DESC, b";

        let ast0 = parse_sql(sql0, &EntryMasking::PlaceHolder).unwrap().0;
        let ast1 = parse_sql(sql1, &EntryMasking::PlaceHolder).unwrap().0;

        assert_eq!(ast0, ast1);
    }

    #[test]
    fn parses_select_sql() {
        let sql = "SELECT a, b, 123, 'abcd', myfunc(b) \
           FROM table_1 \
           WHERE a > b AND b < 100 \
           ORDER BY a DESC, b;";

        let mut s = complete(sql);
        let res = sql_lines(&mut s).unwrap();

        assert_eq!(res, sql);
    }

    #[test]
    fn parses_setter_sql() {
        let sql = "/*!40101 SET NAMES utf8 */;\n";

        let mut s = complete(sql);
        let res = sql_lines(&mut s).unwrap();

        assert_eq!(res, sql.trim());
    }

    #[test]
    fn parses_quoted_terminator_sql() {
        let sql = "SELECT
a.actor_id,
a.first_name,
a.last_name,
GROUP_CONCAT(DISTINCT CONCAT(c.name, ': ',
                (SELECT GROUP_CONCAT(f.title ORDER BY f.title SEPARATOR ', ')
                    FROM sakila.film f
                    INNER JOIN sakila.film_category fc
                      ON f.film_id = fc.film_id
                    INNER JOIN sakila.film_actor fa
                      ON f.film_id = fa.film_id
                    WHERE fc.category_id = c.category_id
                    AND fa.actor_id = a.actor_id
                 )
             )
             ORDER BY c.name SEPARATOR '; ')
AS film_info
FROM sakila.actor a;
";

        let mut s = complete(sql);
        let res = sql_lines(&mut s).unwrap();

        assert_eq!(res, sql.trim());
        assert_eq!(s.as_bytes(), b"\n");
    }

    #[test]
    fn parses_quoted_quoted_terminator_sql() {
        let sql = r#"SELECT
a.actor_id,
a.first_name,
a.last_name,
GROUP_CONCAT(DISTINCT CONCAT(c.name, ': ',
                (SELECT GROUP_CONCAT(f.title ORDER BY f.title SEPARATOR ', ')
                    FROM sakila.film f
                    INNER JOIN sakila.film_category fc
                      ON f.film_id = fc.film_id
                    INNER JOIN sakila.film_actor fa
                      ON f.film_id = fa.film_id
                    WHERE fc.category_id = c.category_id
                    AND fa.actor_id = a.actor_id
                 )
             )
             ORDER BY c.name SEPARATOR '\'\"; ')
AS film_info
FROM sakila.actor a;
"#;

        let mut s = complete(sql);
        let res = sql_lines(&mut s).unwrap();

        assert_eq!(res, sql.trim());
    }

    #[test]
    fn parses_header() {
        let h = "/home/karl/mysql/my-5.7/bin/mysqld, Version: 5.7.20-log (MySQL Community Server (GPL)). started with:
Tcp port: 12345  Unix socket: /tmp/12345/mysql_sandbox12345.sock
Time                 Id Command    Argument\n";

        let mut s = Stream::new(h.as_bytes());

        let res = log_header(&mut s).unwrap();

        assert_eq!(
            res,
            HeaderLines {
                version: Bytes::from("5.7.20-log (MySQL Community Server (GPL))."),
                tcp_port: Some(12345),
                socket: Some(Bytes::from("/tmp/12345/mysql_sandbox12345.sock")),
                named_pipe: None,
            }
        );
        assert!(s.as_bytes().is_empty());
    }

    /// A server on Windows names a pipe where a unix server names its socket.
    #[test]
    fn parses_a_windows_header() {
        let h = "C:\\Program Files\\MySQL\\MySQL Server 8.0\\bin\\mysqld.exe, Version: 8.0.36 (MySQL Community Server - GPL). started with:\r
TCP Port: 3306, Named Pipe: MySQL\r
Time                 Id Command    Argument\r\n";

        let res = log_header(&mut Stream::new(h.as_bytes())).unwrap();

        assert_eq!(
            res,
            HeaderLines {
                version: Bytes::from("8.0.36 (MySQL Community Server - GPL)."),
                tcp_port: Some(3306),
                socket: None,
                named_pipe: Some(Bytes::from("MySQL")),
            }
        );
    }

    /// Text that is not a header is refused on its own first line. The header grammar reads one
    /// line at a time, so a `started with:` further down cannot pull it across the file.
    #[test]
    fn a_header_is_read_one_line_at_a_time() {
        let not_a_header = "SELECT 1, Version: 2;
# Time: 2018-02-05T02:46:43.015898Z
x started with:
Tcp port: 1  Unix socket: /tmp/s
";
        let mut s = Stream::new(not_a_header.as_bytes());
        assert_eq!(opt(log_header).parse_next(&mut s).unwrap(), None);
        assert_eq!(s.as_bytes(), not_a_header.as_bytes());

        // And a partial first line waits for its line ending rather than deciding.
        let mut s = Stream::new(&not_a_header.as_bytes()[..10]);
        assert!(matches!(log_header(&mut s), Err(ErrMode::Incomplete(_))));

        // A port past `usize` is a refusal, never a panic.
        let h = "mysqld, Version: 5.7.20-log (x). started with:
Tcp port: 99999999999999999999999  Unix socket: /tmp/s
Time                 Id Command    Argument\n";
        assert!(refused(log_header(&mut Stream::new(h.as_bytes()))));
    }
}

/// MASKING MUST NOT DESTROY STATEMENTS.
///
/// A tokenizer cannot tell a value from a number the grammar requires, so masking tokens before
/// the parse turns `CHAR(60)` into `CHAR(?)` and the whole `CREATE TABLE` is refused -- filed as
/// an unparseable statement with its raw bytes as its SQL. Masking the tree after the parse
/// cannot do that.
#[cfg(test)]
mod masking_is_not_destructive {
    use crate::EntryMasking::{None as NoMask, PlaceHolder};
    use crate::parser::parse_sql;

    /// A number the grammar requires is not a value, and masking must not reach it.
    #[test]
    fn a_type_parameter_survives_masking() {
        for sql in [
            "CREATE TABLE t (c CHAR(60) NOT NULL)",
            "CREATE TABLE t (c VARCHAR(255) DEFAULT '')",
            "CREATE TABLE t (c DECIMAL(10,2))",
            "ALTER TABLE t ADD COLUMN c INT(11)",
        ] {
            assert!(parse_sql(sql, &NoMask).is_ok(), "{sql}");
            assert!(
                parse_sql(sql, &PlaceHolder).is_ok(),
                "masking refused a statement that parses: {sql}"
            );
        }
    }

    /// And a value still masks, or the flag would be doing nothing.
    #[test]
    fn a_value_is_still_replaced() {
        let one = parse_sql("SELECT * FROM t WHERE id = 1 AND name = 'a'", &PlaceHolder).unwrap();
        let two = parse_sql("SELECT * FROM t WHERE id = 2 AND name = 'b'", &PlaceHolder).unwrap();
        assert_eq!(one.0[0].to_string(), two.0[0].to_string());
        assert!(one.0[0].to_string().contains('?'), "{}", one.0[0]);

        // NOT VACUOUS: unmasked, the same two statements differ. A masker that replaced
        // nothing would pass the first assertion on two identical inputs.
        let a = parse_sql("SELECT * FROM t WHERE id = 1", &NoMask).unwrap();
        let b = parse_sql("SELECT * FROM t WHERE id = 2", &NoMask).unwrap();
        assert_ne!(a.0[0].to_string(), b.0[0].to_string());
    }

    /// Masking must not change WHICH statements parse at all, in either direction.
    #[test]
    fn masking_changes_no_statements_parseability() {
        for sql in [
            "CREATE TABLE t (id INT(11), amount DECIMAL(10,2), name VARCHAR(255))",
            "INSERT INTO t VALUES (1, 2.5, 'x')",
            "SELECT * FROM t LIMIT 10 OFFSET 5",
            "UPDATE t SET amount = 1.5 WHERE id = 3",
            "SELECT SUBSTR(name, 1, 3) FROM t",
        ] {
            assert_eq!(
                parse_sql(sql, &NoMask).is_ok(),
                parse_sql(sql, &PlaceHolder).is_ok(),
                "{sql}"
            );
        }
    }
}

/// THE AUTHOR'S SUBJECT SURVIVES MASKING, AND THE MASK STAYS A MASK.
#[cfg(test)]
mod the_author_keeps_their_literals {
    use crate::EntryMasking::{None as NoMask, PlaceHolder};
    use crate::parser::{LiteralKind, parse_sql};

    fn rendered(sql: &str, mask: &crate::EntryMasking) -> (String, Vec<String>) {
        let (s, ls) = parse_sql(sql, mask).unwrap();
        (
            s[0].to_string(),
            ls.iter()
                .map(|l| String::from_utf8_lossy(&l.rendered).into_owned())
                .collect(),
        )
    }

    /// The literals come back whether or not the statement is masked, so a reader can group on
    /// the mask and still ask which subject.
    #[test]
    fn the_literals_are_recorded_under_either_masking() {
        let sql = "SELECT * FROM t WHERE tenant_id = 42 AND status = 'open' LIMIT 10";

        let (plain, plain_ls) = rendered(sql, &NoMask);
        let (masked, masked_ls) = rendered(sql, &PlaceHolder);

        assert_eq!(plain_ls, vec!["42", "'open'", "10"]);
        assert_eq!(
            masked_ls, plain_ls,
            "masking must not change what was recorded"
        );

        assert!(plain.contains("42") && plain.contains("'open'"), "{plain}");
        assert!(!masked.contains("42"), "{masked}");
        assert_eq!(masked.matches('?').count(), 3, "{masked}");
    }

    /// A VALUE THAT IS NOT AN `Expr::Value`. `DATE '2020-01-01'` is an `Expr::TypedString` and
    /// MySQL's `AGAINST ('term')` is an `Expr::MatchAgainst`; each holds a `Value` without being
    /// one, so an `Expr`-shaped pass would neither mask nor record them.
    #[test]
    fn a_value_that_is_not_an_expr_value_is_still_the_authors() {
        for (sql, expected) in [
            (
                "SELECT * FROM t WHERE d > DATE '2020-01-01'",
                "'2020-01-01'",
            ),
            (
                "SELECT * FROM t WHERE MATCH(body) AGAINST ('needle')",
                "'needle'",
            ),
        ] {
            let (_, ls) = rendered(sql, &NoMask);
            assert!(
                ls.iter().any(|l| l == expected),
                "{sql} -> {ls:?} is missing {expected}"
            );
            let (masked, _) = rendered(sql, &PlaceHolder);
            assert!(!masked.contains(expected), "{masked}");
        }
    }

    /// A MASKED STATEMENT MUST STILL BE SQL. `pre_visit_value` reaches every `Value` in the
    /// tree, including a few that are grammar rather than subject -- a `CEIL(x TO 2)` scale, a
    /// `TABLESAMPLE` seed. Masking after the parse cannot break the parse the way masking tokens
    /// does, but it can render something that will not parse again, and a digest nobody can
    /// re-read is not a digest.
    #[test]
    fn a_masked_statement_still_parses() {
        for sql in [
            "SELECT * FROM t WHERE id = 1",
            "CREATE TABLE t (c CHAR(60), d DECIMAL(10,2))",
            "INSERT INTO t VALUES (1, 'x', 2.5)",
            "SELECT SUBSTR(name, 1, 3) FROM t LIMIT 10 OFFSET 5",
            "SELECT * FROM t WHERE d > DATE '2020-01-01'",
            "UPDATE t SET amount = 1.5 WHERE id = 3",
        ] {
            let (masked, _) = rendered(sql, &PlaceHolder);
            assert!(
                parse_sql(&masked, &NoMask).is_ok(),
                "masked rendering will not re-parse: {sql} -> {masked}"
            );
        }
    }

    /// THE ROUND TRIP, which is what makes the record a record rather than a note. Writing
    /// the filed literals back into the masked statement in the order they were taken must
    /// reproduce exactly what the author wrote.
    ///
    /// The order is why ONE pass does both jobs. `visit_expressions` is pre-order and
    /// `visit_expressions_mut` is post-order, so a collector and a masker on those two hooks
    /// would disagree on every nested expression and nothing about the result would look wrong.
    #[test]
    fn the_literals_and_the_mask_reconstruct_the_author() {
        for sql in [
            "SELECT * FROM t WHERE tenant_id = 42 AND status = 'open' LIMIT 10",
            "INSERT INTO t VALUES (1, 'x', 2.5), (3, 'y', 4.5)",
            "SELECT CONCAT('a', (SELECT max(n) FROM u WHERE k = 7)) FROM t WHERE j = 'z'",
            "UPDATE t SET amount = 1.5, note = 'done' WHERE id = 3",
        ] {
            let (masked, ls) = rendered(sql, &PlaceHolder);
            let (plain, _) = rendered(sql, &NoMask);

            // Replace each `?` with the literal of the same ordinal.
            let mut out = String::new();
            let mut rest = masked.as_str();
            for l in &ls {
                let i = rest
                    .find('?')
                    .expect("one placeholder per recorded literal");
                out.push_str(&rest[..i]);
                out.push_str(l);
                rest = &rest[i + 1..];
            }
            out.push_str(rest);

            assert_eq!(out, plain, "round trip failed for: {sql}");
            assert!(
                !out.contains('?'),
                "a literal was left unaccounted for: {out}"
            );
        }
    }

    #[test]
    fn a_kind_travels_with_every_literal() {
        let (_, ls) = parse_sql(
            "SELECT * FROM t WHERE a = 1 AND b = 'x' AND c = X'ff'",
            &NoMask,
        )
        .unwrap();
        let kinds: Vec<_> = ls.iter().map(|l| l.kind).collect();
        assert_eq!(
            kinds,
            vec![
                LiteralKind::Number,
                LiteralKind::SingleQuotedString,
                LiteralKind::HexString
            ]
        );
        // The payload is the value WITHOUT its quoting, which is what a reader groups by.
        assert_eq!(String::from_utf8_lossy(&ls[1].value), "x");
        assert_eq!(String::from_utf8_lossy(&ls[1].rendered), "'x'");
    }
}

/// WHERE A STATEMENT ENDS.
///
/// MySQL writes the client's text and then `;` and a line ending, so the terminator is found by
/// position and never by reading SQL: a scan that tracks quotes or comments cannot see a `;` the
/// server put after an open quote or inside a `--` comment, and runs to the end of the file.
#[cfg(test)]
mod a_statement_ends_where_the_next_entry_begins {
    use crate::parser::statement_end;

    const NEXT: &str = "\n# Time: 2018-02-05T02:46:43.015898Z\n# User@Host: a[a] @ h []  Id: 1\n";

    /// Statement texts that end at their last byte, each a shape that a scan for the first `;`
    /// outside quotes gets wrong or never finishes.
    const STATEMENTS: &[&str] = &[
        "SELECT 1;",
        "/* user's dashboard */ SELECT 1;",
        "SELECT 1 /* a; b */ FROM dual;",
        "SELECT 1 -- don't\nFROM dual;",
        "SELECT 1 # don't\nFROM dual;",
        // The client sent its own `;` and the server appended another.
        "SELECT 1;;",
        "CREATE PROCEDURE p() BEGIN\n  SELECT 1;\nEND;",
        "CREATE TRIGGER t BEFORE INSERT ON x FOR EACH ROW BEGIN\n  SET NEW.a = 1;\n  SET NEW.b = 2;\nEND;",
        r#"SELECT * FROM t WHERE note = "it's here";"#,
        r#"INSERT INTO t VALUES ("don't", 'say "no"');"#,
        r#"SELECT 'a;b', "c;d", `e;f`; SELECT 2;"#,
        // The server's `;` after a `--` comment the client did not end, and after a quote the
        // client did not close: MySQL logs a statement that failed to parse like any other.
        "SELECT 1 -- note;",
        "SELECT 'unterminated;",
        "SELECT 'a\\';",
    ];

    #[test]
    fn a_statement_ends_at_the_semicolon_before_the_next_entry() {
        for s in STATEMENTS {
            let text = format!("{s}{NEXT}");
            assert_eq!(
                statement_end(text.as_bytes(), false),
                Some(s.len()),
                "{s:?}"
            );
            assert_eq!(statement_end(text.as_bytes(), true), Some(s.len()), "{s:?}");
        }
    }

    /// What opens the next entry: a `# Time:` line, a `# User@Host:` line where the server left
    /// the time out, a header block, or the end of the input.
    #[test]
    fn what_follows_the_terminator_decides_it() {
        let s = "SELECT 1;";
        for after in [
            "\n# Time: 2018-02-05T02:46:43.015898Z\n",
            "\n# User@Host: a[a] @ h []\n",
            "\r\n# Time: 2018-02-05T02:46:43.015898Z\r\n",
            "  \n\n\n# Time: 2018-02-05T02:46:43.015898Z\n",
            "\n/usr/sbin/mysqld, Version: 5.7.20-log (x). started with:\nTcp port: 1  Unix socket: /tmp/s\n",
        ] {
            let text = format!("{s}{after}");
            assert_eq!(
                statement_end(text.as_bytes(), false),
                Some(s.len()),
                "{after:?}"
            );
        }

        // At the end of the input, with or without a line ending.
        for text in [
            "SELECT 1;",
            "SELECT 1;\n",
            "SELECT 1;\r\n",
            "SELECT 1;\n\n  ",
            "SELECT 1;\r",
        ] {
            assert_eq!(statement_end(text.as_bytes(), true), Some(9), "{text:?}");
        }

        // And lines that open nothing: the statement goes on.
        for text in [
            "SELECT 1;\n# administrator command: Quit;\n",
            "SELECT 1;\nFROM dual;",
            "SELECT 1;\n#Time: 2018\n",
            "SELECT 1; \nx, Version: 1\n",
        ] {
            assert_ne!(statement_end(text.as_bytes(), true), Some(9), "{text:?}");
        }
    }

    /// `None` is "not in the bytes I have" and never "not in the file". On a partial buffer
    /// every prefix of the text answers either `None` or the one right answer, so the decoder
    /// frames the same statement however the input is cut.
    #[test]
    fn no_prefix_of_the_input_decides_early() {
        for s in STATEMENTS {
            let text = format!("{s}{NEXT}");
            for k in 0..text.len() {
                let got = statement_end(&text.as_bytes()[..k], false);
                assert!(
                    got.is_none() || got == Some(s.len()),
                    "{s:?} cut at {k} answered {got:?}"
                );
            }
        }

        assert_eq!(statement_end(b"SELECT 1", false), None);
        assert_eq!(
            statement_end(b"SELECT 1;", false),
            None,
            "the line may go on"
        );
        assert_eq!(
            statement_end(b"SELECT 1;\n", false),
            None,
            "the next line decides"
        );
        assert_eq!(statement_end(b"SELECT 1;\n# Ti", false), None);
        assert_eq!(statement_end(b"", false), None);
    }

    /// At the end of the input a statement with no terminator has none.
    #[test]
    fn an_unterminated_statement_is_not_a_statement() {
        assert_eq!(statement_end(b"SELECT 1", true), None);
        assert_eq!(statement_end(b"SELECT 1; SELECT 2", true), None);
        assert_eq!(statement_end(b"", true), None);
    }

    /// What the rule cannot frame, pinned so that it is a decision and not a surprise: text that
    /// quotes a slow log with raw line breaks ends where the quoted entry begins.
    #[test]
    fn a_quoted_slow_log_ends_the_statement_early() {
        let s = "INSERT INTO notes VALUES ('SELECT 1;\n# Time: 2018-02-05T02:46:43Z\n');";
        assert_eq!(
            statement_end(s.as_bytes(), true),
            Some("INSERT INTO notes VALUES ('SELECT 1;".len())
        );
    }
}
