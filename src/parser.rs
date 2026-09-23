use crate::EntryMasking;
use bytes::{BufMut, Bytes, BytesMut};
use sqlparser::ast::{
    AssignmentTarget, BinaryOperator, Expr, ObjectName, SetExpr, Statement, Value, VisitMut,
    VisitorMut,
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
use winnow::ascii::{
    Caseless, alpha1, alphanumeric1, digit1, float, line_ending, multispace0, multispace1,
    till_line_ending,
};
use winnow::combinator::repeat;
use winnow::combinator::{alt, trace};
use winnow::combinator::{not, opt};
use winnow::combinator::{preceded, terminated};
use winnow::error::{ContextError, ErrMode, InputError, Needed};
// ⚠️ Aliased: `sqlparser` exports a `ParserError` of its own and both are used in this file.
use winnow::error::ParserError as WinnowError;
use winnow::stream::{AsBytes, StreamIsPartial};
use winnow::token::{any, literal, take, take_till, take_until};
use winnow::{ModalResult, Parser, Partial, seq};
use winnow_datetime::DateTime;
use winnow_iso8601::datetime::datetime;

pub type Stream<'i> = Partial<&'i [u8]>;

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

/// parses "# Time: .... entry line and returns a `DateTime`
// # Time: 2015-06-26T16:43:23+0200";
pub fn parse_entry_time(i: &mut Stream) -> ModalResult<DateTime> {
    trace("parse_entry_time", move |input: &mut Stream| {
        let dt = seq!(
            _: literal("# Time:"),
            _: multispace1,
            datetime,
        )
        .parse_next(input)?;

        Ok(dt.0)
    })
    .parse_next(i)
}

/// values from the User: entry line
/// ex. # User@Host: msandbox\[msandbox\] @ localhost []  Id:     3
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionLine {
    pub(crate) user: Bytes,
    pub(crate) sys_user: Bytes,
    pub(crate) host: Option<Bytes>,
    pub(crate) ip_address: Option<Bytes>,
    pub(crate) thread_id: u32,
}

impl SessionLine {
    /// returns user as`Bytes`
    pub fn user(&self) -> Bytes {
        self.user.clone()
    }

    /// returns sys_user as`Bytes`
    pub fn sys_user(&self) -> Bytes {
        self.sys_user.clone()
    }

    /// returns possible host as`Option<Bytes>`
    pub fn host(&self) -> Option<Bytes> {
        self.host.clone()
    }

    /// returns possible ip_address as `Option<Bytes>`
    pub fn ip_address(&self) -> Option<Bytes> {
        self.ip_address.clone()
    }

    /// returns thread_id as `Bytes`
    pub fn thread_id(&self) -> u32 {
        self.thread_id
    }
}

/// ⭐⭐⭐ THE REGIME THE FILE DECLARES, AND NOTHING HAS EVER READ IT.
///
/// The first line of a slow log names the server that wrote it. Every claim a downstream reader
/// makes about MySQL's *behaviour* — which statements block which, whether a DDL takes readers
/// down with it — holds in a **regime**, and this is the only place the document states which
/// one. `slow-test-queries.log` says `5.7.20`; a log written by 8.0 obeys different rules for
/// the same statement text.
///
/// ⛔ All three fields were parsed and bound into a struct nothing read, the same shape as the
/// `USE` database being bound to `_`.
#[derive(Debug, PartialEq, Default, Clone)]
pub struct HeaderLines {
    version: Bytes,
    tcp_port: Option<usize>,
    socket: Option<Bytes>,
}

impl HeaderLines {
    /// The server version string exactly as the file spelled it, e.g.
    /// `5.7.20-log (MySQL Community Server (GPL)).`
    ///
    /// ⚠️ Unparsed on purpose. Turning it into a `(major, minor, patch)` is a *reading*, and one
    /// that a distribution suffix (`-log`, `-MariaDB`, `-percona`) can break; whoever needs a
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
}

pub fn log_header<'a>(i: &mut Stream<'_>) -> ModalResult<HeaderLines> {
    trace("log_header", move |input: &mut Stream<'_>| {
        // check for the '#' since the last parser in the set is greedy
        let head = seq!{
            HeaderLines {
                _: not(literal("#")),
                _: take_until(1.., ", Version: "),
                _:  (", Version: "),
                version: take_until(1.., " started with:").map(|v: &[u8]| v.to_owned().into()),
                _: literal(" started with:"),
                _: multispace1,
                _: literal("Tcp port:"),
                _: multispace1,
                tcp_port: opt(digit1).map(|v: Option<&[u8]>| v.and_then(|d| Some(str::from_utf8(d).unwrap().parse().unwrap()))),
                _: multispace1,
                _: literal("Unix socket: "),
                socket: opt(take_till(1.., "\n".as_bytes())).map(|v: Option<&[u8]>| v.and_then(|d| Some(d.to_owned().into()))),
                _: till_line_ending,
                _: line_ending,
                _: till_line_ending,
                _: line_ending,
            }
        }.parse_next(input)?;

        Ok(head)
    }).parse_next(i)
}

/// The statement's bytes, up to and including the first `;` that is not inside a quote.
///
/// ⛔⛔⛔ THE QUOTE STATE WAS A **STACK**, AND SQL QUOTING DOES NOT NEST — SO AN APOSTROPHE
/// INSIDE A DOUBLE-QUOTED STRING SWALLOWED THE REST OF THE LOG. `"it's here"` pushed `"`, then
/// pushed `'` because it did not match the top, then pushed a second `"` for the same reason:
/// the stack never emptied, no `;` ever terminated the statement, and the scan ran to the end
/// of the file. The decoder then reports `bytes remaining on stream` — which the analyzer
/// files as `Coverage::Truncated` — so **one apostrophe in one string silently truncates the
/// corpus at that entry**. Measured: the statement above, in a two-entry log, loses both.
///
/// ⚠️ It is not an exotic input. `"O'Brien"`, `"don't"`, `'he said "no"'` — any English text in
/// a string quoted the other way. What hid it is that both fixtures quote in one style per
/// statement, and `'say "hi"'` happens to pass because its inner quotes are **balanced**: the
/// stack pops as often as it pushes and lands empty for the wrong reason.
///
/// ⭐ Inside a quote the only thing that can happen is the end of that quote, so the state is
/// one `Option<u8>` and not a stack. A doubled quote — `'don''t'` — falls out: the second
/// closes and the third reopens, which is the same span. ⚠️ Backslash escaping applies inside
/// `'` and `"` and **not** inside a backtick, which is MySQL's rule rather than a
/// simplification — and it is the rule under the default `sql_mode`. `NO_BACKSLASH_ESCAPES`
/// changes it, and this crate records that the mode is `unmeasured` rather than assuming it.
///
/// ⛔⛔ AND IT WAS A BYTE AT A TIME THROUGH `any()` INTO A `BytesMut` OF CAPACITY ZERO. Per byte
/// of every statement: one `any()` call, one `put_slice(&[c])` call, and a doubling
/// reallocation whenever the accumulator filled — 9.7% of this codec's instructions, its
/// hottest function. The bytes are already contiguous in the buffer the decoder handed over,
/// so the scan decides a length and `take` takes it: **one copy, into one allocation of the
/// right size**, and the quote state no longer allocates at all.
///
/// ⚠️ THE REFUSAL IS WINNOW'S AND NOT THIS FUNCTION'S. Running out of input used to produce
/// whatever `any()` produces, which is `Incomplete` on a partial stream and a backtrack on a
/// complete one — a distinction the decoder's loop turns into "read more" against "panic". A
/// hand-written `Incomplete` would be right for this crate's one caller and wrong for a
/// `parse()` against a finished slice, so `any_`'s own two arms are reproduced rather than
/// collapsed.
pub fn sql_lines(i: &mut Stream<'_>) -> ModalResult<Bytes> {
    trace("sql_lines", move |input: &mut Stream<'_>| {
        let end = statement_end(input.as_bytes());

        match end {
            Some(n) => Ok(Bytes::copy_from_slice(take(n).parse_next(input)?)),
            None if input.is_partial() => Err(WinnowError::incomplete(input, Needed::new(1))),
            None => Err(WinnowError::from_input(input)),
        }
    })
    .parse_next(i)
}

/// One past the first `;` that is not inside a string or a quoted identifier, or `None` where
/// the bytes in hand do not contain one.
///
/// Split out from [`sql_lines`] so the rule can be tested against text directly rather than
/// only through a decoder over a whole log — see `quoting_does_not_nest`.
pub(crate) fn statement_end(bytes: &[u8]) -> Option<usize> {
    let mut quote: Option<u8> = None;
    let mut escaped = false;

    for (idx, c) in bytes.iter().copied().enumerate() {
        match quote {
            Some(q) => {
                if escaped {
                    escaped = false;
                } else if c == b'\\' && q != b'`' {
                    escaped = true;
                } else if c == q {
                    quote = None;
                }
            }
            None => {
                if c == b'\'' || c == b'"' || c == b'`' {
                    quote = Some(c);
                } else if c == b';' {
                    return Some(idx + 1);
                }
            }
        }
    }

    None
}

pub fn alphanumerichyphen1<'a>(i: &mut Stream<'a>) -> ModalResult<&'a [u8]> {
    alt((alphanumeric1, literal("_"), literal("-"))).parse_next(i)
}

pub fn host_name<'a>(i: &mut Stream<'_>) -> ModalResult<Bytes> {
    trace("host_name", move |input: &mut Stream<'_>| {
        let (mut first, second): (Vec<&[u8]>, &[u8]) = alt((
            ((
                repeat(1.., terminated(alphanumerichyphen1, literal("."))),
                alpha1,
            )),
            ((repeat(1, alphanumerichyphen1), take(0 as usize))),
        ))
        .parse_next(input)?;

        if !second.is_empty() {
            first.push(second);
        }

        let b = first
            .iter()
            .enumerate()
            .fold(BytesMut::new(), |mut acc, (c, p)| {
                if c > 0 {
                    acc.put_slice(".".as_bytes());
                }

                acc.put_slice(p);
                acc
            });

        Ok(b.freeze())
    })
    .parse_next(i)
}

/// ip address handler that only handles IP4
pub fn ip_address<'a>(i: &mut Stream<'_>) -> ModalResult<Bytes> {
    trace("ip_address", move |input: &mut Stream<'_>| {
        let p = seq!(
            digit1,
            preceded(literal("."), digit1),
            preceded(literal("."), digit1),
            preceded(literal("."), digit1),
        )
        .parse_next(input)?;

        let b = [p.0, p.1, p.2, p.3]
            .iter()
            .enumerate()
            .fold(BytesMut::new(), |mut acc, (c, p)| {
                if c > 0 {
                    acc.put_slice(".".as_bytes());
                }

                acc.put_slice(p);
                acc
            });

        Ok(b.freeze())
    })
    .parse_next(i)
}

/// thread id parser for 'Id: [\d+]'
pub fn entry_user_thread_id<'a>(i: &mut Stream<'_>) -> ModalResult<u32> {
    trace("entry_user_thread_id", move |input: &mut Stream<'_>| {
        let id = seq!(
            _: literal("Id:"),
            _: multispace1,
            digit1
        )
        .parse_next(input)?;

        Ok(u32::from_str(str::from_utf8(id.0).unwrap()).unwrap())
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

/// user line parser
pub fn entry_user(i: &mut Stream) -> ModalResult<SessionLine> {
    trace("entry_user", move |input: &mut Stream<'_>| {
        let s = seq! { SessionLine {
            _: multispace0,
            _: literal("# User@Host:"),
            _: multispace1,
            user: user_name,
            _: literal("["),
            sys_user: user_name,
            _: literal("]"),
            _: multispace1,
            _: literal("@"),
            _: multispace1,
            host: opt(host_name),
            _: multispace0,
            _: literal("["),
            _: multispace0,
            ip_address: opt(ip_address),
            _: multispace0,
            _: literal("]"),
            _: multispace1,
            thread_id: entry_user_thread_id,
        }}
        .parse_next(input)?;

        Ok(s)
    })
    .parse_next(i)
}

/// The key/value pairs parsed from the comment preceding a SQL statement.
///
/// ⭐ WHATEVER THE COMMENT SAID, UNDER THE NAMES IT USED. This carried four named fields --
/// `request_id`, `caller`, `function`, `line` -- and their own doc comments called them
/// "example field, should just be part of a HashMap". They were worse than a placeholder:
/// applications annotate with whatever keys they like, and four names admitted four of them.
///
/// ⛔ AND THE NAMES WERE NOT EVEN THE COMMENT'S. The reference mapper put the comment key
/// `file` into a field called `caller` and `method` into one called `function`. That is a
/// READER'S VOCABULARY compiled into the parser, and a reader who disagreed had no way to say
/// so. A parser's job here is to report what the document wrote; deciding that `file` names
/// the same thing as some other log's `caller` is a judgement that belongs to whoever is
/// comparing them, where it can be seen and disagreed with.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SqlStatementContext {
    /// Every pair the comment carried, keys and values exactly as written.
    pub entries: HashMap<Bytes, Bytes>,
}

impl SqlStatementContext {
    /// Builds a context from the pairs a comment parsed into. `None` where there were none,
    /// so an empty comment and an absent one stay distinguishable.
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

pub fn details_comment<'a>(i: &mut Stream) -> ModalResult<HashMap<Bytes, Bytes>> {
    trace("details_comment", move |input: &mut Stream<'_>| {
        let mut name: Option<Bytes> = None;

        let mut res: HashMap<Bytes, BytesMut> = HashMap::new();

        let _ = literal("--").parse_next(input)?;

        loop {
            if name.is_none() {
                if let Ok(n) = details_tag(input) {
                    name.replace(n.clone());
                    if let Some(_) = res.insert(n, BytesMut::new()) {
                        //TODO: see if you need to set the ErrorKind::Assert specifically, like before
                        return Err(ErrMode::Cut(ContextError::new()));
                    }
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
                    // TODO: previously this specified ErrorKind::Assert, figure out if this needs to be specificied still
                    let v = &mut res.get_mut(k).ok_or(ErrMode::Cut(ContextError::new()))?;

                    v.put_bytes(c as u8, 1);
                } else {
                    // TODO: previously this specified ErrorKind::Assert, figure out if this needs to be specificied still
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

pub fn details_tag<'a>(i: &mut Stream) -> ModalResult<Bytes> {
    trace("details_tag", move |input: &mut Stream<'_>| {
        let name = seq!(
            _: multispace0,
            user_name,
            _: multispace0,
            _: alt((literal(":"), literal("="))),
            _: multispace0,
        )
        .parse_next(input)?;

        Ok(name.0.into())
    })
    .parse_next(i)
}

/// values parsed from stats entry line
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct StatsLine {
    /// how long the overall query took
    pub(crate) query_time: f64,
    /// how long the query held locks
    pub(crate) lock_time: f64,
    /// how many rows were sent
    pub(crate) rows_sent: u32,
    /// how many rows were scanned
    pub(crate) rows_examined: u32,
}

impl StatsLine {
    /// how long the overall query took
    pub fn query_time(&self) -> f64 {
        self.query_time.clone()
    }
    /// how long the query held locks
    pub fn lock_time(&self) -> f64 {
        self.lock_time.clone()
    }

    /// how many rows were sent
    pub fn rows_sent(&self) -> u32 {
        self.rows_sent.clone()
    }
    /// how many rows were scanned
    pub fn rows_examined(&self) -> u32 {
        self.rows_examined.clone()
    }
}

/// parse '# Query_time:...' entry line
pub fn parse_entry_stats(i: &mut Stream<'_>) -> ModalResult<StatsLine> {
    trace("parse_entry_stats", move |input: &mut Stream<'_>| {
        let stats = seq! {StatsLine {
            _: literal("#"),
            _: multispace1,
            _: literal("Query_time:"),
            _: multispace1,
            query_time: float,
            _: multispace1,
            _: literal("Lock_time:"),
            _: multispace1,
            lock_time: float,
            _: multispace1,
            _: literal("Rows_sent:"),
            _: multispace1,
            rows_sent: digit1.map(|d| str::from_utf8(d).unwrap().parse().unwrap()),
            _: multispace1,
            _: literal("Rows_examined:"),
            _: multispace1,
            rows_examined: digit1.map(|d| str::from_utf8(d).unwrap().parse().unwrap()),
        }}
        .parse_next(input)?;

        Ok(stats)
    })
    .parse_next(i)
}

/// admin command values parsed from sql lines of an entry
#[derive(Clone, Debug, PartialEq)]
pub struct EntryAdminCommand {
    /// the admin command sent
    pub command: Bytes,
}

/// parse "# administrator command: " entry line
pub fn admin_command<'a>(i: &mut Stream) -> ModalResult<EntryAdminCommand> {
    trace("admin_command", move |input: &mut Stream<'_>| {
        let command = seq!(
            _: literal("# administrator command:"),
            _: multispace1,
            // ⭐ TO THE `;`, NOT ONE WORD. `alphanumerichyphen1` matches a single run of
            // alphanumerics, so every administrator command whose name contains a space failed
            // here and fell through to the SQL branch. MySQL has many: `Init DB`,
            // `Register Slave`, `Binlog Dump`, `Table Dump`, `Change user`, `Close stmt`,
            // `Reset stmt`, `Long Data`, `Set option`, `Field List`, `Create DB`, `Drop DB`,
            // `Process info`, `Connect Out`, `Delayed insert`.
            //
            // ⛔ AND FAILING HERE WAS NOT FREE, WHICH IS WHY THE CALL SITE CHANGED TOO. See
            // `codec.rs`: winnow does not rewind a parser that fails after consuming, so the
            // stream resumed mid-line and the remainder -- `DB;`, `Slave;` -- was read as the
            // statement's SQL. The command name was destroyed and a fragment filed in its place.
            take_till(1.., (b';', b'\r', b'\n')),
            _: literal(";"),
        )
        .parse_next(input)?;

        Ok(EntryAdminCommand {
            // `multispace1` ate the leading run; trailing spaces before the `;` are ours.
            command: command.0.trim_ascii_end().to_owned().into(),
        })
    })
    .parse_next(i)
}

/// parses 'USE database=\w+;' command which shows up at the start of some entry sql
pub fn use_database(i: &mut Stream) -> ModalResult<Bytes> {
    trace("use_database", move |input: &mut Stream<'_>| {
        let db_name = seq!(
            _: literal(Caseless("USE")),
            _: multispace1,
            user_name,
            _: multispace0,
            _: literal(";"),
        )
        .parse_next(input)?;

        Ok(db_name.0.into())
    })
    .parse_next(i)
}

/// parses 'SET timestamp=\d{10};' command which starts
pub fn start_timestamp_command(i: &mut Stream) -> ModalResult<u32> {
    trace("start_timestamp_command", move |input: &mut Stream<'_>| {
        let time = seq!(
            _: literal("SET timestamp"),
            _: multispace0,
            _: literal("="),
            _: multispace0,
            digit1,
            _: multispace0,
            _: literal(";"),
        )
        .parse_next(input)?;

        Ok(u32::from_str(str::from_utf8(time.0).unwrap()).unwrap())
    })
    .parse_next(i)
}

/// One literal value the author wrote.
///
/// ⭐⭐ THE AUTHOR'S SUBJECT, AND THE RECORD USED TO THROW IT AWAY. `WHERE tenant_id = 42` is a
/// claim about which rows the statement was about. Masking replaces it with `?`, which is a
/// READER's assertion that two authors' subjects are interchangeable. Filing the literal is what
/// makes masking a grouping choice rather than an edit to somebody else's document.
///
/// ⚠️ NO SOURCE POSITION, and the reason is not an oversight. The span lives on
/// `sqlparser::ast::ValueWithSpan`, which derives `Visit` but carries no `visit(with = ...)`
/// annotation -- so no visitor hook ever sees it. [`EntryLiteral::ordinal`] is the position, and
/// it is exact rather than approximate because ONE pass both records and masks, so the two can
/// never fall out of step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryLiteral {
    /// Position in the statement's own value order, counting from zero.
    ///
    /// ⛔ Deterministic: the traversal is depth-first in field-declaration order, emitted by
    /// `sqlparser_derive` and pinned by that crate's own doctests. ⚠️ It is stable *within* a
    /// `sqlparser` version and nothing promises it across one.
    pub ordinal: u32,
    /// The literal as the author wrote it, quoting and all.
    pub rendered: Bytes,
    /// The payload without its quoting -- what a reader groups by.
    pub value: Bytes,
    /// Which kind of literal it is.
    pub kind: LiteralKind,
    /// ⭐⭐ THE COLUMN THE AUTHOR COMPARED THIS VALUE AGAINST, where the syntax names one.
    ///
    /// `WHERE tenant_id = 42` filed `42` and threw `tenant_id` away, so every literal in a
    /// corpus sat in one undifferentiated pool and `42` the tenant was indistinguishable from
    /// `42` the row limit. A value only means something **in a domain**, and the domain is a
    /// column of a relation.
    ///
    /// ⛔ `None` is a **measured** absence and not a gap: a `CREATE TABLE` default, a `LIMIT`,
    /// a `SET` value and a function argument are literals the author wrote in a position that
    /// names no column. They select no rows and take no lock. Measured: **252 of 302** on
    /// `slow-test-queries.log` and **136 of 248** on `structure.log`.
    ///
    /// ⚠️ FOUR SHAPES, AND THEY ARE NOT ALL THE SAME CLAIM. A comparison, an `IN` list and a
    /// `BETWEEN` bound name the column a value is **sought** in. `UPDATE … SET qty = 5` and
    /// `INSERT … VALUES` name the column a value is **written** to, which is a key the statement
    /// creates or changes rather than one it looks up. [`Self::sought`] is what tells them apart,
    /// because a lock taken to find a row and a lock taken to write one are different locks.
    pub column: Option<LiteralColumn>,
    /// Whether the author was **looking for** this value or **writing** it.
    ///
    /// ⛔ AND IT IS WHY THE SHIPPED CORPUS LOOKED EMPTY. `slow-test-queries.log` is a sandbox
    /// startup and a `mysqldump` restore: **not one of its 302 literals sits in a predicate.**
    /// Its 50 bound values are every one of them an `INSERT` column or a `SET` target. A rule
    /// that read predicates alone would have measured zero there and called the corpus silent,
    /// when what it actually is is a corpus that only ever wrote.
    ///
    /// ⚠️ `false` on an unbound literal, where it asserts nothing.
    pub sought: bool,
    /// ⭐⭐ The position in the row this value was written at, where the `INSERT` named no
    /// columns: the `n`-th value reaches the table's `n`-th column.
    ///
    /// ⛔ A DOMAIN, AND NOT THE SAME ONE AS [`Self::column`]. Which physical column `#n` is
    /// lives in a catalogue no slow log carries, so a positional domain and a named domain over
    /// one table are kept apart rather than fused on a guess.
    pub column_position: Option<u32>,
}

/// The column name an [`EntryLiteral`] was compared against, exactly as the author spelled it.
///
/// ⚠️ THE WRITTEN NAME AND NOT A RELATION. `e1.dept_id` carries the qualifier the author used,
/// which is an **alias** far more often than a table — and an alias is scoped, so resolving it
/// to a relation is a second hop through the statement's own occurrences. That hop belongs to
/// whoever holds the scope tree, which this struct deliberately does not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiteralColumn {
    /// Everything before the last `.`, joined as written — an alias, a table, or a schema and a
    /// table. `None` where the author wrote a bare column name.
    ///
    /// ⚠️ Measured: **0 of 50** bound literals on `slow-test-queries.log` carry one and **80 of
    /// 125** on `structure.log` do. A bare name fixes a relation only where the statement names
    /// exactly one.
    pub qualifier: Option<Bytes>,
    /// The column name itself.
    pub name: Bytes,
}

/// What kind of literal an [`EntryLiteral`] is.
///
/// ⛔ `E'…'` had an arm and MySQL has no such literal — `MySqlDialect` refuses the text, so
/// nothing could ever produce it. Removed rather than documented: **this crate reads MySQL slow
/// logs**, and an arm no input reaches is one more case every consumer has to handle.
///
/// ⚠️ `"…"` stays, and it is the one that is genuinely ambiguous: MySQL reads it as a string
/// literal by default and as an **identifier** under `ANSI_QUOTES`. Which one it was is
/// `sql_mode`, and a slow log does not record it — see `connection.rs`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

/// ⭐⭐⭐ Re-render a statement with a substitute in place of chosen literals.
///
/// `replacements[i]` is the new **payload** for the `i`-th literal [`parse_sql`] would record,
/// in the same traversal order and under the same arm filter -- so an ordinal from
/// [`EntryLiteral`] indexes this directly and the two can never drift apart. `None` leaves a
/// literal alone, and a short slice leaves the tail alone.
///
/// ⛔⛔ THE KIND IS TAKEN FROM THE ORIGINAL AND NOT FROM THE CALLER, which is what makes the
/// substitution **type-preserving** by construction rather than by convention. A number stays a
/// number and a quoted string stays a quoted string: swap them and the statement stops being the
/// statement, because MySQL compares an integer column against a string by coercing it and takes
/// a different path through the index. The caller cannot get this wrong because it has no way to
/// say it.
///
/// ⚠️ Returns `None` where the text does not parse or is not exactly one statement. A caller
/// with a surrogate to apply and nothing to apply it to must **withhold**, and the `None` is what
/// says so -- silently returning the original would hand back the author's values under a name
/// that promises it did not.
///
/// ⚠️ It re-parses rather than taking a tree, because the substitution a caller wants is
/// corpus-scoped: the whole log has to be read before any surrogate is known, and by then the
/// trees are long gone. The text it re-parses is the tree's own rendering, so the traversal it
/// walks is the traversal that produced the ordinals.
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

/// ⭐⭐⭐ Does this text carry a value the author supplied? `None` where it cannot be tokenized.
///
/// ⛔ FOR THE STATEMENTS THIS GRAMMAR REFUSES, AND ONLY THOSE. A statement that parsed has
/// literals with a **position** — [`EntryLiteral::column`] says whether the author went for a row
/// with it — and that is a far better question than this one. A statement with no parse has no
/// positions, so the only thing left to ask is whether there is a value in it at all.
///
/// ⚠️ IT OVER-APPROXIMATES, AND THE DIRECTION IS THE WHOLE ARGUMENT. `LIMIT 10` and
/// `SET TIME_ZONE='+00:00'` both answer `true` while naming nobody. A caller withholding on this
/// withholds a little more than it must, which costs **fidelity** and never costs privacy --
/// the opposite of the tokenizer-level *masking* this crate removed, where `CHAR(60)` became
/// `CHAR(?)` and destroyed 35 parses in silence. **Deciding is safe where editing was not.**
///
/// ⛔⛔ AND IT OPENS THE VERSION GATES, WITHOUT WHICH IT UNDERCOUNTS. `sqlparser`'s tokenizer
/// files `/*!40101 ... */` as one **comment** while MySQL *executes* it, so a literal inside a
/// gate is invisible to a plain token scan: on `slow-test-queries.log` that is the difference
/// between 130 statements answering `false` and the true figure of 122. The server's regime and
/// the grammar's disagree about the construct, and this is the disagreement arriving as an
/// off-by-eight.
///
/// ⚠️ A value written as an **identifier** is invisible here and no token scan can see it:
/// `DEFINER=`msandbox`@`%`` is a username and a host in backticks. A caller must say so rather
/// than imply this covers it.
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
                    // `!40101 SET ...` -- a gate the server would have run.
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

    fn pre_visit_value(&mut self, value: &mut Value) -> ControlFlow<Self::Break> {
        // ⛔ THE SAME ARMS AS `LiteralPass::pre_visit_value`, AND THAT IS LOAD-BEARING. A
        // boolean, a NULL or a placeholder is recorded by neither, so neither advances its
        // counter over one -- and an ordinal that meant a different literal in the two passes
        // would substitute the author's value into the wrong slot.
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
        // ⭐ Assigning through `&mut Value` leaves the `ValueWithSpan` wrapper alone, for the
        // same reason masking does.
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

/// Records every literal in a statement, and replaces it where asked, in ONE traversal.
///
/// ⛔⛔ AFTER THE PARSE AND NEVER BEFORE IT. Replacing tokens first destroys statements that are
/// perfectly well formed: a number inside a type declaration is not a value, and `CHAR(?)`,
/// `DECIMAL(?,?)` and `INT(?)` are not SQL. That cost **35 of 163 parses** on this crate's own
/// fixture -- every `CREATE TABLE` and `ALTER TABLE` -- and the consumer's default is to mask, so
/// the default was the lossy one. After the parse the ambiguity is gone: a type parameter is not
/// a `Value` and a literal is.
///
/// ⛔ `pre_visit_value` AND NOT `Expr::Value`, which is what this used to match on.
/// `Expr::TypedString` (`DATE '2020-01-01'`) and `Expr::MatchAgainst` (MySQL's
/// `AGAINST ('term')`) hold a `Value` without being one, so an `Expr`-shaped pass neither masked
/// them nor could have recorded them.
///
/// ⚠️ It reaches a few `Value`s that are not row-selecting -- a `CEIL(x TO 2)` scale, a
/// `TABLESAMPLE` seed. Those are grammar, not subject, and masking them is wrong in the same way
/// masking a type parameter was. It cannot break a parse the way the old route did, because the
/// tree already exists; `a_masked_statement_still_parses` is what holds that.
struct LiteralPass {
    literals: Vec<EntryLiteral>,
    mask: bool,
    /// One entry per enclosing `Expr`, saying what a value **directly beneath it** is compared
    /// against.
    ///
    /// ⭐ THE PARENT AND ONLY THE PARENT. `pre_visit_value` fires inside the `Expr::Value` node,
    /// so the stack reads `[…, the comparison, Expr::Value]` and the binding is at `len - 2`.
    /// Searching further up would let `WHERE a = f(g(1))` bind `1` to `a`, which is a claim the
    /// author did not make: the value is an argument, not a key.
    binds: Vec<Option<LiteralColumn>>,
    /// Values reached through a node that is **not** an `Expr`, by the address of the value.
    ///
    /// ⛔⛔ `Assignment` AND AN INSERT COLUMN LIST ARE NOT EXPRESSIONS, so no hook on this
    /// visitor ever sees the column beside the value — and on `slow-test-queries.log` those are
    /// the ONLY bound literals there are. [`Self::binds`] cannot reach them at any depth.
    ///
    /// ⚠️ Keyed on the value's address and never on its payload. `INSERT INTO t (a, b)
    /// VALUES (5, 5)` writes one payload into two columns, and a payload-matched queue would
    /// hand both to whichever it met first. The address is taken in `pre_visit_statement`, which
    /// runs before the statement's children and therefore before anything is masked; masking
    /// assigns *through* `&mut Value` and moves no node, so the address still names the same
    /// slot when `pre_visit_value` reaches it. Nothing is ever dereferenced.
    targets: HashMap<usize, LiteralColumn>,
    /// ⭐⭐ Values written by an `INSERT` that named **no columns**, by address, with the
    /// position in the row they were written at.
    ///
    /// The author's data, and the column IS recoverable -- positionally. An `INSERT` with no
    /// column list writes in the table's own column order, so the `n`-th value reaches the
    /// `n`-th column for every such statement against that table. Kept apart from
    /// [`Self::targets`] because a positional domain and a named one are not known to be the
    /// same domain: deciding that needs the catalogue.
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
/// ⚠️ `UPDATE … SET (a, b) = (…)` -- `AssignmentTarget::Tuple` -- is deliberately not here. The
/// tuple's right-hand side is one `Expr`, not a list, so which column each value inside it goes
/// to is a positional reading of a subquery or a row constructor, and MySQL does not write it.
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
        Statement::Update { assignments, .. } => {
            for a in assignments {
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
                // ⛔⛔ AN INSERT WITH NO COLUMN LIST IS STILL WRITING THE AUTHOR'S DATA, and
                // filing its values as "no column is named here" put them in the same bucket as
                // a `LIMIT` and a `CREATE TABLE` default -- things that name nobody. They are not
                // the same: `INSERT INTO t VALUES (1, 'kay')` writes a row, and on
                // `slow-test-queries.log` that is **98 literals** a rule keyed on the bucket
                // would have shipped in the clear.
                //
                // ⚠️ The column is genuinely not recoverable -- it is the table's `n`-th, and
                // which one that is lives in a catalogue no slow log carries. So this says the
                // value was WRITTEN and declines to name where, which are two different claims
                // and were one.
                if i.columns.is_empty() {
                    // ⭐⭐ AND THE COLUMN IS RECOVERABLE AFTER ALL, POSITIONALLY. An `INSERT`
                    // with no column list writes in the table's own column order, so the `n`-th
                    // value goes to the `n`-th column -- for every such statement against that
                    // table, which is exactly what makes `(relation, #n)` a domain rather than a
                    // label. Two statements writing the same value at the same position really
                    // did go for the same key.
                    //
                    // ⛔ IT IS NOT THE SAME DOMAIN AS A NAMED ONE and must never be fused with
                    // it. `INSERT INTO t (b, a) VALUES (1, 2)` puts `1` in `b`, and
                    // `INSERT INTO t VALUES (1, 2)` puts `1` in the table's first column, which
                    // the log does not say is `b`. Deciding they are one needs the catalogue,
                    // and a slow log carries none -- so `#0` and `b` stay apart, the same way
                    // `_bare` and `_resolved` stay apart one grain up.
                    for (n, e) in row.iter().enumerate() {
                        if let Expr::Value(v) = e {
                            positional.insert(std::ptr::from_ref(&v.value).addr(), n as u32);
                        }
                    }
                    continue;
                }
                for (col, e) in i.columns.iter().zip(row) {
                    put(
                        Some(LiteralColumn {
                            qualifier: None,
                            name: Bytes::from(col.value.clone()),
                        }),
                        e,
                    );
                }
            }
        }
        _ => {}
    }
}

/// The column a value **directly beneath this expression** is sought in, where there is one.
///
/// ⛔ COMPARISON OPERATORS ONLY, and the reason is not fussiness. `Expr::BinaryOp` covers `+`
/// as well as `=`, so a rule that took any binary operator would bind the `1` in `qty + 1` to
/// `qty` — filing arithmetic as a key lookup, in a column whose whole purpose is to say which
/// rows a statement went for.
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
        // ⭐ Every member of an `IN` list is sought in the same column, so one binding serves
        // them all — and they are direct children, which is what makes that exact.
        Expr::InList { expr, list, .. } if list.iter().any(is_value) => column_of(expr),
        // ⭐ A range, which is where InnoDB's next-key locking actually lives: the bound is a
        // claim about a stretch of the index rather than about one row.
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
        // ⚠️ `<=>` is MySQL's own NULL-safe equality and belongs here for the same reason `=`
        // does: it names rows.
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
        // ⚠️ Read BEFORE the value beneath is masked. `pre_visit_value` replaces the value with
        // a placeholder, and a binding computed afterwards would see `?` on both sides.
        self.binds.push(binding_of(expr));
        ControlFlow::Continue(())
    }

    fn post_visit_expr(&mut self, _expr: &mut Expr) -> ControlFlow<Self::Break> {
        self.binds.pop();
        ControlFlow::Continue(())
    }

    fn pre_visit_value(&mut self, value: &mut Value) -> ControlFlow<Self::Break> {
        let (kind, payload) = match value {
            Value::Number(n, _) => (LiteralKind::Number, n.clone()),
            Value::SingleQuotedString(v) => (LiteralKind::SingleQuotedString, v.clone()),
            Value::DoubleQuotedString(v) => (LiteralKind::DoubleQuotedString, v.clone()),
            Value::NationalStringLiteral(v) => (LiteralKind::NationalString, v.clone()),
            Value::HexStringLiteral(v) => (LiteralKind::HexString, v.clone()),
            // ⛔ A boolean, a NULL and a placeholder are not the author's subject: `TRUE` names
            // no rows and `?` was never theirs. Recording them would put the reader's own
            // placeholder into a column of the author's values.
            _ => return ControlFlow::Continue(()),
        };

        // ⚠️ `len - 2` and never a search: see [`LiteralPass::binds`]. A value with no enclosing
        // expression at all -- which the traversal does reach -- binds to nothing.
        let sought = self
            .binds
            .len()
            .checked_sub(2)
            .and_then(|i| self.binds[i].clone());
        // ⭐ The predicate first: a value can only be in one of the two positions, and where it
        // is in neither both are `None`.
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
            // ⭐ The INNER value, not the wrapper. `Expr::value(..)` builds a fresh
            // `ValueWithSpan` through `with_empty_span()`, which throws away a span this crate
            // may one day populate. Assigning through `&mut Value` leaves the wrapper alone.
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

    /// ⭐⭐ EVERY ARM OF [`LiteralKind`], AND THERE ARE FIVE BECAUSE ONE WAS NOT MYSQL'S.
    ///
    /// Two of the six had a witness — `Number` and `SingleQuotedString`. Of the other four,
    /// three are ordinary MySQL and one was `E'…'`, which `MySqlDialect` **refuses**, so nothing
    /// could ever produce it. It is gone rather than documented: this crate reads MySQL slow
    /// logs, and an arm no input reaches is one more case every consumer has to handle.
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
        // ⛔ THE GUARD. Five arms, written out because the enum cannot be iterated. It was six
        // before `EscapedString` went.
        assert_eq!(
            seen.len(),
            5,
            "every LiteralKind arm needs text that reaches it; reached {seen:?}"
        );

        // ⛔ And the arm that was removed stays removed: MySQL has no such literal and this
        // grammar refuses the text, so there is nothing for an arm to hold.
        assert!(
            parse_sql("SELECT 1 FROM t WHERE a = E'x'", &EntryMasking::None).is_err(),
            "E'…' is not MySQL and this parser does not accept it"
        );
    }

    /// ⛔⛔ `"x"` IS A LITERAL OR AN IDENTIFIER AND THE LOG DOES NOT SAY WHICH.
    ///
    /// This is not two dialects disagreeing — it is **MySQL disagreeing with itself** depending
    /// on a setting a slow log never records. By default `"x"` is a string literal; under
    /// `sql_mode = 'ANSI_QUOTES'` the same bytes are a quoted **identifier**, which is a column
    /// and not a subject at all.
    ///
    /// ⭐ So this arm firing is the `sql_mode` risk made concrete rather than argued: the crate
    /// files a row in `literals.parquet` — the author's subject — for text that may have been a
    /// column name. `connection.rs` carries `sql_mode` with its provenance for exactly this, and
    /// on both corpora it is `opaque` or `unmeasured`, so the question stays open.
    ///
    /// ⚠️ The parser is not wrong to pick one: `MySqlDialect` is fixed and honours no mode. What
    /// would be wrong is filing the reading without recording that a reading was made.
    #[test]
    fn a_double_quoted_string_is_the_one_literal_the_mode_can_reinterpret() {
        let got = kinds("SELECT \"name\" FROM person");
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].0, LiteralKind::DoubleQuotedString);
        assert_eq!(got[0].1, "\"name\"", "the author's own spelling is kept");

        // ⭐ Under `ANSI_QUOTES` this same statement has NO literal and names a column — so the
        // count this crate files for it is 1 under one mode and 0 under the other. Nothing else
        // in the record would show that, which is why the mode is carried per connection.
        assert!(
            kinds("SELECT 'name' FROM person")
                .iter()
                .all(|(k, _)| *k == LiteralKind::SingleQuotedString),
            "the unambiguous spelling, for contrast"
        );
    }
}

/// ⭐⭐⭐ THE SUBSTITUTION, WHICH IS WHAT LETS A STATEMENT SHIP WITHOUT ITS SUBJECT.
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

    /// ⭐⭐ THE ROUND TRIP, WHICH IS THE ONLY THING THAT SAYS THE ORDINALS LINE UP.
    ///
    /// Rewrite every literal to its own recorded value and the statement must come back
    /// unchanged. ⛔ If [`RewritePass`] counted one arm differently from [`LiteralPass`] -- a
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

    /// ⛔ AND THE SUBSTITUTION LANDS WHERE THE ORDINAL SAYS, not one literal over.
    #[test]
    fn a_surrogate_replaces_the_literal_its_ordinal_names() {
        let sql = "SELECT a FROM t WHERE ok = TRUE AND id = 42 AND other = 99";
        let rendered = parse_sql(sql, &EntryMasking::None).unwrap().0[0].to_string();
        assert_eq!(lits(&rendered), vec!["42", "99"]);
        let out = rewrite_literals(&rendered, &[Some("7".into()), None]).unwrap();
        assert!(out.contains("id = 7"), "{out}");
        assert!(out.contains("other = 99"), "{out}");
    }

    /// ⛔⛔ THE KIND IS THE ORIGINAL'S AND THE CALLER CANNOT SAY OTHERWISE.
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

        // ⭐ And the mapped statement is still SQL, which is the whole difference between this
        // and a `?` nobody recorded a bind for.
        for out in [n, q] {
            assert!(parse_sql(&out, &EntryMasking::None).is_ok(), "{out}");
        }
    }

    /// ⛔ TEXT WITH NO PARSE GETS `None` AND NEVER ITS OWN BYTES BACK.
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
        // ⚠️ And two statements are refused as well: the ordinals would span them and a caller
        // asking for one statement's literal would reach another's.
        assert_eq!(
            rewrite_literals("SELECT 1; SELECT 2", &[Some("9".into())]),
            None
        );
    }

    /// ⚠️ A short slice leaves the tail alone rather than panicking, because the caller's map
    /// is built per domain and a literal in no domain has no surrogate to offer.
    #[test]
    fn a_literal_with_no_surrogate_is_left_as_the_author_wrote_it() {
        let out = rewrite_literals("SELECT a FROM t WHERE id = 42 LIMIT 10", &[]).unwrap();
        assert!(out.contains("42") && out.contains("10"), "{out}");
    }

    /// ⛔⛔ AN INSERT WITH NO COLUMN LIST IS WRITING DATA, NOT WRITING NOTHING.
    ///
    /// `INSERT INTO t VALUES (1, 'kay')` puts a row in a table. Filing those values as "no
    /// column is named here" — the bucket a `LIMIT` and a `CREATE TABLE` default live in — made
    /// them look like grammar, and on `slow-test-queries.log` that is **98 literals** a rule
    /// keyed on the bucket would have published in the clear.
    ///
    /// ⚠️ The column really is unrecoverable: it is the table's `n`-th and which one that is
    /// lives in a catalogue no slow log carries. So the claim is *written*, and *where* is
    /// declined — two claims that had been one.
    #[test]
    fn an_insert_with_no_column_list_writes_to_a_column_it_can_name_by_position() {
        let ls = parse_sql("INSERT INTO t VALUES (1, 'kay')", &EntryMasking::None)
            .unwrap()
            .1;
        assert_eq!(ls.len(), 2);
        // ⭐⭐ AND THE COLUMN IS RECOVERABLE POSITIONALLY: the `n`-th value reaches the table's
        // `n`-th column, for every such statement against that table.
        assert_eq!(
            ls.iter().map(|l| l.column_position).collect::<Vec<_>>(),
            vec![Some(0), Some(1)]
        );
        assert!(ls.iter().all(|l| l.column.is_none()), "and it is not NAMED");

        // ⭐ A column list names them, so they are named and NOT positional -- the two are
        // exclusive, and the same statement one clause different proves it.
        let named = parse_sql(
            "INSERT INTO t (a, b) VALUES (1, 'kay')",
            &EntryMasking::None,
        )
        .unwrap()
        .1;
        assert!(named.iter().all(|l| l.column_position.is_none()));
        assert!(named.iter().all(|l| l.column.is_some()));

        // ⛔ And a literal that names nobody is in neither: a `LIMIT` is grammar.
        let limit = parse_sql("SELECT a FROM t LIMIT 10", &EntryMasking::None)
            .unwrap()
            .1;
        assert_eq!(limit.len(), 1);
        assert!(limit[0].column_position.is_none() && limit[0].column.is_none());

        // ⛔⛔ EVERY ROW OF A MULTI-ROW INSERT COUNTS FROM ZERO AGAIN. A counter that ran on
        // across rows would file the second row's first value in the table's third column.
        let rows = parse_sql("INSERT INTO t VALUES (1, 2), (3, 4)", &EntryMasking::None)
            .unwrap()
            .1;
        assert_eq!(
            rows.iter().map(|l| l.column_position).collect::<Vec<_>>(),
            vec![Some(0), Some(1), Some(0), Some(1)]
        );
    }

    /// ⛔⛔ THE VERSION GATE IS THE WHOLE DIFFICULTY, and a plain token scan misses it.
    ///
    /// `sqlparser` files `/*!40101 ... */` as one comment; MySQL executes it. A scan that does
    /// not open the gate answers `false` on a statement that sets a value, which on
    /// `slow-test-queries.log` is eight statements' worth of difference.
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
        // ⭐ And the same gate with nothing in it stays false, so the recursion is not a
        // blanket `true` on every gated statement.
        assert_eq!(
            carries_a_value("/*!40101 SET character_set_client = utf8 */;"),
            Some(false)
        );
    }

    /// ⭐ The statements this grammar refuses and that carry nothing -- which on the shipped
    /// corpus is 122 of 131, and is why withholding them all would be withholding for nothing.
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

    /// ⚠️ AND A VALUE WRITTEN AS AN IDENTIFIER IS INVISIBLE, which is stated rather than
    /// implied. `DEFINER=`msandbox`@`%`` is a username and a host, and no scan for literals can
    /// see them -- three of the shipped log's unparseable statements carry exactly that.
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

/// ⭐⭐⭐ THE DOMAIN A VALUE LIVES IN, WHICH THE RECORD THREW AWAY ON EVERY LITERAL.
///
/// `WHERE tenant_id = 42` filed `42` and lost `tenant_id`, so `42` the tenant and `42` the row
/// limit sat in one pool with nothing separating them. A value means nothing outside a domain,
/// and for a lock the domain is a column of a relation.
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

    /// ⭐ Every syntactic shape that names the column a value is **sought** in.
    #[test]
    fn a_literal_carries_the_column_the_author_looked_for_it_in() {
        assert_eq!(
            bound("SELECT id FROM t WHERE tenant_id = 42", &EntryMasking::None),
            [("42".into(), "tenant_id".into(), true)]
        );
        // ⭐ Written either way round: a predicate is a comparison, not an assignment.
        assert_eq!(
            bound("SELECT id FROM t WHERE 42 = tenant_id", &EntryMasking::None),
            [("42".into(), "tenant_id".into(), true)]
        );
        // ⭐ The qualifier the author wrote, which is an alias far more often than a table.
        assert_eq!(
            bound(
                "SELECT id FROM t e1 WHERE e1.dept_id = 4",
                &EntryMasking::None
            ),
            [("4".into(), "e1.dept_id".into(), true)]
        );
        // ⭐ An `IN` list: every member is sought in the same column.
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
        // ⭐⭐ A range, which is where InnoDB's next-key locking actually lives.
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

    /// ⛔⛔ ARITHMETIC IS NOT A KEY LOOKUP, AND THE FIXTURE HAS NINE OF THEM.
    ///
    /// `Expr::BinaryOp` covers `+` as well as `=`. A rule taking any binary operator binds the
    /// `1` in `qty - 1` to `qty` and files a computation as a row the statement went for.
    /// Measured on `structure.log`: **116 bound under the comparison rule against 125 under the
    /// naive one** — `total + 5`, `n + 1` twice, `n + 2` twice, `qty - 1`, `qty - 2`,
    /// `price + 1`, and one more.
    #[test]
    fn arithmetic_is_not_a_key_lookup() {
        // ⚠️ Neither literal is bound: `1` sits under `-`, and `0`'s other side is a
        // computation rather than a column.
        assert_eq!(
            bound("SELECT id FROM t WHERE qty - 1 > 0", &EntryMasking::None),
            [
                ("1".into(), "-".into(), false),
                ("0".into(), "-".into(), false)
            ]
        );
        // ⭐ And the same column with a comparison **is** bound, so the rule is about the
        // operator and not about the shape.
        assert_eq!(
            bound("SELECT id FROM t WHERE qty > 0", &EntryMasking::None),
            [("0".into(), "qty".into(), true)]
        );
    }

    /// ⛔ A VALUE SOUGHT AND A VALUE WRITTEN ARE DIFFERENT CLAIMS, and one statement makes both.
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

    /// ⛔⛔ ONE PAYLOAD WRITTEN TO TWO COLUMNS, which is what rules out matching on the payload.
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

    /// ⭐⭐ THE SHIPPED CORPUS SEEKS NOTHING, which a predicate-only rule would have read as
    /// silence.
    ///
    /// `slow-test-queries.log` is a sandbox startup and a `mysqldump` restore: **0 of its 302
    /// literals sit in a predicate** and all 50 of its bound ones are insert columns. A corpus
    /// that only ever wrote is a different thing from a corpus with no domains in it.
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

    /// ⭐ MASKING MOVES THE RENDER AND NOT THE DOMAIN.
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
        // ⚠️ `rendered` stays the author's under both settings -- it is a column of THEIR
        // document, which is the whole point of filing literals through masking. What masking
        // moves is the statement, so that is where the placeholder is checked.
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
        EntryAdminCommand, HeaderLines, SessionLine, StatsLine, Stream, admin_command,
        details_comment, entry_user, host_name, ip_address, log_header, parse_entry_stats,
        parse_entry_time, parse_sql, sql_lines, start_timestamp_command, use_database,
    };
    use bytes::Bytes;
    use std::assert_eq;
    use std::collections::HashMap;
    use winnow_datetime::{Date, DateTime, Offset, Time};

    /// ⭐⭐ THE MICROSECONDS A SLOW LOG WRITES NOW REACH THE CONSUMER.
    ///
    /// `# Time:` carries six fractional digits and `winnow_datetime::Time` held three, scaled
    /// to milliseconds, so `.015898` arrived as `15` and everything below a millisecond was
    /// gone before any consumer saw it. On `assets/slow-test-queries.log` that collapsed 310
    /// distinct instants onto 80 -- and a downstream writer that truncated further took it to
    /// 4.
    ///
    /// Requires winnow_datetime 0.4. This is the assertion the whole dependency bump is for.
    #[test]
    fn a_time_line_keeps_its_microseconds() {
        let mut i = Stream::new("# Time: 2018-02-05T02:46:43.015898Z".as_bytes());
        let dt = parse_entry_time(&mut i).unwrap();

        assert_eq!(dt.time.second, 43);
        assert_eq!(dt.time.nanosecond, 15_898_000, ".015898 is 15_898_000ns");

        // and two instants a microsecond apart stay two instants
        let mut a = Stream::new("# Time: 2018-02-05T02:46:43.015898Z".as_bytes());
        let mut b = Stream::new("# Time: 2018-02-05T02:46:43.015899Z".as_bytes());
        assert_ne!(
            parse_entry_time(&mut a).unwrap().time.nanosecond,
            parse_entry_time(&mut b).unwrap().time.nanosecond,
        );
    }

    #[test]
    fn parses_time_line() {
        let i = "# Time: 2015-06-26T16:43:23+0200";

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

        //TODO: check for leftovers
        let dt = parse_entry_time(&mut s).unwrap();
        assert_eq!(expected, dt);
    }

    #[test]
    fn parses_use_database() {
        let i = "use mysql;";
        let mut s = Stream::new(i.as_bytes());

        let res = use_database(&mut s).unwrap();
        assert_eq!(
            (s, res),
            (Stream::new("".as_bytes()), "mysql".trim().into())
        );
    }

    #[test]
    fn parses_localhost_host_name() {
        let i = "localhost ";

        let mut s = Stream::new(i.as_bytes());
        let res = host_name(&mut s).unwrap();

        assert_eq!(res, i.trim());
    }

    #[test]
    fn parses_full_host_name() {
        let i = "local.tests.rs ";

        let mut s = Stream::new(i.as_bytes());
        let res = host_name(&mut s).unwrap();

        assert_eq!(res, Bytes::from("local.tests.rs".trim()));
    }

    #[test]
    fn parses_ip_address() {
        let i = "127.0.0.2 ";

        let mut s = Stream::new(i.as_bytes());
        let res = ip_address(&mut s).unwrap();

        assert_eq!(res, Bytes::from(i.trim()));
    }

    #[test]
    fn parses_user_line_no_ip() {
        let i = "# User@Host: msandbox[msandbox] @ localhost []  Id:     3\n";

        let expected = SessionLine {
            user: Bytes::from("msandbox"),
            sys_user: Bytes::from("msandbox"),
            host: Some(Bytes::from("localhost")),
            ip_address: None,
            thread_id: 3,
        };

        let mut s = Stream::new(i.as_bytes());
        let res = entry_user(&mut s).unwrap();
        //TODO: check for left overs
        assert_eq!(expected, res);
    }

    #[test]
    fn parses_user_line_no_host() {
        let i = "# User@Host: lobster[lobster] @ [192.168.56.1]  Id:   190\n";
        let mut s = Stream::new(i.as_bytes());
        let expected = SessionLine {
            user: Bytes::from("lobster"),
            sys_user: Bytes::from("lobster"),
            host: None,
            ip_address: Some(Bytes::from("192.168.56.1")),
            thread_id: 190,
        };

        let res = entry_user(&mut s).unwrap();
        assert_eq!(expected, res);
    }

    #[test]
    fn parses_stats_line() {
        let i = "# Query_time: 1.000016  Lock_time: 2.000000 Rows_sent: 3  Rows_examined: 4\n";

        let expected = StatsLine {
            query_time: 1.000016,
            lock_time: 2.0,
            rows_sent: 3,
            rows_examined: 4,
        };

        let mut s = Stream::new(i.as_bytes());
        let res = parse_entry_stats(&mut s).unwrap();
        //TODO: check for leftovers
        assert_eq!(expected, res);
    }

    #[test]
    fn parses_admin_command_line() {
        let i = "# administrator command: Quit;\n";

        let expected = EntryAdminCommand {
            command: "Quit".into(),
        };

        let mut s = Stream::new(i.as_bytes());
        //TODO: check for leftovers
        let res = admin_command(&mut s).unwrap();
        assert_eq!(expected, res);
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
    fn parses_start_timestamp() {
        let l = "SET timestamp=1517798807;";
        let mut s = Stream::new(l.as_bytes());
        let res = start_timestamp_command(&mut s).unwrap();

        let expected = (Stream::new("".as_bytes()), 1517798807);

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

        let mut s = Stream::new(sql.as_bytes());
        let res = sql_lines(&mut s).unwrap();

        assert_eq!(res, sql);
    }

    #[test]
    fn parses_setter_sql() {
        let sql = "/*!40101 SET NAMES utf8 */;\n";

        let mut s = Stream::new(sql.as_bytes());
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

        let mut s = Stream::new(sql.as_bytes());
        let res = sql_lines(&mut s).unwrap();

        assert_eq!((s, res), (Stream::new("\n".as_bytes()), sql.trim().into()));
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

        let mut s = Stream::new(sql.as_bytes());
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
            (s, res),
            (
                Stream::new("".as_bytes()),
                HeaderLines {
                    version: Bytes::from("5.7.20-log (MySQL Community Server (GPL))."),
                    tcp_port: Some(12345),
                    socket: Some(Bytes::from("/tmp/12345/mysql_sandbox12345.sock")),
                }
            )
        );
    }
}

/// ⛔⛔ MASKING USED TO DESTROY STATEMENTS, AND THE CONSUMER'S DEFAULT WAS TO MASK.
///
/// `mask_tokens` runs before the parser, and a tokenizer cannot tell a value from a number the
/// grammar requires. So `CHAR(60)` became `CHAR(?)` and the whole `CREATE TABLE` stopped
/// parsing -- not misparsed, *refused*, and filed as an unparseable statement with its raw bytes
/// as its SQL. On `assets/slow-test-queries.log` that was **35 of 163 parses**.
///
/// ⭐ Nothing counted it, because nothing ever recorded the parse population under both settings
/// at once. It surfaced from the consumer side, where a fold reported 163 members unmasked and
/// 128 masked over the same file.
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

    /// ⭐ And a value still masks, or the flag would be doing nothing.
    #[test]
    fn a_value_is_still_replaced() {
        let one = parse_sql("SELECT * FROM t WHERE id = 1 AND name = 'a'", &PlaceHolder).unwrap();
        let two = parse_sql("SELECT * FROM t WHERE id = 2 AND name = 'b'", &PlaceHolder).unwrap();
        assert_eq!(one.0[0].to_string(), two.0[0].to_string());
        assert!(one.0[0].to_string().contains('?'), "{}", one.0[0]);

        // ⛔ NOT VACUOUS: unmasked, the same two statements differ. A masker that replaced
        // nothing would pass the first assertion on two identical inputs.
        let a = parse_sql("SELECT * FROM t WHERE id = 1", &NoMask).unwrap();
        let b = parse_sql("SELECT * FROM t WHERE id = 2", &NoMask).unwrap();
        assert_ne!(a.0[0].to_string(), b.0[0].to_string());
    }

    /// ⚠️ Masking must not change WHICH statements parse at all, in either direction.
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

/// ⭐⭐ THE AUTHOR'S SUBJECT SURVIVES MASKING, AND THE MASK STAYS A MASK.
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

    /// ⭐ The literals come back whether or not the statement is masked, so a reader can group on
    /// the mask and still ask which subject. Before this they existed only inside the AST, which
    /// masking then overwrote.
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

    /// ⛔ THE GAP THE OLD `Expr::Value` PASS HAD. `DATE '2020-01-01'` is an `Expr::TypedString`
    /// and MySQL's `AGAINST ('term')` is an `Expr::MatchAgainst`; each holds a `Value` without
    /// being one, so an `Expr`-shaped pass neither masked them nor could have recorded them.
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

    /// ⛔⛔ A MASKED STATEMENT MUST STILL BE SQL. `pre_visit_value` reaches every `Value` in the
    /// tree, including a few that are grammar rather than subject -- a `CEIL(x TO 2)` scale, a
    /// `TABLESAMPLE` seed. Masking after the parse cannot break the parse the way masking tokens
    /// did, but it can render something that will not parse again, and a digest nobody can
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

    /// ⭐⭐ THE ROUND TRIP, which is what makes the record a record rather than a note. Writing
    /// the filed literals back into the masked statement in the order they were taken must
    /// reproduce exactly what the author wrote.
    ///
    /// ⛔ The order is why ONE pass does both jobs. `visit_expressions` is pre-order and
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
        // ⭐ The payload is the value WITHOUT its quoting, which is what a reader groups by.
        assert_eq!(String::from_utf8_lossy(&ls[1].value), "x");
        assert_eq!(String::from_utf8_lossy(&ls[1].rendered), "'x'");
    }
}

/// ⛔⛔⛔ SQL QUOTING DOES NOT NEST, AND THE STATEMENT SCANNER TREATED IT AS A STACK.
///
/// The failure is not a mis-parse. A statement whose terminator is never found consumes the
/// rest of the buffer, the decoder answers `Incomplete` forever, and at EOF the file reports
/// `bytes remaining on stream` — which the analyzer files as `Coverage::Truncated`. **One
/// apostrophe in one double-quoted string ends the log there**, and every entry after it is
/// gone from every artifact with nothing but the coverage flag to say so.
#[cfg(test)]
mod quoting_does_not_nest {
    use crate::parser::statement_end;

    /// The rule, against the cases the stack got wrong and the ones it got right by luck.
    #[test]
    fn a_quote_of_one_kind_inside_another_is_not_a_quote() {
        // ⛔ The four the stack could not terminate. Under it, `"` pushed, `'` pushed because
        // it did not match the top, and the closing `"` pushed again — never empty, never a
        // terminator, and the scan ran off the end of the file.
        for s in [
            r#"SELECT * FROM t WHERE note = "it's here";"#,
            r#"SELECT 'it"s';"#,
            r#"UPDATE t SET name = "O'Brien" WHERE id = 1;"#,
            r#"INSERT INTO t VALUES ("don't", 'say "no"');"#,
        ] {
            assert_eq!(
                statement_end(s.as_bytes()),
                Some(s.len()),
                "the terminator is the last byte: {s}"
            );
        }

        // ⚠️ AND THE ONES THAT PASSED BEFORE STILL PASS, INCLUDING THE ONE THAT PASSED FOR THE
        // WRONG REASON. `'say "hi"'` terminated under the stack because its inner quotes are
        // **balanced** — two pushes and two pops landing empty — which is why a fixture full of
        // well-formed strings witnesses nothing.
        for s in [
            r#"SELECT 'say "hi"';"#,
            r#"SELECT 'don''t';"#,
            r#"SELECT "a" FROM t WHERE b = 'c';"#,
            r#"SELECT `tbl`.`col` FROM t;"#,
            r#"SELECT 'a\'b';"#,
            r#"SELECT 1;"#,
        ] {
            assert_eq!(statement_end(s.as_bytes()), Some(s.len()), "{s}");
        }
    }

    /// ⭐ A `;` inside a quote is not a terminator, which is the whole point of tracking quotes
    /// at all — and the one thing the stack did get right for a single-kind string.
    #[test]
    fn a_semicolon_inside_a_quote_does_not_terminate() {
        let s = r#"SELECT 'a;b', "c;d", `e;f`; SELECT 2;"#;
        let end = statement_end(s.as_bytes()).expect("terminated");

        assert_eq!(&s[..end], r#"SELECT 'a;b', "c;d", `e;f`;"#);
    }

    /// ⚠️ BACKSLASH ESCAPES INSIDE `'` AND `"` AND NOT INSIDE A BACKTICK, which is MySQL's own
    /// rule rather than a simplification. ⛔ Under `NO_BACKSLASH_ESCAPES` the first two change
    /// too — and this crate records `sql_mode` as `unmeasured` rather than assuming it, so the
    /// default is a **reading** and is filed as one.
    #[test]
    fn the_escape_rule_is_the_servers_and_stops_at_a_backtick() {
        // The escaped quote does not close the string, so the terminator is the real one.
        let s = r#"SELECT 'a\'b;c';"#;
        assert_eq!(statement_end(s.as_bytes()), Some(s.len()));

        // ⭐ A backslash before a backtick is a backslash. Escaping it would leave the
        // identifier open and lose the rest of the file, which is the defect one kind over.
        let s = r#"SELECT `a\`, b FROM t;"#;
        assert_eq!(statement_end(s.as_bytes()), Some(s.len()));
    }

    /// ⭐ `None` is *"not in the bytes I have"* and never *"not in the file"* — the decoder turns
    /// it into `Incomplete` and reads more. A scanner that answered `Some(len)` at the end of a
    /// partial buffer would file half a statement as a whole one.
    #[test]
    fn an_unterminated_statement_is_not_a_statement() {
        assert_eq!(statement_end(b"SELECT 1"), None);
        assert_eq!(statement_end(b"SELECT 'unclosed;"), None);
        assert_eq!(statement_end(b""), None);
    }
}
