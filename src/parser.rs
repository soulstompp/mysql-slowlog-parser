use crate::EntryMasking;
use std::ops::ControlFlow;
use bytes::{BufMut, Bytes, BytesMut};
use sqlparser::ast::{Statement, Value, VisitMut, VisitorMut};
use sqlparser::dialect::MySqlDialect;
use sqlparser::parser::{Parser as SQLParser, ParserError};
use sqlparser::tokenizer::Tokenizer;
use std::borrow::Cow;
use std::collections::HashMap;
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
use winnow::error::{ContextError, ErrMode, InputError};
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

pub fn sql_lines<'a>(i: &mut Stream<'_>) -> ModalResult<Bytes> {
    trace("sql_lines", move |input: &mut Stream<'_>| {
        let mut acc = BytesMut::new();

        let mut escaped = false;
        let mut quotes = vec![];

        loop {
            let c = any(input)? as char;

            acc.put_slice(&[c as u8]);

            if escaped.not() && (c == '\'' || c == '\"' || c == '`') {
                if let Some(q) = quotes.last() {
                    if &c == q {
                        let _ = quotes.pop();
                    } else {
                        quotes.push(c);
                    }
                } else {
                    quotes.push(c);
                }
            }

            if escaped.not() && c == '\\' {
                escaped = true;
            } else {
                escaped = false;
            }

            if quotes.len() == 0 && c == ';' {
                return Ok(acc.freeze());
            }
        }
    })
    .parse_next(i)
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
    };
    for s in statements.iter_mut() {
        let _ = s.visit(&mut pass);
    }

    Ok((statements, pass.literals))
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
}

impl VisitorMut for LiteralPass {
    type Break = ();

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

        self.literals.push(EntryLiteral {
            ordinal: self.literals.len() as u32,
            rendered: Bytes::from(value.to_string()),
            value: Bytes::from(payload),
            kind,
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
        assert_eq!(masked_ls, plain_ls, "masking must not change what was recorded");

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
            ("SELECT * FROM t WHERE d > DATE '2020-01-01'", "'2020-01-01'"),
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
                let i = rest.find('?').expect("one placeholder per recorded literal");
                out.push_str(&rest[..i]);
                out.push_str(l);
                rest = &rest[i + 1..];
            }
            out.push_str(rest);

            assert_eq!(out, plain, "round trip failed for: {sql}");
            assert!(!out.contains('?'), "a literal was left unaccounted for: {out}");
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
