use crate::EntryMasking;
use bytes::{BufMut, Bytes, BytesMut};
use sqlparser::ast::Statement;
use sqlparser::dialect::MySqlDialect;
use sqlparser::parser::{Parser as SQLParser, ParserError};
use sqlparser::tokenizer::{Token, Tokenizer};
use std::borrow::Cow;
use std::collections::HashMap;
use std::ops::Not;
use std::str;
use std::str::FromStr;
use winnow::ascii::{
    alpha1, alphanumeric1, digit1, float, line_ending, multispace0, multispace1, till_line_ending,
    Caseless,
};
use winnow::combinator::repeat;
use winnow::combinator::{alt, trace};
use winnow::combinator::{not, opt};
use winnow::combinator::{preceded, terminated};
use winnow::error::{ContextError, ErrMode, InputError};
use winnow::token::{any, literal, take, take_till, take_until};
use winnow::{seq, PResult, Parser, Partial};
use winnow_iso8601::parsers::parse_datetime;
use winnow_iso8601::DateTime;

pub type Stream<'i> = Partial<&'i [u8]>;

/// A struct holding a `DateTime` parsed from the Time: line of the entry
/// ex: `# Time: 2018-02-05T02:46:43.015898Z`
#[derive(Clone, Copy)]
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
pub fn parse_entry_time(i: &mut Stream) -> PResult<DateTime> {
    trace("parse_entry_time", move |input: &mut Stream| {
        let dt = seq!(
            _: literal("# Time:"),
            _: multispace1,
            parse_datetime,
        )
        .parse_next(input)?;

        Ok(dt.0)
    })
    .parse_next(i)
}

/// values from the User: entry line
/// ex. # User@Host: msandbox[msandbox] @ localhost []  Id:     3
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

#[derive(Debug, PartialEq, Default)]
pub struct HeaderLines {
    version: Bytes,
    tcp_port: Option<usize>,
    socket: Option<Bytes>,
}

pub fn log_header<'a>(i: &mut Stream<'_>) -> PResult<HeaderLines> {
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

pub fn sql_lines<'a>(i: &mut Stream<'_>) -> PResult<Bytes> {
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

pub fn alphanumerichyphen1<'a>(i: &mut Stream<'a>) -> PResult<&'a [u8]> {
    alt((alphanumeric1, literal("_"), literal("-"))).parse_next(i)
}

pub fn host_name<'a>(i: &mut Stream<'_>) -> PResult<Bytes> {
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
pub fn ip_address<'a>(i: &mut Stream<'_>) -> PResult<Bytes> {
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
pub fn entry_user_thread_id<'a>(i: &mut Stream<'_>) -> PResult<u32> {
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

pub fn user_name(i: &mut Stream) -> PResult<Bytes> {
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
pub fn entry_user(i: &mut Stream) -> PResult<SessionLine> {
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

/// Struct containing information parsed from the initial comment in a SQL query
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SqlStatementContext {
    /// example field, should just be part of a HashMap
    pub request_id: Option<Bytes>,
    /// example field, should just be part of a HashMap
    pub caller: Option<Bytes>,
    /// example field, should just be part of a HashMap
    pub function: Option<Bytes>,
    /// example field, should just be part of a HashMap
    pub line: Option<u32>,
}

impl SqlStatementContext {
    /// example method, should be replaced by generic key lookup
    pub fn request_id(&self) -> Option<Cow<str>> {
        if let Some(i) = &self.request_id {
            Some(String::from_utf8_lossy(i.as_ref()))
        } else {
            None
        }
    }

    /// example method, should be replaced by generic key lookup
    pub fn caller(&self) -> Option<Cow<str>> {
        if let Some(c) = &self.caller {
            Some(String::from_utf8_lossy(c.as_ref()))
        } else {
            None
        }
    }

    /// example method, should be replaced by generic key lookup
    pub fn function(&self) -> Option<Cow<str>> {
        if let Some(f) = &self.function {
            Some(String::from_utf8_lossy(f.as_ref()))
        } else {
            None
        }
    }

    /// example method, should be replaced by generic key lookup
    pub fn line(&self) -> Option<u32> {
        self.line
    }
}

pub fn details_comment<'a>(i: &mut Stream) -> PResult<HashMap<Bytes, Bytes>> {
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

pub fn details_tag<'a>(i: &mut Stream) -> PResult<Bytes> {
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
pub fn parse_entry_stats(i: &mut Stream<'_>) -> PResult<StatsLine> {
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
pub fn admin_command<'a>(i: &mut Stream) -> PResult<EntryAdminCommand> {
    trace("admin_command", move |input: &mut Stream<'_>| {
        let command = seq!(
            _: literal("# administrator command:"),
            _: multispace1,
            alphanumerichyphen1,
            _: literal(";"),
        )
        .parse_next(input)?;

        Ok(EntryAdminCommand {
            command: command.0.to_owned().into(),
        })
    })
    .parse_next(i)
}

/// parses 'USE database=\w+;' command which shows up at the start of some entry sql
pub fn use_database(i: &mut Stream) -> PResult<Bytes> {
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
pub fn start_timestamp_command(i: &mut Stream) -> PResult<u32> {
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

/// Parses one or more sql statements using `sqlparser::parse_statements`. This uses the
/// `sqlparser::Tokenizer` to first tokenize the SQL and replace tokenized values with an
/// masked value determined by the `&EntryMasking` value passed as an argument. In the case of
/// `EntryMasking::None` this call is identical to calling `sqlparse::parse_statements`.
/// command: " entry line
pub fn parse_sql(sql: &str, mask: &EntryMasking) -> Result<Vec<Statement>, ParserError> {
    let mut tokenizer = Tokenizer::new(&MySqlDialect {}, sql);
    let mut tokens = tokenizer.tokenize()?;

    tokens = mask_tokens(tokens, mask);

    let mut parser = SQLParser::new(&MySqlDialect {}).with_tokens(tokens);

    parser.parse_statements()
}

/// Replaces numbers, strings and literal tokenized by `sql_parser::Tokenizer` and replaces them
/// with a masking values. Passing a value of `EntryMasking::None` will simply return the
/// `Vec<Token>` passed in.
pub fn mask_tokens(tokens: Vec<Token>, mask: &EntryMasking) -> Vec<Token> {
    let mut acc = vec![];

    if mask == &EntryMasking::None {
        return tokens;
    }

    for t in tokens {
        let mt = if let Token::Number(_, _) = t {
            Token::Placeholder("?".into())
        } else if let Token::Number(_, _) = t {
            Token::Placeholder("?".into())
        } else if let Token::SingleQuotedString(_) = t {
            Token::Placeholder("?".into())
        } else if let Token::DoubleQuotedString(_) = t {
            Token::Placeholder("?".into())
        } else if let Token::NationalStringLiteral(_) = t {
            Token::Placeholder("?".into())
        } else if let Token::EscapedStringLiteral(_) = t {
            Token::Placeholder("?".into())
        } else if let Token::HexStringLiteral(_) = t {
            Token::Placeholder("?".into())
        } else {
            t
        };

        acc.push(mt);
    }

    acc
}

#[cfg(test)]
mod tests {
    use crate::parser::{
        admin_command, details_comment, entry_user, host_name, ip_address, log_header,
        parse_entry_stats, parse_entry_time, parse_sql, sql_lines, start_timestamp_command,
        use_database, EntryAdminCommand, HeaderLines, SessionLine, StatsLine, Stream,
    };
    use crate::EntryMasking;
    use bytes::Bytes;
    use std::assert_eq;
    use std::collections::HashMap;
    use winnow_iso8601::{Date, DateTime, Time, Timezone};

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
                millisecond: 0,
                timezone: Timezone {
                    offset_hours: 2,
                    offset_minutes: 0,
                }
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

        let ast0 = parse_sql(sql0, &EntryMasking::PlaceHolder).unwrap();
        let ast1 = parse_sql(sql1, &EntryMasking::PlaceHolder).unwrap();

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
