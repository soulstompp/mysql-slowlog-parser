use bytes::{BufMut, Bytes, BytesMut};
use std::borrow::Cow;
use std::collections::HashMap;
use std::ops::Not;
use std::str;
use std::str::FromStr;

use iso8601::parsers::parse_datetime;
use iso8601::DateTime;
use sqlparser::ast::Statement;
use sqlparser::dialect::MySqlDialect;
use sqlparser::parser::{Parser, ParserError};
use sqlparser::tokenizer::{Token, Tokenizer};
use winnow::branch::alt;
use winnow::bytes::{any, tag, tag_no_case, take, take_till1, take_until1};
use winnow::character::{alpha1, alphanumeric1, digit1, float, multispace0, multispace1};
use winnow::combinator::{not, opt};
use winnow::error::{ErrMode, Error, ErrorKind, Needed};
use winnow::multi::{many1, many_m_n};
use winnow::sequence::{preceded, separated_pair, terminated};
use winnow::{IResult, Partial};

use crate::EntryMasking;

pub type Stream<'i> = Partial<&'i [u8]>;

/// values from the time entry line
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimeLine {
    time: DateTime,
}

impl TimeLine {
    pub fn time(&self) -> DateTime {
        self.time.clone()
    }
}
// "# Time: 2015-06-26T16:43:23+0200";
/// parses "# Time: ...." entry line
pub fn parse_entry_time(i: Stream<'_>) -> IResult<Stream<'_>, DateTime> {
    let (i, _) = tag("# Time:")(i)?;
    let (i, _) = multispace1(i)?;
    let (i, dt) = parse_datetime(*i).or(Err(ErrMode::Incomplete(Needed::Unknown)))?;

    Ok((Stream::new(i), dt))
}

/// values from the user entry line
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionLine {
    pub(crate) user: Bytes,
    pub(crate) sys_user: Bytes,
    pub(crate) host: Option<Bytes>,
    pub(crate) ip_address: Option<Bytes>,
    pub(crate) thread_id: u32,
}

impl SessionLine {
    pub fn user(&self) -> Bytes {
        self.user.clone()
    }

    pub fn sys_user(&self) -> Bytes {
        self.sys_user.clone()
    }

    pub fn host(&self) -> Option<Bytes> {
        self.host.clone()
    }

    pub fn ip_address(&self) -> Option<Bytes> {
        self.ip_address.clone()
    }

    pub fn thread_id(&self) -> u32 {
        self.thread_id
    }
}

#[derive(Debug, PartialEq)]
pub struct HeaderLines {
    version: Bytes,
    tcp_port: Option<usize>,
    socket: Option<Bytes>,
}

pub fn log_header<'a>(i: Stream<'_>) -> IResult<Stream<'_>, HeaderLines> {
    // check for the '#' since the last parser in the set is greedy
    let (i, _) = not(tag("#"))(i)?;
    let (i, _) = take_until1(", Version: ")(i)?;
    let (i, version) = preceded(tag(", Version: "), take_until1(". started with:"))(i)?;
    let (i, tcp_port) = preceded(
        (tag(". started with:"), multispace1),
        preceded(tag("Tcp port: "), opt(digit1)),
    )(i)?;
    let (i, socket) = preceded(
        multispace1,
        preceded(tag("Unix socket: "), opt(take_till1("\n"))),
    )(i)?;
    let (i, _) = multispace1(i)?;
    let (i, _) = take_until1("\n")(i)?;

    Ok((
        i,
        HeaderLines {
            version: version.to_owned().into(),
            tcp_port: tcp_port.and_then(|v| Some(str::from_utf8(v).unwrap().parse().unwrap())),
            socket: socket.and_then(|v| Some(v.to_owned().into())),
        },
    ))
}

pub fn sql_lines<'a>(mut i: Stream<'_>) -> IResult<Stream<'_>, Bytes> {
    let mut acc = BytesMut::new();

    let mut escaped = false;
    let mut quotes = vec![];

    loop {
        let res = any(i)?;

        i = res.0;
        let c = res.1 as char;

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
            return Ok((i, acc.freeze()));
        }
    }
}

pub fn alphanumerichyphen1<'a>(i: Stream<'_>) -> IResult<Stream<'_>, &'_ [u8]> {
    alt((alphanumeric1, tag("_"), tag("-")))(i)
}

pub fn host_name<'a>(i: Stream<'_>) -> IResult<Stream<'_>, Bytes> {
    let (i, (mut first, second)): (Stream<'_>, (Vec<&[u8]>, &[u8])) = alt((
        ((many1(terminated(alphanumerichyphen1, tag("."))), alpha1)),
        ((many_m_n(1, 1, alphanumerichyphen1), take(0 as usize))),
    ))(i)?;

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

    Ok((i, b.freeze()))
}

/// ip address handler that only handles IP4
pub fn ip_address<'a>(i: Stream<'_>) -> IResult<Stream<'_>, Bytes> {
    let (i, p0) = digit1(i)?;
    let (i, p1) = preceded(tag("."), digit1)(i)?;
    let (i, p2) = preceded(tag("."), digit1)(i)?;
    let (i, p3) = preceded(tag("."), digit1)(i)?;

    let b = [p0, p1, p2, p3]
        .iter()
        .enumerate()
        .fold(BytesMut::new(), |mut acc, (c, p)| {
            if c > 0 {
                acc.put_slice(".".as_bytes());
            }

            acc.put_slice(p);
            acc
        });

    Ok((i, b.freeze()))
}

/// thread id parser for 'Id: [\d+]'
pub fn entry_user_thread_id<'a>(i: Stream<'_>) -> IResult<Stream<'_>, u32> {
    let (i, (_, id)) = separated_pair(tag("Id:"), multispace1, digit1)(i)?;

    Ok((i, u32::from_str(str::from_utf8(id).unwrap()).unwrap()))
}

pub fn user_name(i: Stream) -> IResult<Stream, Bytes> {
    let (i, parts): (Stream, Vec<&[u8]>) = many1(alt((alphanumeric1, tag("_"))))(i)?;

    let b = parts.iter().fold(BytesMut::new(), |mut acc, p| {
        acc.put_slice(p);
        acc
    });

    Ok((i, b.freeze()))
}

/// user line parser
pub fn entry_user(i: Stream) -> IResult<Stream, SessionLine> {
    let (i, _) = tag("# User@Host:")(i)?;
    let (i, _) = multispace1(i)?;
    let (i, user) = user_name(i)?;
    let (i, _) = tag("[")(i)?;
    let (i, sys_user) = user_name(i)?;
    let (i, _) = tag("]")(i)?;
    let (i, _) = multispace1(i)?;
    let (i, _) = tag("@")(i)?;
    let (i, _) = multispace1(i)?;
    let (i, host) = opt(host_name)(i)?;
    let (i, _) = multispace0(i)?;
    let (i, _) = tag("[")(i)?;
    let (i, _) = multispace0(i)?;
    let (i, ip_address) = opt(ip_address)(i)?;
    let (i, _) = multispace0(i)?;
    let (i, _) = tag("]")(i)?;
    let (i, _) = multispace1(i)?;
    let (i, thread_id) = entry_user_thread_id(i)?;

    Ok((
        i,
        SessionLine {
            user,
            sys_user,
            host,
            ip_address,
            thread_id,
        },
    ))
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct SqlStatementContext {
    pub request_id: Option<Bytes>,
    pub caller: Option<Bytes>,
    pub function: Option<Bytes>,
    pub line: Option<u32>,
}

impl SqlStatementContext {
    pub fn request_id(&self) -> Option<Cow<str>> {
        if let Some(i) = &self.request_id {
            Some(String::from_utf8_lossy(i.as_ref()))
        } else {
            None
        }
    }

    pub fn caller(&self) -> Option<Cow<str>> {
        if let Some(c) = &self.caller {
            Some(String::from_utf8_lossy(c.as_ref()))
        } else {
            None
        }
    }

    pub fn function(&self) -> Option<Cow<str>> {
        if let Some(f) = &self.function {
            Some(String::from_utf8_lossy(f.as_ref()))
        } else {
            None
        }
    }

    pub fn line(&self) -> Option<u32> {
        self.line
    }
}

pub fn details_comment<'a>(i: Stream<'_>) -> IResult<Stream<'_>, HashMap<Bytes, Bytes>> {
    let mut name: Option<Bytes> = None;

    let mut res: HashMap<Bytes, BytesMut> = HashMap::new();

    let (mut i, _) = tag("--")(i)?;

    loop {
        if let Ok((ii, n)) = details_tag(i) {
            i = ii;

            name.replace(n.clone().into());

            if let Some(_) = res.insert(n, BytesMut::new()) {
                return Err(ErrMode::Cut(Error {
                    input: i,
                    kind: ErrorKind::Assert,
                }));
            }
        }

        if let Ok((ii, c)) = any::<&[u8], Error<_>>(*i) {
            i = Stream::new(ii);

            let c = c as char;

            if c == '\n' || c == '\r' {
                break;
            }

            if let Some(k) = &name {
                let v = &mut res.get_mut(k).ok_or(ErrMode::Cut(Error {
                    input: i,
                    kind: ErrorKind::Assert,
                }))?;

                v.put_bytes(c as u8, 1);
            } else {
                return Err(ErrMode::Cut(Error {
                    input: i,
                    kind: ErrorKind::Assert,
                }));
            }

            continue;
        } else {
            break;
        }
    }

    Ok((i, res.into_iter().map(|(k, v)| (k, v.freeze())).collect()))
}

pub fn details_tag<'a>(i: Stream<'_>) -> IResult<Stream<'_>, Bytes> {
    let (i, _) = opt(tag(","))(i)?;
    let (i, _) = multispace0(i)?;
    let (i, name) = user_name(i)?;
    let (i, _) = multispace0(i)?;
    let (i, _) = alt((tag(":"), tag("=")))(i)?;
    let (i, _) = multispace1(i)?;

    Ok((i, name.into()))
}

/// values parsed from stats entry line
#[derive(Clone, Debug, PartialEq)]
pub struct StatsLine {
    pub(crate) query_time: f64,
    pub(crate) lock_time: f64,
    pub(crate) rows_sent: u32,
    pub(crate) rows_examined: u32,
}

impl StatsLine {
    pub fn query_time(&self) -> f64 {
        self.query_time.clone()
    }
    pub fn lock_time(&self) -> f64 {
        self.lock_time.clone()
    }

    pub fn rows_sent(&self) -> u32 {
        self.rows_sent.clone()
    }
    pub fn rows_examined(&self) -> u32 {
        self.rows_examined.clone()
    }
}

/// parse '# Query_time:...' entry line
pub fn parse_entry_stats(i: Stream<'_>) -> IResult<Stream<'_>, StatsLine> {
    let (i, _) = tag("#")(i)?;
    let (i, _) = multispace1(i)?;
    let (i, _) = tag("Query_time:")(i)?;
    let (i, _) = multispace1(i)?;
    let (i, query_time) = float(i)?;
    let (i, _) = multispace1(i)?;
    let (i, _) = tag("Lock_time:")(i)?;
    let (i, _) = multispace1(i)?;
    let (i, lock_time) = float(i)?;
    let (i, _) = multispace1(i)?;
    let (i, _) = tag("Rows_sent:")(i)?;
    let (i, _) = multispace1(i)?;
    let (i, rows_sent) = digit1(i)?;
    let (i, _) = multispace1(i)?;
    let (i, _) = tag("Rows_examined:")(i)?;
    let (i, _) = multispace1(i)?;
    let (i, rows_examined) = digit1(i)?;

    Ok((
        i,
        StatsLine {
            query_time,
            lock_time,
            rows_sent: u32::from_str(str::from_utf8(rows_sent).unwrap()).unwrap(),
            rows_examined: u32::from_str(str::from_utf8(rows_examined).unwrap()).unwrap(),
        },
    ))
}

/// admin command values parsed from sql lines of an entry
#[derive(Clone, Debug, PartialEq)]
pub struct EntryAdminCommand {
    pub command: Bytes,
}

/// parse "# administrator command: " entry line
pub fn admin_command<'a>(i: Stream<'_>) -> IResult<Stream<'_>, EntryAdminCommand> {
    let (i, _) = tag("# administrator command:")(i)?;
    let (i, _) = multispace1(i)?;
    let (i, command) = alphanumerichyphen1(i)?;
    let (i, _) = tag(";")(i)?;

    Ok((
        i,
        EntryAdminCommand {
            command: command.to_owned().into(),
        },
    ))
}

/// parses 'USE database=\w+;' command which shows up at the start of some entry sql
pub fn use_database(i: Stream<'_>) -> IResult<Stream<'_>, Bytes> {
    let (i, _) = tag_no_case("USE")(i)?;
    let (i, _) = multispace1(i)?;
    let (i, db_name) = user_name(i)?;
    let (i, _) = multispace0(i)?;
    let (i, _) = tag(";")(i)?;

    Ok((i, db_name.into()))
}

/// parses 'SET timestamp=\d{10};' command which starts
pub fn start_timestamp_command(i: Stream<'_>) -> IResult<Stream<'_>, u32> {
    let (i, _) = tag("SET timestamp")(i)?;
    let (i, _) = multispace0(i)?;
    let (i, _) = tag("=")(i)?;
    let (i, _) = multispace0(i)?;
    let (i, time) = digit1(i)?;
    let (i, _) = multispace0(i)?;
    let (i, _) = tag(";")(i)?;

    Ok((i, u32::from_str(str::from_utf8(time).unwrap()).unwrap()))
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

    let mut parser = Parser::new(&MySqlDialect {}).with_tokens(tokens);

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
    use iso8601::{Date, DateTime, Time};
    use std::assert_eq;
    use std::collections::HashMap;

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
                tz_offset_hours: 2,
                tz_offset_minutes: 0,
            },
        };

        let res = parse_entry_time(Stream::new(i.as_bytes())).unwrap();
        assert_eq!(expected, res.1);
    }

    #[test]
    fn parses_use_database() {
        let i = "use mysql;";

        let res = use_database(Stream::new(i.as_bytes())).unwrap();

        assert_eq!(res, (Stream::new("".as_bytes()), "mysql".trim().into()));
    }

    #[test]
    fn parses_localhost_host_name() {
        let i = "localhost ";

        let res = host_name(Stream::new(i.as_bytes())).unwrap();

        assert_eq!(res, (Stream::new(" ".as_bytes()), i.trim().into()));
    }

    #[test]
    fn parses_full_host_name() {
        let i = "local.tests.rs ";

        let res = host_name(Stream::new(i.as_bytes())).unwrap();

        assert_eq!(
            res,
            (
                Stream::new(" ".as_bytes()),
                Bytes::from("local.tests.rs".trim())
            )
        );
    }

    #[test]
    fn parses_ip_address() {
        let i = "127.0.0.2 ";

        let res = ip_address(Stream::new(i.as_bytes())).unwrap();

        assert_eq!(res, (Stream::new(" ".as_bytes()), Bytes::from(i.trim())));
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

        let res = entry_user(Stream::new(i.as_bytes())).unwrap();
        assert_eq!(expected, res.1);
    }

    #[test]
    fn parses_user_line_no_host() {
        let i = "# User@Host: lobster[lobster] @ [192.168.56.1]  Id:   190\n";

        let expected = SessionLine {
            user: Bytes::from("lobster"),
            sys_user: Bytes::from("lobster"),
            host: None,
            ip_address: Some(Bytes::from("192.168.56.1")),
            thread_id: 190,
        };

        let res = entry_user(Stream::new(i.as_bytes())).unwrap();
        assert_eq!(expected, res.1);
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

        let res = parse_entry_stats(Stream::new(i.as_bytes())).unwrap();
        assert_eq!(expected, res.1);
    }

    #[test]
    fn parses_admin_command_line() {
        let i = "# administrator command: Quit;\n";

        let expected = EntryAdminCommand {
            command: "Quit".into(),
        };

        let res = admin_command(Stream::new(i.as_bytes())).unwrap();
        assert_eq!(expected, res.1);
    }

    #[test]
    fn parses_details_comment() {
        let s0 = "-- Id: 123 long: some kind of details here caller: hello_world()\n";
        let s1 = "-- Id: 123, long: some kind of details here, caller : hello_world()\n";
        let s2 = "-- Id= 123, long = some kind of details here, caller= hello_world()\n";

        let res0 = details_comment(Stream::new(s0.as_bytes())).unwrap();
        let res1 = details_comment(Stream::new(s1.as_bytes())).unwrap();
        let res2 = details_comment(Stream::new(s2.as_bytes())).unwrap();

        let expected = (
            Stream::new("".as_bytes()),
            HashMap::from([
                ("Id".into(), "123".into()),
                ("long".into(), "some kind of details here".into()),
                ("caller".into(), "hello_world()".into()),
            ]),
        );

        assert_eq!(res0, expected);
        assert_eq!(res1, expected);
        assert_eq!(res2, expected);
    }

    #[test]
    fn parses_details_comment_trailing_key() {
        let s0 = "-- Id: 123 long: some kind of details here caller: hello_world():52\n";
        let s1 = "-- Id: 123 long: some kind of details here caller: hello_world(): 52\n";

        let res0 = details_comment(Stream::new(s0.as_bytes())).unwrap();
        let res1 = details_comment(Stream::new(s1.as_bytes())).unwrap();

        let expected0 = (
            Stream::new("".as_bytes()),
            HashMap::from([
                ("Id".into(), "123".into()),
                ("long".into(), "some kind of details here".into()),
                ("caller".into(), "hello_world():52".into()),
            ]),
        );

        let expected1 = (
            Stream::new("".as_bytes()),
            HashMap::from([
                ("Id".into(), "123".into()),
                ("long".into(), "some kind of details here".into()),
                ("caller".into(), "hello_world(): 52".into()),
            ]),
        );

        assert_eq!(res0, expected0);
        assert_eq!(res1, expected1);
    }

    #[test]
    fn parses_start_timestamp() {
        let l = "SET timestamp=1517798807;";

        let res = start_timestamp_command(Stream::new(l.as_bytes())).unwrap();

        let expected = (Stream::new("".as_bytes()), 1517798807);

        assert_eq!(res, expected);
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

        let res = sql_lines(Stream::new(sql.as_bytes())).unwrap();

        assert_eq!(res, (Stream::new("".as_bytes()), sql.into()));
    }

    #[test]
    fn parses_setter_sql() {
        let sql = "/*!40101 SET NAMES utf8 */;\n";

        let res = sql_lines(Stream::new(sql.as_bytes())).unwrap();

        assert_eq!(res, (Stream::new("\n".as_bytes()), sql.trim().into()));
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

        let res = sql_lines(Stream::new(sql.as_bytes())).unwrap();

        assert_eq!(res, (Stream::new("\n".as_bytes()), sql.trim().into()));
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

        let res = sql_lines(Stream::new(sql.as_bytes())).unwrap();

        assert_eq!(res, (Stream::new("\n".as_bytes()), sql.trim().into()));
    }

    #[test]
    fn parses_header() {
        let h = "/home/karl/mysql/my-5.7/bin/mysqld, Version: 5.7.20-log (MySQL Community Server (GPL)). started with:
Tcp port: 12345  Unix socket: /tmp/12345/mysql_sandbox12345.sock
Time                 Id Command    Argument\n";

        let res = log_header(Stream::new(h.as_bytes())).unwrap();

        assert_eq!(
            res,
            (
                Stream::new("\n".as_bytes()),
                HeaderLines {
                    version: Bytes::from("5.7.20-log (MySQL Community Server (GPL))"),
                    tcp_port: Some(12345),
                    socket: Some(Bytes::from("/tmp/12345/mysql_sandbox12345.sock")),
                }
            )
        );
    }
}
