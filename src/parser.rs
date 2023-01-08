use nom::bytes::complete::tag;
use nom::character::complete::{alphanumeric1, anychar, digit1, multispace1};
use nom::character::is_space;
use nom::combinator::rest;
use nom::error::{Error, ErrorKind};
use nom::number::complete::double;
use nom::sequence::tuple;
use nom::Err as nomErr;
use nom::IResult;

use iso8601::parsers::parse_datetime;
use iso8601::DateTime;

use thiserror::Error;
#[derive(Error, Debug)]
pub enum ParseEntryError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntryTime {
    time: DateTime,
}

impl EntryTime {
    pub fn time(&self) -> DateTime {
        self.time.clone()
    }
}

pub fn parse_entry_time<'a>(i: &'a str) -> IResult<&'a str, EntryTime> {
    let (i, _) = tag("# Time:")(i)?;
    let (i, _) = multispace1(i)?;

    parse_datetime(i.as_bytes())
        .and_then(|(_, dt)| Ok(("", EntryTime { time: dt })))
        .or(Err(nomErr::Error(Error {
            input: "",
            code: ErrorKind::Fail,
        })))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntryUser {
    user: String,
    sys_user: String,
    host: String,
}

impl EntryUser {
    pub fn user(&self) -> String {
        self.user.clone()
    }

    pub fn sys_user(&self) -> String {
        self.sys_user.clone()
    }

    pub fn host(&self) -> String {
        self.host.clone()
    }
}

pub fn parse_host<'a>(i: &'_ str) -> IResult<&'_ str, String> {
    let mut acc = String::new();

    let mut i = i;

    loop {
        let (ii, c) = anychar(i)?;

        i = ii;

        if is_space(c as u8) {
            return Ok((i, acc));
        }

        acc.push(c);
    }
}

pub fn parse_entry_user<'a>(i: &'_ str) -> IResult<&'_ str, EntryUser> {
    let (i, (_, _, user, _, sys_user, _, _, _, _, host, _)) = tuple((
        tag("# User@Host:"),
        multispace1,
        alphanumeric1,
        tag("["),
        alphanumeric1,
        tag("]"),
        multispace1,
        tag("@"),
        multispace1,
        parse_host,
        rest,
    ))(i)?;

    Ok((
        i,
        EntryUser {
            user: user.into(),
            sys_user: sys_user.into(),
            host,
        },
    ))
}

#[derive(Clone, Debug, PartialEq)]
pub struct EntryStats {
    query_time: f64,
    lock_time: f64,
    rows_sent: u32,
    rows_examined: u32,
}

impl EntryStats {
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

pub fn parse_entry_stats<'a>(i: &'a str) -> IResult<&'a str, EntryStats> {
    let (
        i,
        (_, _, _, _, query_time, _, _, _, lock_time, _, _, _, rows_sent, _, _, _, rows_examined),
    ) = tuple((
        tag("#"),
        multispace1,
        tag("Query_time:"),
        multispace1,
        double,
        multispace1,
        tag("Lock_time:"),
        multispace1,
        double,
        multispace1,
        tag("Rows_sent:"),
        multispace1,
        digit1,
        multispace1,
        tag("Rows_examined:"),
        multispace1,
        digit1,
    ))(i)?;

    Ok((
        i,
        EntryStats {
            query_time,
            lock_time,
            rows_sent: rows_sent.parse().unwrap(),
            rows_examined: rows_examined.parse().unwrap(),
        },
    ))
}

#[cfg(test)]
mod tests {
    use crate::parser::{
        parse_entry_stats, parse_entry_time, parse_entry_user, EntryStats, EntryTime, EntryUser,
    };
    use iso8601::{Date, DateTime, Time};

    #[test]
    fn parse_time_line() {
        let i = "# Time: 2015-06-26T16:43:23+0200";

        let expected = EntryTime {
            time: DateTime {
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
            },
        };

        let res = parse_entry_time(i).unwrap();
        assert_eq!(expected, res.1);
    }

    #[test]
    fn parse_user_line() {
        let i = "# User@Host: msandbox[msandbox] @ localhost []  Id:     3";

        let expected = EntryUser {
            user: "msandbox".to_string(),
            sys_user: "msandbox".to_string(),
            host: "localhost".to_string(),
        };

        let res = parse_entry_user(i).unwrap();
        assert_eq!(expected, res.1);
    }

    #[test]
    fn parse_stats_line() {
        let i = "# Query_time: 1.000016  Lock_time: 2.000000 Rows_sent: 3  Rows_examined: 4";

        let expected = EntryStats {
            query_time: 1.000016,
            lock_time: 2.0,
            rows_sent: 3,
            rows_examined: 4,
        };

        let res = parse_entry_stats(i).unwrap();
        assert_eq!(expected, res.1);
    }
}
