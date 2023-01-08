use thiserror::Error;

use crate::parser::{
    parse_entry_stats, parse_entry_time, parse_entry_user, EntryStats, EntryTime, EntryUser,
};
use crate::ReadError::{IncompleteEntry, InvalidStatsLine, InvalidTimeLine, InvalidUserLine};
use iso8601::DateTime;
use std::fs::File;
use std::io;
use std::io::{BufRead, BufReader};

mod parser;

#[derive(Error, Debug)]
pub enum ReadError {
    #[error("file read error: {0}")]
    IO(#[from] io::Error),
    #[error("invalid time line: {0}")]
    InvalidTimeLine(String),
    #[error("invalid user line: {0}")]
    InvalidUserLine(String),
    #[error("invalid stats line: {0}")]
    InvalidStatsLine(String),
    #[error("Entry started but not completed")]
    IncompleteEntry,
    #[error("Invalid log format or format contains no entries")]
    IncompleteLog,
}

#[derive(Default)]
pub struct EntryContext {
    time: Option<EntryTime>,
    user: Option<EntryUser>,
    stats: Option<EntryStats>,
    sql: Option<String>,
}

impl EntryContext {
    fn append_sql(&mut self, s: &str) -> Result<(), ReadError> {
        if self.sql.is_none() {
            self.sql = Some(String::new());
        }

        self.sql.as_mut().unwrap().push_str(&s);

        Ok(())
    }

    fn entry(&self) -> Result<Entry, ()> {
        let time = self.time.clone().ok_or(())?;
        let user = self.user.clone().ok_or(())?;
        let stats = self.stats.clone().ok_or(())?;

        Ok(Entry {
            time: time.time(),
            user: user.user(),
            sys_user: user.sys_user(),
            host: user.host(),
            query_time: stats.query_time(),
            lock_time: stats.lock_time(),
            rows_sent: stats.rows_sent(),
            rows_examined: stats.rows_examined(),
            sql: self.sql.clone().ok_or(())?,
        })
    }

    fn started(&self) -> bool {
        if self.time.is_some() {
            true
        } else {
            false
        }
    }
}

pub struct Reader {
    reader: BufReader<File>,
    context: EntryContext,
    header: Option<String>,
}

impl Reader {
    pub fn new(s: &str) -> Result<Self, ReadError> {
        let reader = BufReader::new(File::open(s)?);

        Ok(Self {
            reader,
            context: Default::default(),
            header: Default::default(),
        })
    }

    fn read_line(&mut self) -> Result<Option<String>, ReadError> {
        let mut l = String::new();

        let bytes = self.reader.read_line(&mut l)?;

        if bytes == 0 {
            return Ok(None);
        }

        Ok(Some(l))
    }

    pub fn read_entry(&mut self) -> Result<Option<Entry>, ReadError> {
        if self.header.is_none() {
            let mut h = String::new();

            loop {
                let line = self.read_line()?;

                if let Some(l) = line {
                    if l.starts_with("#") {
                        self.start_entry(&l)?;
                        break;
                    } else {
                        h.push_str(&l);
                    }
                } else {
                    return Err(ReadError::IncompleteLog);
                }
            }

            self.header = Some(h);
        }

        if !self.context.started() {
            let line = self.read_line()?;

            if let Some(l) = line {
                if let Ok((_, t)) = parse_entry_time(&l) {
                    self.context.time = Some(t);
                } else {
                    return Err(InvalidTimeLine(l));
                }
            } else {
                return Err(InvalidTimeLine("".into()));
            }
        }

        let line = self.read_line()?;

        if let Some(l) = line {
            if let Ok((_, u)) = parse_entry_user(&l) {
                self.context.user = Some(u);
            } else {
                return Err(InvalidUserLine(l));
            }
        } else {
            return if self.context.started() {
                Ok(None)
            } else {
                Err(IncompleteEntry)
            };
        }

        let line = self.read_line()?;

        if let Some(l) = line {
            if let Ok((_, s)) = parse_entry_stats(&l) {
                self.context.stats = Some(s);
            } else {
                return Err(InvalidStatsLine(l));
            }
        } else {
            return Err(InvalidStatsLine("".into()));
        }

        let mut count: usize = 0;

        loop {
            let line = self.read_line()?;

            if let Some(l) = line {
                if l.starts_with("#") && !l.starts_with("# administrator command:") {
                    let e = self.context.entry().or(Err(IncompleteEntry))?;

                    self.start_entry(&l)?;

                    return Ok(Some(e));
                } else {
                    self.context.append_sql(&l)?;
                    count += 1;
                }
            } else {
                if let Ok(e) = self.context.entry() {
                    return Ok(Some(e));
                } else {
                    if count == 0 {
                        return Err(IncompleteEntry);
                    } else {
                        return Ok(None);
                    }
                }
            }
        }
    }

    fn start_entry(&mut self, l: &str) -> Result<(), ReadError> {
        if let Ok((_, t)) = parse_entry_time(&l) {
            self.context = EntryContext {
                time: Some(t),
                ..Default::default()
            };

            Ok(())
        } else {
            Err(InvalidTimeLine(l.into()))
        }
    }
}

#[derive(Debug)]
pub struct Entry {
    time: DateTime,
    user: String,
    sys_user: String,
    host: String,
    query_time: f64,
    lock_time: f64,
    rows_sent: u32,
    rows_examined: u32,
    sql: String,
}

#[cfg(test)]
mod tests {
    use crate::Reader;

    #[test]
    fn parse_slow_log() {
        let mut p = Reader::new("data/slow-test-queries.log").unwrap();

        let mut i = 0usize;

        while let Some(_) = p.read_entry().unwrap() {
            i += 1;
        }

        assert_eq!(i, 310);
    }
}
