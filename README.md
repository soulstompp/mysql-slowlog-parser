# mysql-slowlog-parser - streaming slow query log parser

[![crates.io](https://img.shields.io/crates/v/mysql-slowlog-parser?style=flat-square)](https://crates.io/crates/mysql-slowlog-parser)
[![docs.rs docs](https://img.shields.io/badge/docs-latest-blue.svg?style=flat-square)](https://docs.rs/mysql-slowlog-parser)

## About

This library parses [MySQL slow query logs](https://dev.mysql.com/doc/refman/8.0/en/slow-query-log.html).
While certainly not the first slowlog parser written, this one extracts a great deal more information
than its predecessors: nearly every value on every line of an entry reaches the `Entry` it hands back.

The statement inside an entry is parsed as well, so an entry carries its AST, the kind of statement it
is, the relations and schemas it names, every literal the author wrote, and — through `StatementGraph` —
where each relation sits in the statement, which relations are joined to which, and every comparison the
author wrote with its place in the boolean tree. Values can be masked, which normalizes repeated calls of
one query to a single text.

Since it is a fairly common practice to include important information in the comment of a query, the
comment preceding a statement is parsed for key-value pairs, which come back under the names the comment
used.

This library reads streaming data from a variety of sources and handles large logs without holding them
in memory.

### Limitations
It reads the slow logs MySQL 5.5 to 8.4, MariaDB and Percona Server write, including
[log_slow_extra](https://dev.mysql.com/doc/refman/8.4/en/server-system-variables.html#sysvar_log_slow_extra).
Input it cannot read returns a `CodecError` naming the entry and the line, and the stream ends there.
Known gaps:
* MariaDB's `# explain:` block and Percona's `# No InnoDB statistics` line are not read.
* A statement ends at a line ending in `;` that is followed by a new entry, a header or the end of the
  log. A statement whose own text holds such a line followed by one beginning `# Time:` or
  `# User@Host:` is split there.

A statement the SQL grammar refuses is not malformed input. It arrives as
`EntryStatement::InvalidStatement` carrying the log's own bytes, and an entry holding one is an ordinary
entry in every other respect.

### Usage
#### Parsing
The parser is built as a [tokio codec](https://docs.rs/tokio-util/latest/tokio_util/codec/index.html) and
so can accept anything that
[FramedRead](https://docs.rs/tokio-util/latest/tokio_util/codec/struct.FramedRead.html) supports.

```rust
use futures::StreamExt;
use mysql_slowlog_parser::EntryCodec;
use tokio::fs::File;
use tokio_util::codec::FramedRead;

#[tokio::main]
async fn main() {
    let file = File::open("mysql-slow.log").await.unwrap();
    let mut entries = FramedRead::new(file, EntryCodec::default());

    while let Some(entry) = entries.next().await {
        let entry = entry.unwrap();
        println!("{:.6}s {}", entry.query_time(), entry.sql_attributes.sql());
    }
}
```

#### Masking
`EntryCodec::default()` leaves values in place. `EntryCodec::new` takes an `EntryCodecConfig`, whose
`masking` field set to `EntryMasking::PlaceHolder` renders every literal as a `?` placeholder, so that
two calls of one query differing only in their values share a single `sql`. A parsed statement is masked
in its tree; a statement the grammar refuses is masked token by token over the author's text. A value
inside an optimizer hint of a parsed statement is not masked.

Masking moves the rendering and nothing else. `EntrySqlAttributes::sql_raw` is the author's own bytes at
either setting, and `EntrySqlAttributes::literals` records every literal at either setting.
`rewrite_literals` goes the other way: give it the author's text or an unmasked rendering and one
substitute per literal, indexed by `EntryLiteral::ordinal`, and it returns the statement with those
substitutes in place. It takes each literal's kind from the original, escapes a string substitute, and
returns `None` where a substitute is not a valid literal of that kind or the text is not exactly one
statement it can parse.

#### Handling Dates
As of 0.3.0, the parsers return the AST objects from
[winnow-datetime](https://crates.io/crates/winnow_datetime); for information on how to convert dates to
your preferred date library see the documentation for that crate.

### Entries
The parsers and the codec return an `Entry` for each entry found in the log, holding the following.
Most of it can be reached through functions on `Entry` itself as well as on the structs below.

#### Call Information
`EntryCall`: the `# Time:` instant the log recorded for the entry, the `SET timestamp` value in force
while the query ran, and the `insert_id` and `last_insert_id` the server set alongside it.

#### Session Information
`EntrySession`: the user name, system user name, host name, IP address and thread id of the connection
that made the call.

#### Query Stats
`EntryStats`: `Query_time`, `Lock_time`, `Rows_sent` and `Rows_examined`, and in `extra` every further
field `log_slow_extra`, MariaDB or Percona wrote for the entry, in the order written.

#### Query Information
`EntrySqlAttributes` holds what the entry says about its statement:

* `sql` — the reader's rendering: the AST rendered back to text where the statement parsed, the command
word for an administrator command, the log's own bytes where the grammar refused it.
* `sql_raw` — the author's own bytes, `;` included. This is the only record of keyword case, line layout,
in-statement comments and unmasked literals. `None` on an administrator command, where `sql` is already
the log's own bytes.
* `literals` — every literal the author wrote, in traversal order, whether or not masking is on. Each
carries the literal as written, its payload without quoting, its kind, the column the syntax compared it
against where one is named, and whether the author was looking the value up or writing it.
* `use_database` — the database the log said was current. MySQL writes `USE` only when the database
changes, so this is `None` on every entry that did not carry one, and carrying it forward along a
connection is a reader's inference.
* `statement` — an `EntryStatement`: the [sqlparser](https://crates.io/crates/sqlparser) AST where the
statement parsed, the command for an administrator command, or the log's bytes where the grammar refused
it.

`EntrySqlAttributes::sql_type` gives the statement's kind as an `EntrySqlType` and
`EntrySqlAttributes::objects` gives the relations and schemas a parsed statement names.
`Entry::sql_context` gives the pairs from the comment preceding the statement as a
`SqlStatementContext`, which holds every pair the comment wrote under the keys it used; a consumer that
would rather filter, rename or reject pairs registers a function in
`EntryCodecConfig::map_comment_context`.

### The statement graph
`EntryStatement::relation_graph` returns a `StatementGraph` where the statement parsed, and `None` for an
administrator command or a statement the grammar refused — the two that have no AST to walk.

`objects` folds a parse into a set of names, which loses the multiplicity, the position, the nesting
depth and every relationship: a self-join arrives there as one name, a table named inside a
`CREATE VIEW` body looks like a table that was read, and a CTE reference looks like a physical table. The
graph is the same parse without those losses.

* `occurrences` — one entry per relation the statement named, and not one per table: `FROM employee e1
JOIN employee e2` is two, because the statement said it twice. Each carries the scope it sits in, its
written schema and object name, its alias — which is its identity, since an alias is scoped and SQL
itself forbids a collision within one scope — and its `RelationRole`. The roles keep apart what a set of
names puts together: the relation an `UPDATE` writes to from the ones it reads, a `LOCK TABLES … WRITE`
from a `LOCK TABLES … READ`, an `ALTER` from a `CREATE`. A CTE reference, and an alias a multi-table
`DELETE` named its target by, are kept and recorded with what they resolve to, so a consumer asking
which physical tables a statement touched can pass over them.
* `scopes` — the naming scopes, `scopes[0]` being the statement's own, each with its parent, its depth
and its `ScopeKind`. `ScopeKind::ViewBody` is what separates a table read from a table named. Each scope
also carries the row-reducing stages written in it — filter and having conjuncts, grouping terms,
aggregate calls, `DISTINCT`, sort terms and directions, `LIMIT` rows and offset, the set operator — and
the row lock its own `FOR UPDATE` / `FOR SHARE` asks for, with what it does when those rows are already
locked. Each occurrence carries the lock taken on it, since `FOR UPDATE OF t` locks only `t`.
* `edges` — one entry per relationship the statement wrote down, with the `JoinOp` that made it, the
`ConstraintKind` it matched on, and whether its endpoints sit in different scopes, which for a predicate
edge is what a correlation is. `TableWithJoins.joins` is a flat left-deep list, so the branching
structure of a join is in the `ON` clauses and nowhere else.
* `predicates` — one entry per comparison the author wrote, with the clause it was written in, its path
of connectives from the scope's root (so two comparisons sit in one disjunction exactly when their paths
share a prefix ending in an `Or`), the operator, both sides, what the right side is, and, for a
comparison written in a join clause, which join brought the occurrence in. A comparison with both sides
occupied is a relationship — the join — and one with a single side is a filter.
* `index_hints` — `USE`, `FORCE` and `IGNORE INDEX`, which is the author naming an index and the one
place a slow log names one at all, with the occurrence the hint was written against and the part of the
statement it applies to.
* `partitions` — the partitions a `FROM t PARTITION (p0)` restricted an occurrence to.
* `optimizer_hints` — the `/*+ … */` comments, carried as the author's own bytes.

`StatementGraph::measures` reports the nodes, edges, components and cycle space of the join graph as the
statement wrote it. `measures_collapsed_by_name` reports the same after collapsing every occurrence onto
its written `[schema.]object` name; nothing in a slow log says that `sakila.film` and `film` are one
relation, so that reading is a reader's and is offered beside the statement's own rather than instead of
it.

Text this grammar accepts and MySQL has no syntax for is not filed as though the server ran it. The
landing arms `JoinOp::NotMySql`, `PredicateOp::NotMySql`, `SetOperator::NotMySql` and
`Stages::not_mysql` say that the grammar read something this server could
not have written, and they are diagnostics rather than data. Some constructs are read and deliberately
not decomposed: an optimizer hint is carried as bytes because `sqlparser` hands the comment body over
unstructured, and `SHOW INDEX FROM t` arrives as a token list rather than as a structure, so no relation
is read out of it. No per-relation cost is here at all: a slow log measures statements, so the incidence
is complete and every per-relation figure is absent.

Every enum here publishes its arms' names through `name()` and `NAMES`, so a caller writing them to a
column uses the crate's spelling rather than its own.

### Additional Information
See the docs for the `Entry` struct, which holds everything returned for a single entry, in the
[docs][docs].

# License

MIT Licensed. See [LICENSE](LICENSE).

[docs]: https://docs.rs/mysql-slowlog-parser/
