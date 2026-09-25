# Changelog

## 0.6.0 - 2026-09-25

### Breaking
* sqlparser 0.56 to 0.63. Its AST is part of this crate's API, and the crate is re-exported as
  `mysql_slowlog_parser::sqlparser`. 0.63 executes MySQL version gates, so statements inside
  `/*!40101 ... */` now parse instead of arriving as `InvalidStatement`.
* winnow 0.7 to 1.0, winnow_iso8601 0.6 to 0.7 and winnow_datetime 0.3 to 0.4, re-exported as
  `mysql_slowlog_parser::winnow_datetime`. A `# Time:` line now keeps its microseconds.
* Every public enum is `#[non_exhaustive]`.
* The decoder returns errors instead of panicking. `CodecError` gains `Malformed`, `Truncated`
  and `MissingTime`, each saying which entry and which line; input that ends inside an entry is
  `Truncated` rather than `IO`. `DecodeStage` names the line that failed.
* `Rows_sent` and `Rows_examined` are `u64`, as MySQL writes them. `EntryStats` and `StatsLine`
  are no longer `Copy`.
* The thread id is `Option<u32>` on `Entry`, `EntrySession` and `SessionLine`; MySQL 5.5 and
  MariaDB can omit it.
* `SqlStatementContext` keeps every key the comment wrote. Its fixed fields (`request_id`,
  `caller`, `function`, `line`) are replaced by `entries: HashMap<Bytes, Bytes>` with `get`,
  `get_bytes`, `get_parsed`, `keys`, `is_empty` and `new`. With no `map_comment_context`
  registered, the context is now kept instead of dropped.
* `EntrySqlAttributes` gains the fields `sql_raw`, `literals` and `use_database`; `EntryCall`
  gains `insert_id` and `last_insert_id`; `EntryStats` gains `extra`.
* `EntrySqlType` adds `Analyze`, `Truncate`, `RenameTable`, `Replace`, `AlterView`, `DropView`,
  `DropDatabase`, `DropIndex` and `ShowCreateView`, and drops `AlterIndex` and `SetTransaction`,
  which no MySQL statement reaches. `Drop` now means only `DROP TABLE` and `ShowCreate` only
  `SHOW CREATE TABLE`; other object types are `Unknown`. `Display` for `Unknown` is `UNKNOWN`
  rather than `NULL`, and for `ShowVariable` is `SHOW`.
* `objects()` names relations by their unquoted identifiers, so `` `actor` `` and `actor` are one
  object, and the schema of `SHOW TABLES FROM db` is no longer filed as one.
* Removed `EntryContext`, `EntryError`, `ReadError`, `ReaderBuildError` and
  `CodecError::IncompleteEntry`, none of which a caller could receive.
* Requires Rust 1.88.

### Added
* `StatementGraph`, from `EntryStatement::relation_graph()` or
  `EntrySqlStatement::relation_graph()`: every relation a statement names, with the scope it sits
  in, the role it plays there and the row lock taken on it; the scope tree with each scope's
  filters, grouping, sorting, limits and set operator; every join and comparison with its
  operator, clause and place in the boolean tree; index hints, partition restrictions and
  optimizer hints. `measures` and `measures_collapsed_by_name` summarise the join graph. Syntax the
  grammar accepts but MySQL cannot write lands on `NotMySql` arms rather than on MySQL ones.
* `EntrySqlAttributes::literals`, with `EntryLiteral`, `LiteralColumn` and `LiteralKind`: every
  literal in the statement, with the column it was written to or compared with, under either
  masking setting.
* `rewrite_literals`, to substitute values into a statement, validating each substitute against
  the literal's kind, and `carries_a_value`, to ask whether a statement carries a value at all.
* `EntrySqlAttributes::sql_raw`, the statement as the log wrote it, and
  `EntrySqlAttributes::use_database`, the database a `use` line in the entry switched to.
* `FileScope`, with `EntryCodec::resume`, `file_scope`, `headers`, `header_count` and
  `processed`, so shards of one log can be read with the header the first shard carried.
* `EntryStats::extra` and `extra_value` carry the fields `log_slow_extra`, MariaDB and Percona add
  to an entry. `HeaderLines::named_pipe` reads the Windows header.
* Every public enum publishes its arms' names through `name()` and `NAMES`, and a fieldless one
  through `all()`.
* `EntrySqlStatement`, `HeaderLines`, `Partition` and `OptimizerHintText` are exported; public
  signatures already named them.

### Fixed
* A statement ends where the next entry begins, not at its first `;`. A quote or `;` inside a
  comment, a `;;`, a stored-program body and a quote of one kind inside the other no longer end
  the read or lose the rest of the log.
* Lines real servers write no longer stop the reader: user and host names with hyphens or dots,
  IPv6 client addresses, an empty user or host, a missing `Id:`, a `use` of a hyphenated or quoted
  database, row counts above `u32::MAX`, `log_slow_extra`, MariaDB and Percona `# Name: value`
  lines, `SET insert_id=...,last_insert_id=...,timestamp=...`, the pre-5.7 `# Time: 180205
  2:46:47` format, an entry with no `# Time:` line (it takes the previous entry's time), the
  Windows header and consecutive header blocks.
* A `--` comment before a statement that is not key/value pairs is kept as part of the statement
  rather than eating its first characters.
* Masking made statements unparseable by replacing numbers the grammar requires, such as
  `CHAR(60)`. Values are now masked after parsing, and a statement the grammar refuses is masked
  token by token. Bit literals are masked, and a negative number masks to `?` rather than `-?`.
* The server version, port and socket from the log header were reset after the first entry.
* Multi-word administrator commands were truncated, and a failed match consumed its input.
* `UNLOCK TABLES` was typed `LockTables`, `REPLACE` `Insert`, `DROP VIEW`, `DROP DATABASE` and
  `DROP INDEX` `Drop` (displayed as `DROP TABLE`), and `WITH ... INSERT/UPDATE/DELETE` a query.

### Changed
* The decoder no longer clones each statement's AST twice or copies the buffer per entry, and
  is about 25% faster with identical output. `examples/throughput.rs` measures it.

### Known issues
* MariaDB's `# explain:` block and Percona's `# No InnoDB statistics` line are not read; an entry
  carrying one returns `CodecError::Malformed`, and the stream ends there.
* A statement whose own text holds a line ending in `;` followed by a line beginning `# Time:` or
  `# User@Host:` is split at that line.
* A value inside an optimizer hint of a parsed statement is neither recorded nor masked.
* sqlparser renders a backslash in a string without escaping it, so `'a\\b'` appears in `sql` as
  `'a\b'`.

## 0.5.0 - 2025-06-11
* upgrade to winnow-datetime 0.3.0 objects
* Removed Copy trait from TimeLine and EntryCall since underlying winnow-datetime 0.3.0 objects are no longer Copy
* This is a small set of changes but it is a breaking change since the `TimeLine` and `EntryCall` objects are no longer
  Copy and the DateTime objects exposed from winnow-datetime 0.3.0 have changed. Most use-cases should not be affected.
* Allow for latest 0.7.x versions of winnow since they adhere well to semver.

## 0.4.0 - 2025-05-24
* upgrade to rust edition 2024
* fixed a warning introduced in previous release
* Update EntrySqlType to match new sqlparser AST
* upgrade bytes to 1.10.0
* upgrade futures to 0.3.31
* upgrade winnow to 0.7.10
* upgrade winnow_datetime to 0.2.3
* upgrade sqlparser to 0.56.0
* upgrade thiserror to 2.0.12
* upgrade log to 0.4.27
* upgrade tokio to 1.45.1
* upgrade tokio-util to 0.7.15

## 0.3.1 - 2025-05-13
* Upgrade of winnow-datetime crates, since older version had a bug
* Removed unused dependencies
* Upgrade of internal dependencies, sqlparser will wait for 0.4.0 since the AST is accessible to consumers.

## 0.3.0 - 2025-05-04
* Upgrade to winnow 0.7 and use ModalResult returns from parsers
* Upgrade to winnow-iso8601 0.5.0 which depends on winnow-datetime
* Return winnow-datetime 0.2.0 which will now need to be used by consumers

## 0.2.0 - 2024-11-24
* Export only DateTime types winnow-iso8601
* Changed CodecConfig to `EntryCodecConfig` so it better matches EntryCodec when exporting.
* Change type for `EntryCodecConfig.map_comment_context` to
  `Option<fn(HashMap<Bytes, Bytes>)...` so that `EntryCodecConfig` can derive `Clone`.
* Minor documentation improvements

## 0.1.0 - 2024-11-19
Initial release
