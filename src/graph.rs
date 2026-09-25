//! The relation graph of a parsed statement: which relations it names, where each one sits, and
//! which ones are joined to which.
//!
//! What it reads: every relation occurrence in the statement, the naming scope each one sits in,
//! the role it plays there, the relationships the statement wrote between them, the comparisons in
//! each scope's boolean tree, and the row-reducing stages, locking clauses, index hints, partition
//! restrictions and optimizer-hint comments each scope carries. `objects()` folds the same parse
//! into a set of names: a self-join arrives as one name there, a table named inside a
//! `CREATE VIEW` body looks like a table that was scanned, and a CTE reference looks like a
//! physical table.
//!
//! It is walked by hand rather than by a visitor, because `sqlparser`'s visitor fires on
//! `ObjectName`, `TableFactor`, `Expr`, `Query`, `Statement` and `Value` and on nothing else.
//! Nothing on `Join`, `JoinOperator`, `JoinConstraint`, `TableWithJoins`, `Cte` or `With` is
//! annotated for it, so a visitor sees join *operands* as an undifferentiated stream and never
//! sees the join *operator* or its predicate.
//!
//! ## What a node is
//!
//! An occurrence and never a table. `FROM employee e1 JOIN employee e2` is two nodes, because the
//! statement said it twice; collapsing the two onto one table name is a claim about a catalogue
//! this crate has never seen, and belongs to whoever holds the catalogue.
//! [`RelationOccurrence::alias`] is the identity, and
//! [`RelationOccurrence::object_name`] is what a later reader would collapse *by*.
//!
//! ## What the walk refuses, and what it declines to interpret
//!
//! Text `sqlparser` builds and MySQL cannot write is not filed as though the server ran it: the
//! landing arms [`JoinOp::NotMySql`], [`PredicateOp::NotMySql`], [`SetOperator::NotMySql`] and
//! [`Stages::not_mysql`] say that the grammar accepted something this server has no syntax for.
//! A claim about MySQL's behaviour holds inside a server version, and these arms are where the two
//! regimes are kept apart.
//!
//! Some constructs are read and deliberately not decomposed. An optimizer hint is carried as the
//! author's own bytes, because `sqlparser` hands the whole comment body over unstructured and
//! naming each hint and its target would be this walk lexing where everything else parses. `SHOW
//! INDEX FROM t` and `SHOW TABLE STATUS FROM db` arrive as token lists rather than as structures,
//! so no relation is read out of them for the same reason. The figures a relation occurrence
//! would carry are not here at all: a slow log measures statements and not relations.
//!
//! ## What the walker does not see
//!
//! The walk names the clauses it reads, and inside each one finds every subquery with
//! `sqlparser`'s own expression visitor, so no `Expr` form hides one. A subquery in a clause the
//! walk does not name would be a relation this graph does not hold. That gap is checked rather
//! than latent: the crate's tests count the same subqueries over the whole statement, by a route
//! that names no clause, and hold the two counts together.

use bytes::Bytes;
use sqlparser::ast::{
    Assignment, AssignmentTarget, Cte, Delete, Distinct, Expr, FromTable, GroupByExpr,
    GroupByWithModifier, Ident, Insert, JoinConstraint, JoinOperator, LockClause, LockTableType,
    LockType, NonBlock, ObjectName, ObjectNamePart, ObjectType, OnInsert, OptimizerHintStyle,
    OrderByKind, Query, Select, SetExpr, ShowCreateObject, Statement, TableFactor,
    TableIndexHintForClause, TableIndexHintType, TableIndexType, TableObject, TableWithJoins,
    UpdateTableFromKind, Visit, Visitor,
};
use std::ops::ControlFlow;

/// Where in its statement a relation occurrence sits.
///
/// The target arms are why a set of names will not do: `objects()` puts the table an `UPDATE`
/// writes to and the tables it reads from into one collection with nothing separating them, so a
/// reader summing over "the tables this statement touched" sums a write and a read together.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum RelationRole {
    /// the first relation of a `FROM` clause, or of a multi-table `UPDATE`'s table list where the
    /// statement only reads it
    From,
    /// a relation introduced by a `JOIN`, or by a comma in a `FROM` list
    Join,
    /// the relation an `INSERT` writes to
    InsertTarget,
    /// the relation an `UPDATE` writes to
    ///
    /// In a multi-table `UPDATE` that is each relation a `SET` assignment names by its qualifier,
    /// and a relation joined in only to be read keeps [`RelationRole::From`] or
    /// [`RelationRole::Join`]. An unqualified assignment there belongs to whichever relation has
    /// the column, which only the catalogue can say, so every base relation of the statement is
    /// filed as a target: a write filed as a read would hide a conflict, where the reverse only
    /// proposes one. MySQL's comma form, `UPDATE a, b SET …`, is refused by this grammar and
    /// reaches a caller as an invalid statement.
    UpdateTarget,
    /// a relation a `DELETE` removes rows from
    DeleteTarget,
    /// the relation a `CREATE` statement brings into being
    CreateTarget,
    /// the relation an `ALTER TABLE` changes the definition of
    ///
    /// Kept apart from [`RelationRole::CreateTarget`]: a `CREATE` names a relation that did not
    /// exist, so nothing was reading it and nothing could be blocked, while an `ALTER` names one
    /// that does exist and takes `MDL_EXCLUSIVE` on it, which blocks every reader for the
    /// duration. One name for both would put the DDL that cannot block anybody under the same
    /// name as the one that blocks everybody.
    AlterTarget,
    /// the relation a `DROP` removes
    DropTarget,
    /// the relation a `TRUNCATE` empties
    ///
    /// Not a `DELETE`: InnoDB implements `TRUNCATE TABLE` by dropping and recreating the
    /// tablespace, so it takes `MDL_EXCLUSIVE` where a `DELETE FROM t` takes row locks.
    TruncateTarget,
    /// a relation `LOCK TABLES … WRITE` holds
    ///
    /// The statement that takes the lock a slow log measures the wait for: `Lock_time` is
    /// table-level and metadata lock wait, and `LOCK TABLES` is how a client asks for exactly
    /// that. `LockTables.tables` carries no `visit_relation` annotation, so the tables it holds
    /// reach `objects()` not at all and are only in the graph because this walk reads them.
    LockExclusiveTarget,
    /// a relation `LOCK TABLES … READ` holds
    ///
    /// Filed apart from [`RelationRole::LockExclusiveTarget`] because the modes exclude different
    /// things: a read lock admits other readers and shuts out writers, and a write lock shuts out
    /// both.
    LockSharedTarget,
    /// the relation an `ANALYZE TABLE` samples
    AnalyzeTarget,
    /// Named by a statement that opens the table, takes a **shared** metadata lock and reads no
    /// rows: `EXPLAIN t`, `DESCRIBE t`, `SHOW CREATE TABLE t`, `SHOW COLUMNS FROM t`.
    ///
    /// Not [`RelationRole::From`]: these read the data dictionary rather than the table, so a
    /// reader taking `rows_examined` against them is right to see a zero while a reader asking who
    /// held a metadata lock is right to see them. Folding them into `From` would make the first
    /// unreadable, and dropping them would make the second.
    MetadataTarget,
    /// `FLUSH TABLES t` — takes an **exclusive** metadata lock and closes the table.
    ///
    /// Filed apart from [`RelationRole::MetadataTarget`] because the lock is the opposite one:
    /// this excludes every reader, as a DDL does, which is a different claim about MySQL from the
    /// one above.
    FlushTarget,
}

vocabulary!(RelationRole {
    AlterTarget => "alter_target",
    AnalyzeTarget => "analyze_target",
    CreateTarget => "create_target",
    DeleteTarget => "delete_target",
    DropTarget => "drop_target",
    FlushTarget => "flush_target",
    From => "from",
    InsertTarget => "insert_target",
    Join => "join",
    LockExclusiveTarget => "lock_exclusive_target",
    LockSharedTarget => "lock_shared_target",
    MetadataTarget => "metadata_target",
    TruncateTarget => "truncate_target",
    UpdateTarget => "update_target",
});

/// The kind of naming scope a relation occurrence was found in.
///
/// This is what separates a table scanned from a table named. A relation under a
/// [`ScopeKind::ViewBody`] is mentioned in a definition that ran once and read nothing; a relation
/// under [`ScopeKind::Statement`] was visited. `objects()` spells the two the same, so a sum over
/// tables weighted by query time can be drawn entirely from statements that never touched them.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ScopeKind {
    /// the statement's own top level
    Statement,
    /// the body of a `CREATE VIEW`
    ViewBody,
    /// the body of a common table expression
    Cte,
    /// a subquery in relation position, i.e. a derived table
    Derived,
    /// a subquery in expression position
    Subquery,
    /// one side of a `UNION`, `EXCEPT` or `INTERSECT`
    SetOp,
}

vocabulary!(ScopeKind {
    Cte => "cte",
    Derived => "derived",
    SetOp => "set_op",
    Statement => "statement",
    Subquery => "subquery",
    ViewBody => "view_body",
});

/// How two relation occurrences were put together.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum JoinOp {
    /// `JOIN` / `INNER JOIN`
    Inner,
    /// `LEFT JOIN`
    Left,
    /// `RIGHT JOIN`
    Right,
    /// `CROSS JOIN`
    Cross,
    /// `STRAIGHT_JOIN`
    Straight,
    /// a comma in a `FROM` list
    Comma,
    /// Not a join operator at all: a comparison written in a predicate clause — `WHERE`,
    /// `HAVING`, or an expression in the projection — whose two sides name different relations.
    ///
    /// This is not the same thing as a correlation. A correlation is the cross-scope case, and
    /// this arm also holds the ordinary same-scope predicate — which for a comma join is the join
    /// condition itself, since old-style SQL has no `ON` to put it in. Whether an edge crosses a
    /// scope is [`Edge::crosses_scope`], so the two facts stay two fields and a correlation is
    /// the reading `op == Predicate && crosses_scope`. A variant for it would define `op` out of
    /// `crosses_scope`.
    Predicate,
    /// A join operator MySQL cannot write.
    ///
    /// `sqlparser` is a multi-dialect parser and `MySqlDialect` gates very little, so it will
    /// build `FULL OUTER JOIN`, `SEMI`/`ANTI JOIN`, `CROSS`/`OUTER APPLY` and `ASOF JOIN` out of
    /// text MySQL has no syntax for. This crate reads MySQL slow logs, so one arm covers all of
    /// them rather than naming cases that cannot occur in front of every caller and every match.
    ///
    /// A comparison relating two relations with an operator MySQL does not have lands here too,
    /// rather than on [`JoinOp::Predicate`].
    ///
    /// An edge carrying this is a diagnostic and not data: either the input was not a MySQL slow
    /// log, or `sqlparser` built a tree the server could not have run. The author's bytes are on
    /// the entry either way.
    NotMySql,
}

vocabulary!(JoinOp {
    Comma => "comma",
    Cross => "cross",
    Inner => "inner",
    Left => "left",
    NotMySql => "not_mysql",
    Predicate => "predicate",
    Right => "right",
    Straight => "straight",
});

/// What the join said about how to match rows.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ConstraintKind {
    /// `ON <predicate>`
    On,
    /// `USING (cols)`
    Using,
    /// `NATURAL`
    Natural,
    /// no join constraint was written: a comma, a join with no `ON` or `USING`, and every edge a
    /// comparison in a `WHERE`, a `HAVING` or the projection draws, which sits in no join
    None,
}

vocabulary!(ConstraintKind {
    Natural => "natural",
    None => "none",
    On => "on",
    Using => "using",
});

/// Which clause a split was written in.
///
/// On an outer join `ON p` and `WHERE p` are different queries, so this is not decoration.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum Clause {
    /// A join's `ON`.
    On,
    /// The scope's `WHERE`.
    Where,
    /// The scope's `HAVING`, which filters groups rather than rows.
    Having,
    /// `USING (cols)`, which names columns without writing a comparison.
    JoinUsing,
    /// A comparison in the projection — a `CASE`, a boolean expression selected as a value.
    Projection,
}

vocabulary!(Clause {
    Having => "having",
    JoinUsing => "join_using",
    On => "on",
    Projection => "projection",
    Where => "where",
});

/// A boolean connective, as a step on the path from a scope's root to one comparison.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum Connective {
    /// `AND`. This grammar binds MySQL's `&&` tighter than `=`, so `a = 1 && b = 2` arrives as one
    /// comparison over no column and never as this connective.
    And,
    /// `OR`. MySQL reads `||` as `OR` by default; this grammar reads it as concatenation bound
    /// tighter than `=`, so `a = 1 || b = 2` arrives as one comparison over no column.
    Or,
    /// MySQL's `XOR`, which no other dialect spells this way. This grammar binds it tighter than
    /// `=`, so only operands written in parentheses, `(a = 1) XOR (b = 2)`, reach this connective.
    Xor,
    /// `NOT`, which negates the branch beneath it.
    Not,
}

vocabulary!(Connective {
    And => "and",
    Not => "not",
    Or => "or",
    Xor => "xor",
});

/// One step of a comparison's position in its scope's boolean tree.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct PathStep {
    /// The connective at this level.
    pub connective: Connective,
    /// Which operand of that connective this branch is.
    pub branch: u16,
}

/// How a split compares its sides.
///
/// The subquery arms are the shape MySQL plans differently: `IN (SELECT …)` admits semi-join and
/// materialisation, `EXISTS` is a correlated probe, and a scalar subquery is evaluated once.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum PredicateOp {
    /// `=`
    Eq,
    /// `!=` or `<>`
    Ne,
    /// `<`
    Lt,
    /// `<=`
    Le,
    /// `>`
    Gt,
    /// `>=`
    Ge,
    /// `<=>`
    NullSafeEq,
    /// `IN (a, b, c)` — a finite set of points.
    InList,
    /// `NOT IN (a, b, c)` — everything outside a finite set.
    NotInList,
    /// `BETWEEN lo AND hi`
    Between,
    /// `NOT BETWEEN lo AND hi` — everything outside a range, which is not a range.
    NotBetween,
    /// `LIKE`.
    Like,
    /// `NOT LIKE`.
    NotLike,
    /// `REGEXP` or `RLIKE`.
    Regexp,
    /// `NOT REGEXP` or `NOT RLIKE`.
    NotRegexp,
    /// `MATCH (…) AGAINST (…)` — a fulltext search, which uses a `FULLTEXT` index and no other.
    MatchAgainst,
    /// `IS NULL`.
    IsNull,
    /// `IS NOT NULL`, which selects the complement of what [`Self::IsNull`] selects.
    IsNotNull,
    /// `IN (SELECT …)`
    InSubquery,
    /// `NOT IN (SELECT …)`
    NotInSubquery,
    /// `EXISTS (SELECT …)`
    Exists,
    /// `NOT EXISTS (SELECT …)`
    NotExists,
    /// `> ANY (SELECT …)`
    Any,
    /// `> ALL (SELECT …)`
    All,
    /// A comparison whose right-hand side is a single-row subquery.
    Scalar,
    /// An operator MySQL has no syntax for. A diagnostic and not data, exactly as
    /// [`JoinOp::NotMySql`] is.
    NotMySql,
}

vocabulary!(PredicateOp {
    All => "all",
    Any => "any",
    Between => "between",
    Eq => "eq",
    Exists => "exists",
    Ge => "ge",
    Gt => "gt",
    InList => "in_list",
    InSubquery => "in_subquery",
    IsNotNull => "is_not_null",
    IsNull => "is_null",
    Le => "le",
    Like => "like",
    Lt => "lt",
    MatchAgainst => "match_against",
    Ne => "ne",
    NotBetween => "not_between",
    NotExists => "not_exists",
    NotInList => "not_in_list",
    NotInSubquery => "not_in_subquery",
    NotLike => "not_like",
    NotMySql => "not_mysql",
    NotRegexp => "not_regexp",
    NullSafeEq => "null_safe_eq",
    Regexp => "regexp",
    Scalar => "scalar",
});

/// What the right-hand side of a split is.
///
/// `Subquery` is what makes the walk recursive: a subselect is an operand of a split rather than a
/// scope that merely exists, so [`Predicate::rhs_scope`] leads to its own predicates.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum RhsKind {
    /// Another column, which is what makes a split a relationship.
    Column,
    /// A value the author wrote.
    Literal,
    /// A subselect — see [`Predicate::rhs_scope`].
    Subquery,
    /// Anything computed: a function call, arithmetic, a `CASE`.
    Expression,
    /// `(a, b)`, a row constructor.
    RowConstructor,
    /// A unary split — `IS NULL`, `EXISTS` — which has no right-hand side.
    None,
}

vocabulary!(RhsKind {
    Column => "column",
    Expression => "expression",
    Literal => "literal",
    None => "none",
    RowConstructor => "row_constructor",
    Subquery => "subquery",
});

/// One side of a split, as the author spelled it.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Side {
    /// The occurrence a written qualifier resolved to. `None` where the column was unqualified,
    /// which a caller holding the whole statement can resolve against its sole relation.
    pub occ: Option<u32>,
    /// The column as the author spelled it.
    pub column: Option<Bytes>,
}

/// One comparison the author wrote, with where it sits in the boolean tree.
///
/// A split with both sides occupied is a relationship — the join — and one with a single side is a
/// filter. They are the same kind of object, which is why they share a row type.
#[derive(Clone, Debug, PartialEq)]
pub struct Predicate {
    /// The scope whose boolean tree this split sits in.
    pub scope: u32,
    /// Which clause the author wrote it in.
    pub clause: Clause,
    /// Connectives from the scope's root down to this comparison, outermost first. Two splits sit
    /// in one disjunction exactly when their paths share a prefix ending in [`Connective::Or`].
    pub path: Vec<PathStep>,
    /// How the two sides are compared.
    pub op: PredicateOp,
    /// The left side.
    pub lhs: Side,
    /// The right side, empty on a unary split.
    pub rhs: Side,
    /// What the right side is.
    pub rhs_kind: RhsKind,
    /// The subquery's scope, where `rhs_kind` is [`RhsKind::Subquery`].
    pub rhs_scope: Option<u32>,
    /// The occurrence the join brought in, where this split was written in a join clause.
    ///
    /// `clause` says a split sat in an `ON`, and with two joins in one statement that is not
    /// enough to say **which**. This names the join: it is the occurrence on the right of the
    /// join operator, which is what [`Edge::rhs`] carries, so the pair joins on it and the
    /// operator above the split becomes readable.
    ///
    /// That operator is not decoration: under a `LEFT JOIN` an `ON` predicate restricts the
    /// null-supplying side and removes no row of the preserved side, while the same predicate in a
    /// `WHERE` removes rows and takes the outerness with it. [`Self::path`] cannot see that,
    /// because the join sits above the boolean tree it describes.
    ///
    /// `None` on a `WHERE`, `HAVING` or projection split, which no join clause encloses.
    pub join_occ: Option<u32>,
}

/// Which set operation combined two queries.
///
/// `UNION` deduplicates and `UNION ALL` does not, which is a sort or a temporary table. `INTERSECT`
/// and `EXCEPT` are MySQL 8.0.31 and later, so a log from an older server cannot contain one.
#[derive(Copy, Clone, Debug, Default, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum SetOperator {
    /// `UNION`, which deduplicates.
    Union,
    /// `UNION ALL`, which does not.
    UnionAll,
    /// `INTERSECT`
    Intersect,
    /// `INTERSECT ALL`
    IntersectAll,
    /// `EXCEPT`
    Except,
    /// `EXCEPT ALL`
    ExceptAll,
    /// This scope is not an operand of a set operation.
    #[default]
    NotApplicable,
    /// An operator MySQL has no syntax for, such as Oracle's `MINUS`. A diagnostic and not data.
    NotMySql,
}

vocabulary!(SetOperator {
    Except => "except",
    ExceptAll => "except_all",
    Intersect => "intersect",
    IntersectAll => "intersect_all",
    NotApplicable => "not_applicable",
    NotMySql => "not_mysql",
    Union => "union",
    UnionAll => "union_all",
});

/// The directions an `ORDER BY` wrote, which decide whether an index can be walked to satisfy it.
#[derive(Copy, Clone, Debug, Default, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum SortDirections {
    /// Every term ascending, written or defaulted.
    Asc,
    /// Every term descending.
    Desc,
    /// Terms in both directions, which no single index walk satisfies.
    Mixed,
    /// This scope wrote no `ORDER BY`.
    #[default]
    NotApplicable,
}

vocabulary!(SortDirections {
    Asc => "asc",
    Desc => "desc",
    Mixed => "mixed",
    NotApplicable => "not_applicable",
});

/// The row lock a `FOR UPDATE` / `FOR SHARE` clause asks for.
///
/// `None` is an ordinary read, whose isolation from a concurrent write is decided by the
/// transaction isolation level. The other two are taken whatever that level is.
///
/// Ordered by strength, so the stronger of two claims on one relation is the greater.
#[derive(Copy, Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum LockStrength {
    /// no locking clause
    #[default]
    None,
    /// `FOR SHARE`: other readers admitted, writers excluded
    Shared,
    /// `FOR UPDATE`: readers of the same rows under a locking read excluded, and writers
    Exclusive,
}

vocabulary!(LockStrength {
    Exclusive => "exclusive",
    None => "none",
    Shared => "shared",
});

/// What a locking scope does when the rows it wants are already locked.
///
/// `Wait` is the default and is what `Lock_time` measures. Under the other two a statement
/// reports no lock wait by construction, so a zero there is not evidence of no contention.
#[derive(Copy, Clone, Debug, Default, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum LockWait {
    /// block until the lock is available, or until `innodb_lock_wait_timeout`
    #[default]
    Wait,
    /// `NOWAIT`: fail immediately instead of waiting
    NoWait,
    /// `SKIP LOCKED`: omit the locked rows from the result instead of waiting
    SkipLocked,
}

vocabulary!(LockWait {
    NoWait => "nowait",
    SkipLocked => "skip_locked",
    Wait => "wait",
});

/// What an index hint tells the optimiser to do with the indexes it names.
///
/// MySQL's own ordering: `USE` is a suggestion the optimiser may decline, `FORCE` is a `USE` that
/// also makes a table scan maximally expensive, and `IGNORE` removes the named indexes from
/// consideration.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum IndexHintKind {
    /// `USE INDEX (…)`
    Use,
    /// `FORCE INDEX (…)`
    Force,
    /// `IGNORE INDEX (…)`
    Ignore,
}

vocabulary!(IndexHintKind {
    Force => "force",
    Ignore => "ignore",
    Use => "use",
});

/// Which part of the statement an index hint applies to.
///
/// `Any` is a hint written without a `FOR` clause, which MySQL applies to every part. It is a
/// written absence and not a blank: the author wrote a hint and named no scope for it.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum IndexHintScope {
    /// no `FOR` clause
    Any,
    /// `FOR JOIN`
    Join,
    /// `FOR ORDER BY`
    OrderBy,
    /// `FOR GROUP BY`
    GroupBy,
}

vocabulary!(IndexHintScope {
    Any => "any",
    GroupBy => "group_by",
    Join => "join",
    OrderBy => "order_by",
});

/// An index hint the author wrote against one relation occurrence.
///
/// This is the only construct in a slow log that names an index. Every other claim this crate
/// makes about access paths is a claim about the region a predicate sought, because the index
/// that would serve it is schema and a slow log carries none — so the rows here are the
/// exception, and they are the author's own words rather than a reader's inference.
#[derive(Clone, Debug, PartialEq)]
pub struct IndexHint {
    /// the occurrence the hint was written against
    pub occ: u32,
    /// what the hint tells the optimiser to do
    pub kind: IndexHintKind,
    /// which part of the statement it applies to
    pub scope: IndexHintScope,
    /// the index names, as the author spelled them
    pub names: Vec<Bytes>,
    /// whether the author wrote `KEY` rather than `INDEX`. The two are synonyms in MySQL, and
    /// this records which word was used rather than asserting they differ.
    pub spelled_key: bool,
}

/// A partition the author restricted an occurrence to.
///
/// `FROM t PARTITION (p0, p1)` is the author naming which partitions may be read. A partitioned
/// table carries a local index per partition, so a restriction here decides which index trees exist
/// to be walked — and two statements restricted to disjoint partitions touch no page in common.
#[derive(Clone, Debug, PartialEq)]
pub struct Partition {
    /// the occurrence the restriction was written against
    pub occ: u32,
    /// the partition name, as the author spelled it
    pub name: Bytes,
}

/// One optimizer-hint comment the author wrote, carried as the author's own bytes.
///
/// `/*+ NO_ICP(t idx) NO_MRR(t) */` names index access methods outright, which makes it the same
/// family as an index hint. One row per **comment** and not per hint: `sqlparser` hands the whole
/// comment body over as raw text without separating the hints inside it, so naming each hint, its
/// target table and its target index would be this walk lexing where everything else parses.
#[derive(Clone, Debug, PartialEq)]
pub struct OptimizerHintText {
    /// the scope the hint was written in
    pub scope: u32,
    /// the hint's own text, without the comment markers
    pub text: Bytes,
    /// a prefix between the comment marker and `+`, empty for a standard `/*+ ... */`
    pub prefix: Bytes,
    /// whether the author wrote the hint as a block comment or a line comment
    pub line_comment: bool,
}

/// A naming scope: the statement itself, or something nested inside it.
#[derive(Clone, Debug, PartialEq)]
pub struct Scope {
    /// index of this scope in [`StatementGraph::scopes`]
    pub id: u32,
    /// the enclosing scope, or `None` for the statement's own
    pub parent: Option<u32>,
    /// how deeply nested this scope is; the statement's own is 0
    pub depth: u16,
    /// what kind of scope this is
    pub kind: ScopeKind,
    /// the name a CTE was given, where this scope is one
    pub name: Option<Bytes>,
    /// whether a `WITH` introducing this scope said `RECURSIVE`
    pub recursive: bool,
    /// The row-reducing and row-reordering stages this scope writes down.
    ///
    /// A statement is a pipeline: each scope may filter, then group, then filter the groups, then
    /// order, then cut.
    ///
    /// The structure is the author's and the cost is nobody's. A slow log carries one
    /// `Query_time` for the whole pipeline and nothing per stage, so no per-stage cost is
    /// available here at any setting.
    pub stages: Stages,
    /// The strongest row lock this scope's own `FOR UPDATE` / `FOR SHARE` clauses ask for.
    ///
    /// Per scope, because MySQL locks the tables of the block the clause is written in: a
    /// subquery under a locking outer select is not itself locked unless it says so. Which of the
    /// scope's relations a clause locks is on the occurrence, [`RelationOccurrence::locking`],
    /// because `FOR UPDATE OF t` restricts it to the relations it names.
    pub locking: LockStrength,
    /// What this scope does when the rows it wants are already locked. `Wait` where
    /// [`Self::locking`] is [`LockStrength::None`], since nothing is being waited for. With
    /// several clauses, the last one that does not wait.
    pub lock_wait: LockWait,
}

/// The lock a `FOR UPDATE` / `FOR SHARE` clause asks for, and what it does when it cannot have
/// it.
fn locking_of(lock: &LockClause) -> (LockStrength, LockWait) {
    let strength = match lock.lock_type {
        LockType::Share => LockStrength::Shared,
        LockType::Update => LockStrength::Exclusive,
    };
    let wait = match lock.nonblock {
        None => LockWait::Wait,
        Some(NonBlock::Nowait) => LockWait::NoWait,
        Some(NonBlock::SkipLocked) => LockWait::SkipLocked,
    };
    (strength, wait)
}

/// What one scope does to its rows, counted rather than judged.
///
/// A scope is not one `Select`, so these counts accumulate: `INSERT ... SELECT ... WHERE` walks
/// its source into the same scope as the insert target, and `UPDATE`/`DELETE` carry a `WHERE` with
/// no `Select` at all. Assigning rather than accumulating would lose whichever came second.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stages {
    /// Top-level `AND` conjuncts of this scope's `WHERE`. `0` means the parse looked and there was
    /// no filter, rather than that nobody looked.
    pub filter_terms: u32,
    /// `GROUP BY` terms.
    pub group_terms: u32,
    /// Of those, how many are **not** a plain or qualified column.
    ///
    /// The count is the text's. Whether an expression forces a temporary table is a claim about
    /// the server and is not made here.
    pub group_expression_terms: u32,
    /// Top-level `AND` conjuncts of `HAVING`.
    pub having_terms: u32,
    /// Calls to a built-in aggregate in `HAVING`.
    ///
    /// The scope's own: an aggregate inside a subquery groups that subquery, and one with an
    /// `OVER` clause is a window function, which aggregates over a window and groups nothing.
    ///
    /// A lower bound: matched against MySQL's built-in aggregate names, so a
    /// `CREATE AGGREGATE FUNCTION` UDF is not on the list and is not counted.
    pub having_aggregate_calls: u32,
    /// Calls to a built-in aggregate in the projection, counted as `having_aggregate_calls` is.
    ///
    /// `group_terms == 0 && projection_aggregate_calls > 0` is implicit grouping — the whole
    /// result is one group — so a reading of `group_terms` alone would say there is no grouping
    /// stage where there is one.
    pub projection_aggregate_calls: u32,
    /// Whether the scope wrote `SELECT DISTINCT`. `SELECT DISTINCT a` and `SELECT a` do different
    /// work, so a caller keying on these stages needs the two to differ.
    pub distinct_present: bool,
    /// `ORDER BY` terms on the `Query` this scope heads: `ORDER BY` and `LIMIT` hang off `Query`
    /// and not off `Select`.
    pub sort_terms: u32,
    /// Whether the query this scope heads carried a `LIMIT`.
    pub limit_present: bool,
    /// The row count a `LIMIT` asked for, where it wrote a literal one.
    ///
    /// `None` under a placeholder, which is a measured absence rather than a zero.
    pub limit_rows: Option<u64>,
    /// The offset a `LIMIT` skipped. A deep one reads and discards every row before it.
    pub limit_offset: Option<u64>,
    /// The directions the `ORDER BY` wrote.
    pub sort_directions: SortDirections,
    /// The set operation this scope is an operand of, where it is one.
    pub set_operator: SetOperator,
    /// The scope carried a construct this grammar reaches and MySQL has no syntax for: `PREWHERE`,
    /// `QUALIFY`, `GROUP BY ALL`, a `GROUP BY` modifier other than `WITH ROLLUP`, `DISTINCT ON`,
    /// Hive's `SORT BY`/`CLUSTER BY`/`DISTRIBUTE BY`, `TOP`, `CONNECT BY`, `ORDER BY ALL`,
    /// `NULLS FIRST`/`NULLS LAST`, `ORDER BY … USING`, a `PIVOT`, `UNPIVOT` or
    /// `MATCH_RECOGNIZE` in its `FROM`, or an alias on a parenthesised join.
    ///
    /// One flag rather than one per construct, as with [`JoinOp::NotMySql`]: naming them would
    /// put cases that cannot occur in front of every caller. `true` is a diagnostic and not data.
    pub not_mysql: bool,
}

/// Top-level `AND` conjuncts of a predicate.
///
/// `AND` only. `a = 1 OR b = 2` is one condition on two columns, and splitting it would say the
/// author wrote two filters where they wrote a disjunction.
fn conjuncts(e: &Expr) -> u32 {
    match e {
        Expr::BinaryOp {
            left,
            op: sqlparser::ast::BinaryOperator::And,
            right,
        } => conjuncts(left) + conjuncts(right),
        Expr::Nested(inner) => conjuncts(inner),
        _ => 1,
    }
}

/// MySQL 8.0's built-in aggregates, by name.
///
/// A lower bound: a `CREATE AGGREGATE FUNCTION` UDF is not on this list, and whether a function
/// aggregates is not decidable from a log.
const AGGREGATES: [&str; 18] = [
    "COUNT",
    "SUM",
    "AVG",
    "MIN",
    "MAX",
    "GROUP_CONCAT",
    "JSON_ARRAYAGG",
    "JSON_OBJECTAGG",
    "STD",
    "STDDEV",
    "STDDEV_POP",
    "STDDEV_SAMP",
    "VARIANCE",
    "VAR_POP",
    "VAR_SAMP",
    "BIT_AND",
    "BIT_OR",
    "BIT_XOR",
];

/// Calls to a built-in aggregate that group the scope an expression sits in.
///
/// Not a subquery's, which group that subquery's own scope, and not a window function's:
/// `SUM(x) OVER (…)` aggregates over a window and leaves every row in place.
fn aggregate_calls(e: &Expr) -> u32 {
    struct Counter {
        depth: usize,
        n: u32,
    }
    impl Visitor for Counter {
        type Break = ();
        fn pre_visit_query(&mut self, _: &Query) -> ControlFlow<()> {
            self.depth += 1;
            ControlFlow::Continue(())
        }
        fn post_visit_query(&mut self, _: &Query) -> ControlFlow<()> {
            self.depth -= 1;
            ControlFlow::Continue(())
        }
        fn pre_visit_expr(&mut self, e: &Expr) -> ControlFlow<()> {
            if self.depth == 0
                && let Expr::Function(f) = e
                && f.over.is_none()
            {
                let last = f.name.0.last().map(|p| p.to_string().to_ascii_uppercase());
                if last.is_some_and(|l| AGGREGATES.contains(&l.trim_matches('`'))) {
                    self.n += 1;
                }
            }
            ControlFlow::Continue(())
        }
    }
    let mut c = Counter { depth: 0, n: 0 };
    let _ = e.visit(&mut c);
    c.n
}

/// One appearance of a relation in a statement.
#[derive(Clone, Debug, PartialEq)]
pub struct RelationOccurrence {
    /// index of this occurrence in [`StatementGraph::occurrences`]
    pub occ: u32,
    /// the scope it was found in
    pub scope: u32,
    /// the schema it was qualified with, where it was
    pub schema_name: Option<Bytes>,
    /// the relation's written name; `None` for a derived table, which has only an alias
    pub object_name: Option<Bytes>,
    /// the identity of this node. `None` where the statement gave none, in which case
    /// `object_name` is doing the work.
    pub alias: Option<Bytes>,
    /// where in the statement it sits
    pub role: RelationRole,
    /// the scope of the CTE this name resolves to, where it resolves to one. A CTE reference parses
    /// as an ordinary table, so `objects()` files one as a physical relation that does not exist.
    pub resolves_to_cte: Option<u32>,
    /// The occurrence this one refers to, where it refers to one rather than naming a relation of
    /// its own. MySQL's multi-table `DELETE o, p FROM orders o JOIN payments p` names its targets
    /// by alias and sqlparser hands that list over as `ObjectName`s, so without this an
    /// occurrence called `o` would stand for a relation that does not exist while the write on
    /// `orders` would be recorded nowhere.
    ///
    /// The mention is kept rather than dropped, because the statement wrote those words; what it
    /// points at is recorded beside it, as [`Self::resolves_to_cte`] does for a CTE reference. A
    /// caller asking which physical tables a statement touched skips an occurrence that
    /// resolves, and one asking what the statement wrote carries the role over to the referent.
    pub resolves_to_occ: Option<u32>,
    /// The row lock its scope's `FOR UPDATE` / `FOR SHARE` clauses take on this relation's rows.
    ///
    /// A clause with no `OF` locks every relation its scope reads, [`RelationRole::From`] and
    /// [`RelationRole::Join`]; `FOR UPDATE OF t` locks only the relation it names, by its
    /// identity. So in `SELECT … FROM a JOIN b … FOR UPDATE OF a` the row of `b` is a snapshot
    /// read, and `FOR SHARE OF a FOR UPDATE OF b` locks the two differently. MySQL's list form
    /// `OF a, b` is refused by this grammar, which reads one name per clause, and reaches a caller
    /// as an invalid statement.
    pub locking: LockStrength,
    /// What the clause that locks this relation does when the rows are already locked. `Wait`
    /// where [`Self::locking`] is [`LockStrength::None`].
    pub lock_wait: LockWait,
}

impl RelationOccurrence {
    /// The name a reader would collapse this occurrence *by*: its alias if it has one, else its
    /// written object name.
    ///
    /// This is the statement's own spelling and not a catalogue's. Two occurrences agreeing here
    /// are two the statement spelled the same way; whether they are one table is a different
    /// question, and nothing in a slow log answers it.
    pub fn identity(&self) -> Option<Bytes> {
        self.alias.clone().or_else(|| self.object_name.clone())
    }
}

/// An edge between two relation occurrences.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct Edge {
    /// one endpoint
    pub lhs: u32,
    /// the other endpoint
    pub rhs: u32,
    /// how they were put together
    pub op: JoinOp,
    /// what the join said about matching
    pub constraint: ConstraintKind,
    /// whether the endpoints sit in different scopes, which with [`JoinOp::Predicate`] is what a
    /// correlation is
    pub crosses_scope: bool,
}

/// Every relation a statement names, and every relationship between them that the statement wrote
/// down.
///
/// See the module header for what this holds that `objects()` does not.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct StatementGraph {
    /// the naming scopes, `scopes[0]` being the statement's own
    pub scopes: Vec<Scope>,
    /// the nodes
    pub occurrences: Vec<RelationOccurrence>,
    /// the edges
    pub edges: Vec<Edge>,
    /// every comparison the statement wrote, with its place in the boolean tree
    pub predicates: Vec<Predicate>,
    /// the index hints the author wrote, which is the only place a slow log names an index
    pub index_hints: Vec<IndexHint>,
    /// the partitions the author restricted an occurrence to
    pub partitions: Vec<Partition>,
    /// the optimizer hints the author wrote, as their own bytes
    pub optimizer_hints: Vec<OptimizerHintText>,
}

impl StatementGraph {
    /// Walks a parsed statement and returns its graph.
    pub fn of(statement: &Statement) -> Self {
        let mut b = Builder::default();
        let root = b.push_scope(None, ScopeKind::Statement, None, false);
        b.walk_statement(statement, root);
        b.resolve_references();
        b.graph
    }

    /// Nodes, edges and components of the graph as the statement wrote it: one node per
    /// occurrence.
    ///
    /// One node per occurrence is what an alias is. An alias is scoped, so the `fa` an outer query
    /// binds and the `fa` a subquery rebinds are two names and not one, the same way two locals in
    /// two functions are. Within a single scope SQL itself forbids the collision (`FROM a JOIN a`
    /// is "Not unique table/alias"), so the keying is injective by the language's own rule rather
    /// than by an assumption made here.
    ///
    /// [`Self::measures_collapsed_by_name`] is the other reading, and it belongs to a reader.
    ///
    /// An occurrence that refers to another ([`RelationOccurrence::resolves_to_occ`]) is measured
    /// as the one it refers to, under either reading: a multi-table `DELETE`'s target list names
    /// relations the statement already introduced and adds none of its own.
    pub fn measures(&self) -> GraphMeasures {
        self.measure_by(|_, occ| format!("\u{0}occ{occ}").into_bytes())
    }

    /// The same measures after collapsing every occurrence onto its written `[schema.]object`
    /// name.
    ///
    /// This is a reader's mapping and not the document's: nothing in a slow log says `sakila.film`
    /// and `film` are one relation — a catalogue says that, and this crate has never seen one. It
    /// is offered beside [`StatementGraph::measures`] rather than instead of it, so the difference
    /// between the two readings is a quantity a caller can take.
    ///
    /// A self-join becomes a loop, and a loop is an edge: `FROM employee e1 JOIN employee e2`
    /// collapses to one node carrying one edge to itself, so `m - n + c` is 1 and the cycle the
    /// collapse created is counted rather than dropped.
    pub fn measures_collapsed_by_name(&self) -> GraphMeasures {
        self.measure_by(|o, occ| match (&o.schema_name, &o.object_name) {
            (Some(s), Some(n)) => [s.as_ref(), b".", n.as_ref()].concat(),
            (None, Some(n)) => n.to_vec(),
            // A derived table has no written name, so it cannot be collapsed onto one and stays
            // itself. Merging the unnamed would be an assertion nobody made.
            _ => format!("\u{0}occ{occ}").into_bytes(),
        })
    }

    fn measure_by(&self, key_of: impl Fn(&RelationOccurrence, u32) -> Vec<u8>) -> GraphMeasures {
        // One hop and no further: a referent is a relation the statement introduced, never
        // another reference.
        let referent = |occ: u32| -> u32 {
            self.occurrences
                .get(occ as usize)
                .and_then(|o| o.resolves_to_occ)
                .filter(|r| self.occurrences.get(*r as usize).is_some())
                .unwrap_or(occ)
        };
        let key = |occ: u32| -> Vec<u8> {
            let occ = referent(occ);
            match self.occurrences.get(occ as usize) {
                Some(o) => key_of(o, occ),
                None => format!("\u{0}gone{occ}").into_bytes(),
            }
        };

        let mut nodes: Vec<Vec<u8>> = self.occurrences.iter().map(|o| key(o.occ)).collect();
        nodes.sort();
        nodes.dedup();
        let index = |k: &Vec<u8>| nodes.binary_search(k).expect("node was collected above");

        let mut simple: Vec<(usize, usize)> = self
            .edges
            .iter()
            .map(|e| {
                let (a, b) = (index(&key(e.lhs)), index(&key(e.rhs)));
                if a <= b { (a, b) } else { (b, a) }
            })
            .collect();
        simple.sort_unstable();
        simple.dedup();

        let mut parent: Vec<usize> = (0..nodes.len()).collect();
        fn find(parent: &mut [usize], mut x: usize) -> usize {
            while parent[x] != x {
                parent[x] = parent[parent[x]];
                x = parent[x];
            }
            x
        }
        for (a, b) in &simple {
            let (ra, rb) = (find(&mut parent, *a), find(&mut parent, *b));
            parent[ra] = rb;
        }
        let mut roots: Vec<usize> = (0..nodes.len()).map(|v| find(&mut parent, v)).collect();
        roots.sort_unstable();
        roots.dedup();

        let (n, m, c) = (nodes.len(), simple.len(), roots.len());
        GraphMeasures {
            nodes: n,
            edges: m,
            components: c,
            // `m - n + c` is the undirected cycle space. It cannot go negative, because a
            // component of `k` nodes carries at least `k - 1` edges; the saturating subtraction is
            // hygiene rather than a case that arises.
            cycle_space: (m + c).saturating_sub(n),
            incidences: self.edges.len(),
        }
    }

    /// Whether an occurrence sits anywhere beneath the body of a `CREATE VIEW`.
    ///
    /// A relation this is true of was named and not read. See [`ScopeKind::ViewBody`].
    pub fn in_view_body(&self, occ: u32) -> bool {
        let mut at = self.occurrences.get(occ as usize).map(|o| o.scope);
        while let Some(id) = at {
            let Some(s) = self.scopes.get(id as usize) else {
                return false;
            };
            if s.kind == ScopeKind::ViewBody {
                return true;
            }
            at = s.parent;
        }
        false
    }

    /// The deepest scope the walk reached.
    pub fn deepest(&self) -> u16 {
        self.scopes.iter().map(|s| s.depth).max().unwrap_or(0)
    }
}

/// Nodes, edges and components of a [`StatementGraph`], and the cycle space they fix.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct GraphMeasures {
    /// distinct node identities
    pub nodes: usize,
    /// distinct unordered edges. Loops are edges and are counted: under
    /// [`StatementGraph::measures_collapsed_by_name`] a self-join becomes one node carrying an
    /// edge to itself, and dropping it would hide the cycle the mapping made.
    pub edges: usize,
    /// connected components
    pub components: usize,
    /// `m - n + c`, the dimension of the undirected cycle space. Zero means the graph is a forest.
    /// A statement whose join graph is a tree reaches every relation one way; one whose graph is
    /// not reaches some relation by two routes, and the second route is a double count.
    pub cycle_space: usize,
    /// edges before deduplication, i.e. the length of [`StatementGraph::edges`]
    pub incidences: usize,
}

#[derive(Default)]
struct Builder {
    graph: StatementGraph,
    /// Which scope each subquery expression opened, keyed on its address — see
    /// [`Builder::note_subquery_scope`].
    subquery_scopes: std::collections::BTreeMap<usize, u32>,
    /// The non-recursive CTEs whose own definitions are being walked, which a name inside them
    /// does not resolve to.
    defining: Vec<u32>,
}

impl Builder {
    fn push_scope(
        &mut self,
        parent: Option<u32>,
        kind: ScopeKind,
        name: Option<Bytes>,
        recursive: bool,
    ) -> u32 {
        let id = self.graph.scopes.len() as u32;
        let depth = parent
            .and_then(|p| self.graph.scopes.get(p as usize))
            .map(|s| s.depth + 1)
            .unwrap_or(0);
        self.graph.scopes.push(Scope {
            id,
            parent,
            depth,
            kind,
            name,
            recursive,
            stages: Stages::default(),
            locking: LockStrength::None,
            lock_wait: LockWait::Wait,
        });
        id
    }

    fn push_occurrence(
        &mut self,
        scope: u32,
        name: Option<&ObjectName>,
        alias: Option<Bytes>,
        role: RelationRole,
    ) -> u32 {
        let (schema_name, object_name) = match name {
            Some(n) => split_name(n),
            None => (None, None),
        };
        // Resolved against the scopes that enclose this one, innermost first, because a CTE
        // shadows a physical table of the same name and a reader who misses that files a relation
        // the server never opened.
        let resolves_to_cte = object_name
            .as_ref()
            .filter(|_| schema_name.is_none())
            .and_then(|n| self.cte_in_scope(scope, n));
        let occ = self.graph.occurrences.len() as u32;
        self.graph.occurrences.push(RelationOccurrence {
            occ,
            scope,
            schema_name,
            object_name,
            alias,
            role,
            resolves_to_cte,
            // Filled by `resolve_references` once the whole statement has been walked: a target
            // list is written before the `FROM` it refers to, so nothing to resolve against
            // exists yet at this point.
            resolves_to_occ: None,
            // Set once the scope's query has been walked, by `lock_occurrences`.
            locking: LockStrength::None,
            lock_wait: LockWait::Wait,
        });
        occ
    }

    /// Applies one locking clause to the relations of its scope: every relation the scope reads,
    /// or the one its `OF` names. The stronger clause holds where two reach one relation.
    fn lock_occurrences(
        &mut self,
        scope: u32,
        of: Option<&ObjectName>,
        strength: LockStrength,
        wait: LockWait,
    ) {
        let named = of.map(|n| {
            let (schema, name) = split_name(n);
            name.and_then(|name| self.find_in_scope(&Qualifier { schema, name }, scope))
        });
        for o in self.graph.occurrences.iter_mut() {
            let locked = match named {
                Some(target) => target == Some(o.occ),
                None => {
                    o.scope == scope && matches!(o.role, RelationRole::From | RelationRole::Join)
                }
            };
            if locked && strength > o.locking {
                o.locking = strength;
                o.lock_wait = wait;
            }
        }
    }

    /// Resolves a target list against the relations the statement already introduced, because a
    /// multi-table `DELETE` names its targets by alias: `DELETE o, p FROM orders o JOIN payments p
    /// ON ...` writes four relation mentions and opens two tables.
    ///
    /// Matched on [`RelationOccurrence::identity`] and not on the written name, because that is
    /// the rule MySQL enforces: a relation given an alias must be referred to by that alias and
    /// may not be referred to by its table name. So `identity()` is exactly the set of names a
    /// target list is allowed to use, and matching anything else would invent a resolution the
    /// server would have rejected.
    ///
    /// Scope-local, because a target list and the `FROM` it refers to are the same statement level
    /// by the grammar: a correlated name from an enclosing scope cannot be a delete target.
    fn resolve_references(&mut self) {
        for i in 0..self.graph.occurrences.len() {
            let o = &self.graph.occurrences[i];
            if o.role != RelationRole::DeleteTarget || o.schema_name.is_some() {
                continue;
            }
            let (Some(name), scope) = (o.object_name.clone(), o.scope) else {
                continue;
            };
            let referent = self.graph.occurrences.iter().find(|c| {
                c.occ != i as u32
                    && c.scope == scope
                    && matches!(c.role, RelationRole::From | RelationRole::Join)
                    && c.identity().as_ref() == Some(&name)
            });
            if let Some(r) = referent.map(|r| r.occ) {
                self.graph.occurrences[i].resolves_to_occ = Some(r);
            }
        }
    }

    /// The CTE a name resolves to from `scope`, innermost first.
    ///
    /// Only CTEs already built are candidates, which is MySQL's own rule: a CTE may refer to the
    /// ones defined before it in the same `WITH` and not to those defined after.
    fn cte_in_scope(&self, scope: u32, name: &Bytes) -> Option<u32> {
        let mut at = Some(scope);
        while let Some(id) = at {
            let s = self.graph.scopes.get(id as usize)?;
            // A CTE is a sibling of the scope that references it, so check the scopes already
            // built under the same parent as well as the chain itself.
            if let Some(found) = self.graph.scopes.iter().find(|c| {
                c.kind == ScopeKind::Cte
                    && c.parent == Some(id)
                    && c.name.as_ref().is_some_and(|n| n == name)
                    && !self.defining.contains(&c.id)
            }) {
                return Some(found.id);
            }
            at = s.parent;
        }
        None
    }

    fn push_edge(&mut self, lhs: u32, rhs: u32, op: JoinOp, constraint: ConstraintKind) {
        if lhs == rhs {
            return;
        }
        let crosses_scope = self.graph.occurrences.get(lhs as usize).map(|o| o.scope)
            != self.graph.occurrences.get(rhs as usize).map(|o| o.scope);
        self.graph.edges.push(Edge {
            lhs,
            rhs,
            op,
            constraint,
            crosses_scope,
        });
    }

    /// Finds the occurrence a qualifier names, searching the given scope and then outwards.
    ///
    /// Innermost wins, because that is what SQL does: a correlated subquery may rebind an alias
    /// the outer query already bound to a different relation.
    fn resolve(&self, qualifier: &Qualifier, scope: u32) -> Option<u32> {
        let mut at = Some(scope);
        while let Some(id) = at {
            if let Some(o) = self.find_in_scope(qualifier, id) {
                return Some(o);
            }
            at = self.graph.scopes.get(id as usize)?.parent;
        }
        None
    }

    /// The occurrence a qualifier names inside one scope.
    ///
    /// A relation the scope reads — [`RelationRole::From`] or [`RelationRole::Join`] — is taken
    /// before a mention of the same name in a write position, because that is where a clause's
    /// columns come from. `DELETE t1 FROM t1 JOIN t2 ON t1.id = t2.id` mentions `t1` twice, and
    /// the `ON` compares the one the `FROM` reads; `INSERT INTO t SELECT t.a FROM t` shares one
    /// scope between the target and the source, and `t.a` is the source's column.
    ///
    /// An alias is matched before a written name, and a qualifier written with a schema matches no
    /// alias, since MySQL does not qualify one.
    fn find_in_scope(&self, qualifier: &Qualifier, scope: u32) -> Option<u32> {
        let names = |o: &RelationOccurrence, by_alias: bool| match (&o.alias, by_alias) {
            (Some(a), true) => qualifier.schema.is_none() && *a == qualifier.name,
            (None, false) => {
                o.object_name.as_ref() == Some(&qualifier.name)
                    && (qualifier.schema.is_none()
                        || o.schema_name.is_none()
                        || o.schema_name == qualifier.schema)
            }
            _ => false,
        };
        let reads =
            |o: &RelationOccurrence| matches!(o.role, RelationRole::From | RelationRole::Join);
        for reads_only in [true, false] {
            for by_alias in [true, false] {
                if let Some(o) =
                    self.graph.occurrences.iter().find(|o| {
                        o.scope == scope && (!reads_only || reads(o)) && names(o, by_alias)
                    })
                {
                    return Some(o.occ);
                }
            }
        }
        None
    }

    /// Files the relations an `UPDATE`'s assignments write as its targets, among the occurrences
    /// its table list introduced.
    ///
    /// Decided by the assignments and not by position: `UPDATE a JOIN b ON … SET b.x = 1` writes
    /// `b` and only reads `a`. See [`RelationRole::UpdateTarget`] for an unqualified assignment.
    fn mark_update_targets(
        &mut self,
        assignments: &[Assignment],
        scope: u32,
        listed: std::ops::Range<usize>,
    ) {
        let mut targets: Vec<usize> = Vec::new();
        let mut unattributed = false;
        for a in assignments {
            let columns: Vec<&ObjectName> = match &a.target {
                AssignmentTarget::ColumnName(n) => vec![n],
                AssignmentTarget::Tuple(ns) => ns.iter().collect(),
            };
            for n in columns {
                let parts: Vec<&Ident> = n.0.iter().filter_map(|p| p.as_ident()).collect();
                let written = qualified_column(&parts)
                    .and_then(|(q, _)| q)
                    .and_then(|q| self.find_in_scope(&q, scope))
                    .map(|o| o as usize)
                    .filter(|o| listed.contains(o));
                match written {
                    Some(o) if !targets.contains(&o) => targets.push(o),
                    Some(_) => {}
                    None => unattributed = true,
                }
            }
        }
        if unattributed {
            // A derived table and a CTE are not updatable in MySQL, so neither can own the column.
            for i in listed {
                let o = &self.graph.occurrences[i];
                if o.scope == scope
                    && o.object_name.is_some()
                    && o.resolves_to_cte.is_none()
                    && !targets.contains(&i)
                {
                    targets.push(i);
                }
            }
        }
        for t in targets {
            self.graph.occurrences[t].role = RelationRole::UpdateTarget;
        }
    }

    fn walk_statement(&mut self, statement: &Statement, scope: u32) {
        match statement {
            Statement::Query(q) => self.walk_query(q, scope),
            Statement::Insert(Insert {
                table,
                source,
                assignments,
                on,
                partitioned,
                optimizer_hints,
                ..
            }) => {
                self.push_optimizer_hints(optimizer_hints, scope);
                if let TableObject::TableName(name) = table {
                    let occ =
                        self.push_occurrence(scope, Some(name), None, RelationRole::InsertTarget);
                    // `INSERT INTO t PARTITION (p0)` restricts the write, and the restriction is
                    // a field of the statement rather than of a table factor: an insert target is
                    // a `TableObject`, so it does not pass the one site that reads a relation's
                    // partitions. A write is the statement kind the disjointness claim matters
                    // most for.
                    for e in partitioned.iter().flatten() {
                        if let Expr::Identifier(i) = e {
                            self.graph.partitions.push(Partition {
                                occ,
                                name: ident_bytes(i),
                            });
                        }
                    }
                }
                // `INSERT ... SELECT` is a write and a whole read subgraph at once, which
                // `objects()` puts in one undifferentiated set.
                if let Some(q) = source {
                    self.walk_query(q, scope);
                }
                // MySQL's `INSERT INTO t SET a = (SELECT …)` and `ON DUPLICATE KEY UPDATE
                // x = (SELECT …)` read a relation that is not the insert target, in clauses
                // nothing else here reaches.
                self.walk_expr(assignments, scope);
                if let Some(OnInsert::DuplicateKeyUpdate(assignments)) = on {
                    self.walk_expr(assignments, scope);
                }
            }
            Statement::Update(u) => {
                self.push_optimizer_hints(&u.optimizer_hints, scope);
                let (table, from, selection) = (&u.table, &u.from, &u.selection);
                // MySQL's multi-table `UPDATE a JOIN b` puts a whole join graph in the target
                // position, so this is a `TableWithJoins` and not a name, and which of its
                // relations are written is for the assignments to say.
                let first = self.graph.occurrences.len();
                let ids = self.collect_from(std::slice::from_ref(table), scope, RelationRole::From);
                let listed = first..self.graph.occurrences.len();
                self.mark_update_targets(&u.assignments, scope, listed);
                self.join_edges(std::slice::from_ref(table), scope, &ids);
                if let Some(UpdateTableFromKind::BeforeSet(f) | UpdateTableFromKind::AfterSet(f)) =
                    from
                {
                    let ids = self.collect_from(f, scope, RelationRole::From);
                    self.join_edges(f, scope, &ids);
                    self.comma_edges(&ids);
                }
                // `SET n = (SELECT … FROM other)` reads `other`. `objects()` sees it, because
                // `Assignment.value` carries the `visit_relation` annotation.
                self.walk_expr(&u.assignments, scope);
                // An `UPDATE`/`DELETE` `WHERE` is a filter stage with no `Select` at all, so
                // it is recorded here or nowhere: a scope is not one `Select`.
                if let Some(e) = selection {
                    self.graph.scopes[scope as usize].stages.filter_terms += conjuncts(e);
                }
                if let Some(e) = selection {
                    self.walk_expr(e, scope);
                    self.predicate_edges(e, scope);
                }
                // MySQL's single-table `UPDATE … ORDER BY … LIMIT`.
                self.walk_expr(&u.order_by, scope);
                self.walk_expr(&u.limit, scope);
            }
            Statement::Delete(Delete {
                tables,
                from,
                using,
                selection,
                order_by,
                limit,
                optimizer_hints,
                ..
            }) => {
                self.push_optimizer_hints(optimizer_hints, scope);
                for name in tables {
                    // Never visited by `visit_relations`: `Delete.tables` carries no
                    // `visit_relation` annotation, so MySQL's `DELETE t1, t2 FROM ...` target
                    // list is absent from `objects()` entirely.
                    self.push_occurrence(scope, Some(name), None, RelationRole::DeleteTarget);
                }
                let (FromTable::WithFromKeyword(f) | FromTable::WithoutKeyword(f)) = from;
                // `tables` is populated only by the multi-table `DELETE a, b FROM …` form.
                // With it empty the `FROM` names the relation being deleted from — whether or
                // not a `USING` clause supplies the source — so the target role is decided here
                // and nowhere else.
                let base = if tables.is_empty() {
                    RelationRole::DeleteTarget
                } else {
                    RelationRole::From
                };
                let ids = self.collect_from(f, scope, base);
                self.join_edges(f, scope, &ids);
                // Under `USING` the `FROM` is a list of the tables deleted from, and its commas
                // separate names rather than joining relations.
                if using.is_none() {
                    self.comma_edges(&ids);
                }
                if let Some(u) = using {
                    let ids = self.collect_from(u, scope, RelationRole::From);
                    self.join_edges(u, scope, &ids);
                    self.comma_edges(&ids);
                }
                // An `UPDATE`/`DELETE` `WHERE` is a filter stage with no `Select` at all, so
                // it is recorded here or nowhere: a scope is not one `Select`.
                if let Some(e) = selection {
                    self.graph.scopes[scope as usize].stages.filter_terms += conjuncts(e);
                }
                if let Some(e) = selection {
                    self.walk_expr(e, scope);
                    self.predicate_edges(e, scope);
                }
                // MySQL's single-table `DELETE … ORDER BY … LIMIT`.
                self.walk_expr(order_by, scope);
                self.walk_expr(limit, scope);
            }
            Statement::CreateView(cv) => {
                let (name, query) = (&cv.name, &cv.query);
                // `CreateView.name` carries no `visit_relation` annotation either, so the view
                // a statement brings into being is missing from `objects()` while every relation
                // in its body is present.
                self.push_occurrence(scope, Some(name), None, RelationRole::CreateTarget);
                let body = self.push_scope(Some(scope), ScopeKind::ViewBody, None, false);
                self.walk_query(query, body);
            }
            Statement::CreateTable(ct) => {
                self.push_occurrence(scope, Some(&ct.name), None, RelationRole::CreateTarget);
                // `CREATE TABLE t AS SELECT …` reads every row its query selects, as
                // `INSERT … SELECT` does, so the query is walked into the statement's own scope
                // beside the target. A view body is named and never read; this one runs.
                if let Some(q) = &ct.query {
                    self.walk_query(q, scope);
                }
            }
            // An `ALTER` and a `DROP` name a relation that already exists and take
            // `MDL_EXCLUSIVE` on it, so they block every reader of it — which a `CREATE` cannot
            // do, the table not having existed. A caller separating a DDL from a row write
            // needs these as occurrences, so they are walked here: `AlterTable.name` carries
            // `visit_relation` and so reaches `objects()`, while `Drop.names` carries none and
            // reaches nothing else. `ALTER VIEW` files the same way, redefining a relation that
            // already exists.
            Statement::AlterTable(at) => {
                self.push_occurrence(scope, Some(&at.name), None, RelationRole::AlterTarget);
            }
            Statement::AlterView { name, .. } => {
                self.push_occurrence(scope, Some(name), None, RelationRole::AlterTarget);
            }
            // An index is not a relation, and the table is what gets locked:
            // `CREATE INDEX idx ON invoice (year)` files as an alter of `invoice`. `idx` is named
            // by the statement and is not something another statement can contend for, so it gets
            // no occurrence and no role of its own.
            Statement::CreateIndex(ci) => {
                self.push_occurrence(scope, Some(&ci.table_name), None, RelationRole::AlterTarget);
            }
            Statement::Truncate(tr) => {
                for t in &tr.table_names {
                    self.push_occurrence(scope, Some(&t.name), None, RelationRole::TruncateTarget);
                }
            }
            // A rename is filed as a drop and a create, which is a claim about the names rather
            // than about the data: MySQL moves the table rather than rebuilding it, and after
            // `RENAME TABLE a TO b` nothing can open `a` while `b` is openable where it was not.
            // Both ends take `MDL_EXCLUSIVE`.
            Statement::RenameTable(renames) => {
                for r in renames {
                    self.push_occurrence(scope, Some(&r.old_name), None, RelationRole::DropTarget);
                    self.push_occurrence(
                        scope,
                        Some(&r.new_name),
                        None,
                        RelationRole::CreateTarget,
                    );
                }
            }
            // `LockTables.tables` carries no `visit_relation` annotation, so a table a client
            // locked explicitly reaches `objects()` not at all. The alias is the author's and is
            // kept as the occurrence's identity, as in a `FROM` clause: `LOCK TABLES invoice AS i
            // READ` names `i`.
            Statement::LockTables { tables } => {
                for t in tables {
                    let role = match t.lock_type {
                        LockTableType::Write { .. } => RelationRole::LockExclusiveTarget,
                        LockTableType::Read { .. } => RelationRole::LockSharedTarget,
                    };
                    let alias = t.alias.as_ref().map(ident_bytes);
                    // `LockTable.table` is an `Ident` and not an `ObjectName`, so this grammar
                    // cannot express `LOCK TABLES shop.invoice WRITE` at all: MySQL accepts that
                    // and `sqlparser` refuses it, which reaches a caller as an invalid statement.
                    // The unqualified name is lifted into an `ObjectName` of one part so it files
                    // like every other relation.
                    let name = ObjectName(vec![ObjectNamePart::Identifier(t.table.clone())]);
                    self.push_occurrence(scope, Some(&name), alias, role);
                }
            }
            // `Analyze.table_name` is an `Option`, because a dialect can write `ANALYZE` with no
            // table. MySQL cannot, so `None` names nothing and files nothing rather than being
            // unwrapped.
            Statement::Analyze(an) => {
                if let Some(name) = &an.table_name {
                    self.push_occurrence(scope, Some(name), None, RelationRole::AnalyzeTarget);
                }
            }
            Statement::Drop {
                object_type: ObjectType::Table | ObjectType::View,
                names,
                ..
            } => {
                for name in names {
                    self.push_occurrence(scope, Some(name), None, RelationRole::DropTarget);
                }
            }
            // `DROP INDEX idx ON t` alters `t` rather than dropping it, which is what MySQL does
            // with it, and it takes the same exclusive metadata lock `CREATE INDEX` does. The
            // index is named in `names` and the relation in `table`; only the relation is filed.
            Statement::Drop {
                object_type: ObjectType::Index,
                table: Some(name),
                ..
            } => {
                self.push_occurrence(scope, Some(name), None, RelationRole::AlterTarget);
            }
            // `EXPLAIN <statement>` wraps a whole statement, so it is descended into rather than
            // given a role of its own: the relations inside it take their ordinary roles, a plain
            // `EXPLAIN` plans without executing and so examines no rows, and the statement's own
            // kind already says it was an `EXPLAIN`. A role here would assert something those do
            // not. `EXPLAIN t` is a different node and is handled below.
            //
            // `OPTIMIZE`, `CHECK` and `REPAIR TABLE` and `LOAD DATA INFILE … INTO TABLE t` are
            // valid MySQL that `sqlparser` will not parse, so they never reach this walk at all
            // and arrive at a caller as invalid statements with the author's bytes intact.
            Statement::Explain { statement, .. } => self.walk_statement(statement, scope),
            // `EXPLAIN t` / `DESCRIBE t` -- a name and no statement.
            Statement::ExplainTable { table_name, .. } => {
                self.push_occurrence(scope, Some(table_name), None, RelationRole::MetadataTarget);
            }
            Statement::ShowCreate { obj_type, obj_name } => {
                // Only the two that name a relation: `SHOW CREATE FUNCTION|PROCEDURE|EVENT|
                // TRIGGER` names a routine, which is not a relation and has nowhere to go here.
                if matches!(obj_type, ShowCreateObject::Table | ShowCreateObject::View) {
                    self.push_occurrence(scope, Some(obj_name), None, RelationRole::MetadataTarget);
                }
            }
            Statement::ShowColumns { show_options, .. } => {
                // `SHOW COLUMNS FROM t` puts `t` in `show_in.parent_name`, and so does
                // `SHOW TABLES FROM db` -- where the name is a schema. The clause is what tells
                // them apart, and reading the name without it is what makes `objects()` file
                // `mysql` from `SHOW TABLES FROM mysql` as though it were a table.
                if let Some(show_in) = &show_options.show_in
                    && let Some(name) = &show_in.parent_name
                {
                    self.push_occurrence(scope, Some(name), None, RelationRole::MetadataTarget);
                }
            }
            Statement::Flush { tables, .. } => {
                for name in tables {
                    self.push_occurrence(scope, Some(name), None, RelationRole::FlushTarget);
                }
            }
            // `SET @x = (SELECT MAX(id) FROM t)` names no relation of its own and reads `t`.
            Statement::Set(set) => self.walk_expr(set, scope),
            // What is declined here, and why each is a decision rather than a gap:
            //
            // | statement | names | declined because |
            // |---|---|---|
            // | `SHOW TABLES FROM db` | a schema | not a relation, and the name sits in the same field `SHOW COLUMNS FROM t` uses |
            // | `GRANT SELECT ON db.* TO …` | a privilege scope | `db.*` is a wildcard over a schema; the statement opens no table and takes no lock on one |
            // | `REVOKE … ON db.* FROM …` | the same | the same |
            // | `CREATE`/`DROP DATABASE db` | a schema | a relation graph has nowhere to put one |
            // | `KILL`, `FLUSH` with no table list, `SAVEPOINT`, `USE` | nothing | no relation is named at all |
            //
            // The first four name something and the last names nothing, which are two different
            // reasons reaching one filing.
            _ => {}
        }
    }

    fn walk_query(&mut self, query: &Query, scope: u32) {
        if let Some(with) = &query.with {
            for Cte { alias, query, .. } in &with.cte_tables {
                // A CTE's name is an `Ident` on its alias and not an `ObjectName`, so the
                // definition site is invisible to `visit_relations` while every reference to it
                // parses as an ordinary table and is visited. That is how a name that is not a
                // relation ends up filed as one by `objects()`.
                let name = Some(ident_bytes(&alias.name));
                let cte = self.push_scope(Some(scope), ScopeKind::Cte, name, with.recursive);
                // Only `WITH RECURSIVE` puts a CTE in scope inside its own definition. Without it
                // `WITH t AS (SELECT … FROM t)` reads whatever `t` named outside: the base table,
                // or an enclosing CTE of that name.
                if !with.recursive {
                    self.defining.push(cte);
                }
                self.walk_query(query, cte);
                if !with.recursive {
                    self.defining.pop();
                }
            }
        }
        // `ORDER BY` and `LIMIT` hang off the `Query` and not off the `Select`, so they are read
        // here and filed on the scope the query heads.
        let st = &mut self.graph.scopes[scope as usize].stages;
        if let Some(o) = &query.order_by {
            match &o.kind {
                OrderByKind::Expressions(terms) => {
                    st.sort_terms += terms.len() as u32;
                    let (directions, not_mysql) = directions_of(terms);
                    st.sort_directions = directions;
                    st.not_mysql |= not_mysql;
                }
                // `ORDER BY ALL` is not MySQL.
                OrderByKind::All(_) => st.not_mysql = true,
            }
        }
        st.limit_present |= query.limit_clause.is_some();
        if let Some(limit) = &query.limit_clause {
            let (rows, offset) = limit_operands(limit);
            st.limit_rows = st.limit_rows.or(rows);
            st.limit_offset = st.limit_offset.or(offset);
        }
        for lock in &query.locks {
            let (strength, wait) = locking_of(lock);
            // A scope may carry more than one clause; the stronger claim is the one that holds.
            if strength > self.graph.scopes[scope as usize].locking {
                self.graph.scopes[scope as usize].locking = strength;
            }
            if wait != LockWait::Wait {
                self.graph.scopes[scope as usize].lock_wait = wait;
            }
        }
        self.walk_set_expr(&query.body, scope);
        // After the body, whose relations are the ones a clause locks.
        for lock in &query.locks {
            let (strength, wait) = locking_of(lock);
            self.lock_occurrences(scope, lock.of.as_ref(), strength, wait);
        }
        // `ORDER BY (SELECT …)` sorts on a relation no `FROM` names. Walked after the body so
        // the scope is the one the body established.
        self.walk_expr(&query.order_by, scope);
        self.walk_expr(&query.limit_clause, scope);
    }

    fn walk_set_expr(&mut self, body: &SetExpr, scope: u32) {
        match body {
            SetExpr::Select(s) => self.walk_select(s, scope),
            SetExpr::Query(q) => self.walk_query(q, scope),
            // MySQL has no `MERGE`, but the statement inside one names relations whatever dialect
            // wrote it, so it is walked rather than dropped: a relation missing from the graph
            // must mean the statement did not name it.
            SetExpr::Merge(s) => self.walk_statement(s, scope),
            SetExpr::SetOperation {
                left,
                right,
                op,
                set_quantifier,
            } => {
                let operator = set_operator_of(op, set_quantifier);
                for side in [left, right] {
                    let s = self.push_scope(Some(scope), ScopeKind::SetOp, None, false);
                    self.graph.scopes[s as usize].stages.set_operator = operator;
                    self.walk_set_expr(side, s);
                }
            }
            SetExpr::Insert(s) | SetExpr::Update(s) | SetExpr::Delete(s) => {
                self.walk_statement(s, scope)
            }
            // A `VALUES` row may hold a scalar subquery, which reads a relation of its own.
            SetExpr::Values(values) => {
                for row in &values.rows {
                    for e in &row.content {
                        self.walk_expr(e, scope);
                    }
                }
            }
            SetExpr::Table(_) => {}
        }
    }

    /// What this scope does to its rows, recorded rather than judged.
    ///
    /// Accumulates, because a scope is not one `Select`: `INSERT ... SELECT ... WHERE` walks its
    /// source into the same scope as the insert target, so assigning once would lose one of them.
    fn record_stages(&mut self, select: &Select, scope: u32) {
        let (mut g, mut gx, mut nm) = (0u32, 0u32, false);
        match &select.group_by {
            GroupByExpr::Expressions(terms, modifiers) => {
                g = terms.len() as u32;
                gx = terms
                    .iter()
                    .filter(|e| !matches!(e, Expr::Identifier(_) | Expr::CompoundIdentifier(_)))
                    .count() as u32;
                // `WITH ROLLUP` is MySQL's own and has been since 4.1. `CUBE`, `TOTALS` and
                // `GROUPING SETS` are other dialects', so they land on the diagnostic arm and
                // `ROLLUP` does not.
                nm |= modifiers
                    .iter()
                    .any(|m| !matches!(m, GroupByWithModifier::Rollup));
            }
            // `GROUP BY ALL` is not MySQL.
            GroupByExpr::All(_) => nm = true,
        }
        nm |= select.prewhere.is_some()
            || select.qualify.is_some()
            || select.top.is_some()
            || !select.connect_by.is_empty()
            || !select.sort_by.is_empty()
            || !select.cluster_by.is_empty()
            || !select.distribute_by.is_empty()
            || matches!(select.distinct, Some(Distinct::On(_)));

        let projection_aggregates: u32 = select
            .projection
            .iter()
            .flat_map(select_item_exprs)
            .map(aggregate_calls)
            .sum();

        let st = &mut self.graph.scopes[scope as usize].stages;
        st.filter_terms += select.selection.as_ref().map_or(0, conjuncts);
        st.group_terms += g;
        st.group_expression_terms += gx;
        st.having_terms += select.having.as_ref().map_or(0, conjuncts);
        st.having_aggregate_calls += select.having.as_ref().map_or(0, aggregate_calls);
        st.projection_aggregate_calls += projection_aggregates;
        st.distinct_present |= select.distinct.is_some();
        st.not_mysql |= nm;
    }

    /// The optimizer hints written against one scope.
    ///
    /// MySQL admits `/*+ ... */` on `SELECT`, `INSERT`, `REPLACE`, `UPDATE` and `DELETE`, and
    /// `sqlparser` carries the field on each of those nodes, so reading it on `Select` alone would
    /// answer for one statement kind of five.
    fn push_optimizer_hints(&mut self, hints: &[sqlparser::ast::OptimizerHint], scope: u32) {
        for h in hints {
            self.graph.optimizer_hints.push(OptimizerHintText {
                scope,
                text: Bytes::copy_from_slice(h.text.as_bytes()),
                prefix: Bytes::copy_from_slice(h.prefix.as_bytes()),
                line_comment: matches!(h.style, OptimizerHintStyle::SingleLine { .. }),
            });
        }
    }

    fn walk_select(&mut self, select: &Select, scope: u32) {
        self.record_stages(select, scope);
        self.push_optimizer_hints(&select.optimizer_hints, scope);
        // Two passes, and the order matters: every occurrence has to exist before any predicate
        // is resolved, because a join's `ON` clause routinely names a relation the walk has not
        // reached yet and a one-pass walk would drop that edge.
        let ids = self.collect_from(&select.from, scope, RelationRole::From);
        self.join_edges(&select.from, scope, &ids);
        self.comma_edges(&ids);

        let clauses = [
            (select.selection.as_ref(), Clause::Where),
            (select.having.as_ref(), Clause::Having),
            // `PREWHERE` and `QUALIFY` are not MySQL; `Stages::not_mysql` already records that,
            // and the split is filed under the clause it was written in either way.
            (select.prewhere.as_ref(), Clause::Where),
            (select.qualify.as_ref(), Clause::Having),
        ];
        for (expr, clause) in clauses {
            let Some(e) = expr else { continue };
            self.walk_expr(e, scope);
            let mut path = Vec::new();
            self.walk_condition(e, scope, clause, true, None, &mut path);
        }
        // Clauses that hold expressions and write no split: a subquery there still reads a
        // relation.
        self.walk_expr(&select.group_by, scope);
        self.walk_expr(&select.named_window, scope);
        // A correlated subquery can sit inside a function call inside another function call in
        // the projection, which is why the projection is walked at all.
        self.walk_expr(&select.projection, scope);
        for item in &select.projection {
            for e in select_item_exprs(item) {
                let mut path = Vec::new();
                self.walk_condition(e, scope, Clause::Projection, true, None, &mut path);
            }
        }
    }

    /// Pass one: every relation occurrence in a `FROM` list, in written order.
    /// `base` is the role the first relation of each `FROM` item takes. It is a parameter and
    /// not a constant because the same syntactic position means different things per statement:
    /// a `SELECT`'s is read, an `UPDATE`'s is written, and a single-table `DELETE`'s is deleted.
    fn collect_from(
        &mut self,
        from: &[TableWithJoins],
        scope: u32,
        base: RelationRole,
    ) -> Vec<Vec<u32>> {
        from.iter()
            .map(|twj| {
                let mut ids = vec![self.walk_table_factor(&twj.relation, scope, base)];
                for j in &twj.joins {
                    ids.push(self.walk_table_factor(&j.relation, scope, RelationRole::Join));
                }
                ids
            })
            .collect()
    }

    /// Pass two: the edges, read out of the join predicates rather than out of the order.
    ///
    /// `TableWithJoins.joins` is a flat left-deep chain and not a tree, so joining each relation
    /// to its predecessor would draw a branching join as a chain — one relation joined to two
    /// others reads as two links in a row. The branch exists only in the `ON` clauses, so that is
    /// where it is read from, and the chain is the fallback for a join that says nothing this walk
    /// can resolve.
    fn join_edges(&mut self, from: &[TableWithJoins], scope: u32, ids: &[Vec<u32>]) {
        for (twj, ids) in from.iter().zip(ids) {
            for (i, j) in twj.joins.iter().enumerate() {
                let rhs = ids[i + 1];
                let (op, constraint) = classify(&j.join_operator);
                let named = match constraint_expr(&j.join_operator) {
                    Some(e) => self.resolved_qualifiers(e, scope),
                    None => Vec::new(),
                };
                // The `ON` condition's splits, with no edges: the pair is drawn below from the
                // `FROM` structure, so walking for edges here would draw each one twice. Its
                // subqueries are walked first, so a split comparing against one names its scope.
                if let Some(e) = constraint_expr(&j.join_operator) {
                    self.walk_expr(e, scope);
                    let mut path = Vec::new();
                    self.walk_condition(e, scope, Clause::On, false, Some(rhs), &mut path);
                }
                // A `USING (i, j)` list is a relationship per named column. MySQL matches the
                // same column name on both sides, so each name is an equality whose two sides are
                // the two relations the join brought together -- the same fact an `ON` writes as
                // an expression, which is why `clause` is what separates them and not the shape of
                // the row. `NATURAL` names no column and writes none: which columns it matched is
                // a fact about the catalogue and not about the statement.
                if let Some(cols) = constraint_using(&j.join_operator) {
                    for n in cols {
                        let Some(column) = split_name(n).1 else {
                            continue;
                        };
                        self.push_predicate_sides(
                            scope,
                            Clause::JoinUsing,
                            &[],
                            PredicateOp::Eq,
                            Side {
                                occ: Some(ids[i]),
                                column: Some(column.clone()),
                            },
                            Side {
                                occ: Some(rhs),
                                column: Some(column),
                            },
                            RhsKind::Column,
                            None,
                            Some(rhs),
                        );
                    }
                }
                let mut drawn = false;
                for lhs in named.into_iter().filter(|o| *o != rhs) {
                    self.push_edge(lhs, rhs, op, constraint);
                    drawn = true;
                }
                if !drawn {
                    self.push_edge(ids[i], rhs, op, constraint);
                }
            }
        }
    }

    /// The commas of a `FROM` list: a cross join between whole `TableWithJoins`, drawn between
    /// the first relations of each rather than inside one.
    ///
    /// Apart from [`Builder::join_edges`] because not every list joins: a `DELETE … USING`
    /// target list names the tables deleted from.
    fn comma_edges(&mut self, ids: &[Vec<u32>]) {
        for pair in ids.windows(2) {
            if let (Some(a), Some(b)) = (pair[0].first(), pair[1].first()) {
                self.push_edge(*a, *b, JoinOp::Comma, ConstraintKind::None);
            }
        }
    }

    fn walk_table_factor(&mut self, tf: &TableFactor, scope: u32, role: RelationRole) -> u32 {
        match tf {
            TableFactor::Table {
                name,
                alias,
                index_hints,
                partitions,
                ..
            } => {
                let a = alias.as_ref().map(|a| ident_bytes(&a.name));
                let occ = self.push_occurrence(scope, Some(name), a, role);
                for p in partitions {
                    self.graph.partitions.push(Partition {
                        occ,
                        name: ident_bytes(p),
                    });
                }
                for h in index_hints {
                    self.graph.index_hints.push(IndexHint {
                        occ,
                        kind: match h.hint_type {
                            TableIndexHintType::Use => IndexHintKind::Use,
                            TableIndexHintType::Force => IndexHintKind::Force,
                            TableIndexHintType::Ignore => IndexHintKind::Ignore,
                        },
                        scope: match h.for_clause {
                            None => IndexHintScope::Any,
                            Some(TableIndexHintForClause::Join) => IndexHintScope::Join,
                            Some(TableIndexHintForClause::OrderBy) => IndexHintScope::OrderBy,
                            Some(TableIndexHintForClause::GroupBy) => IndexHintScope::GroupBy,
                        },
                        names: h.index_names.iter().map(ident_bytes).collect(),
                        spelled_key: matches!(h.index_type, TableIndexType::Key),
                    });
                }
                occ
            }
            TableFactor::Derived {
                subquery, alias, ..
            } => {
                // A derived table is a node in the outer scope with no object name at all, and
                // `visit_relations` cannot see it: `TableFactor::Derived` carries no `ObjectName`,
                // so only the base tables inside its subquery are visited and the thing the rest
                // of the query joins to is absent from `objects()`.
                let a = alias.as_ref().map(|a| ident_bytes(&a.name));
                let occ = self.push_occurrence(scope, None, a, role);
                let inner = self.push_scope(Some(scope), ScopeKind::Derived, None, false);
                self.walk_query(subquery, inner);
                occ
            }
            // `(a JOIN b ON …)` groups relations and is not one: it adds no node, its first
            // relation takes the role the group holds, and it stands for the group wherever the
            // enclosing join needs one relation — the right side a split names as its join, and
            // the fallback end of an edge.
            TableFactor::NestedJoin {
                table_with_joins,
                alias,
            } => {
                // MySQL gives a parenthesised join no alias, so one is the diagnostic arm.
                if alias.is_some() {
                    self.graph.scopes[scope as usize].stages.not_mysql = true;
                }
                let group = std::slice::from_ref(table_with_joins.as_ref());
                let ids = self.collect_from(group, scope, role);
                self.join_edges(group, scope, &ids);
                ids[0][0]
            }
            TableFactor::Function {
                name, alias, args, ..
            } => {
                // Also unannotated, so also absent from `objects()`.
                let a = alias.as_ref().map(|a| ident_bytes(&a.name));
                let occ = self.push_occurrence(scope, Some(name), a, role);
                self.walk_expr(args, scope);
                occ
            }
            // `PIVOT`, `UNPIVOT` and `MATCH_RECOGNIZE` are other dialects'; MySQL writes
            // conditional aggregation instead. Each wraps a base table, so the relation is kept --
            // dropping it would leave the statement naming nothing and make the occurrence
            // indistinguishable from a derived table -- and the scope lands on the diagnostic arm,
            // which is what says the grammar built a tree the server could not have run.
            TableFactor::Pivot { table, .. }
            | TableFactor::Unpivot { table, .. }
            | TableFactor::MatchRecognize { table, .. } => {
                self.graph.scopes[scope as usize].stages.not_mysql = true;
                self.walk_table_factor(table, scope, role)
            }
            // `JSON_TABLE(expr, …)` and the other table functions: a relation with no written
            // name, whose argument may itself be a subquery.
            other => {
                let a = table_factor_alias(other);
                let occ = self.push_occurrence(scope, None, a, role);
                self.walk_expr(other, scope);
                occ
            }
        }
    }

    /// Walks every subquery a node holds in expression position, each into a scope of its own
    /// under `scope`.
    ///
    /// Found by `sqlparser`'s own expression visitor rather than by naming the `Expr` forms that
    /// can hold one, so no form hides a subquery: `SUBSTRING((SELECT …), 1)`,
    /// `INTERVAL (SELECT …) DAY` and a window's `ORDER BY` are reached by the rule that reaches
    /// `WHERE x IN (SELECT …)`. A subquery nested inside another is left for the inner one's walk,
    /// which reaches it from that scope.
    fn walk_expr(&mut self, node: &impl Visit, scope: u32) {
        struct Finder<'b> {
            builder: &'b mut Builder,
            scope: u32,
            depth: usize,
        }
        impl Visitor for Finder<'_> {
            type Break = ();
            fn pre_visit_query(&mut self, _: &Query) -> ControlFlow<()> {
                self.depth += 1;
                ControlFlow::Continue(())
            }
            fn post_visit_query(&mut self, _: &Query) -> ControlFlow<()> {
                self.depth -= 1;
                ControlFlow::Continue(())
            }
            // On the way out, so the operand of `(SELECT …) IN (SELECT …)` opens its scope
            // before the subquery it is compared with, in written order.
            fn post_visit_expr(&mut self, expr: &Expr) -> ControlFlow<()> {
                if self.depth == 0
                    && let Expr::Subquery(q)
                    | Expr::Exists { subquery: q, .. }
                    | Expr::InSubquery { subquery: q, .. } = expr
                {
                    let inner =
                        self.builder
                            .push_scope(Some(self.scope), ScopeKind::Subquery, None, false);
                    self.builder.note_subquery_scope(expr, inner);
                    self.builder.walk_query(q, inner);
                }
                ControlFlow::Continue(())
            }
        }
        let _ = node.visit(&mut Finder {
            builder: self,
            scope,
            depth: 0,
        });
    }

    /// Draws edges between the occurrences a predicate names on either side of a comparison.
    ///
    /// A connective is not a comparison, and treating one as a comparison manufactures edges:
    /// read `a.x = b.x AND c.y = d.y` as one operator with two sides and the qualifiers on each
    /// side cross-multiply into four edges, of which `a–d` and `c–b` were never written down. Only
    /// the comparison arms carry an edge; `AND`, `OR` and `XOR` are descended through and
    /// contribute none of their own.
    fn predicate_edges(&mut self, expr: &Expr, scope: u32) {
        let mut path = Vec::new();
        self.walk_condition(expr, scope, Clause::Where, true, None, &mut path);
    }

    /// Walks one condition, emitting the edges it draws and the splits it writes.
    ///
    /// One walk and not two: the edges and the predicates are the same recursion over the same
    /// boolean tree, and separating them would be two lists that must agree with nothing making
    /// them agree.
    ///
    /// `emit_edges` is false for a join's `ON`, whose pair is already drawn from the `FROM`
    /// structure by [`Builder::join_edges`]. The splits are still recorded, so a disjunctive join
    /// naming a third relation reaches the predicates even though it draws no edge.
    fn walk_condition(
        &mut self,
        expr: &Expr,
        scope: u32,
        clause: Clause,
        emit_edges: bool,
        join_occ: Option<u32>,
        path: &mut Vec<PathStep>,
    ) {
        use sqlparser::ast::BinaryOperator as B;
        match expr {
            Expr::BinaryOp {
                left,
                right,
                op: b @ (B::And | B::Or | B::Xor),
            } => {
                let connective = match b {
                    B::Or => Connective::Or,
                    B::Xor => Connective::Xor,
                    _ => Connective::And,
                };
                path.push(PathStep {
                    connective,
                    branch: 0,
                });
                self.walk_condition(left, scope, clause, emit_edges, join_occ, path);
                if let Some(last) = path.last_mut() {
                    last.branch = 1;
                }
                self.walk_condition(right, scope, clause, emit_edges, join_occ, path);
                path.pop();
            }
            // Only a comparison relates two relations. `a.x + b.y` computes a value from both
            // and says nothing about which rows of one go with which of the other.
            Expr::BinaryOp { left, right, op: b } => {
                let Some(pop) = comparison_op(b) else {
                    return;
                };
                if emit_edges {
                    let (l, r) = (
                        self.resolved_qualifiers(left, scope),
                        self.resolved_qualifiers(right, scope),
                    );
                    // A comparison MySQL has no operator for is not filed as one it has.
                    let op = match pop {
                        PredicateOp::NotMySql => JoinOp::NotMySql,
                        _ => JoinOp::Predicate,
                    };
                    for a in &l {
                        for b in &r {
                            if a != b {
                                self.push_edge(*a, *b, op, ConstraintKind::None);
                            }
                        }
                    }
                }
                let rhs_scope = self.subquery_scope_of(right, scope);
                let (rhs_kind, pop) = match rhs_scope {
                    Some(_) => (RhsKind::Subquery, PredicateOp::Scalar),
                    None => (rhs_kind_of(right), pop),
                };
                self.push_predicate(
                    scope, clause, path, pop, left, right, rhs_kind, rhs_scope, join_occ,
                );
            }
            Expr::UnaryOp {
                op: sqlparser::ast::UnaryOperator::Not,
                expr: e,
            } => {
                path.push(PathStep {
                    connective: Connective::Not,
                    branch: 0,
                });
                self.walk_condition(e, scope, clause, emit_edges, join_occ, path);
                path.pop();
            }
            Expr::Nested(e) | Expr::UnaryOp { expr: e, .. } => {
                self.walk_condition(e, scope, clause, emit_edges, join_occ, path)
            }
            Expr::IsNull(e) => {
                self.push_predicate(
                    scope,
                    clause,
                    path,
                    PredicateOp::IsNull,
                    e,
                    e,
                    RhsKind::None,
                    None,
                    join_occ,
                );
            }
            Expr::IsNotNull(e) => {
                self.push_predicate(
                    scope,
                    clause,
                    path,
                    PredicateOp::IsNotNull,
                    e,
                    e,
                    RhsKind::None,
                    None,
                    join_occ,
                );
            }
            Expr::InList {
                expr: e, negated, ..
            } => {
                let pop = if *negated {
                    PredicateOp::NotInList
                } else {
                    PredicateOp::InList
                };
                self.push_predicate(
                    scope,
                    clause,
                    path,
                    pop,
                    e,
                    e,
                    RhsKind::Literal,
                    None,
                    join_occ,
                );
            }
            Expr::Between {
                expr: e, negated, ..
            } => {
                let pop = if *negated {
                    PredicateOp::NotBetween
                } else {
                    PredicateOp::Between
                };
                self.push_predicate(
                    scope,
                    clause,
                    path,
                    pop,
                    e,
                    e,
                    RhsKind::Literal,
                    None,
                    join_occ,
                );
            }
            // `ILIKE` is PostgreSQL's; MySQL's `LIKE` is collation-insensitive already, so there
            // is no MySQL text that produces one and it lands on the diagnostic arm.
            Expr::ILike { expr: e, .. } | Expr::SimilarTo { expr: e, .. } => {
                self.push_predicate(
                    scope,
                    clause,
                    path,
                    PredicateOp::NotMySql,
                    e,
                    e,
                    RhsKind::Literal,
                    None,
                    join_occ,
                );
            }
            Expr::Like {
                expr: e, negated, ..
            } => {
                let pop = if *negated {
                    PredicateOp::NotLike
                } else {
                    PredicateOp::Like
                };
                self.push_predicate(
                    scope,
                    clause,
                    path,
                    pop,
                    e,
                    e,
                    RhsKind::Literal,
                    None,
                    join_occ,
                );
            }
            // MySQL's regex predicate. It is a filter on a column like any other, and it can
            // use no index at all.
            Expr::RLike {
                expr: e, negated, ..
            } => {
                let pop = if *negated {
                    PredicateOp::NotRegexp
                } else {
                    PredicateOp::Regexp
                };
                self.push_predicate(
                    scope,
                    clause,
                    path,
                    pop,
                    e,
                    e,
                    RhsKind::Literal,
                    None,
                    join_occ,
                );
            }
            // `MATCH (a, b) AGAINST ('x')` searches a `FULLTEXT` index and nothing else, so the
            // columns it names are the ones the index covers. Filed against the first, which is
            // the one an unqualified reading would resolve.
            Expr::MatchAgainst { columns, .. } => {
                if let Some(first) = columns.first() {
                    let parts: Vec<&Ident> = first.0.iter().filter_map(|p| p.as_ident()).collect();
                    let lhs = match qualified_column(&parts) {
                        Some((qualifier, column)) => Side {
                            occ: qualifier.and_then(|q| self.resolve(&q, scope)),
                            column: Some(column),
                        },
                        None => Side::default(),
                    };
                    self.push_predicate_sides(
                        scope,
                        clause,
                        path,
                        PredicateOp::MatchAgainst,
                        lhs,
                        Side::default(),
                        RhsKind::Literal,
                        None,
                        join_occ,
                    );
                }
            }
            Expr::InSubquery {
                expr: e, negated, ..
            } => {
                let rhs_scope = self.subquery_scope_of(expr, scope);
                let pop = if *negated {
                    PredicateOp::NotInSubquery
                } else {
                    PredicateOp::InSubquery
                };
                self.push_predicate(
                    scope,
                    clause,
                    path,
                    pop,
                    e,
                    e,
                    RhsKind::Subquery,
                    rhs_scope,
                    join_occ,
                );
            }
            Expr::Exists { negated, .. } => {
                let rhs_scope = self.subquery_scope_of(expr, scope);
                let pop = if *negated {
                    PredicateOp::NotExists
                } else {
                    PredicateOp::Exists
                };
                self.push_predicate_sides(
                    scope,
                    clause,
                    path,
                    pop,
                    Side::default(),
                    Side::default(),
                    RhsKind::Subquery,
                    rhs_scope,
                    join_occ,
                );
            }
            Expr::AnyOp { left, right, .. } | Expr::AllOp { left, right, .. } => {
                let pop = if matches!(expr, Expr::AnyOp { .. }) {
                    PredicateOp::Any
                } else {
                    PredicateOp::All
                };
                // The subquery is the right operand, so the scope is looked up against that and
                // not against the comparison holding it.
                let rhs_scope = self.subquery_scope_of(right, scope);
                self.push_predicate(
                    scope,
                    clause,
                    path,
                    pop,
                    left,
                    left,
                    RhsKind::Subquery,
                    rhs_scope,
                    join_occ,
                );
            }
            _ => {}
        }
    }

    /// Files one split, resolving each side's written qualifier to an occurrence.
    #[allow(clippy::too_many_arguments)]
    fn push_predicate(
        &mut self,
        scope: u32,
        clause: Clause,
        path: &[PathStep],
        op: PredicateOp,
        left: &Expr,
        right: &Expr,
        rhs_kind: RhsKind,
        rhs_scope: Option<u32>,
        join_occ: Option<u32>,
    ) {
        let lhs = self.side_of(left, scope);
        let rhs = if std::ptr::eq(left, right) {
            Side::default()
        } else {
            self.side_of(right, scope)
        };
        self.push_predicate_sides(
            scope, clause, path, op, lhs, rhs, rhs_kind, rhs_scope, join_occ,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn push_predicate_sides(
        &mut self,
        scope: u32,
        clause: Clause,
        path: &[PathStep],
        op: PredicateOp,
        lhs: Side,
        rhs: Side,
        rhs_kind: RhsKind,
        rhs_scope: Option<u32>,
        join_occ: Option<u32>,
    ) {
        self.graph.predicates.push(Predicate {
            scope,
            clause,
            path: path.to_vec(),
            op,
            lhs,
            rhs,
            rhs_kind,
            rhs_scope,
            join_occ,
        });
    }

    /// The column one side names, with its qualifier resolved where it wrote one.
    ///
    /// An unqualified column leaves `occ` empty rather than guessing: a caller holding the whole
    /// statement can fall back to its sole relation, and this walk cannot.
    fn side_of(&self, expr: &Expr, scope: u32) -> Side {
        match column_ref(expr) {
            Some((qualifier, column)) => Side {
                occ: qualifier.and_then(|q| self.resolve(&q, scope)),
                column: Some(column),
            },
            None => Side::default(),
        }
    }

    /// Remembers which scope one subquery expression opened.
    ///
    /// Keyed on the expression's address, which is stable because the whole walk borrows one
    /// `Statement`. A positional rule — "the last subquery scope under this parent" — is wrong
    /// the moment a scope holds two of them, and `WHERE a IN (…) AND b IN (…)` is ordinary.
    fn note_subquery_scope(&mut self, expr: &Expr, inner: u32) {
        self.subquery_scopes
            .insert(std::ptr::from_ref(expr) as usize, inner);
    }

    /// The scope a subquery on this side was walked into, where there is one.
    ///
    /// Parentheses are looked through: `x = ((SELECT …))` compares against the subquery, whose
    /// scope is keyed on the subquery node and not on the parentheses around it.
    fn subquery_scope_of(&self, expr: &Expr, _scope: u32) -> Option<u32> {
        let mut expr = expr;
        while let Expr::Nested(inner) = expr {
            expr = inner;
        }
        self.subquery_scopes
            .get(&(std::ptr::from_ref(expr) as usize))
            .copied()
    }

    /// The occurrences named by the qualifiers of every `alias.column` in an expression.
    ///
    /// Does not descend into a nested subquery: a qualifier written inside one is resolved in that
    /// subquery's own scope when the walk reaches it, and pulling it up here would draw the
    /// correlation twice.
    fn resolved_qualifiers(&self, expr: &Expr, scope: u32) -> Vec<u32> {
        let mut out = Vec::new();
        collect_qualifiers(expr, &mut |q| {
            if let Some(occ) = self.resolve(&q, scope)
                && !out.contains(&occ)
            {
                out.push(occ);
            }
        });
        out
    }
}

/// The comparison a binary operator makes, or `None` where it is arithmetic rather than a split.
///
/// `Expr::BinaryOp` covers `+` as well as `=`, so taking every binary operator would file a
/// computation as a row the statement went for. Three answers rather than two: the comparison,
/// `None` for an operator MySQL has that compares nothing, and the diagnostic arm for one MySQL
/// does not have at all. A foreign comparison producing no row would be a silence where the
/// grammar built a tree the server could not have run.
///
/// The `None` list is MySQL's own operator set and not `sqlparser`'s naming of it, which is why
/// `PGBitwiseShiftLeft` and `PGBitwiseShiftRight` are in it: those are MySQL's `<<` and `>>`.
/// The catch-all therefore answers the diagnostic arm, so an operator a later `sqlparser` adds
/// is visible rather than silently absent.
fn comparison_op(op: &sqlparser::ast::BinaryOperator) -> Option<PredicateOp> {
    use sqlparser::ast::BinaryOperator as B;
    Some(match op {
        B::Eq => PredicateOp::Eq,
        B::NotEq => PredicateOp::Ne,
        B::Lt => PredicateOp::Lt,
        B::LtEq => PredicateOp::Le,
        B::Gt => PredicateOp::Gt,
        B::GtEq => PredicateOp::Ge,
        B::Spaceship => PredicateOp::NullSafeEq,
        // MySQL's own, and none of them compares: arithmetic, `DIV`, the bitwise set, the JSON
        // extractors, `:=`, which assigns a user variable, and the connectives, which are read
        // as boolean structure elsewhere.
        B::Plus
        | B::Minus
        | B::Multiply
        | B::Divide
        | B::Modulo
        | B::MyIntegerDivide
        | B::StringConcat
        | B::BitwiseOr
        | B::BitwiseAnd
        | B::BitwiseXor
        | B::PGBitwiseShiftLeft
        | B::PGBitwiseShiftRight
        | B::Arrow
        | B::LongArrow
        | B::Assignment
        | B::And
        | B::Or
        | B::Xor => return None,
        _ => PredicateOp::NotMySql,
    })
}

/// What kind of thing one side of a split is.
fn rhs_kind_of(expr: &Expr) -> RhsKind {
    match expr {
        Expr::Identifier(_) | Expr::CompoundIdentifier(_) => RhsKind::Column,
        Expr::Value(_) => RhsKind::Literal,
        Expr::Subquery(_) | Expr::InSubquery { .. } | Expr::Exists { .. } => RhsKind::Subquery,
        Expr::Tuple(_) => RhsKind::RowConstructor,
        Expr::Nested(inner) => rhs_kind_of(inner),
        _ => RhsKind::Expression,
    }
}

/// The relation a column reference names, as the author wrote it.
struct Qualifier {
    /// the schema the relation was qualified with, where it was
    schema: Option<Bytes>,
    /// the relation's alias or written name
    name: Bytes,
}

/// The `(qualifier, column)` a dotted name writes: `c`, `t.c` or `db.t.c`.
///
/// The last part is the column and the one before it the relation, so `schema.table.column`
/// resolves on `table` — the rule MySQL itself enforces, since a relation given an alias may not
/// be referred to by its name. Every reading of a column reference goes through here, so the side
/// of a split and the edge it draws cannot disagree about which relation a qualifier names.
fn qualified_column(parts: &[&Ident]) -> Option<(Option<Qualifier>, Bytes)> {
    let (column, rest) = parts.split_last()?;
    let qualifier = rest.split_last().map(|(name, rest)| Qualifier {
        schema: rest.last().map(|s| ident_bytes(s)),
        name: ident_bytes(name),
    });
    Some((qualifier, ident_bytes(column)))
}

/// The `(qualifier, column)` a side names, where it names one. See [`qualified_column`].
fn column_ref(expr: &Expr) -> Option<(Option<Qualifier>, Bytes)> {
    match expr {
        Expr::Identifier(i) => qualified_column(&[i]),
        Expr::CompoundIdentifier(parts) => qualified_column(&parts.iter().collect::<Vec<_>>()),
        Expr::Nested(inner) => column_ref(inner),
        _ => None,
    }
}

/// The directions an `ORDER BY` wrote, with an unwritten one reading as ascending, and whether it
/// wrote a construct MySQL has no syntax for.
fn directions_of(terms: &[sqlparser::ast::OrderByExpr]) -> (SortDirections, bool) {
    use sqlparser::ast::OrderBySort as S;
    let mut asc = false;
    let mut desc = false;
    let mut not_mysql = false;
    for t in terms {
        // `ORDER BY x` is ascending; MySQL has no way to leave it undecided. `USING <op>` is
        // PostgreSQL's, and MySQL has no `NULLS FIRST` / `NULLS LAST` — it sorts NULLs first
        // ascending and last descending, with no way to say otherwise.
        match t.options.sort {
            Some(S::Desc) => desc = true,
            Some(S::Using(_)) => not_mysql = true,
            _ => asc = true,
        }
        not_mysql |= t.options.nulls_first.is_some();
    }
    let directions = match (asc, desc) {
        (true, true) => SortDirections::Mixed,
        (false, true) => SortDirections::Desc,
        (true, false) => SortDirections::Asc,
        (false, false) => SortDirections::NotApplicable,
    };
    (directions, not_mysql)
}

/// The `(rows, offset)` a `LIMIT` wrote, where it wrote literal ones.
///
/// A placeholder leaves the operand `None`, which is a measured absence: the author wrote a limit
/// and the value is not in the document.
fn limit_operands(limit: &sqlparser::ast::LimitClause) -> (Option<u64>, Option<u64>) {
    use sqlparser::ast::LimitClause as L;
    let literal = |e: &Expr| -> Option<u64> {
        match e {
            Expr::Value(v) => match &v.value {
                sqlparser::ast::Value::Number(n, _) => n.parse().ok(),
                _ => None,
            },
            _ => None,
        }
    };
    match limit {
        L::LimitOffset { limit, offset, .. } => (
            limit.as_ref().and_then(literal),
            offset.as_ref().and_then(|o| literal(&o.value)),
        ),
        // MySQL's `LIMIT offset, rows`.
        L::OffsetCommaLimit { offset, limit } => (literal(limit), literal(offset)),
    }
}

/// Which set operation an arm heads.
fn set_operator_of(
    op: &sqlparser::ast::SetOperator,
    quantifier: &sqlparser::ast::SetQuantifier,
) -> SetOperator {
    use sqlparser::ast::SetOperator as O;
    use sqlparser::ast::SetQuantifier as Q;
    let all = matches!(quantifier, Q::All | Q::AllByName);
    match op {
        O::Union if all => SetOperator::UnionAll,
        O::Union => SetOperator::Union,
        O::Intersect if all => SetOperator::IntersectAll,
        O::Intersect => SetOperator::Intersect,
        O::Except if all => SetOperator::ExceptAll,
        O::Except => SetOperator::Except,
        // `MINUS` is Oracle's. It means what `EXCEPT` means and MySQL has no such keyword, so
        // filing it as `except` would put a statement the server could not have run on a MySQL
        // arm -- the defect the landing arms exist to stop.
        O::Minus => SetOperator::NotMySql,
    }
}

fn collect_qualifiers(expr: &Expr, f: &mut impl FnMut(Qualifier)) {
    match expr {
        Expr::CompoundIdentifier(_) => {
            if let Some((Some(q), _)) = column_ref(expr) {
                f(q);
            }
        }
        Expr::BinaryOp { left, right, .. } => {
            collect_qualifiers(left, f);
            collect_qualifiers(right, f);
        }
        Expr::UnaryOp { expr, .. }
        | Expr::Nested(expr)
        | Expr::Cast { expr, .. }
        | Expr::Collate { expr, .. } => collect_qualifiers(expr, f),
        Expr::Function(fun) => {
            for e in function_arg_exprs(fun) {
                collect_qualifiers(e, f);
            }
        }
        _ => {}
    }
}

fn function_arg_exprs(f: &sqlparser::ast::Function) -> Vec<&Expr> {
    use sqlparser::ast::{FunctionArg, FunctionArgExpr, FunctionArguments};
    let mut out = Vec::new();
    if let FunctionArguments::List(list) = &f.args {
        for a in &list.args {
            let e = match a {
                FunctionArg::Named { arg, .. }
                | FunctionArg::ExprNamed { arg, .. }
                | FunctionArg::Unnamed(arg) => arg,
            };
            if let FunctionArgExpr::Expr(e) = e {
                out.push(e);
            }
        }
    }
    out
}

fn select_item_exprs(item: &sqlparser::ast::SelectItem) -> Vec<&Expr> {
    use sqlparser::ast::SelectItem;
    match item {
        SelectItem::UnnamedExpr(e) => vec![e],
        SelectItem::ExprWithAlias { expr, .. } => vec![expr],
        _ => Vec::new(),
    }
}

fn table_factor_alias(tf: &TableFactor) -> Option<Bytes> {
    let a = match tf {
        TableFactor::TableFunction { alias, .. }
        | TableFactor::UNNEST { alias, .. }
        | TableFactor::JsonTable { alias, .. }
        | TableFactor::OpenJsonTable { alias, .. }
        | TableFactor::Pivot { alias, .. }
        | TableFactor::Unpivot { alias, .. }
        | TableFactor::MatchRecognize { alias, .. }
        | TableFactor::XmlTable { alias, .. } => alias,
        _ => &None,
    };
    a.as_ref().map(|a| ident_bytes(&a.name))
}

fn classify(op: &JoinOperator) -> (JoinOp, ConstraintKind) {
    use JoinOperator as J;
    let kind = |c: &JoinConstraint| match c {
        JoinConstraint::On(_) => ConstraintKind::On,
        JoinConstraint::Using(_) => ConstraintKind::Using,
        JoinConstraint::Natural => ConstraintKind::Natural,
        JoinConstraint::None => ConstraintKind::None,
    };
    match op {
        J::Join(c) | J::Inner(c) => (JoinOp::Inner, kind(c)),
        J::Left(c) | J::LeftOuter(c) => (JoinOp::Left, kind(c)),
        J::Right(c) | J::RightOuter(c) => (JoinOp::Right, kind(c)),
        J::StraightJoin(c) => (JoinOp::Straight, kind(c)),
        // `CrossJoin` carries a constraint, and MySQL allows one: `CROSS JOIN`, `INNER JOIN` and
        // `JOIN` are synonyms there and all three accept an `ON` clause, so a cross join that
        // writes one files it rather than being forced to `none`.
        J::CrossJoin(c) => (JoinOp::Cross, kind(c)),
        // MySQL has no syntax for any of these. See [`JoinOp::NotMySql`].
        J::FullOuter(c)
        | J::Semi(c)
        | J::LeftSemi(c)
        | J::RightSemi(c)
        | J::Anti(c)
        | J::LeftAnti(c)
        | J::RightAnti(c) => (JoinOp::NotMySql, kind(c)),
        J::AsOf { constraint, .. } => (JoinOp::NotMySql, kind(constraint)),
        // Another dialect's operators, `ARRAY JOIN` among them. They land on the one arm without
        // anyone deciding anything, which is the argument for having a landing arm rather than
        // naming every dialect's operators: upstream's enum can grow and this crate's vocabulary
        // does not.
        J::CrossApply | J::OuterApply | J::ArrayJoin | J::LeftArrayJoin | J::InnerArrayJoin => {
            (JoinOp::NotMySql, ConstraintKind::None)
        }
    }
}

fn constraint_expr(op: &JoinOperator) -> Option<&Expr> {
    match join_constraint(op) {
        Some(JoinConstraint::On(e)) => Some(e),
        _ => None,
    }
}

/// The columns a `USING` list names, where the join wrote one.
fn constraint_using(op: &JoinOperator) -> Option<&Vec<ObjectName>> {
    match join_constraint(op) {
        Some(JoinConstraint::Using(cols)) => Some(cols),
        _ => None,
    }
}

fn join_constraint(op: &JoinOperator) -> Option<&JoinConstraint> {
    use JoinOperator as J;
    let c = match op {
        J::Join(c)
        | J::Inner(c)
        | J::Left(c)
        | J::LeftOuter(c)
        | J::Right(c)
        | J::RightOuter(c)
        | J::FullOuter(c)
        | J::Semi(c)
        | J::LeftSemi(c)
        | J::RightSemi(c)
        | J::Anti(c)
        | J::LeftAnti(c)
        | J::RightAnti(c)
        | J::StraightJoin(c)
        | J::AsOf { constraint: c, .. } => c,
        J::CrossJoin(c) => c,
        J::CrossApply | J::OuterApply | J::ArrayJoin | J::LeftArrayJoin | J::InnerArrayJoin => {
            return None;
        }
    };
    Some(c)
}

fn ident_bytes(i: &Ident) -> Bytes {
    Bytes::from(i.value.clone())
}

fn split_name(n: &ObjectName) -> (Option<Bytes>, Option<Bytes>) {
    let parts: Vec<Bytes> =
        n.0.iter()
            .filter_map(|p| match p {
                ObjectNamePart::Identifier(i) => Some(ident_bytes(i)),
                // `ObjectNamePart::Function` is for dialects that let a function produce an
                // identifier. MySQL has no such syntax, so a part of that shape names no relation
                // this crate can file, and it is dropped rather than turned into a name invented
                // out of a call.
                ObjectNamePart::Function(_) => None,
            })
            .collect();
    match parts.len() {
        0 => (None, None),
        1 => (None, Some(parts[0].clone())),
        // Three parts is `catalog.schema.object`: the catalogue is dropped and the last two kept,
        // which is the reading `objects()` takes.
        _ => (
            Some(parts[parts.len() - 2].clone()),
            Some(parts[parts.len() - 1].clone()),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlparser::ast::{visit_expressions, visit_relations};
    use sqlparser::dialect::MySqlDialect;
    use sqlparser::parser::Parser;

    fn graph(sql: &str) -> StatementGraph {
        StatementGraph::of(&one(sql))
    }

    /// The stages of the statement's own scope.
    fn st(sql: &str) -> Stages {
        graph(sql).scopes[0].stages
    }

    /// Every split a statement wrote, as `(clause, path, op)`.
    fn splits(sql: &str) -> Vec<(Clause, String, PredicateOp)> {
        graph(sql)
            .predicates
            .iter()
            .map(|p| (p.clause, render_path(&p.path), p.op))
            .collect()
    }

    fn render_path(path: &[PathStep]) -> String {
        path.iter()
            .map(|s| {
                let c = match s.connective {
                    Connective::And => "and",
                    Connective::Or => "or",
                    Connective::Xor => "xor",
                    Connective::Not => "not",
                };
                format!("{c}[{}]", s.branch)
            })
            .collect::<Vec<_>>()
            .join("/")
    }

    /// A disjunction is one condition and two splits.
    ///
    /// `Stages::filter_terms` counts `AND` conjuncts and must stay 1, because the author wrote one
    /// condition; the splits beneath it are what the boolean path carries.
    #[test]
    fn a_disjunction_is_one_condition_and_two_splits() {
        let sql = "SELECT a FROM t WHERE x = 1 OR y = 2";
        assert_eq!(st(sql).filter_terms, 1, "one condition");

        let s = splits(sql);
        assert_eq!(s.len(), 2, "two splits");
        assert_eq!(s[0], (Clause::Where, "or[0]".into(), PredicateOp::Eq));
        assert_eq!(s[1], (Clause::Where, "or[1]".into(), PredicateOp::Eq));
    }

    /// The path separates a conjunct inside a disjunction from one outside it, which is what
    /// decides whether a split can act as an index condition on its own.
    #[test]
    fn the_path_says_which_splits_share_a_disjunction() {
        let s = splits("SELECT a FROM t WHERE z = 9 AND (x = 1 OR y = 2)");
        let paths: Vec<&str> = s.iter().map(|(_, p, _)| p.as_str()).collect();
        assert_eq!(paths, ["and[0]", "and[1]/or[0]", "and[1]/or[1]"]);

        let disjunctive = |p: &str| p.contains("or[");
        assert!(!disjunctive(paths[0]), "z = 9 stands alone");
        assert!(disjunctive(paths[1]) && disjunctive(paths[2]));
    }

    /// The clause is recorded, because on an outer join `ON p` and `WHERE p` are different
    /// queries and nothing else in the record separates them.
    #[test]
    fn a_join_condition_and_a_filter_are_the_same_object_in_different_clauses() {
        let on = splits("SELECT a FROM t LEFT JOIN u ON u.x = 1");
        let wh = splits("SELECT a FROM t LEFT JOIN u ON t.i = u.i WHERE u.x = 1");
        assert_eq!(on[0].0, Clause::On);
        assert_eq!(wh.iter().filter(|(c, ..)| *c == Clause::Where).count(), 1);
        assert_eq!(wh.iter().filter(|(c, ..)| *c == Clause::On).count(), 1);
    }

    /// The operator, which decides the shape of the region a statement went for.
    #[test]
    fn the_comparison_operator_is_recorded_and_arithmetic_is_not() {
        let ops: Vec<PredicateOp> =
            splits("SELECT a FROM t WHERE a = 1 AND b > 2 AND c BETWEEN 3 AND 4 AND d IN (5, 6)")
                .into_iter()
                .map(|(_, _, o)| o)
                .collect();
        assert_eq!(
            ops,
            [
                PredicateOp::Eq,
                PredicateOp::Gt,
                PredicateOp::Between,
                PredicateOp::InList
            ]
        );

        // `Expr::BinaryOp` covers `+` as well as `=`, and a computation is not a split. The
        // projection is walked for the correlated subqueries it can hide, so this is where an
        // arithmetic expression arrives at the top of a branch and must file nothing.
        assert!(
            splits("SELECT qty - 1 FROM t").is_empty(),
            "arithmetic is not a split"
        );

        // And a comparison is a leaf: it does not descend into its own operands, so an
        // expression on one side is part of the split rather than another one.
        let over = splits("SELECT a FROM t WHERE qty - 1 = 5");
        assert_eq!(over.len(), 1, "one split, not one per operator");
        assert_eq!(over[0].2, PredicateOp::Eq);
    }

    /// A subquery is an operand of a split, so the walk descends through it.
    #[test]
    fn a_subquery_is_an_operand_and_carries_its_own_splits() {
        let g = graph("SELECT a FROM t WHERE t.x IN (SELECT u.y FROM u WHERE u.z = 1 OR u.z = 2)");

        let outer = g
            .predicates
            .iter()
            .find(|p| p.op == PredicateOp::InSubquery)
            .expect("the IN is a split");
        assert_eq!(outer.rhs_kind, RhsKind::Subquery);
        let inner_scope = outer.rhs_scope.expect("and it names the scope it opened");

        let inner: Vec<&Predicate> = g
            .predicates
            .iter()
            .filter(|p| p.scope == inner_scope)
            .collect();
        assert_eq!(inner.len(), 2, "the subquery's own disjunction");
        assert!(
            inner.iter().all(|p| p.path[0].connective == Connective::Or),
            "and they share it"
        );
        assert_ne!(outer.scope, inner_scope, "two levels, not one");
    }

    /// A statement that names a relation and takes a metadata lock on it files both facts.
    ///
    /// The role is the lock, and the two are opposite: `SHOW`/`EXPLAIN` take a **shared** one and
    /// `FLUSH TABLES` an **exclusive** one. Folding them into a single "administrative" arm would
    /// fuse the two least alike events in MySQL's locking behaviour.
    #[test]
    fn a_metadata_statement_names_the_relation_and_the_lock_it_takes() {
        for (sql, want) in [
            ("SHOW CREATE TABLE ledger", RelationRole::MetadataTarget),
            ("SHOW COLUMNS FROM ledger", RelationRole::MetadataTarget),
            ("EXPLAIN ledger", RelationRole::MetadataTarget),
            ("DESCRIBE ledger", RelationRole::MetadataTarget),
            ("FLUSH TABLES ledger", RelationRole::FlushTarget),
        ] {
            let g = graph(sql);
            let got: Vec<(RelationRole, String)> = g
                .occurrences
                .iter()
                .map(|o| {
                    (
                        o.role,
                        String::from_utf8_lossy(o.object_name.as_deref().unwrap_or(b""))
                            .into_owned(),
                    )
                })
                .collect();
            assert_eq!(got, vec![(want, "ledger".to_string())], "{sql}");
        }
    }

    /// `SHOW TABLES FROM db` names a **schema**, and the walk declines it.
    ///
    /// The name sits in the same `show_in.parent_name` that `SHOW COLUMNS FROM t` uses, so a rule
    /// reading the field without its clause files a schema as a relation — which is exactly the
    /// one exception `objects()` has to carry.
    #[test]
    fn show_tables_names_a_schema_and_is_not_a_relation() {
        assert!(graph("SHOW TABLES FROM shop").occurrences.is_empty());
        assert_eq!(graph("SHOW COLUMNS FROM shop").occurrences.len(), 1);
    }

    /// `EXPLAIN <statement>` is descended into, so the statement it wraps reaches the graph: its
    /// relation, its split and its scope.
    #[test]
    fn explain_descends_into_the_statement_it_wraps() {
        let g = graph("EXPLAIN SELECT id FROM ledger WHERE id = 5");
        let named: Vec<String> = g
            .occurrences
            .iter()
            .filter_map(|o| o.object_name.as_deref())
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .collect();
        assert_eq!(named, vec!["ledger".to_string()]);
        // The ordinary role, not one of its own: `EXPLAIN` does not execute, `rows_examined`
        // is the measured zero that says so, and `sql_type` already names the form. A role here
        // would be this walk asserting something those three do not.
        assert_eq!(g.occurrences[0].role, RelationRole::From);
        assert_eq!(g.predicates.len(), 1, "the split is recovered too");
    }

    /// A split written in a join clause names the join, which `clause` alone cannot.
    ///
    /// With two joins in one statement, `clause = On` says both sat in a join clause and nothing
    /// says which — so the operator above each one is unreachable, and an outer join's `ON` reads
    /// like an inner join's.
    #[test]
    fn a_split_names_the_join_it_sits_under() {
        let g = graph(
            "SELECT p.id FROM pallet p \
             JOIN crate q ON p.id = q.pallet_id AND q.grade = 'B' \
             LEFT JOIN depot d ON p.depot_id = d.id AND d.region = 'north'",
        );
        let joins: Vec<Option<u32>> = g
            .predicates
            .iter()
            .filter(|p| p.clause == Clause::On)
            .map(|p| p.join_occ)
            .collect();
        assert_eq!(joins.len(), 4, "two splits in each of two join clauses");
        let distinct: std::collections::BTreeSet<Option<u32>> = joins.iter().copied().collect();
        assert_eq!(
            distinct.len(),
            2,
            "the two clauses name two joins: {joins:?}"
        );
        assert!(joins.iter().all(|j| j.is_some()));
        // And a `WHERE` names none, which is the other half of the two-sided claim.
        let g2 = graph("SELECT id FROM t WHERE id = 1");
        assert!(g2.predicates.iter().all(|p| p.join_occ.is_none()));
    }

    /// A negated comparison is a different operator, not the same one with the `NOT` dropped.
    ///
    /// The region a negation selects is the complement of the region the positive form selects, so
    /// `NOT BETWEEN` filed as `Between` would describe a range it excludes. The enum names the
    /// negation for the subquery forms too.
    #[test]
    fn a_negated_comparison_is_not_the_comparison() {
        let cases = [
            (
                "SELECT a FROM t WHERE a BETWEEN 1 AND 9",
                PredicateOp::Between,
            ),
            (
                "SELECT a FROM t WHERE a NOT BETWEEN 1 AND 9",
                PredicateOp::NotBetween,
            ),
            ("SELECT a FROM t WHERE a IN (1, 2)", PredicateOp::InList),
            (
                "SELECT a FROM t WHERE a NOT IN (1, 2)",
                PredicateOp::NotInList,
            ),
            ("SELECT a FROM t WHERE a LIKE 'x%'", PredicateOp::Like),
            (
                "SELECT a FROM t WHERE a NOT LIKE 'x%'",
                PredicateOp::NotLike,
            ),
            ("SELECT a FROM t WHERE a IS NULL", PredicateOp::IsNull),
            (
                "SELECT a FROM t WHERE a IS NOT NULL",
                PredicateOp::IsNotNull,
            ),
            ("SELECT a FROM t WHERE a REGEXP '^x'", PredicateOp::Regexp),
            (
                "SELECT a FROM t WHERE a NOT REGEXP '^x'",
                PredicateOp::NotRegexp,
            ),
            ("SELECT a FROM t WHERE a RLIKE '^x'", PredicateOp::Regexp),
            (
                "SELECT a FROM t WHERE MATCH(a) AGAINST ('x')",
                PredicateOp::MatchAgainst,
            ),
        ];
        for (sql, want) in cases {
            let ops: Vec<PredicateOp> = splits(sql).into_iter().map(|(_, _, o)| o).collect();
            assert_eq!(ops, vec![want], "{sql}");
        }
        // `MATCH (a, b) AGAINST (…)` names several columns and files one split, against the first.
        let g = graph("SELECT a FROM t WHERE MATCH(a, b) AGAINST ('x')");
        assert_eq!(g.predicates.len(), 1);
        assert_eq!(g.predicates[0].op, PredicateOp::MatchAgainst);
    }

    /// A construct this grammar accepts and MySQL cannot write lands in a diagnostic arm.
    ///
    /// `NULLS FIRST` is not MySQL, which sorts NULLs first ascending and last descending with no
    /// way to say otherwise. It is a tree the server could not have run, so the artifact says so
    /// rather than filing it as ordinary.
    #[test]
    fn a_clause_mysql_cannot_write_is_marked_and_not_filed_as_ordinary() {
        assert!(!st("SELECT id FROM t ORDER BY a DESC").not_mysql);
        assert!(st("SELECT id FROM t ORDER BY a ASC NULLS FIRST").not_mysql);
        assert!(st("SELECT id FROM t ORDER BY a NULLS LAST").not_mysql);
    }

    /// A partition restriction divides the relation, and the division is a partition rather than a
    /// cover.
    ///
    /// Every row of a partitioned table is in exactly one partition, so the parts are disjoint and
    /// they cover the whole. A partitioned table also carries a local index per partition, so a
    /// restriction here decides which index trees exist to be walked — and two statements
    /// restricted to disjoint partitions touch no page in common whatever else they share.
    #[test]
    fn a_partition_restriction_divides_the_relation() {
        let g = graph("SELECT id FROM t PARTITION (p0, p1) WHERE x = 1");
        assert_eq!(g.partitions.len(), 2);
        assert_eq!(g.partitions[0].occ, 0);
        assert_eq!(g.partitions[0].name, Bytes::from_static(b"p0"));
        assert_eq!(g.partitions[1].name, Bytes::from_static(b"p1"));

        // One row per name rather than a list on the occurrence, so a reader asking which
        // statements restricted to a given partition joins rather than splitting a string.
        let g =
            graph("SELECT a.id FROM t PARTITION (p0) a JOIN u PARTITION (q1, q2) b ON a.id = b.id");
        assert_eq!(g.partitions.len(), 3);
        assert_eq!(g.partitions[0].occ, 0);
        assert_eq!(g.partitions[1].occ, 1);
        assert_eq!(g.partitions[2].occ, 1);

        // An unrestricted occurrence files nothing, which is a written absence and not a blank:
        // the author named no partition, so every one is in play.
        assert!(graph("SELECT id FROM t WHERE x = 1").partitions.is_empty());

        // THE WRITES, and `INSERT` is the one that does not route through a table factor at all:
        // its target is a `TableObject` and its restriction a field of the statement, so the site
        // reading a table factor's partitions does not see it. A write is the statement kind the
        // disjointness reading matters most for -- two writers on disjoint partitions cannot
        // contend, and a reader that could not see the restriction would pair them.
        for sql in [
            "INSERT INTO t PARTITION (p0) VALUES (1)",
            "UPDATE t PARTITION (p0) SET a = 1",
            "DELETE FROM t PARTITION (p0) WHERE x = 1",
        ] {
            let g = graph(sql);
            assert_eq!(g.partitions.len(), 1, "{sql}: no partition read");
            assert_eq!(g.partitions[0].name, Bytes::from_static(b"p0"), "{sql}");
            assert_eq!(
                g.partitions[0].occ, g.occurrences[0].occ,
                "{sql}: the restriction belongs to the relation it was written on"
            );
        }
    }

    /// An optimizer hint is carried as the author's own bytes and deliberately not decomposed.
    ///
    /// `NO_ICP`, `NO_MRR`, `INDEX_MERGE` and `BKA` name index access methods outright, which makes
    /// them the same family as an index hint. But `sqlparser` hands the whole comment body over as
    /// raw text without separating the hints inside it, so naming each hint, its target table and
    /// its target index would be this walk lexing where everything else parses — the judgement
    /// already made about `SHOW INDEX FROM t`.
    #[test]
    fn an_optimizer_hint_is_carried_as_the_authors_bytes() {
        let g = graph("SELECT /*+ NO_ICP(t idx) NO_MRR(t) */ id FROM t WHERE x = 1");
        // One row per COMMENT and not per hint: the grammar does not separate the hints inside the
        // body, so two hints in one comment are one row and its text holds both.
        assert_eq!(g.optimizer_hints.len(), 1);
        assert_eq!(g.optimizer_hints[0].scope, 0);
        // Verbatim, including the whitespace the author wrote around the body. Trimming would be
        // this walk editing the author's bytes, which is the one thing `sql_raw` exists to refuse.
        assert_eq!(
            g.optimizer_hints[0].text,
            Bytes::from_static(b" NO_ICP(t idx) NO_MRR(t) ")
        );
        assert!(!g.optimizer_hints[0].line_comment);
        assert!(g.optimizer_hints[0].prefix.is_empty());

        // A hint written in a nested scope is filed against that scope: the optimiser applies it
        // to the block it was written in, and the statement's own scope is 0.
        let g = graph("SELECT id FROM t WHERE x IN (SELECT /*+ BKA(u) */ y FROM u)");
        assert_eq!(g.optimizer_hints.len(), 1);
        assert!(g.optimizer_hints[0].scope > 0);

        assert!(
            graph("SELECT id FROM t WHERE x = 1")
                .optimizer_hints
                .is_empty()
        );

        // Every statement kind MySQL admits a hint on, not just `SELECT`.
        for sql in [
            "SELECT /*+ NO_ICP(t idx) */ id FROM t WHERE x = 1",
            "UPDATE /*+ NO_ICP(t idx) */ t SET a = 1 WHERE x = 1",
            "DELETE /*+ NO_ICP(t idx) */ FROM t WHERE x = 1",
            "INSERT /*+ NO_ICP(t idx) */ INTO t (a) VALUES (1)",
            "REPLACE /*+ NO_ICP(t idx) */ INTO t (a) VALUES (1)",
        ] {
            let g = graph(sql);
            assert_eq!(g.optimizer_hints.len(), 1, "{sql}: no hint read");
            assert_eq!(
                g.optimizer_hints[0].text,
                Bytes::from_static(b" NO_ICP(t idx) "),
                "{sql}"
            );
        }
    }

    /// An index hint is the author naming an index, filed against the occurrence it was written on.
    ///
    /// The only construct in a slow log that names an index at all. Several hints may sit on one
    /// relation, and the `FOR` clause says which part of the statement each applies to.
    #[test]
    fn an_index_hint_names_the_occurrence_it_was_written_on() {
        let g = graph("SELECT id FROM t a USE INDEX (i1) WHERE a.x = 1");
        assert_eq!(g.index_hints.len(), 1);
        let h = &g.index_hints[0];
        assert_eq!(h.occ, 0);
        assert_eq!(h.kind, IndexHintKind::Use);
        assert_eq!(h.scope, IndexHintScope::Any);
        assert_eq!(h.names, vec![Bytes::from_static(b"i1")]);
        assert!(!h.spelled_key);

        // The three kinds and the three `FOR` clauses, each a different claim on the optimiser.
        for (sql, kind, scope) in [
            (
                "SELECT id FROM t a FORCE INDEX FOR ORDER BY (i1)",
                IndexHintKind::Force,
                IndexHintScope::OrderBy,
            ),
            (
                "SELECT id FROM t a IGNORE INDEX FOR JOIN (i1)",
                IndexHintKind::Ignore,
                IndexHintScope::Join,
            ),
            (
                "SELECT id FROM t a USE KEY FOR GROUP BY (i1)",
                IndexHintKind::Use,
                IndexHintScope::GroupBy,
            ),
        ] {
            let g = graph(sql);
            assert_eq!(g.index_hints[0].kind, kind, "{sql}");
            assert_eq!(g.index_hints[0].scope, scope, "{sql}");
        }
        assert!(graph("SELECT id FROM t a USE KEY FOR GROUP BY (i1)").index_hints[0].spelled_key);

        // Each hint travels with its own relation, which is what makes `occ` the key.
        let g = graph("SELECT id FROM a USE INDEX (ia) JOIN b FORCE INDEX (ib) ON a.i = b.i");
        let pairs: Vec<(u32, IndexHintKind)> =
            g.index_hints.iter().map(|h| (h.occ, h.kind)).collect();
        assert_eq!(
            pairs,
            vec![(0, IndexHintKind::Use), (1, IndexHintKind::Force)]
        );

        // And a statement naming no index files none, which is a measured zero.
        assert!(graph("SELECT id FROM t WHERE x = 1").index_hints.is_empty());
    }

    /// A single-table `DELETE` names its target in the `FROM`, and the role says it was written.
    ///
    /// `Delete.tables` is populated only by the multi-table form, so reading the target from
    /// there alone files the ordinary `DELETE FROM t` as a read of `t`.
    #[test]
    fn a_delete_names_the_relation_it_deletes_from() {
        for sql in [
            "DELETE FROM invoice WHERE id = 1",
            "DELETE FROM invoice",
            "DELETE FROM invoice USING invoice JOIN line ON line.iid = invoice.id",
        ] {
            let g = graph(sql);
            assert_eq!(g.occurrences[0].role, RelationRole::DeleteTarget, "{sql}");
        }
        // The multi-table form still names its targets by alias and its sources in the `FROM`.
        let g = graph("DELETE o, p FROM orders o JOIN payments p ON p.oid = o.id");
        let roles: Vec<RelationRole> = g.occurrences.iter().map(|o| o.role).collect();
        assert_eq!(
            roles,
            vec![
                RelationRole::DeleteTarget,
                RelationRole::DeleteTarget,
                RelationRole::From,
                RelationRole::Join,
            ]
        );
    }

    /// The expression positions that can hold a subquery are walked, so the relation it reads and
    /// the splits it writes reach the graph.
    ///
    /// Each of these is visited by `objects()`, so leaving it out makes the two readings of one
    /// statement disagree about a relation it names.
    #[test]
    fn a_subquery_outside_a_clause_the_walk_knows_still_names_its_relation() {
        for sql in [
            "UPDATE invoice SET n = (SELECT MAX(x) FROM ledger WHERE ledger.z = 3)",
            "INSERT INTO invoice (id) VALUES ((SELECT MAX(id) FROM ledger WHERE ledger.z = 3))",
            "INSERT INTO invoice (id) VALUES (1) ON DUPLICATE KEY UPDATE \
             id = (SELECT MAX(id) FROM ledger WHERE ledger.z = 3)",
            "SELECT id FROM invoice ORDER BY (SELECT MAX(x) FROM ledger WHERE ledger.z = 3)",
        ] {
            let g = graph(sql);
            let named: Vec<&[u8]> = g
                .occurrences
                .iter()
                .filter_map(|o| o.object_name.as_deref())
                .collect();
            assert!(named.contains(&&b"ledger"[..]), "{sql}: {named:?}");
            assert_eq!(g.predicates.len(), 1, "{sql}");
        }
    }

    /// A `FOR UPDATE` or `FOR SHARE` is filed on the scope that wrote it and on no other.
    ///
    /// MySQL locks the tables of the block the clause sits in, so a subquery under a locking
    /// outer select is not itself locking.
    #[test]
    fn a_locking_read_says_which_lock_it_took_and_where() {
        let cases = [
            ("SELECT id FROM t", LockStrength::None, LockWait::Wait),
            (
                "SELECT id FROM t FOR SHARE",
                LockStrength::Shared,
                LockWait::Wait,
            ),
            (
                "SELECT id FROM t FOR UPDATE",
                LockStrength::Exclusive,
                LockWait::Wait,
            ),
            (
                "SELECT id FROM t FOR UPDATE NOWAIT",
                LockStrength::Exclusive,
                LockWait::NoWait,
            ),
            (
                "SELECT id FROM t FOR UPDATE SKIP LOCKED",
                LockStrength::Exclusive,
                LockWait::SkipLocked,
            ),
        ];
        for (sql, strength, wait) in cases {
            let g = graph(sql);
            assert_eq!(g.scopes[0].locking, strength, "{sql}");
            assert_eq!(g.scopes[0].lock_wait, wait, "{sql}");
        }
        let g = graph("SELECT id FROM t WHERE id IN (SELECT id FROM u) FOR UPDATE");
        assert_eq!(g.scopes[0].locking, LockStrength::Exclusive);
        assert_eq!(g.scopes[1].locking, LockStrength::None, "the subquery");
    }

    /// A quantified comparison holds its subquery on the right, and the walk descends into it.
    ///
    /// Without the descent the relation the subquery reads reaches no artifact at all, and the
    /// split naming it carries a subquery operand with no scope — the row contradicting itself.
    #[test]
    fn a_quantified_comparison_descends_into_its_subquery() {
        for sql in [
            "SELECT p.id FROM pallet p WHERE p.weight > ANY (SELECT c.weight FROM crate c)",
            "SELECT p.id FROM pallet p WHERE p.weight > ALL (SELECT c.weight FROM crate c)",
        ] {
            let g = graph(sql);
            let named: Vec<String> = g
                .occurrences
                .iter()
                .filter_map(|o| o.object_name.as_ref())
                .map(|b| String::from_utf8_lossy(b.as_ref()).into_owned())
                .collect();
            assert!(named.contains(&"crate".to_string()), "{sql}: {named:?}");

            let p = g
                .predicates
                .iter()
                .find(|p| matches!(p.op, PredicateOp::Any | PredicateOp::All))
                .expect("the quantified comparison is a split");
            assert_eq!(p.rhs_kind, RhsKind::Subquery);
            assert!(
                p.rhs_scope.is_some(),
                "{sql}: a subquery operand with no scope is a row contradicting itself"
            );
        }
    }

    /// Two subqueries in one scope point at two scopes.
    ///
    /// A positional rule — "the last subquery scope under this parent" — gives both splits the
    /// same scope, and `WHERE a IN (…) AND b IN (…)` is ordinary. The mapping is by expression
    /// identity instead.
    #[test]
    fn two_subqueries_in_one_scope_are_two_operands() {
        let g = graph(
            "SELECT a FROM t WHERE t.x IN (SELECT u.y FROM u) AND t.z IN (SELECT v.w FROM v)",
        );
        let scopes: Vec<Option<u32>> = g
            .predicates
            .iter()
            .filter(|p| p.op == PredicateOp::InSubquery)
            .map(|p| p.rhs_scope)
            .collect();

        assert_eq!(scopes.len(), 2, "two splits");
        assert!(scopes.iter().all(Option::is_some), "each names a scope");
        assert_ne!(scopes[0], scopes[1], "and they are not the same scope");

        // And each points at a scope that really is a subquery of this statement.
        for s in scopes.into_iter().flatten() {
            let sc = &g.scopes[s as usize];
            assert_eq!(sc.kind, ScopeKind::Subquery);
            assert_eq!(sc.parent, Some(0));
        }
    }

    /// Both sides occupied is a relationship; one side is a filter.
    #[test]
    fn a_split_with_two_sides_is_the_join_the_statement_wrote() {
        let g = graph("SELECT a FROM t JOIN u ON t.i = u.j WHERE t.x = 1");
        let join = g
            .predicates
            .iter()
            .find(|p| p.clause == Clause::On)
            .unwrap();
        assert!(join.lhs.occ.is_some() && join.rhs.occ.is_some());
        assert_eq!(join.lhs.column.as_deref(), Some(&b"i"[..]));
        assert_eq!(join.rhs.column.as_deref(), Some(&b"j"[..]));

        let filter = g
            .predicates
            .iter()
            .find(|p| p.clause == Clause::Where)
            .unwrap();
        assert!(filter.lhs.occ.is_some() && filter.rhs.occ.is_none());
    }

    /// A STATEMENT IS A PIPELINE AND THE SCOPE TREE IS ITS SKELETON.
    ///
    /// Each scope may filter, then group, then filter the groups, then order, then cut.
    #[test]
    fn a_scope_records_what_it_does_to_its_rows() {
        let a = st(
            "SELECT a FROM t WHERE x = 1 AND y = 2 GROUP BY a HAVING COUNT(*) > 3 ORDER BY a LIMIT 5",
        );
        assert_eq!(a.filter_terms, 2, "top-level AND conjuncts");
        assert_eq!(a.group_terms, 1);
        assert_eq!(a.having_terms, 1);
        assert_eq!(a.having_aggregate_calls, 1);
        assert_eq!(a.sort_terms, 1);
        assert!(a.limit_present);
        assert!(!a.distinct_present);
        assert!(!a.not_mysql);

        // A MEASURED ZERO. The parse looked and there was no filter, which is a different
        // claim from a scope that has no query at all.
        let b = st("SELECT a FROM t");
        assert_eq!((b.filter_terms, b.group_terms, b.having_terms), (0, 0, 0));
    }

    /// `AND` ONLY. `a = 1 OR b = 2` is ONE condition on two columns; splitting it would say
    /// the author wrote two row-reducing terms where they wrote a disjunction.
    #[test]
    fn a_disjunction_is_one_filter_term_and_not_two() {
        assert_eq!(st("SELECT a FROM t WHERE x = 1 OR y = 2").filter_terms, 1);
        assert_eq!(
            st("SELECT a FROM t WHERE (x = 1 AND y = 2) AND z = 3").filter_terms,
            3
        );
    }

    /// IMPLICIT GROUPING, which `group_terms` alone calls no grouping at all.
    ///
    /// `SELECT COUNT(*) FROM t` has no `GROUP BY` and one group — the whole result. A reading
    /// that looked only at `group_terms` would say there is no grouping stage where there is one.
    #[test]
    fn an_aggregate_with_no_group_by_is_still_a_grouping_stage() {
        let a = st("SELECT COUNT(*) FROM t");
        assert_eq!((a.group_terms, a.projection_aggregate_calls), (0, 1));
        let b = st("SELECT a, COUNT(*) FROM t GROUP BY a");
        assert_eq!((b.group_terms, b.projection_aggregate_calls), (1, 1));
        // And a function that is not an aggregate is not one. The list is MySQL's built-ins
        // and a UDF is not on it, so this count is a LOWER BOUND and is stated as one.
        assert_eq!(st("SELECT UPPER(a) FROM t").projection_aggregate_calls, 0);
    }

    /// A `GROUP BY` ON AN EXPRESSION is counted and NOT judged. *"An expression forces a
    /// temporary table"* is a claim about the server; this is a claim about the text.
    #[test]
    fn a_grouping_on_an_expression_is_counted_and_not_judged() {
        let a = st("SELECT YEAR(d), COUNT(*) FROM t GROUP BY YEAR(d)");
        assert_eq!((a.group_terms, a.group_expression_terms), (1, 1));
        let b = st("SELECT a, COUNT(*) FROM t GROUP BY t.a");
        assert_eq!(
            (b.group_terms, b.group_expression_terms),
            (1, 0),
            "a qualified column is a column"
        );
    }

    /// A SCOPE IS NOT ONE `Select`, SO THE STAGES ACCUMULATE.
    ///
    /// `INSERT ... SELECT ... WHERE` walks its source into the **same** scope as the insert
    /// target, and an `UPDATE`/`DELETE` `WHERE` has no `Select` at all. Assigning once rather
    /// than accumulating would lose whichever arrived second.
    #[test]
    fn a_scope_is_not_one_select_so_the_stages_accumulate() {
        assert_eq!(
            st("UPDATE t SET a = 1 WHERE x = 2 AND y = 3").filter_terms,
            2
        );
        assert_eq!(st("DELETE FROM t WHERE x = 2").filter_terms, 1);
        // The insert target and the source select share one scope, so one filter lands there.
        assert_eq!(
            st("INSERT INTO t (a) SELECT b FROM u WHERE x = 1").filter_terms,
            1
        );
    }

    /// ONE LANDING ARM FOR WHAT MYSQL HAS NO SYNTAX FOR, exactly as [`JoinOp::NotMySql`].
    ///
    /// `MySqlDialect` gates very little, so `sqlparser` will build `QUALIFY`, `DISTINCT ON`,
    /// Hive's `SORT BY` and the rest out of text MySQL cannot run. Naming each would put
    /// impossible cases in front of every caller; one diagnostic arm does not.
    #[test]
    fn a_construct_mysql_cannot_write_lands_on_one_arm() {
        for sql in [
            "SELECT DISTINCT ON (a) a FROM t",
            "SELECT a FROM t QUALIFY ROW_NUMBER() OVER () = 1",
            "SELECT a FROM t SORT BY a",
            "SELECT a FROM t CLUSTER BY a",
            "SELECT a, COUNT(*) FROM t GROUP BY a WITH CUBE",
            "SELECT * FROM t PIVOT (SUM(a) FOR b IN ('x'))",
            "SELECT * FROM t UNPIVOT (a FOR b IN (c))",
        ] {
            let g = StatementGraph::of(&one(sql));
            assert!(
                g.scopes[0].stages.not_mysql,
                "{sql} should land on the diagnostic arm"
            );
        }
        // And the relation is kept even where the construct is not MySQL's. Dropping it would
        // leave the occurrence nameless and indistinguishable from a derived table, so the
        // statement would name nothing at all.
        for sql in [
            "SELECT * FROM t PIVOT (SUM(a) FOR b IN ('x'))",
            "SELECT * FROM t UNPIVOT (a FOR b IN (c))",
        ] {
            let g = StatementGraph::of(&one(sql));
            assert_eq!(
                g.occurrences
                    .iter()
                    .filter_map(|o| o.object_name.as_deref())
                    .collect::<Vec<_>>(),
                vec![b"t".as_slice()],
                "{sql}: the base relation is the author's and survives the regime"
            );
        }
        // And ordinary MySQL never does.
        for sql in [
            "SELECT DISTINCT a FROM t",
            "SELECT a FROM t GROUP BY a HAVING COUNT(*) > 1 ORDER BY a LIMIT 2",
            // `WITH ROLLUP` is the pair that makes the two halves discriminate: the grammar
            // hands every group-by modifier over the same way, and exactly one of them is MySQL.
            "SELECT a, COUNT(*) FROM t GROUP BY a WITH ROLLUP",
        ] {
            assert!(!st(sql).not_mysql, "{sql} is ordinary MySQL");
        }
    }

    /// EVERY ARM OF [`JoinOp`], WITH THE TEXT THAT REACHES IT.
    ///
    /// The arms split two ways:
    ///
    /// - **seven** are ordinary MySQL.
    /// - the rest are other dialects' — `FULL OUTER JOIN`, `SEMI`/`ANTI JOIN`, `CROSS`/`OUTER
    ///   APPLY` and `ASOF JOIN`, which `MySqlDialect` accepts because `sqlparser`'s parser is
    ///   largely shared and the dialect gates very little.
    ///
    /// **This crate reads MySQL slow logs**, so the second group is one arm. It lands on
    /// [`JoinOp::NotMySql`], which this test holds it to — the point being that nothing foreign
    /// leaks into a MySQL arm, not which foreign thing it was.
    #[test]
    fn every_join_operator_the_grammar_can_build_is_classified() {
        // Reachable from MySQL itself: each of these is valid text for the server that wrote
        // the log.
        let mysql: &[(&str, JoinOp, ConstraintKind)] = &[
            (
                "SELECT 1 FROM a JOIN b ON a.i = b.i",
                JoinOp::Inner,
                ConstraintKind::On,
            ),
            (
                "SELECT 1 FROM a INNER JOIN b ON a.i = b.i",
                JoinOp::Inner,
                ConstraintKind::On,
            ),
            (
                "SELECT 1 FROM a LEFT JOIN b ON a.i = b.i",
                JoinOp::Left,
                ConstraintKind::On,
            ),
            (
                "SELECT 1 FROM a LEFT OUTER JOIN b ON a.i = b.i",
                JoinOp::Left,
                ConstraintKind::On,
            ),
            (
                "SELECT 1 FROM a RIGHT JOIN b ON a.i = b.i",
                JoinOp::Right,
                ConstraintKind::On,
            ),
            (
                "SELECT 1 FROM a RIGHT OUTER JOIN b ON a.i = b.i",
                JoinOp::Right,
                ConstraintKind::On,
            ),
            (
                "SELECT 1 FROM a CROSS JOIN b",
                JoinOp::Cross,
                ConstraintKind::None,
            ),
            (
                "SELECT 1 FROM a STRAIGHT_JOIN b ON a.i = b.i",
                JoinOp::Straight,
                ConstraintKind::On,
            ),
            (
                "SELECT 1 FROM a STRAIGHT_JOIN b",
                JoinOp::Straight,
                ConstraintKind::None,
            ),
            (
                "SELECT 1 FROM a JOIN b USING (i)",
                JoinOp::Inner,
                ConstraintKind::Using,
            ),
            (
                "SELECT 1 FROM a NATURAL JOIN b",
                JoinOp::Inner,
                ConstraintKind::Natural,
            ),
            (
                "SELECT 1 FROM a NATURAL LEFT JOIN b",
                JoinOp::Left,
                ConstraintKind::Natural,
            ),
            (
                "SELECT 1 FROM a NATURAL RIGHT JOIN b",
                JoinOp::Right,
                ConstraintKind::Natural,
            ),
        ];
        // Text MySQL cannot write, parsed here so the arm is known to be live code rather than
        // assumed to be. No MySQL slow log can contain any of these.
        let not_mysql: &[&str] = &[
            "SELECT 1 FROM a FULL OUTER JOIN b ON a.i = b.i",
            "SELECT 1 FROM a SEMI JOIN b ON a.i = b.i",
            "SELECT 1 FROM a LEFT SEMI JOIN b ON a.i = b.i",
            "SELECT 1 FROM a ANTI JOIN b ON a.i = b.i",
            "SELECT 1 FROM a CROSS APPLY b",
            "SELECT 1 FROM a OUTER APPLY b",
            "SELECT 1 FROM a ASOF JOIN b MATCH_CONDITION (a.t >= b.t) ON a.i = b.i",
        ];

        let mut seen: std::collections::BTreeSet<String> = Default::default();
        for (sql, want_op, want_con) in mysql {
            let g = graph(sql);
            let e = g
                .edges
                .iter()
                .find(|e| e.op == *want_op)
                .unwrap_or_else(|| panic!("{sql}: no {want_op:?} edge in {:?}", g.edges));
            assert_eq!(e.constraint, *want_con, "{sql}");
            assert!(
                !e.crosses_scope,
                "{sql}: a FROM-list join stays in its scope"
            );
            seen.insert(format!("{want_op:?}"));
        }
        for sql in not_mysql {
            let g = graph(sql);
            // The whole claim: it lands on the one arm, and on no MySQL arm.
            assert!(
                g.edges.iter().any(|e| e.op == JoinOp::NotMySql),
                "{sql}: no NotMySql edge in {:?}",
                g.edges
            );
            assert!(
                !g.edges.iter().any(|e| matches!(
                    e.op,
                    JoinOp::Inner | JoinOp::Left | JoinOp::Right | JoinOp::Cross | JoinOp::Straight
                )),
                "{sql}: something MySQL cannot write reached a MySQL arm — {:?}",
                g.edges
            );
            seen.insert("NotMySql".to_string());
        }

        // The two arms no join operator produces: a comma in the FROM list, and a predicate.
        for (sql, want) in [
            ("SELECT 1 FROM a, b", JoinOp::Comma),
            ("SELECT 1 FROM a, b WHERE a.i = b.i", JoinOp::Predicate),
        ] {
            assert!(graph(sql).edges.iter().any(|e| e.op == want), "{sql}");
            seen.insert(format!("{want:?}"));
        }

        // THE GUARD, and it is derived: `all()` is the same arm list `name()` is built from, so an
        // arm added above with no text that reaches it fails here with no number to edit.
        assert_eq!(
            seen.len(),
            JoinOp::all().count(),
            "every JoinOp arm needs text that reaches it; reached {seen:?}"
        );
        assert_eq!(mysql.len() + not_mysql.len(), 20, "cases, for the record");
    }

    /// EVERY ARM OF [`SetOperator`], WITH THE TEXT THAT REACHES IT.
    ///
    /// `MINUS` is Oracle's spelling of `EXCEPT` and `MySqlDialect` builds it. Filed as `Except`
    /// it would be a statement the server could not have run, on a MySQL arm.
    ///
    /// `INTERSECT` and `EXCEPT` with and without `ALL` are MySQL 8.0.31+, so each is an ordinary
    /// arm rather than one to hold to zero.
    #[test]
    fn every_set_operator_the_grammar_can_build_is_classified() {
        let mysql: &[(&str, SetOperator)] = &[
            (
                "SELECT a FROM t1 UNION SELECT a FROM t2",
                SetOperator::Union,
            ),
            (
                "SELECT a FROM t1 UNION ALL SELECT a FROM t2",
                SetOperator::UnionAll,
            ),
            (
                "SELECT a FROM t1 INTERSECT SELECT a FROM t2",
                SetOperator::Intersect,
            ),
            (
                "SELECT a FROM t1 INTERSECT ALL SELECT a FROM t2",
                SetOperator::IntersectAll,
            ),
            (
                "SELECT a FROM t1 EXCEPT SELECT a FROM t2",
                SetOperator::Except,
            ),
            (
                "SELECT a FROM t1 EXCEPT ALL SELECT a FROM t2",
                SetOperator::ExceptAll,
            ),
        ];
        let mut seen: std::collections::BTreeSet<String> = Default::default();
        for (sql, want) in mysql {
            let g = graph(sql);
            assert!(
                g.scopes.iter().any(|sc| sc.stages.set_operator == *want),
                "{sql}: no {want:?} scope in {:?}",
                g.scopes
                    .iter()
                    .map(|sc| sc.stages.set_operator)
                    .collect::<Vec<_>>()
            );
            seen.insert(format!("{want:?}"));
        }

        // Oracle's, and the whole claim is that it reaches the landing arm and no MySQL one.
        let g = graph("SELECT a FROM t1 MINUS SELECT a FROM t2");
        assert!(
            g.scopes
                .iter()
                .any(|sc| sc.stages.set_operator == SetOperator::NotMySql),
            "MINUS should land on the diagnostic arm"
        );
        assert!(
            !g.scopes
                .iter()
                .any(|sc| sc.stages.set_operator == SetOperator::Except),
            "MINUS reached a MySQL arm — it means what EXCEPT means and MySQL has no such keyword"
        );
        seen.insert("NotMySql".to_string());

        // The arm a scope heading no set operation takes, which is a measurement and not a blank.
        assert!(
            graph("SELECT a FROM t")
                .scopes
                .iter()
                .all(|sc| sc.stages.set_operator == SetOperator::NotApplicable),
            "a statement with no set operation is NotApplicable throughout"
        );
        seen.insert("NotApplicable".to_string());

        // THE GUARD, and it is derived: `all()` is the same arm list `name()` is built from, so an
        // arm added above with no text that reaches it fails here with no number to edit.
        assert_eq!(
            seen.len(),
            SetOperator::all().count(),
            "every SetOperator arm needs text that reaches it; reached {seen:?}"
        );
    }

    /// EVERY ARM OF [`RelationRole`], WITH THE TEXT THAT REACHES IT.
    ///
    /// This is the widest enum in the crate and the most consequential: a caller maps `role` to
    /// a read, a write or a DDL, and that mapping is what decides whether two statements holding
    /// one table exclude each other. A write target regressing to [`RelationRole::From`] would be
    /// read as a read, and nothing else would notice.
    #[test]
    fn every_relation_role_the_walk_files_is_reached() {
        let cases: &[(&str, RelationRole)] = &[
            ("SELECT a FROM t", RelationRole::From),
            (
                "SELECT a FROM t1 JOIN t2 ON t1.i = t2.i",
                RelationRole::Join,
            ),
            ("INSERT INTO t (a) VALUES (1)", RelationRole::InsertTarget),
            ("UPDATE t SET a = 1", RelationRole::UpdateTarget),
            ("DELETE FROM t WHERE x = 1", RelationRole::DeleteTarget),
            ("CREATE TABLE t (a INT)", RelationRole::CreateTarget),
            ("CREATE INDEX i ON t (a)", RelationRole::AlterTarget),
            ("DROP TABLE t", RelationRole::DropTarget),
            ("TRUNCATE TABLE t", RelationRole::TruncateTarget),
            ("LOCK TABLES t WRITE", RelationRole::LockExclusiveTarget),
            ("LOCK TABLES t READ", RelationRole::LockSharedTarget),
            ("ANALYZE TABLE t", RelationRole::AnalyzeTarget),
            ("SHOW CREATE TABLE t", RelationRole::MetadataTarget),
            ("FLUSH TABLES t", RelationRole::FlushTarget),
        ];
        let mut seen: std::collections::BTreeSet<String> = Default::default();
        for (sql, want) in cases {
            let g = graph(sql);
            assert!(
                g.occurrences.iter().any(|o| o.role == *want),
                "{sql}: no {want:?} occurrence in {:?}",
                g.occurrences
                    .iter()
                    .map(|o| (o.object_name.clone(), o.role))
                    .collect::<Vec<_>>()
            );
            seen.insert(format!("{want:?}"));
        }

        // THE GUARD, and it is derived: `all()` is the same arm list `name()` is built from, so an
        // arm added above with no text that reaches it fails here with no number to edit.
        assert_eq!(
            seen.len(),
            RelationRole::all().count(),
            "every RelationRole arm needs text that reaches it; reached {seen:?}"
        );

        // And a write must not be filed as a read. Both of these are the ordinary single-table
        // form, where the target list upstream reads is empty and the relation arrives in the
        // `FROM`.
        for (sql, want) in [
            ("UPDATE t SET a = 1", RelationRole::UpdateTarget),
            ("DELETE FROM t WHERE x = 1", RelationRole::DeleteTarget),
        ] {
            let g = graph(sql);
            assert_eq!(g.occurrences.len(), 1, "{sql}");
            assert_eq!(
                g.occurrences[0].role, want,
                "{sql}: a write filed as {:?}",
                g.occurrences[0].role
            );
        }
    }

    /// A COMPARISON MYSQL CANNOT WRITE LANDS ON THE DIAGNOSTIC ARM RATHER THAN ON NO ROW.
    ///
    /// A foreign comparison producing **no predicate row at all** would be a silence where the
    /// grammar built a tree the server could not have run, and `ILIKE` must not file as `LIKE`.
    ///
    /// The second half is what makes the catch-all safe: MySQL's own operators that compare
    /// nothing must still produce no predicate of their own. `<<` and `>>` are the sharp pair,
    /// because `sqlparser` names them `PGBitwiseShiftLeft`/`Right` and they are MySQL's.
    #[test]
    fn a_comparison_mysql_cannot_write_lands_on_one_arm() {
        for sql in [
            "SELECT a FROM t WHERE a ILIKE 'x'",
            "SELECT a FROM t WHERE a SIMILAR TO 'x'",
            "SELECT a FROM t WHERE a ~ 'x'",
            "SELECT a FROM t WHERE a @> b",
            "SELECT a FROM t WHERE a OVERLAPS b",
        ] {
            let g = graph(sql);
            assert!(
                g.predicates.iter().any(|pr| pr.op == PredicateOp::NotMySql),
                "{sql}: no NotMySql predicate in {:?}",
                g.predicates.iter().map(|pr| pr.op).collect::<Vec<_>>()
            );
            assert!(
                !g.predicates.iter().any(|pr| matches!(
                    pr.op,
                    PredicateOp::Like | PredicateOp::NotLike | PredicateOp::Eq
                )),
                "{sql}: something MySQL cannot write reached a MySQL arm — {:?}",
                g.predicates.iter().map(|pr| pr.op).collect::<Vec<_>>()
            );
        }

        for sql in [
            "SELECT a FROM t WHERE a + 1 = 2",
            "SELECT a FROM t WHERE a DIV 2 = 1",
            "SELECT a FROM t WHERE j -> '$.a' = 1",
            "SELECT a FROM t WHERE a << 2 = 4",
            "SELECT a FROM t WHERE a >> 2 = 1",
            "SELECT a FROM t WHERE a | b = 1",
        ] {
            let g = graph(sql);
            assert_eq!(
                g.predicates.len(),
                1,
                "{sql}: the comparison and not the arithmetic — {:?}",
                g.predicates.iter().map(|pr| pr.op).collect::<Vec<_>>()
            );
            assert_eq!(g.predicates[0].op, PredicateOp::Eq, "{sql}");
        }
    }

    /// A `USING` LIST WRITES THE RELATIONSHIP IT NAMES, UNDER [`Clause::JoinUsing`].
    ///
    /// Without it a reader asking which columns realise a relationship would get an answer for
    /// `ON` and none for `USING`.
    #[test]
    fn a_using_list_writes_one_relationship_per_column() {
        let g = graph("SELECT a FROM t1 JOIN t2 USING (i, j)");
        let using: Vec<_> = g
            .predicates
            .iter()
            .filter(|pr| pr.clause == Clause::JoinUsing)
            .collect();
        assert_eq!(
            using.len(),
            2,
            "one per named column, got {:?}",
            g.predicates
        );
        for pr in &using {
            assert_eq!(pr.op, PredicateOp::Eq, "a USING column is an equality");
            assert_eq!(
                pr.lhs.column, pr.rhs.column,
                "MySQL matches one name on both sides"
            );
            assert!(
                pr.lhs.occ.is_some() && pr.rhs.occ.is_some(),
                "both sides occupied, so it is a relationship and not a filter"
            );
            assert_ne!(
                pr.lhs.occ, pr.rhs.occ,
                "the two sides are the two relations the join brought together"
            );
            assert_eq!(
                pr.join_occ, pr.rhs.occ,
                "the join brought the right side in"
            );
        }

        // `NATURAL` names no column and writes none: which columns it matched is a fact about
        // the catalogue, which a slow log carries none of.
        assert!(
            graph("SELECT a FROM t1 NATURAL JOIN t2")
                .predicates
                .is_empty(),
            "NATURAL names no column, so it can write no split"
        );

        // THE GUARD: an `ON` over the same pair writes the same relationship in a different
        // clause, so `clause` is what separates them rather than the shape of the row.
        let on = graph("SELECT a FROM t1 JOIN t2 ON t1.i = t2.i");
        assert_eq!(on.predicates.len(), 1, "{:?}", on.predicates);
        assert_eq!(on.predicates[0].clause, Clause::On);
        assert_eq!(on.predicates[0].op, PredicateOp::Eq);
    }

    /// `op == Predicate` IS NOT A CORRELATION.
    ///
    /// A correlation is a predicate in a nested scope naming a relation from an enclosing one. An
    /// ordinary `WHERE a.i = b.i` over two tables in **one** scope draws the same edge, and for a
    /// comma join it is the join condition itself — old-style SQL has no `ON` to put it in.
    ///
    /// Both kinds here, distinguished by `crosses_scope`.
    #[test]
    fn a_predicate_edge_is_a_correlation_only_when_it_crosses_a_scope() {
        // Same scope: the comma join's condition.
        let g = graph("SELECT 1 FROM a, b WHERE a.i = b.i");
        let p: Vec<_> = g
            .edges
            .iter()
            .filter(|e| e.op == JoinOp::Predicate)
            .collect();
        assert_eq!(p.len(), 1, "{:?}", g.edges);
        assert!(
            !p[0].crosses_scope,
            "a WHERE over two FROM-list tables stays put"
        );

        // And the comma join writes ONE relationship that arrives as TWO edges: the adjacency
        // from the FROM list, and the condition from the WHERE. They join the same pair, which is
        // why `measures()` deduplicates on the node pair and the written count is the larger one.
        let comma: Vec<_> = g.edges.iter().filter(|e| e.op == JoinOp::Comma).collect();
        assert_eq!(comma.len(), 1);
        assert_eq!(
            (comma[0].lhs, comma[0].rhs).min((comma[0].rhs, comma[0].lhs)),
            (p[0].lhs, p[0].rhs).min((p[0].rhs, p[0].lhs)),
            "the adjacency and the condition are about the same pair"
        );
        assert_eq!(g.edges.len(), 2);
        assert_eq!(g.measures().edges, 1, "deduplicated onto the pair");

        // Crossing a scope: the real correlation, and the edge that makes a descent stop being
        // a tree.
        let g = graph("SELECT 1 FROM a WHERE EXISTS (SELECT 1 FROM b WHERE b.i = a.i)");
        let p: Vec<_> = g
            .edges
            .iter()
            .filter(|e| e.op == JoinOp::Predicate)
            .collect();
        assert_eq!(p.len(), 1, "{:?}", g.edges);
        assert!(
            p[0].crosses_scope,
            "the inner WHERE names the outer relation"
        );
    }

    fn one(sql: &str) -> Statement {
        let mut s = Parser::parse_sql(&MySqlDialect {}, sql).expect("fixture SQL must parse");
        assert_eq!(s.len(), 1, "each fixture is one statement");
        s.remove(0)
    }

    fn ids(g: &StatementGraph) -> Vec<String> {
        g.occurrences
            .iter()
            .map(|o| match o.identity() {
                Some(b) => String::from_utf8_lossy(&b).into_owned(),
                None => "<unnamed>".to_string(),
            })
            .collect()
    }

    /// THE CASE `objects()` CANNOT EXPRESS AT ALL. Its `BTreeSet` returns one name, so a flat
    /// set of names records this statement as naming one relation — which is true of the set and
    /// false of the statement. Two occurrences is what the statement said.
    #[test]
    fn a_self_join_is_two_nodes() {
        let g = graph("SELECT * FROM employee e1 JOIN employee e2 ON e1.manager_id = e2.id");
        assert_eq!(ids(&g), vec!["e1", "e2"]);
        assert_eq!(g.edges.len(), 1);
        let m = g.measures();
        assert_eq!((m.nodes, m.edges, m.cycle_space), (2, 1, 0));

        // Both occurrences carry the same written name, so a reader holding a catalogue can
        // still collapse them. The collapse is theirs to make and this crate does not make it.
        let names: Vec<_> = g
            .occurrences
            .iter()
            .map(|o| o.object_name.clone())
            .collect();
        assert_eq!(names[0], names[1]);
    }

    /// A CTE NAME IS NOT A RELATION, AND `objects()` FILES IT AS ONE. The definition site is an
    /// `Ident` on the CTE's alias and carries no `visit_relation` annotation, so it is invisible;
    /// every reference parses as an ordinary table and is visited. The net effect is a physical
    /// relation in the output that the server never opened.
    #[test]
    fn a_cte_reference_is_not_a_physical_table() {
        let g = graph(
            "WITH recent AS (SELECT id FROM orders) \
             SELECT * FROM recent r JOIN customers c ON r.id = c.order_id",
        );
        let cte = g
            .occurrences
            .iter()
            .find(|o| o.object_name.as_deref() == Some(b"recent".as_ref()))
            .expect("the reference to the CTE is an occurrence");
        assert!(
            cte.resolves_to_cte.is_some(),
            "the reference must name the CTE's scope, not a table"
        );

        let orders = g
            .occurrences
            .iter()
            .find(|o| o.object_name.as_deref() == Some(b"orders".as_ref()))
            .expect("the CTE body's own relation is an occurrence");
        assert!(orders.resolves_to_cte.is_none());
        assert_eq!(
            g.scopes[orders.scope as usize].kind,
            ScopeKind::Cte,
            "and it sits inside the CTE's scope"
        );
    }

    /// `TableFactor::Derived` CARRIES NO `ObjectName`, so `visit_relations` never sees the
    /// derived table at all — only the base tables inside it. The node the rest of the query
    /// actually joins to is absent from `objects()` entirely.
    #[test]
    fn a_derived_table_is_a_node_with_no_name() {
        let g = graph("SELECT * FROM (SELECT id FROM t) d JOIN u ON d.id = u.t_id");
        let d = g
            .occurrences
            .iter()
            .find(|o| o.alias.as_deref() == Some(b"d".as_ref()))
            .expect("the derived table is a node");
        assert_eq!(d.object_name, None, "it has an alias and nothing else");
        assert_eq!(d.identity().unwrap(), Bytes::from("d"));
        assert!(
            g.scopes.iter().any(|s| s.kind == ScopeKind::Derived),
            "and its subquery is a scope of its own"
        );
        assert_eq!(g.edges.len(), 1, "d joins u");
    }

    /// THE BRANCH IS IN THE PREDICATE AND NOWHERE ELSE. `TableWithJoins.joins` is a flat
    /// left-deep `Vec`, so joining each relation to its predecessor draws `sales_by_store` as a
    /// seven-link chain. It is not one: `store` is joined to `address` and to `staff` both, and
    /// the only record of that is the `ON` clauses.
    #[test]
    fn the_branch_is_read_from_the_predicate_not_the_order() {
        let g = graph(
            "SELECT 1 FROM payment AS p \
             INNER JOIN rental AS r ON p.rental_id = r.rental_id \
             INNER JOIN inventory AS i ON r.inventory_id = i.inventory_id \
             INNER JOIN store AS s ON i.store_id = s.store_id \
             INNER JOIN address AS a ON s.address_id = a.address_id \
             INNER JOIN city AS c ON a.city_id = c.city_id \
             INNER JOIN country AS cy ON c.country_id = cy.country_id \
             INNER JOIN staff AS m ON s.manager_staff_id = m.staff_id",
        );
        let s = g
            .occurrences
            .iter()
            .find(|o| o.alias.as_deref() == Some(b"s".as_ref()))
            .unwrap()
            .occ;
        let degree = g.edges.iter().filter(|e| e.lhs == s || e.rhs == s).count();
        assert_eq!(degree, 3, "store joins inventory, address and staff");

        let m = g.measures();
        assert_eq!(
            (m.nodes, m.edges, m.components, m.cycle_space),
            (8, 7, 1, 0),
            "a branching tree is still a tree"
        );
    }

    /// A DESCENT THAT IS NOT A TREE. `actor_info` reaches it: `film_category` and `film_actor` are
    /// each named twice, once in the outer join chain and once inside the correlated subquery, and
    /// the two correlation edges close a cycle.
    #[test]
    fn a_correlated_subquery_can_make_the_descent_stop_being_a_tree() {
        let g = graph(
            "SELECT a.actor_id, GROUP_CONCAT(CONCAT(c.name, ': ', \
                 (SELECT GROUP_CONCAT(f.title) FROM sakila.film f \
                  INNER JOIN sakila.film_category fc ON f.film_id = fc.film_id \
                  INNER JOIN sakila.film_actor fa ON f.film_id = fa.film_id \
                  WHERE fc.category_id = c.category_id AND fa.actor_id = a.actor_id))) \
             FROM sakila.actor a \
             LEFT JOIN sakila.film_actor fa ON a.actor_id = fa.actor_id \
             LEFT JOIN sakila.film_category fc ON fa.film_id = fc.film_id \
             LEFT JOIN sakila.category c ON fc.category_id = c.category_id \
             GROUP BY a.actor_id",
        );

        // Seven occurrences: four outer, three inner. The inner `fa` and `fc` SHADOW the outer
        // ones, which is why they are distinct nodes and why resolution has to go innermost-first.
        assert_eq!(g.occurrences.len(), 7, "{:?}", ids(&g));

        let crossing = g.edges.iter().filter(|e| e.crosses_scope).count();
        assert_eq!(crossing, 2, "the two correlations reach back up");

        let m = g.measures();
        assert_eq!(
            (m.nodes, m.edges, m.components, m.cycle_space),
            (7, 7, 1, 1),
            "NOT A TREE"
        );

        // And the loss is exact: a set of names keeps five of the seven and none of the edges.
        let mut names: Vec<_> = g
            .occurrences
            .iter()
            .filter_map(|o| o.object_name.clone())
            .collect();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), 5);
    }

    /// A RELATION NAMED IN A VIEW BODY WAS NOT READ, and `objects()` spells the two the same.
    #[test]
    fn a_view_body_is_not_a_scan_and_the_view_itself_is_a_node() {
        let g = graph(
            "CREATE VIEW customer_list AS SELECT cu.customer_id FROM customer AS cu \
             JOIN address AS a ON cu.address_id = a.address_id",
        );
        let view = g
            .occurrences
            .iter()
            .find(|o| o.role == RelationRole::CreateTarget)
            .expect("⛔ CreateView.name is unannotated, so objects() never sees the view at all");
        assert_eq!(view.object_name.as_deref(), Some(b"customer_list".as_ref()));
        assert!(
            !g.in_view_body(view.occ),
            "the view is not inside its own body"
        );

        for o in g.occurrences.iter().filter(|o| o.occ != view.occ) {
            assert!(
                g.in_view_body(o.occ),
                "{:?} was named, not scanned",
                ids(&g)
            );
        }
    }

    /// THE DDL THAT CAN BLOCK A READER NAMES THE TABLE IT LOCKS. An `ALTER` or a `DROP` takes
    /// `MDL_EXCLUSIVE` on a table that exists and blocks every reader of it, which a `CREATE`,
    /// naming a relation that did not exist, cannot do.
    ///
    /// And they are three roles rather than one, because a `CREATE` names a relation that was
    /// not there before and a `DROP` names one that is not there after.
    #[test]
    fn the_ddl_that_can_block_a_reader_names_the_table_it_locks() {
        // `ALTER TABLE ... DISABLE KEYS` is refused by `sqlparser` outright, so such rows are
        // `invalid` and reach no graph at all. The role has a witness through the forms that do
        // parse.
        let g = graph("ALTER TABLE `actor` ADD COLUMN last_seen DATETIME");
        let o = g
            .occurrences
            .iter()
            .find(|o| o.role == RelationRole::AlterTarget)
            .expect("⛔ ALTER TABLE reached `objects()` and no artifact that has roles");
        assert_eq!(o.object_name.as_deref(), Some(b"actor".as_ref()));

        // `DROP INDEX idx ON t` alters `t`, and the relation is in `Drop.table` rather than in
        // `names`.
        let g = graph("DROP INDEX idx_last_name ON actor");
        let o = g
            .occurrences
            .iter()
            .find(|o| o.role == RelationRole::AlterTarget)
            .expect("DROP INDEX names the table it alters");
        assert_eq!(o.object_name.as_deref(), Some(b"actor".as_ref()));
        assert_eq!(g.occurrences.len(), 1, "the index is not a relation");

        let g = graph("DROP TABLE IF EXISTS sakila.film_text, sakila.staff_list");
        let dropped: Vec<_> = g
            .occurrences
            .iter()
            .filter(|o| o.role == RelationRole::DropTarget)
            .filter_map(|o| o.object_name.clone())
            .collect();
        assert_eq!(
            dropped.len(),
            2,
            "⛔ `Drop.names` is unannotated: {dropped:?}"
        );
        assert_eq!(dropped[0].as_ref(), b"film_text");

        // And the schema survives.
        let schemas: Vec<_> = g
            .occurrences
            .iter()
            .filter_map(|o| o.schema_name.clone())
            .collect();
        assert_eq!(schemas.len(), 2);
    }

    /// THE LOCK THE LOG MEASURES THE WAIT FOR, AND THE STATEMENT THAT TAKES IT.
    ///
    /// `Lock_time` in a slow log is table-level and metadata lock wait. `LOCK TABLES` is how a
    /// client asks for precisely that, `mysqldump` writes one before every table it restores,
    /// and `LockTables.tables` carries no `visit_relation` annotation, so `objects()` never sees
    /// the tables it locks.
    ///
    /// The two modes are two roles because they exclude different things: a read lock admits
    /// other readers and shuts out writers; a write lock shuts out both.
    #[test]
    fn an_explicit_table_lock_names_the_table_it_holds_and_in_which_mode() {
        let g = graph("LOCK TABLES invoice WRITE, catalog AS c READ LOCAL");
        let got: Vec<(RelationRole, String, Option<String>)> = g
            .occurrences
            .iter()
            .map(|o| {
                let name = String::from_utf8(o.object_name.clone().unwrap().to_vec()).unwrap();
                let alias = o
                    .alias
                    .clone()
                    .map(|a| String::from_utf8(a.to_vec()).unwrap());
                (o.role, name, alias)
            })
            .collect();
        assert_eq!(
            got,
            vec![
                (RelationRole::LockExclusiveTarget, "invoice".into(), None),
                (
                    RelationRole::LockSharedTarget,
                    "catalog".into(),
                    Some("c".into())
                ),
            ]
        );

        // AND THE GRAMMAR CANNOT SAY IT ABOUT A QUALIFIED TABLE. `LockTable.table` is an
        // `Ident`, so `LOCK TABLES shop.invoice WRITE` — valid MySQL — is refused outright and
        // becomes an `invalid` entry with no graph. That is the grammar's regime and not the
        // server's, and the two are different claims.
        use sqlparser::dialect::MySqlDialect;
        use sqlparser::parser::Parser as SqlParser;
        assert!(SqlParser::parse_sql(&MySqlDialect {}, "LOCK TABLES shop.i WRITE").is_err());
    }

    /// THE REST OF THE WALK, each form the reason it is here.
    ///
    /// | statement | files | because |
    /// |---|---|---|
    /// | `TRUNCATE t` | `TruncateTarget` | InnoDB drops and recreates the tablespace — `MDL_EXCLUSIVE`, not row locks |
    /// | `CREATE INDEX i ON t` | `AlterTarget` on `t` | the index is not a relation; the table is what gets locked |
    /// | `RENAME TABLE a TO b` | `DropTarget` + `CreateTarget` | false about the data, exact about the names |
    /// | `ALTER VIEW v` | `AlterTarget` | it redefines a relation that already exists |
    /// | `ANALYZE TABLE t` | `AnalyzeTarget` | single-table only — this grammar refuses MySQL's list form |
    #[test]
    fn the_rest_of_the_statements_that_name_a_relation_name_it() {
        let roles = |sql: &str| -> Vec<(RelationRole, String)> {
            graph(sql)
                .occurrences
                .iter()
                .map(|o| {
                    (
                        o.role,
                        String::from_utf8(o.object_name.clone().unwrap().to_vec()).unwrap(),
                    )
                })
                .collect()
        };
        use RelationRole::*;
        assert_eq!(
            roles("TRUNCATE TABLE invoice, catalog"),
            vec![
                (TruncateTarget, "invoice".into()),
                (TruncateTarget, "catalog".into())
            ]
        );
        assert_eq!(
            roles("CREATE INDEX idx_year ON shop.invoice (year)"),
            vec![(AlterTarget, "invoice".into())],
            "the index is not a relation and the table is the one that gets locked"
        );
        assert_eq!(
            roles("RENAME TABLE invoice TO invoice_old"),
            vec![
                (DropTarget, "invoice".into()),
                (CreateTarget, "invoice_old".into())
            ]
        );
        assert_eq!(
            roles("ALTER VIEW invoice_summary AS SELECT id FROM invoice")[0].0,
            AlterTarget
        );
        assert_eq!(
            roles("ANALYZE TABLE shop.invoice"),
            vec![(AnalyzeTarget, "invoice".into())]
        );

        // THE SCHEMA SURVIVES WHERE THE GRAMMAR CARRIES ONE, rather than degenerating to a bare
        // name.
        let g = graph("CREATE INDEX idx_year ON shop.invoice (year)");
        assert_eq!(
            g.occurrences[0].schema_name.as_deref(),
            Some(b"shop".as_ref())
        );
    }

    /// `Delete.tables` carries no `visit_relation` annotation, so MySQL's multi-table delete
    /// target list is absent from `objects()` while the `FROM` side is present.
    #[test]
    fn a_multi_table_delete_names_its_targets() {
        let g = graph("DELETE t1, t2 FROM t1 JOIN t2 ON t1.id = t2.t1_id WHERE t1.x = 1");
        let targets = g
            .occurrences
            .iter()
            .filter(|o| o.role == RelationRole::DeleteTarget)
            .count();
        assert_eq!(targets, 2);
    }

    /// AND THE TARGETS ARE NOT RELATIONS OF THEIR OWN, which the count above cannot see. MySQL
    /// names a multi-table delete's targets **by alias**, so unresolved,
    /// `DELETE o, p FROM orders o JOIN payments p` would file two relations called `o` and `p` —
    /// tables that do not exist — and record no write against `orders` or `payments` at all.
    #[test]
    fn a_delete_target_written_as_an_alias_resolves_to_the_relation_it_names() {
        let g = graph(
            "DELETE o, p FROM orders o JOIN payments p ON p.order_id = o.id WHERE o.total > 5",
        );
        let by = |occ: u32| g.occurrences.iter().find(|o| o.occ == occ).unwrap();
        let targets: Vec<&RelationOccurrence> = g
            .occurrences
            .iter()
            .filter(|o| o.role == RelationRole::DeleteTarget)
            .collect();
        assert_eq!(targets.len(), 2);
        for t in &targets {
            let r = t
                .resolves_to_occ
                .unwrap_or_else(|| panic!("{:?} resolves to nothing", t.object_name));
            // The referent is a real relation, and the alias the target used is its identity.
            assert_eq!(by(r).identity(), t.object_name);
            assert!(by(r).object_name.is_some());
            assert_ne!(by(r).object_name, t.object_name);
        }
        let named: Vec<Option<Bytes>> = targets
            .iter()
            .map(|t| by(t.resolves_to_occ.unwrap()).object_name.clone())
            .collect();
        assert_eq!(
            named,
            vec![Some(Bytes::from("orders")), Some(Bytes::from("payments"))]
        );

        // NON-VACUITY FROM THE OTHER SIDE: a target list written with the table names rather
        // than aliases resolves too, because then the table name IS the identity.
        let g2 = graph("DELETE t1, t2 FROM t1 JOIN t2 ON t1.id = t2.t1_id");
        assert!(
            g2.occurrences
                .iter()
                .filter(|o| o.role == RelationRole::DeleteTarget)
                .all(|o| o.resolves_to_occ.is_some())
        );

        // AND A RELATION THAT NAMES ITSELF RESOLVES TO NOTHING, which is what stops this from
        // marking every occurrence as a reference. A single-table delete has no target list.
        let g3 = graph("DELETE FROM orders WHERE id = 1");
        assert!(g3.occurrences.iter().all(|o| o.resolves_to_occ.is_none()));
    }

    #[test]
    fn a_union_puts_each_side_in_its_own_scope() {
        let g = graph("SELECT a FROM t1 UNION SELECT b FROM t2");
        assert_eq!(
            g.scopes
                .iter()
                .filter(|s| s.kind == ScopeKind::SetOp)
                .count(),
            2
        );
        let m = g.measures();
        assert_eq!(
            (m.nodes, m.components, m.cycle_space),
            (2, 2, 0),
            "two sides that share nothing are two components"
        );
    }

    #[test]
    fn a_comma_join_is_an_edge() {
        let g = graph("SELECT 1 FROM a, b WHERE a.id = b.a_id");
        assert!(g.edges.iter().any(|e| e.op == JoinOp::Comma));
        assert_eq!(g.measures().nodes, 2);
    }

    #[test]
    fn an_insert_select_is_a_write_and_a_read() {
        let g = graph("INSERT INTO dst (a) SELECT a FROM src JOIN other o ON src.id = o.src_id");
        assert_eq!(
            g.occurrences
                .iter()
                .filter(|o| o.role == RelationRole::InsertTarget)
                .count(),
            1
        );
        assert_eq!(g.measures().nodes, 3);
    }

    /// Subqueries in expression position anywhere in the statement, counted by `sqlparser`'s own
    /// `visit_expressions`, which names no clause.
    fn nested_query_count(statement: &Statement) -> usize {
        let mut n = 0usize;
        let _ = visit_expressions(statement, |e| {
            if matches!(
                e,
                Expr::Subquery(_) | Expr::InSubquery { .. } | Expr::Exists { .. }
            ) {
                n += 1;
            }
            ControlFlow::<()>::Continue(())
        });
        n
    }

    /// THE GUARD ON THIS MODULE'S OWN BLIND SPOT. The walk reads the clauses it names, and a
    /// subquery in a clause it does not name would simply be missing, with nothing about the
    /// resulting graph looking wrong. This counts the same subqueries over the whole statement by
    /// a route that names no clause, and holds every relation `visit_relations` finds — which is
    /// what `objects()` reads — to an occurrence in the graph.
    #[test]
    fn the_two_routes_to_a_subquery_agree() {
        let cases = [
            "SELECT (SELECT max(x) FROM b) FROM a",
            "SELECT * FROM a WHERE id IN (SELECT id FROM b)",
            "SELECT * FROM a WHERE EXISTS (SELECT 1 FROM b WHERE b.a_id = a.id)",
            "SELECT CONCAT('x', (SELECT y FROM b LIMIT 1)) FROM a",
            "SELECT CASE WHEN x THEN (SELECT y FROM b LIMIT 1) ELSE 0 END FROM a",
            "SELECT * FROM a WHERE x BETWEEN (SELECT lo FROM b) AND (SELECT hi FROM b)",
            "SELECT * FROM a WHERE NOT (id IN (SELECT id FROM b))",
            "SELECT a.actor_id, GROUP_CONCAT(CONCAT(c.name, (SELECT t FROM f))) \
             FROM actor a JOIN category c ON a.id = c.id",
            // The positions and forms a list of named `Expr` arms missed.
            "SELECT * FROM a LEFT JOIN b ON b.id = (SELECT MAX(id) FROM c WHERE c.a_id = a.id)",
            "SELECT SUBSTRING((SELECT name FROM b LIMIT 1), 1, 2) FROM a",
            "SELECT CONVERT((SELECT name FROM b LIMIT 1), CHAR) FROM a",
            "SELECT TRIM((SELECT name FROM b LIMIT 1)) FROM a",
            "SELECT d + INTERVAL (SELECT MAX(n) FROM b) DAY FROM a",
            "SELECT x FROM a GROUP BY (SELECT MAX(id) FROM b)",
            "SELECT SUM(x) OVER (ORDER BY (SELECT MAX(id) FROM b)) FROM a",
            "SELECT SUM(x) OVER w FROM a WINDOW w AS (ORDER BY (SELECT MAX(id) FROM b))",
            "DELETE FROM a ORDER BY (SELECT MAX(id) FROM b) LIMIT 1",
            "UPDATE a SET x = 1 ORDER BY (SELECT MAX(id) FROM b) LIMIT 1",
            "INSERT INTO a SET x = (SELECT MAX(id) FROM b)",
            "SET @x = (SELECT MAX(id) FROM b)",
            "SELECT * FROM JSON_TABLE((SELECT doc FROM b LIMIT 1), '$[*]' \
             COLUMNS (x INT PATH '$')) AS jt",
            "SELECT * FROM a WHERE (SELECT x FROM b) IN (SELECT y FROM c)",
            "SELECT * FROM a WHERE x = ((SELECT MAX(y) FROM b))",
        ];
        for sql in cases {
            let s = one(sql);
            let g = StatementGraph::of(&s);
            let walked = g
                .scopes
                .iter()
                .filter(|s| s.kind == ScopeKind::Subquery)
                .count();
            assert_eq!(
                walked,
                nested_query_count(&s),
                "the walk and visit_expressions disagree on: {sql}"
            );
            let _ = visit_relations(&s, |r| {
                let name = split_name(r).1;
                assert!(
                    g.occurrences.iter().any(|o| o.object_name == name),
                    "{sql}: {name:?} is a relation the graph does not hold"
                );
                ControlFlow::<()>::Continue(())
            });
        }
    }

    /// THE READER'S MAPPING IS A QUANTITY, NOT A SETTING. Under the statement's own reading a
    /// self-join is two nodes and a tree. Collapse the two onto the table they name and the graph
    /// acquires a loop it did not have — cycle space goes 0 to 1 — and that difference is exactly
    /// what the mapping did. Shipping only the collapsed number would report the loop as though
    /// the statement had written one.
    #[test]
    fn the_collapse_by_name_is_what_creates_the_loop() {
        let g = graph("SELECT * FROM employee e1 JOIN employee e2 ON e1.manager_id = e2.id");

        let said = g.measures();
        assert_eq!(
            (said.nodes, said.edges, said.components, said.cycle_space),
            (2, 1, 1, 0),
            "what the statement said"
        );

        let read = g.measures_collapsed_by_name();
        assert_eq!(
            (read.nodes, read.edges, read.components, read.cycle_space),
            (1, 1, 1, 1),
            "what a reader holding a catalogue asserts"
        );

        assert_eq!(
            read.cycle_space - said.cycle_space,
            1,
            "and the delta is the mapping's own contribution"
        );
    }

    /// The same two readings over the correlated case. Note that the cycle survives BOTH: it is
    /// closed by the correlation edges, not by the collapse, so this non-tree descent does not
    /// depend on which identity a reader takes.
    #[test]
    fn a_correlation_cycle_survives_either_identity() {
        let g = graph(
            "SELECT a.actor_id, GROUP_CONCAT(CONCAT(c.name, ': ', \
                 (SELECT GROUP_CONCAT(f.title) FROM sakila.film f \
                  INNER JOIN sakila.film_category fc ON f.film_id = fc.film_id \
                  INNER JOIN sakila.film_actor fa ON f.film_id = fa.film_id \
                  WHERE fc.category_id = c.category_id AND fa.actor_id = a.actor_id))) \
             FROM sakila.actor a \
             LEFT JOIN sakila.film_actor fa ON a.actor_id = fa.actor_id \
             LEFT JOIN sakila.film_category fc ON fa.film_id = fc.film_id \
             LEFT JOIN sakila.category c ON fc.category_id = c.category_id \
             GROUP BY a.actor_id",
        );
        let said = g.measures();
        let read = g.measures_collapsed_by_name();
        assert_eq!(
            (said.nodes, said.edges, said.cycle_space),
            (7, 7, 1),
            "seven occurrences, because the subquery rebinds fa and fc"
        );
        assert_eq!(
            (read.nodes, read.edges, read.cycle_space),
            (5, 5, 1),
            "five tables, and the cycle is still there"
        );
        assert_eq!(said.cycle_space, read.cycle_space);
    }

    /// An unparseable statement and an admin command have no graph, and that is the same
    /// three-state discriminator `objects()` already carries.
    #[test]
    fn a_statement_naming_no_relation_has_an_empty_graph_and_not_a_missing_one() {
        let g = graph("SELECT @@version_comment");
        assert!(g.occurrences.is_empty());
        assert!(g.edges.is_empty());
        assert_eq!(g.measures().nodes, 0);
        assert_eq!(
            g.scopes.len(),
            1,
            "the statement's own scope exists even when it names nothing"
        );
    }

    /// The occurrence with this identity that is not a write-position mention of it.
    fn read_occ(g: &StatementGraph, identity: &str) -> u32 {
        g.occurrences
            .iter()
            .find(|o| {
                o.identity().as_deref() == Some(identity.as_bytes())
                    && matches!(o.role, RelationRole::From | RelationRole::Join)
            })
            .unwrap_or_else(|| panic!("no read of {identity} in {:?}", ids(g)))
            .occ
    }

    /// A QUALIFIER BINDS TO THE RELATION THE CLAUSE READS, not to a mention of the same name in a
    /// write position.
    ///
    /// A multi-table `DELETE`'s target list and an `INSERT … SELECT`'s target are walked before
    /// the `FROM` they sit beside, so a first-match rule hands every `t1.x` to the mention: the
    /// join's condition lands on names that read nothing and the relation actually read is left
    /// isolated.
    #[test]
    fn a_qualifier_binds_to_the_relation_the_clause_reads() {
        for sql in [
            "DELETE t1, t2 FROM t1 JOIN t2 ON t1.id = t2.t1_id WHERE t1.x = 1",
            "DELETE FROM t1 USING t1 JOIN t2 ON t1.id = t2.t1_id WHERE t1.x = 1",
            "DELETE FROM t1, t2 USING t1 JOIN t2 ON t1.id = t2.t1_id WHERE t1.x = 1",
        ] {
            let g = graph(sql);
            let (t1, t2) = (read_occ(&g, "t1"), read_occ(&g, "t2"));
            let on = g
                .predicates
                .iter()
                .find(|p| p.clause == Clause::On)
                .unwrap();
            assert_eq!((on.lhs.occ, on.rhs.occ), (Some(t1), Some(t2)), "{sql}");
            let wh = g
                .predicates
                .iter()
                .find(|p| p.clause == Clause::Where)
                .unwrap();
            assert_eq!(wh.lhs.occ, Some(t1), "{sql}");
            assert!(
                g.edges
                    .iter()
                    .all(|e| [t1, t2].contains(&e.lhs) && [t1, t2].contains(&e.rhs)),
                "{sql}: an edge touches a mention: {:?}",
                g.edges
            );
            let m = g.measures();
            assert_eq!((m.nodes, m.edges, m.components), (2, 1, 1), "{sql}");
        }

        let g = graph("INSERT INTO t (a) SELECT t.a FROM t JOIN u ON u.id = t.id WHERE t.b = 2");
        let (t, u) = (read_occ(&g, "t"), read_occ(&g, "u"));
        assert_eq!(g.occurrences[0].role, RelationRole::InsertTarget);
        assert_ne!(t, 0, "the source's t, not the target");
        let on = g
            .predicates
            .iter()
            .find(|p| p.clause == Clause::On)
            .unwrap();
        assert_eq!((on.lhs.occ, on.rhs.occ), (Some(u), Some(t)));
        let wh = g
            .predicates
            .iter()
            .find(|p| p.clause == Clause::Where)
            .unwrap();
        assert_eq!(wh.lhs.occ, Some(t));
        assert_eq!(g.edges.len(), 1);
        assert_eq!((g.edges[0].lhs, g.edges[0].rhs), (t, u));

        // And where nothing reads the name, the write position is what it names: a single-table
        // statement's target is also the relation its `WHERE` filters.
        let g = graph("DELETE FROM t WHERE t.x = 1");
        assert_eq!(g.predicates[0].lhs.occ, Some(0));
    }

    /// A MULTI-TABLE `UPDATE` WRITES WHAT ITS ASSIGNMENTS NAME, whatever position it holds.
    #[test]
    fn an_update_writes_the_relations_its_assignments_name() {
        let roles = |sql: &str| -> Vec<(String, RelationRole)> {
            let g = graph(sql);
            ids(&g)
                .into_iter()
                .zip(g.occurrences.iter().map(|o| o.role))
                .collect()
        };
        use RelationRole::*;
        assert_eq!(
            roles("UPDATE a JOIN b ON a.id = b.id SET b.x = 1"),
            vec![("a".into(), From), ("b".into(), UpdateTarget)]
        );
        assert_eq!(
            roles("UPDATE orders o JOIN customers c ON o.cid = c.id SET o.status = c.tier"),
            vec![("o".into(), UpdateTarget), ("c".into(), Join)]
        );
        assert_eq!(
            roles("UPDATE a JOIN b ON a.id = b.id SET a.x = 1, b.y = 2"),
            vec![("a".into(), UpdateTarget), ("b".into(), UpdateTarget)]
        );
        // MySQL's comma form is the grammar's refusal and not the server's.
        assert!(Parser::parse_sql(&MySqlDialect {}, "UPDATE a, b SET a.x = 1").is_err());
        // Unqualified in a single-table `UPDATE`: the one relation there is.
        assert_eq!(
            roles("UPDATE t SET a = 1"),
            vec![("t".into(), UpdateTarget)]
        );
        assert_eq!(
            roles("UPDATE shop.t SET shop.t.a = 1"),
            vec![("t".into(), UpdateTarget)]
        );
        // Unqualified in a multi-table one: the column's owner is the catalogue's to say, so
        // every base relation is a target and the derived table, which MySQL cannot update, is
        // not.
        assert_eq!(
            roles("UPDATE a JOIN b ON a.id = b.id SET x = 1"),
            vec![("a".into(), UpdateTarget), ("b".into(), UpdateTarget)]
        );
        assert_eq!(
            roles("UPDATE a JOIN (SELECT id FROM c) d ON a.id = d.id SET x = 1"),
            vec![
                ("a".into(), UpdateTarget),
                ("d".into(), Join),
                ("c".into(), From)
            ]
        );
    }

    /// THE TARGETS OF A `DELETE … USING` ARE A LIST AND NOT A JOIN. The commas separate the
    /// names of the tables deleted from, so drawing them as comma joins relates two relations the
    /// statement never put together.
    #[test]
    fn a_delete_target_list_joins_nothing() {
        let g = graph("DELETE FROM t1, t2 USING t1 JOIN t2 ON t1.id = t2.id");
        assert!(
            g.edges.iter().all(|e| e.op != JoinOp::Comma),
            "{:?}",
            g.edges
        );
        let m = g.measures();
        assert_eq!((m.nodes, m.edges, m.cycle_space), (2, 1, 0));

        // The source list of a multi-table delete is a `FROM` like any other, and its commas do
        // join.
        let g = graph("DELETE t1 FROM t1, t2 WHERE t1.id = t2.id");
        assert!(g.edges.iter().any(|e| e.op == JoinOp::Comma));
    }

    /// A SCHEMA-QUALIFIED COLUMN NAMES ITS RELATION BY THE PART BEFORE THE COLUMN, for the split
    /// and for the edge alike. Read one way for one and another way for the other, both sides of
    /// `shop.a.id = shop.b.a_id` resolve and no relationship is drawn.
    #[test]
    fn a_schema_qualified_column_draws_the_edge_its_split_names() {
        let g = graph("SELECT 1 FROM shop.a, shop.b WHERE shop.a.id = shop.b.a_id");
        let p = &g.predicates[0];
        assert_eq!((p.lhs.occ, p.rhs.occ), (Some(0), Some(1)));
        assert!(
            g.edges
                .iter()
                .any(|e| e.op == JoinOp::Predicate && (e.lhs, e.rhs) == (0, 1)),
            "{:?}",
            g.edges
        );

        // The schema is part of the match where the relation was written with one.
        let g = graph("SELECT 1 FROM shop.a, other.a AS x WHERE other.a.id = 1");
        assert_eq!(g.predicates[0].lhs.occ, None, "other.a is aliased as x");
        let g = graph("SELECT 1 FROM shop.a JOIN other.b ON shop.a.id = other.b.id");
        assert_eq!(g.edges.len(), 1);
        assert_eq!((g.edges[0].lhs, g.edges[0].rhs), (0, 1));
    }

    /// PARENTHESES GROUP RELATIONS AND ARE NOT ONE. A node for the group would stand for a
    /// relation nobody named, and since nothing joins to it by name it splits a connected join
    /// into two components.
    #[test]
    fn a_parenthesised_join_adds_no_node() {
        for sql in [
            "SELECT * FROM (a JOIN b ON a.id = b.id) JOIN c ON c.id = a.id",
            "SELECT * FROM a JOIN (b JOIN c ON b.id = c.id) ON a.id = b.id",
            "SELECT * FROM (a JOIN b ON a.id = b.id) LEFT JOIN c USING (id)",
        ] {
            let g = graph(sql);
            assert_eq!(ids(&g), vec!["a", "b", "c"], "{sql}");
            let m = g.measures();
            assert_eq!(
                (m.nodes, m.edges, m.components, m.cycle_space),
                (3, 2, 1, 0),
                "{sql}: {:?}",
                g.edges
            );
            assert!(!g.scopes[0].stages.not_mysql, "{sql}");
        }
        // The group's first relation takes the role the group holds.
        let g = graph("SELECT * FROM a JOIN (b JOIN c ON b.id = c.id) ON a.id = b.id");
        let roles: Vec<RelationRole> = g.occurrences.iter().map(|o| o.role).collect();
        assert_eq!(
            roles,
            vec![RelationRole::From, RelationRole::Join, RelationRole::Join]
        );
        // MySQL gives the group no alias, so one is the grammar's and lands on the diagnostic arm.
        let g = graph("SELECT * FROM (a JOIN b ON a.id = b.id) AS x");
        assert_eq!(ids(&g), vec!["a", "b"]);
        assert!(g.scopes[0].stages.not_mysql);
    }

    /// A SUBQUERY IN A JOIN'S `ON` IS AN OPERAND LIKE ANY OTHER: the relation it reads is in the
    /// graph, the split comparing against it names its scope, and its correlation reaches back to
    /// the relation it names outside.
    #[test]
    fn a_subquery_in_an_on_clause_is_walked() {
        let g = graph(
            "SELECT * FROM a LEFT JOIN b ON b.id = (SELECT MAX(id) FROM c WHERE c.a_id = a.id)",
        );
        assert_eq!(ids(&g), vec!["a", "b", "c"]);
        let on = g
            .predicates
            .iter()
            .find(|p| p.clause == Clause::On)
            .unwrap();
        assert_eq!(on.op, PredicateOp::Scalar);
        let inner = on.rhs_scope.expect("the split names the subquery's scope");
        assert_eq!(g.occurrences[2].scope, inner);
        assert!(
            g.edges
                .iter()
                .any(|e| e.crosses_scope && (e.lhs, e.rhs) == (2, 0)),
            "{:?}",
            g.edges
        );
    }

    /// `CREATE TABLE … AS SELECT` READS WHAT IT SELECTS. It is `INSERT … SELECT` into a table
    /// that did not exist, so its relations are read in the statement's own scope — not named in a
    /// body that ran once and read nothing, which is what a view is.
    #[test]
    fn a_create_table_as_select_reads_its_source() {
        let g = graph("CREATE TABLE t2 AS SELECT a.id FROM t1 a JOIN t3 ON a.id = t3.id");
        assert!(g.scopes.iter().all(|s| s.kind != ScopeKind::ViewBody));
        let roles: Vec<(String, RelationRole)> = ids(&g)
            .into_iter()
            .zip(g.occurrences.iter().map(|o| o.role))
            .collect();
        assert_eq!(
            roles,
            vec![
                ("t2".into(), RelationRole::CreateTarget),
                ("a".into(), RelationRole::From),
                ("t3".into(), RelationRole::Join),
            ]
        );
        assert!(g.occurrences.iter().all(|o| !g.in_view_body(o.occ)));
        assert!(g.occurrences.iter().all(|o| o.scope == 0));
        assert_eq!(g.edges.len(), 1);
    }

    /// A NON-RECURSIVE CTE IS NOT IN SCOPE INSIDE ITS OWN DEFINITION, and a CTE sees only the
    /// ones defined before it.
    ///
    /// `WITH orders AS (SELECT * FROM orders …)` reads the base table `orders`; resolved to the
    /// CTE, the only physical relation the statement touches would be filed as a reference to
    /// itself.
    #[test]
    fn a_cte_does_not_see_itself_unless_it_is_recursive() {
        let cte_of = |g: &StatementGraph| -> Vec<Option<u32>> {
            g.occurrences.iter().map(|o| o.resolves_to_cte).collect()
        };

        let g = graph("WITH orders AS (SELECT * FROM orders WHERE total > 5) SELECT * FROM orders");
        assert_eq!(g.occurrences[0].scope, 1, "the definition's own orders");
        assert_eq!(cte_of(&g), vec![None, Some(1)]);

        // Inside its own definition the name reads whatever it named outside, here an enclosing
        // CTE of the same name.
        let g = graph(
            "WITH orders AS (SELECT 1 AS id) \
             SELECT * FROM (WITH orders AS (SELECT * FROM orders) SELECT * FROM orders) d",
        );
        let outer = g
            .scopes
            .iter()
            .find(|s| s.kind == ScopeKind::Cte && s.parent == Some(0))
            .unwrap()
            .id;
        let inner = g
            .scopes
            .iter()
            .find(|s| s.kind == ScopeKind::Cte && s.id != outer)
            .unwrap()
            .id;
        let resolved: Vec<Option<u32>> = g
            .occurrences
            .iter()
            .filter(|o| o.object_name.as_deref() == Some(b"orders".as_ref()))
            .map(|o| o.resolves_to_cte)
            .collect();
        assert_eq!(resolved, vec![Some(outer), Some(inner)]);

        // `WITH RECURSIVE` is the one form that sees itself.
        let g = graph(
            "WITH RECURSIVE r AS (SELECT 1 AS n UNION ALL SELECT n + 1 FROM r WHERE n < 5) \
             SELECT * FROM r",
        );
        assert_eq!(cte_of(&g), vec![Some(1), Some(1)]);

        // A later CTE sees an earlier one, and not the reverse.
        let g = graph("WITH a AS (SELECT * FROM b), b AS (SELECT * FROM a) SELECT * FROM b");
        let got: Vec<(String, Option<u32>)> = ids(&g).into_iter().zip(cte_of(&g)).collect();
        assert_eq!(
            got,
            vec![
                ("b".into(), None),
                ("a".into(), Some(1)),
                ("b".into(), Some(2))
            ]
        );
    }

    /// `FOR UPDATE OF t` IS MYSQL 8.0, and it locks the relations it names and no others.
    ///
    /// A relation the clause leaves out is a snapshot read, so a reader treating the whole scope
    /// as locked would pair it with every writer, and one treating the clause as foreign would
    /// pair it with none.
    #[test]
    fn a_locking_clause_locks_the_relations_it_names() {
        let locks = |sql: &str| -> Vec<(String, LockStrength, LockWait)> {
            let g = graph(sql);
            ids(&g)
                .into_iter()
                .zip(g.occurrences.iter().map(|o| (o.locking, o.lock_wait)))
                .map(|(i, (s, w))| (i, s, w))
                .collect()
        };
        use LockStrength::*;
        use LockWait::*;
        assert_eq!(
            locks("SELECT * FROM t1 JOIN t2 ON t1.id = t2.id FOR UPDATE"),
            vec![
                ("t1".into(), Exclusive, Wait),
                ("t2".into(), Exclusive, Wait)
            ]
        );
        assert_eq!(
            locks("SELECT * FROM t1 a JOIN t2 ON a.id = t2.id FOR UPDATE OF a"),
            vec![("a".into(), Exclusive, Wait), ("t2".into(), None, Wait)]
        );
        assert_eq!(
            locks("SELECT * FROM t1, t2 FOR SHARE OF t1 FOR UPDATE OF t2 NOWAIT"),
            vec![
                ("t1".into(), Shared, Wait),
                ("t2".into(), Exclusive, NoWait)
            ]
        );
        let g = graph("SELECT * FROM t1, t2 FOR SHARE OF t1 FOR UPDATE OF t2 NOWAIT");
        assert_eq!(
            (g.scopes[0].locking, g.scopes[0].lock_wait),
            (Exclusive, NoWait)
        );

        // The clause locks what the query reads, and not the table an `INSERT … SELECT` writes;
        // nor a subquery's relations, which are another block.
        assert_eq!(
            locks("INSERT INTO t SELECT * FROM u FOR UPDATE"),
            vec![("t".into(), None, Wait), ("u".into(), Exclusive, Wait)]
        );
        assert_eq!(
            locks("SELECT * FROM t WHERE id IN (SELECT id FROM u) FOR UPDATE"),
            vec![("t".into(), Exclusive, Wait), ("u".into(), None, Wait)]
        );

        // MySQL's list form is the grammar's refusal and not the server's.
        assert!(
            Parser::parse_sql(
                &MySqlDialect {},
                "SELECT * FROM t1, t2 FOR UPDATE OF t1, t2"
            )
            .is_err()
        );
    }

    /// `:=` ASSIGNS A USER VARIABLE AND COMPARES NOTHING. It is MySQL, so it is not the
    /// diagnostic arm, and it is not a comparison, so it is no split at all.
    #[test]
    fn an_assignment_is_not_a_comparison() {
        let g = graph("SELECT @r := @r + 1 FROM t");
        assert!(g.predicates.is_empty(), "{:?}", g.predicates);
        let g = graph("SELECT a FROM t WHERE (@r := a) = 1");
        assert_eq!(g.predicates.len(), 1);
        assert_eq!(g.predicates[0].op, PredicateOp::Eq);
    }

    /// ONLY A COMPARISON RELATES TWO RELATIONS. `a.x + b.y` computes one value out of both and
    /// says nothing about which rows go together, so it draws no edge; and a `WHERE` comparison
    /// wrote no join constraint, so its edge does not claim an `ON`.
    #[test]
    fn arithmetic_draws_no_edge_and_a_where_edge_claims_no_on() {
        let g = graph("SELECT a.x + b.y FROM a, b");
        let ops: Vec<JoinOp> = g.edges.iter().map(|e| e.op).collect();
        assert_eq!(ops, vec![JoinOp::Comma]);
        assert!(g.predicates.is_empty());

        // One side computed from both relations and the other from neither relates nothing.
        let g = graph("SELECT 1 FROM a, b WHERE a.x + b.y = 5");
        assert!(g.edges.iter().all(|e| e.op == JoinOp::Comma));

        let g = graph("SELECT 1 FROM a, b WHERE a.x + 1 = b.y");
        let p: Vec<&Edge> = g
            .edges
            .iter()
            .filter(|e| e.op == JoinOp::Predicate)
            .collect();
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].constraint, ConstraintKind::None);

        for sql in [
            "UPDATE a JOIN b ON a.id = b.id SET a.x = 1 WHERE a.k = b.k",
            "SELECT 1 FROM a, b GROUP BY a.id HAVING MAX(a.x) = MAX(b.y)",
            "SELECT a.x = b.y FROM a, b",
        ] {
            let g = graph(sql);
            assert!(
                g.edges
                    .iter()
                    .filter(|e| e.op == JoinOp::Predicate)
                    .all(|e| e.constraint == ConstraintKind::None),
                "{sql}: {:?}",
                g.edges
            );
            assert!(g.edges.iter().any(|e| e.op == JoinOp::Predicate), "{sql}");
        }
        // And a join's own `ON` still says so.
        let g = graph("SELECT 1 FROM a JOIN b ON a.id = b.id");
        assert_eq!(g.edges[0].constraint, ConstraintKind::On);
    }

    /// AN AGGREGATE GROUPS ITS OWN SCOPE, AND A WINDOW FUNCTION GROUPS NOTHING.
    ///
    /// `projection_aggregate_calls > 0` with no `GROUP BY` reads as implicit grouping, so an
    /// aggregate counted from a subquery — or a `SUM(x) OVER (…)`, which keeps every row — would
    /// say a statement collapses to one row when it does not.
    #[test]
    fn an_aggregate_is_counted_in_the_scope_it_groups() {
        let g = graph("SELECT id, (SELECT COUNT(*) FROM u) FROM t");
        assert_eq!(g.scopes[0].stages.projection_aggregate_calls, 0);
        assert_eq!(g.scopes[1].stages.projection_aggregate_calls, 1);

        assert_eq!(
            st("SELECT SUM(x) OVER (PARTITION BY y) FROM t").projection_aggregate_calls,
            0
        );
        assert_eq!(
            st("SELECT SUM(x) OVER w FROM t WINDOW w AS (ORDER BY y)").projection_aggregate_calls,
            0
        );
        // The inner aggregate groups and the window over it does not.
        assert_eq!(
            st("SELECT SUM(COUNT(*)) OVER () FROM t GROUP BY a").projection_aggregate_calls,
            1
        );
        assert_eq!(
            st("SELECT a FROM t GROUP BY a HAVING COUNT(*) > (SELECT AVG(n) FROM u)")
                .having_aggregate_calls,
            1
        );
        // The IN's left operand is the scope's own; the subquery it is compared with is not.
        assert_eq!(
            st("SELECT a FROM t GROUP BY a HAVING MAX(b) IN (SELECT MAX(c) FROM u)")
                .having_aggregate_calls,
            1
        );

        // MySQL 8.0's whole list.
        assert_eq!(
            st("SELECT BIT_XOR(a), JSON_ARRAYAGG(a), JSON_OBJECTAGG(a, b) FROM t")
                .projection_aggregate_calls,
            3
        );
    }

    /// `MATCH (col) AGAINST (…)` NAMES ITS COLUMN, qualified or not, as every other split does.
    #[test]
    fn a_fulltext_search_names_its_column() {
        let g = graph("SELECT a FROM t WHERE MATCH (body) AGAINST ('x')");
        let lhs = &g.predicates[0].lhs;
        assert_eq!(lhs.column.as_deref(), Some(b"body".as_ref()));
        assert_eq!(lhs.occ, None, "unqualified, as any unqualified column");

        let g = graph("SELECT a FROM t JOIN u ON t.id = u.id WHERE MATCH (u.body) AGAINST ('x')");
        let m = g
            .predicates
            .iter()
            .find(|p| p.op == PredicateOp::MatchAgainst)
            .unwrap();
        assert_eq!(m.lhs.occ, Some(1));
        assert_eq!(m.lhs.column.as_deref(), Some(b"body".as_ref()));
    }

    /// A SUBQUERY IN PARENTHESES IS STILL THE SUBQUERY. `x = ((SELECT …))` compares against it,
    /// so the split is scalar and names the scope, rather than an `=` against an operand with no
    /// scope.
    #[test]
    fn parentheses_around_a_subquery_are_looked_through() {
        let g = graph("SELECT a FROM t WHERE x = ((SELECT MAX(y) FROM u))");
        let p = &g.predicates[0];
        assert_eq!(p.op, PredicateOp::Scalar);
        assert_eq!(p.rhs_kind, RhsKind::Subquery);
        assert_eq!(p.rhs_scope, Some(1));

        let g = graph("SELECT a FROM t WHERE x > ANY ((SELECT y FROM u))");
        assert_eq!(g.predicates[0].rhs_scope, Some(1));
    }

    /// `XOR`, `||` AND `&&` ARE BOUND TIGHTER THAN `=` BY THIS GRAMMAR, and looser by MySQL.
    ///
    /// The text is accepted and the tree is not the one the server ran, so each arrives as one
    /// comparison over no column. This is the grammar's regime and is recorded rather than
    /// re-parsed; parenthesised operands are read as MySQL reads them.
    #[test]
    fn xor_and_the_symbol_connectives_are_bound_by_the_grammar() {
        for sql in [
            "SELECT a FROM t WHERE a = 1 XOR b = 2",
            "SELECT a FROM t WHERE a = 1 || b = 2",
            "SELECT a FROM t WHERE a = 1 && b = 2",
        ] {
            let g = graph(sql);
            assert_eq!(g.predicates.len(), 1, "{sql}");
            assert_eq!(g.predicates[0].lhs.column, None, "{sql}");
        }
        let s = splits("SELECT a FROM t WHERE (a = 1) XOR (b = 2)");
        let paths: Vec<&str> = s.iter().map(|(_, p, _)| p.as_str()).collect();
        assert_eq!(paths, ["xor[0]", "xor[1]"]);
    }
}
