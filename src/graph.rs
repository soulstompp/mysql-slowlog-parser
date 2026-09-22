//! The relation graph of a parsed statement: which relations it names, where each one sits, and
//! which ones are joined to which.
//!
//! ⭐⭐ THIS IS THE STRUCTURE `objects()` THROWS AWAY. That accessor folds the whole parse into a
//! `BTreeSet` of names, which discards four different things at once: how many times a relation is
//! touched, what position it was touched in, how deep it was nested, and every edge. A self-join
//! arrives as one name, a table named inside a `CREATE VIEW` body arrives looking exactly like a
//! table that was scanned, and a CTE reference arrives looking like a physical table.
//!
//! ⛔ AND IT CANNOT BE BUILT WITH A VISITOR. `sqlparser`'s visitor fires on `ObjectName`,
//! `TableFactor`, `Expr`, `Query`, `Statement` and `Value`, and on nothing else. There is no
//! `visit(with = ...)` annotation anywhere on `Join`, `JoinOperator`, `JoinConstraint`,
//! `TableWithJoins`, `Cte` or `With`, so a visitor sees join *operands* as an undifferentiated
//! stream and never sees the join *operator* or its predicate at all. The edges have to be walked
//! by hand.
//!
//! ## What a node is
//!
//! ⭐ AN OCCURRENCE, NEVER A TABLE. `FROM employee e1 JOIN employee e2` is two nodes, because the
//! statement said it twice and a filing carries the document's value rather than the reader's.
//! Collapsing the two onto one table name is a claim about a catalogue this crate has never seen,
//! so it belongs to whoever holds the catalogue. [`RelationOccurrence::alias`] is the identity;
//! [`RelationOccurrence::object_name`] is what a later reader would collapse *by*.
//!
//! ## What the walker does not see
//!
//! ⚠️ [`Builder::walk_expr`] names the `Expr` forms it descends into and does nothing with the
//! rest, so a subquery hidden inside a form not listed there is a relation this graph does not
//! hold. That gap is not left to a reader to notice: [`StatementGraph::nested_query_count`]
//! counts the same subqueries by a second route — `sqlparser`'s own `visit_expressions` — and
//! `tests::the_two_routes_to_a_subquery_agree` holds them together.

use bytes::Bytes;
use sqlparser::ast::{
    Cte, Delete, Expr, FromTable, Insert, JoinConstraint, JoinOperator, ObjectName,
    LockTableType, ObjectNamePart, ObjectType, Query, Select, SetExpr, Statement, TableFactor,
    TableObject, TableWithJoins, UpdateTableFromKind, visit_expressions,
};
use std::ops::ControlFlow;

/// Where in its statement a relation occurrence sits.
///
/// ⭐ THE TARGET ARMS ARE WHY THIS IS NOT A SET. `objects()` puts the table an `UPDATE` writes to
/// and the tables it reads from into one collection with nothing separating them, so a reader
/// summing anything over "the tables this statement touched" sums a write and a read together.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub enum RelationRole {
    /// the first relation of a `FROM` clause
    From,
    /// a relation introduced by a `JOIN`, or by a comma in a `FROM` list
    Join,
    /// the relation an `INSERT` writes to
    InsertTarget,
    /// the relation an `UPDATE` writes to
    UpdateTarget,
    /// a relation a `DELETE` removes rows from
    DeleteTarget,
    /// the relation a `CREATE` statement brings into being
    CreateTarget,
    /// the relation an `ALTER TABLE` changes the definition of
    ///
    /// ⭐⭐ NOT `CreateTarget`, AND THE DIFFERENCE IS THE WHOLE POINT OF FILING IT. A `CREATE`
    /// names a relation that did not exist, so nothing was reading it and nothing could be
    /// blocked. An `ALTER` names one that does exist and takes `MDL_EXCLUSIVE` on it, which
    /// blocks every reader of it for the duration. Filing both as "a DDL target" would put the
    /// one DDL that cannot block anybody under the same name as the one that blocks everybody.
    AlterTarget,
    /// the relation a `DROP` removes
    DropTarget,
    /// the relation a `TRUNCATE` empties
    ///
    /// ⚠️ Not a `DELETE`. InnoDB implements `TRUNCATE TABLE` by dropping and recreating the
    /// tablespace, so it takes `MDL_EXCLUSIVE` where a `DELETE FROM t` takes row locks — the two
    /// statements a reader would most expect to be alike are the two furthest apart here.
    TruncateTarget,
    /// a relation `LOCK TABLES … WRITE` holds
    ///
    /// ⭐⭐⭐ THE STATEMENT THAT TAKES THE LOCK THE LOG MEASURES THE WAIT FOR. `Lock_time` in a
    /// slow log is table-level and metadata lock wait; `LOCK TABLES` is how a client asks for
    /// exactly that, and `LockTables.tables` carries no `visit_relation` annotation, so the
    /// tables it holds were absent from `objects()` and from every artifact downstream of it.
    LockExclusiveTarget,
    /// a relation `LOCK TABLES … READ` holds
    ///
    /// ⚠️ Filed apart from [`RelationRole::LockExclusiveTarget`] because the modes exclude
    /// different things: a read lock admits other readers and shuts out writers, a write lock
    /// shuts out both. One role for both would be the `ddl`/`write` fusion one statement over.
    LockSharedTarget,
    /// the relation an `ANALYZE TABLE` samples
    AnalyzeTarget,
}

/// The kind of naming scope a relation occurrence was found in.
///
/// ⭐ THIS IS WHAT SEPARATES A TABLE SCANNED FROM A TABLE NAMED. A relation under a
/// [`ScopeKind::ViewBody`] is mentioned in a definition that ran once and read nothing; a relation
/// under [`ScopeKind::Statement`] was actually visited. `objects()` spells them the same, and on
/// the corpus this crate is tested against *every* multi-relation statement is a `CREATE VIEW`,
/// so a sum over tables weighted by query time is drawn entirely from statements that never
/// touched them.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
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

/// How two relation occurrences were put together.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub enum JoinOp {
    /// `JOIN` / `INNER JOIN`
    Inner,
    /// `LEFT JOIN`
    Left,
    /// `RIGHT JOIN`
    Right,
    /// `FULL OUTER JOIN`
    FullOuter,
    /// `CROSS JOIN`
    Cross,
    /// `SEMI` in any of its spellings
    Semi,
    /// `ANTI` in any of its spellings
    Anti,
    /// `STRAIGHT_JOIN`
    Straight,
    /// `CROSS APPLY` / `OUTER APPLY`
    Apply,
    /// `ASOF`
    AsOf,
    /// a comma in a `FROM` list
    Comma,
    /// ⭐ not a join at all: a predicate in a nested scope naming a relation from an enclosing
    /// one. This is the edge that makes a descent stop being a tree.
    Correlation,
}

/// What the join said about how to match rows.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub enum ConstraintKind {
    /// `ON <predicate>`
    On,
    /// `USING (cols)`
    Using,
    /// `NATURAL`
    Natural,
    /// no constraint was written
    None,
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
    /// the name a CTE or derived table was given, where it has one
    pub name: Option<Bytes>,
    /// whether a `WITH` introducing this scope said `RECURSIVE`
    pub recursive: bool,
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
    /// ⭐ the identity of this node. `None` where the statement gave none, in which case
    /// `object_name` is doing the work.
    pub alias: Option<Bytes>,
    /// where in the statement it sits
    pub role: RelationRole,
    /// ⚠️ the scope of the CTE this name resolves to, where it resolves to one. A CTE reference
    /// parses as an ordinary table and `objects()` files it as a physical relation that does not
    /// exist.
    pub resolves_to_cte: Option<u32>,
    /// ⛔⛔ THE OCCURRENCE THIS ONE REFERS TO, where it refers to one rather than naming a
    /// relation of its own. MySQL's multi-table `DELETE o, p FROM orders o JOIN payments p`
    /// names its targets **by alias**, and sqlparser hands that list over as `ObjectName`s — so
    /// the graph filed two relations called `o` and `p` that do not exist, while the write on
    /// `orders` and on `payments` was recorded nowhere at all.
    ///
    /// ⭐ The mention is kept rather than dropped, because the statement did write those words.
    /// What is recorded beside it is what they point at, exactly as [`Self::resolves_to_cte`]
    /// records it for a CTE reference. A consumer asking which physical tables a statement
    /// touched skips an occurrence that resolves, and one asking what the statement WROTE
    /// carries the role over to the referent.
    pub resolves_to_occ: Option<u32>,
}

impl RelationOccurrence {
    /// The name a reader would collapse this occurrence *by*: its alias if it has one, else its
    /// written object name.
    ///
    /// ⛔ THIS IS THE DOCUMENT'S VALUE AND NOT A CATALOGUE'S. Two occurrences agreeing here are
    /// two occurrences the statement spelled the same way, which is a fact about the statement.
    /// Whether they are one table is a different question and nothing in a slow log answers it.
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
    /// ⭐ whether the endpoints sit in different scopes, i.e. whether this is a correlation
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

    /// Nodes, edges and components of the graph as the statement wrote it: **one node per
    /// occurrence**.
    ///
    /// ⭐ AND THAT IS NOT A SIMPLIFICATION, IT IS WHAT AN ALIAS IS. An alias is scoped, so the
    /// `fa` an outer query binds and the `fa` a subquery rebinds are two names and not one — the
    /// same way two locals in two functions are. Within a single scope SQL itself forbids the
    /// collision (`FROM a JOIN a` is "Not unique table/alias"), so one node per occurrence is
    /// injective by the language's own rule rather than by an assumption made here.
    ///
    /// [`Self::measures_collapsed_by_name`] is the other reading, and it belongs to a reader.
    pub fn measures(&self) -> GraphMeasures {
        self.measure_by(|_, occ| format!("\u{0}occ{occ}").into_bytes())
    }

    /// The same measures after collapsing every occurrence onto its written `[schema.]object`
    /// name.
    ///
    /// ⛔ THIS IS A READER'S MAPPING AND NEVER THE DOCUMENT'S. Nothing in a slow log says
    /// `sakila.film` and `film` are one relation; a catalogue says that, and this crate has never
    /// seen one. The collapse ships as a second measure rather than as the only one so that the
    /// difference between the two is a quantity — the loops the mapping created — instead of a
    /// decision nobody recorded.
    ///
    /// ⚠️ A self-join becomes a **loop**, and a loop is an edge. `FROM employee e1 JOIN employee
    /// e2` collapses to one node carrying one edge to itself: `m - n + c` is `1 - 1 + 1 = 1`, so
    /// the cycle the collapse created is counted rather than dropped.
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
        let key = |occ: u32| -> Vec<u8> {
            match self.occurrences.get(occ as usize) {
                Some(o) => key_of(o, occ),
                None => format!("\u{0}gone{occ}").into_bytes(),
            }
        };

        let mut nodes: Vec<Vec<u8>> = self.occurrences.iter().map(|o| key_of(o, o.occ)).collect();
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
            // ⛔ `m - n + c` is the UNDIRECTED cycle space. On a graph with no loops it cannot go
            // negative, because a component of `k` nodes carries at least `k - 1` edges; the
            // saturating subtraction is hygiene rather than a case that arises.
            cycle_space: (m + c).saturating_sub(n),
            incidences: self.edges.len(),
        }
    }

    /// Whether an occurrence sits anywhere beneath the body of a `CREATE VIEW`.
    ///
    /// ⭐ A relation this is true of was NAMED and not READ. See [`ScopeKind::ViewBody`].
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

    /// Subqueries in expression position, counted by `sqlparser`'s own `visit_expressions`
    /// rather than by this module's walk.
    ///
    /// ⛔ THIS EXISTS TO BE DISAGREED WITH. [`Builder::walk_expr`] descends into a named list of
    /// `Expr` forms and does nothing with the rest, so a subquery inside a form it does not name
    /// would be silently absent. A count taken by a route that shares no code with the walk is
    /// what turns that from an invisible omission into a failing test.
    pub fn nested_query_count(statement: &Statement) -> usize {
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
}

/// Nodes, edges and components of a [`StatementGraph`], and the cycle space they fix.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct GraphMeasures {
    /// distinct node identities
    pub nodes: usize,
    /// distinct unordered edges. ⚠️ **Loops are edges and are counted**, which is not an
    /// oversight: under [`StatementGraph::measures_collapsed_by_name`] a self-join becomes one
    /// node carrying an edge to itself, and dropping it would hide the cycle the mapping made.
    pub edges: usize,
    /// connected components
    pub components: usize,
    /// ⭐ `m - n + c`, the dimension of the UNDIRECTED cycle space. Zero means the graph is a
    /// forest. A statement whose join graph is a tree reaches every relation one way; one whose
    /// is not reaches some relation by two routes, and the second route is a double count.
    pub cycle_space: usize,
    /// edges before deduplication, i.e. how many relationships the statement wrote down
    pub incidences: usize,
}

#[derive(Default)]
struct Builder {
    graph: StatementGraph,
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
        // ⭐ Resolved against the scopes that ENCLOSE this one, innermost first, because a CTE
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
            // list is written BEFORE the `FROM` it refers to, so nothing to resolve against
            // exists yet at this point.
            resolves_to_occ: None,
        });
        occ
    }

    /// ⛔⛔ A TARGET LIST NAMES RELATIONS THE STATEMENT ALREADY INTRODUCED, AND NAMES THEM BY
    /// ALIAS. `DELETE o, p FROM orders o JOIN payments p ON ...` wrote four relation mentions
    /// and opened two tables. Without this the graph said it opened four, two of them called
    /// `o` and `p`, and the only two the server actually wrote to were filed as reads.
    ///
    /// ⚠️ MATCHED ON [`RelationOccurrence::identity`] AND NOT ON THE WRITTEN NAME, because that
    /// is the rule MySQL itself enforces: a relation given an alias must be referred to by that
    /// alias and may not be referred to by its table name. So `identity()` is exactly the set of
    /// names a target list is allowed to use, and matching anything else would invent a
    /// resolution the server would have rejected.
    ///
    /// ⚠️ Scope-local, and that is not a simplification: a target list and the `FROM` it refers
    /// to are the same statement level by the grammar. A correlated name from an enclosing scope
    /// cannot be a delete target.
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
    /// ⛔ INNERMOST WINS, because that is what SQL does. `actor_info` reuses `fa` and `fc` inside
    /// its correlated subquery for different relations than the outer query binds them to.
    fn resolve(&self, qualifier: &Bytes, scope: u32) -> Option<u32> {
        let mut at = Some(scope);
        while let Some(id) = at {
            if let Some(o) = self
                .graph
                .occurrences
                .iter()
                .find(|o| o.scope == id && o.alias.as_ref() == Some(qualifier))
            {
                return Some(o.occ);
            }
            if let Some(o) = self.graph.occurrences.iter().find(|o| {
                o.scope == id && o.alias.is_none() && o.object_name.as_ref() == Some(qualifier)
            }) {
                return Some(o.occ);
            }
            at = self.graph.scopes.get(id as usize)?.parent;
        }
        None
    }

    fn walk_statement(&mut self, statement: &Statement, scope: u32) {
        match statement {
            Statement::Query(q) => self.walk_query(q, scope),
            Statement::Insert(Insert { table, source, .. }) => {
                if let TableObject::TableName(name) = table {
                    self.push_occurrence(scope, Some(name), None, RelationRole::InsertTarget);
                }
                // ⭐ `INSERT ... SELECT` is a write edge and a whole read subgraph at once, and
                // `objects()` puts both sides in one undifferentiated set.
                if let Some(q) = source {
                    self.walk_query(q, scope);
                }
            }
            Statement::Update {
                table,
                from,
                selection,
                ..
            } => {
                // ⚠️ MySQL's multi-table `UPDATE a JOIN b` puts a whole join graph in the TARGET
                // position, so this is a `TableWithJoins` and not a name.
                let ids = self.collect_from(std::slice::from_ref(table), scope, true);
                self.join_edges(std::slice::from_ref(table), scope, &ids);
                if let Some(UpdateTableFromKind::BeforeSet(f) | UpdateTableFromKind::AfterSet(f)) =
                    from
                {
                    let ids = self.collect_from(f, scope, false);
                    self.join_edges(f, scope, &ids);
                }
                if let Some(e) = selection {
                    self.walk_expr(e, scope);
                    self.predicate_edges(e, scope, JoinOp::Correlation, ConstraintKind::On);
                }
            }
            Statement::Delete(Delete {
                tables,
                from,
                using,
                selection,
                ..
            }) => {
                for name in tables {
                    // ⛔ Never visited by `visit_relations`: `Delete.tables` carries no
                    // `visit_relation` annotation, so MySQL's `DELETE t1, t2 FROM ...` target
                    // list is absent from `objects()` entirely.
                    self.push_occurrence(scope, Some(name), None, RelationRole::DeleteTarget);
                }
                let (FromTable::WithFromKeyword(f) | FromTable::WithoutKeyword(f)) = from;
                let ids = self.collect_from(f, scope, false);
                self.join_edges(f, scope, &ids);
                if let Some(u) = using {
                    let ids = self.collect_from(u, scope, false);
                    self.join_edges(u, scope, &ids);
                }
                if let Some(e) = selection {
                    self.walk_expr(e, scope);
                    self.predicate_edges(e, scope, JoinOp::Correlation, ConstraintKind::On);
                }
            }
            Statement::CreateView { name, query, .. } => {
                // ⛔ `CreateView.name` carries no `visit_relation` annotation either, so the view
                // a statement brings into being is missing from `objects()` while every relation
                // in its body is present.
                self.push_occurrence(scope, Some(name), None, RelationRole::CreateTarget);
                let body = self.push_scope(Some(scope), ScopeKind::ViewBody, None, false);
                self.walk_query(query, body);
            }
            Statement::CreateTable(ct) => {
                self.push_occurrence(scope, Some(&ct.name), None, RelationRole::CreateTarget);
                if let Some(q) = &ct.query {
                    let body = self.push_scope(Some(scope), ScopeKind::ViewBody, None, false);
                    self.walk_query(q, body);
                }
            }
            // ⛔⛔ A READER NEEDS THEM AS NODES NOW, AND THIS ARM USED TO SAY SO AND LEAVE THEM.
            // `demand.parquet` separates a `ddl` from a `write` because a DDL takes
            // `MDL_EXCLUSIVE` and blocks every reader of its table while a row write does not —
            // and the only two statements that reached that role were `CREATE VIEW` and
            // `CREATE TABLE`, neither of which can block a reader of an existing table, because
            // the table did not exist. The 32 `ALTER TABLE`s and 11 `DROP`s in the shipped log
            // contributed no occurrence at all, so the strongest claim that artifact makes about
            // MySQL applied to nothing in it.
            //
            // ⚠️ `AlterTable.name` carries `visit_relation`, so it was at least in `objects()`.
            // `Drop.names` carries no annotation, so a dropped table was absent from every
            // artifact in both crates.
            // ⚠️ `ALTER VIEW` files the same way: it redefines a relation that already exists.
            Statement::AlterTable { name, .. } | Statement::AlterView { name, .. } => {
                self.push_occurrence(scope, Some(name), None, RelationRole::AlterTarget);
            }
            // ⭐ AN INDEX IS NOT A RELATION, AND THE TABLE IS THE ONE THAT GETS LOCKED.
            // `CREATE INDEX idx ON invoice (year)` is filed as an alter of `invoice`; `idx` is
            // named by the statement and is not a thing another statement can contend for, so
            // it gets no occurrence and no role of its own.
            Statement::CreateIndex(ci) => {
                self.push_occurrence(scope, Some(&ci.table_name), None, RelationRole::AlterTarget);
            }
            Statement::Truncate { table_names, .. } => {
                for t in table_names {
                    self.push_occurrence(
                        scope,
                        Some(&t.name),
                        None,
                        RelationRole::TruncateTarget,
                    );
                }
            }
            // ⛔ A RENAME IS A DROP AND A CREATE, AND THAT IS A CLAIM THIS FILE MAKES ON PURPOSE.
            // It is false about the data — MySQL moves the table rather than rebuilding it — and
            // exact about the NAMES, which is what a relation graph is about: after
            // `RENAME TABLE a TO b` nothing can open `a` and `b` is openable where it was not.
            // Both ends take `MDL_EXCLUSIVE`, so both reach the same class downstream.
            Statement::RenameTable(renames) => {
                for r in renames {
                    self.push_occurrence(scope, Some(&r.old_name), None, RelationRole::DropTarget);
                    self.push_occurrence(scope, Some(&r.new_name), None, RelationRole::CreateTarget);
                }
            }
            // ⭐⭐ `LockTables.tables` CARRIES NO `visit_relation` ANNOTATION, so a table a client
            // locked explicitly was invisible to `objects()` and to everything built on it.
            // ⚠️ The alias is the author's and is kept as the occurrence's identity, exactly as
            // in a `FROM` clause: `LOCK TABLES invoice AS i READ` names `i`.
            Statement::LockTables { tables } => {
                for t in tables {
                    let role = match t.lock_type {
                        LockTableType::Write { .. } => RelationRole::LockExclusiveTarget,
                        LockTableType::Read { .. } => RelationRole::LockSharedTarget,
                    };
                    let alias = t.alias.as_ref().map(ident_bytes);
                    // ⛔ `LockTable.table` IS AN `Ident` AND NOT AN `ObjectName`, so this
                    // grammar cannot express `LOCK TABLES shop.invoice WRITE` at all — MySQL
                    // accepts it and `sqlparser` refuses it. The name is lifted into an
                    // `ObjectName` of one part so it files like every other relation, and a
                    // lock on a qualified table is a statement this reader files as `invalid`.
                    let name = ObjectName(vec![ObjectNamePart::Identifier(t.table.clone())]);
                    self.push_occurrence(scope, Some(&name), alias, role);
                }
            }
            Statement::Analyze { table_name, .. } => {
                self.push_occurrence(scope, Some(table_name), None, RelationRole::AnalyzeTarget);
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
            // ⚠️ WHAT IS STILL NOT WALKED, AND WHY, because "every other form names nothing" was
            // wrong twice already:
            //
            // | form | names a relation | state |
            // |---|---|---|
            // | `FLUSH TABLES t` | `Flush.tables`, **unannotated** | ⛔ not walked — takes a metadata lock and is invisible |
            // | `SHOW CREATE TABLE t` | `ShowCreate.obj_name`, unannotated | ⛔ not walked — reads the dictionary, opens nothing |
            // | `EXPLAIN t` / `DESCRIBE t` | `ExplainTable.table_name`, annotated | ⛔ not walked — reads the dictionary |
            // | `OPTIMIZE` / `CHECK` / `REPAIR TABLE` | — | ⛔ `sqlparser` refuses them outright |
            // | `DROP INDEX idx ON t` | — | ⛔ `sqlparser` refuses MySQL's form |
            // | `LOAD DATA INFILE … INTO TABLE t` | — | ⛔ `sqlparser` refuses MySQL's form |
            //
            // ⛔ The annotated ones are held by a law rather than by this comment:
            // `nothing objects() found may be missing from the graph` fires the moment one
            // appears in a corpus, which is what makes the row above a decision and not a gap.
            _ => {}
        }
    }

    fn walk_query(&mut self, query: &Query, scope: u32) {
        if let Some(with) = &query.with {
            for Cte { alias, query, .. } in &with.cte_tables {
                // ⛔ A CTE's name is an `Ident` on its alias and NOT an `ObjectName`, so the
                // definition site is invisible to `visit_relations` while every reference to it
                // parses as an ordinary table and is visited. That is how a name that is not a
                // relation ends up filed as one.
                let name = Some(ident_bytes(&alias.name));
                let cte = self.push_scope(Some(scope), ScopeKind::Cte, name, with.recursive);
                self.walk_query(query, cte);
            }
        }
        self.walk_set_expr(&query.body, scope);
    }

    fn walk_set_expr(&mut self, body: &SetExpr, scope: u32) {
        match body {
            SetExpr::Select(s) => self.walk_select(s, scope),
            SetExpr::Query(q) => self.walk_query(q, scope),
            SetExpr::SetOperation { left, right, .. } => {
                for side in [left, right] {
                    let s = self.push_scope(Some(scope), ScopeKind::SetOp, None, false);
                    self.walk_set_expr(side, s);
                }
            }
            SetExpr::Insert(s) | SetExpr::Update(s) | SetExpr::Delete(s) => {
                self.walk_statement(s, scope)
            }
            SetExpr::Values(_) | SetExpr::Table(_) => {}
        }
    }

    fn walk_select(&mut self, select: &Select, scope: u32) {
        // ⭐ TWO PASSES, AND THE ORDER IS THE POINT. Every occurrence has to exist before any
        // predicate is resolved, because a join's `ON` clause routinely names a relation the
        // parser has not reached yet and a one-pass walk would drop that edge.
        let ids = self.collect_from(&select.from, scope, false);
        self.join_edges(&select.from, scope, &ids);

        for e in select
            .selection
            .iter()
            .chain(select.having.iter())
            .chain(select.prewhere.iter())
            .chain(select.qualify.iter())
        {
            self.walk_expr(e, scope);
            self.predicate_edges(e, scope, JoinOp::Correlation, ConstraintKind::On);
        }
        for item in &select.projection {
            // ⭐ `actor_info`'s correlated subquery lives inside a `GROUP_CONCAT` inside a
            // `CONCAT` in the projection, which is why the projection is walked at all.
            for e in select_item_exprs(item) {
                self.walk_expr(e, scope);
                self.predicate_edges(e, scope, JoinOp::Correlation, ConstraintKind::On);
            }
        }
    }

    /// Pass one: every relation occurrence in a `FROM` list, in written order.
    fn collect_from(&mut self, from: &[TableWithJoins], scope: u32, target: bool) -> Vec<Vec<u32>> {
        from.iter()
            .map(|twj| {
                let base = if target {
                    RelationRole::UpdateTarget
                } else {
                    RelationRole::From
                };
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
    /// ⛔ `TableWithJoins.joins` IS A FLAT LEFT-DEEP CHAIN, NOT A TREE. Joining each relation to
    /// its predecessor would draw `sales_by_store` as a seven-link chain when it is a branch:
    /// `store` is joined to `address` and to `staff` both. The branch exists only in the `ON`
    /// clauses, so that is where it is read from, and the chain is the fallback for a join that
    /// says nothing this walk can resolve.
    fn join_edges(&mut self, from: &[TableWithJoins], scope: u32, ids: &[Vec<u32>]) {
        for (twj, ids) in from.iter().zip(ids) {
            // A comma in a `FROM` list is a cross join between whole `TableWithJoins`, which is
            // why it is drawn between the first relations of each rather than inside one.
            for (i, j) in twj.joins.iter().enumerate() {
                let rhs = ids[i + 1];
                let (op, constraint) = classify(&j.join_operator);
                let named = match constraint_expr(&j.join_operator) {
                    Some(e) => self.resolved_qualifiers(e, scope),
                    None => Vec::new(),
                };
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
        for pair in ids.windows(2) {
            if let (Some(a), Some(b)) = (pair[0].first(), pair[1].first()) {
                self.push_edge(*a, *b, JoinOp::Comma, ConstraintKind::None);
            }
        }
    }

    fn walk_table_factor(&mut self, tf: &TableFactor, scope: u32, role: RelationRole) -> u32 {
        match tf {
            TableFactor::Table { name, alias, .. } => {
                let a = alias.as_ref().map(|a| ident_bytes(&a.name));
                self.push_occurrence(scope, Some(name), a, role)
            }
            TableFactor::Derived {
                subquery, alias, ..
            } => {
                // ⭐ A derived table is a node in the OUTER scope with no object name at all, and
                // `visit_relations` cannot see it: `TableFactor::Derived` carries no `ObjectName`,
                // so only the base tables inside its subquery are ever visited and the thing the
                // rest of the query joins to is absent.
                let a = alias.as_ref().map(|a| ident_bytes(&a.name));
                let occ = self.push_occurrence(scope, None, a, role);
                let inner = self.push_scope(Some(scope), ScopeKind::Derived, None, false);
                self.walk_query(subquery, inner);
                occ
            }
            TableFactor::NestedJoin {
                table_with_joins,
                alias,
            } => {
                let a = alias.as_ref().map(|a| ident_bytes(&a.name));
                let occ = self.push_occurrence(scope, None, a, role);
                let ids = self.collect_from(std::slice::from_ref(table_with_joins), scope, false);
                self.join_edges(std::slice::from_ref(table_with_joins), scope, &ids);
                occ
            }
            TableFactor::Function { name, alias, .. } => {
                // ⛔ Also unannotated, so also absent from `objects()`.
                let a = alias.as_ref().map(|a| ident_bytes(&a.name));
                self.push_occurrence(scope, Some(name), a, role)
            }
            other => {
                let a = table_factor_alias(other);
                self.push_occurrence(scope, None, a, role)
            }
        }
    }

    /// Descends into an expression looking for subqueries.
    ///
    /// ⚠️ The forms named here are the ones this walk descends into. Anything else is a leaf as
    /// far as this module is concerned, and [`StatementGraph::nested_query_count`] is the second
    /// route that makes such an omission fail a test rather than pass quietly.
    fn walk_expr(&mut self, expr: &Expr, scope: u32) {
        match expr {
            Expr::Subquery(q) | Expr::Exists { subquery: q, .. } => {
                let inner = self.push_scope(Some(scope), ScopeKind::Subquery, None, false);
                self.walk_query(q, inner);
            }
            Expr::InSubquery { expr, subquery, .. } => {
                // ⚠️ `InSubquery.subquery` is a `SetExpr` and NOT a `Query`, so it has no `with`
                // field and cannot carry CTEs, while `Exists` and `Subquery` hold a whole `Query`
                // and can. One entry point for both silently drops the difference.
                self.walk_expr(expr, scope);
                let inner = self.push_scope(Some(scope), ScopeKind::Subquery, None, false);
                self.walk_set_expr(subquery, inner);
            }
            Expr::BinaryOp { left, right, .. } => {
                self.walk_expr(left, scope);
                self.walk_expr(right, scope);
            }
            Expr::UnaryOp { expr, .. }
            | Expr::Nested(expr)
            | Expr::IsNull(expr)
            | Expr::IsNotNull(expr)
            | Expr::IsTrue(expr)
            | Expr::IsNotTrue(expr)
            | Expr::IsFalse(expr)
            | Expr::IsNotFalse(expr)
            | Expr::Cast { expr, .. }
            | Expr::Collate { expr, .. } => self.walk_expr(expr, scope),
            Expr::Between {
                expr, low, high, ..
            } => {
                for e in [expr, low, high] {
                    self.walk_expr(e, scope);
                }
            }
            Expr::InList { expr, list, .. } => {
                self.walk_expr(expr, scope);
                for e in list {
                    self.walk_expr(e, scope);
                }
            }
            Expr::Like { expr, pattern, .. } | Expr::ILike { expr, pattern, .. } => {
                self.walk_expr(expr, scope);
                self.walk_expr(pattern, scope);
            }
            Expr::Case {
                operand,
                conditions,
                else_result,
                ..
            } => {
                for e in operand.iter().chain(else_result.iter()) {
                    self.walk_expr(e, scope);
                }
                for w in conditions {
                    self.walk_expr(&w.condition, scope);
                    self.walk_expr(&w.result, scope);
                }
            }
            Expr::Function(f) => {
                for e in function_arg_exprs(f) {
                    self.walk_expr(e, scope);
                }
            }
            Expr::Tuple(es) => {
                for e in es {
                    self.walk_expr(e, scope);
                }
            }
            _ => {}
        }
    }

    /// Draws edges between the occurrences a predicate names on either side of a comparison.
    ///
    /// ⛔ A CONNECTIVE IS NOT A COMPARISON, AND CONFLATING THEM MANUFACTURES EDGES. Read
    /// `a.x = b.x AND c.y = d.y` as one operator with two sides and the qualifiers on each side
    /// cross-multiply: four edges, of which `a–d` and `c–b` were never written down. Only the
    /// comparison arms carry an edge; `AND`, `OR` and `XOR` are descended through and contribute
    /// none of their own.
    fn predicate_edges(&mut self, expr: &Expr, scope: u32, op: JoinOp, constraint: ConstraintKind) {
        use sqlparser::ast::BinaryOperator as B;
        match expr {
            Expr::BinaryOp {
                left,
                right,
                op: B::And | B::Or | B::Xor,
            } => {
                self.predicate_edges(left, scope, op, constraint);
                self.predicate_edges(right, scope, op, constraint);
            }
            Expr::BinaryOp { left, right, .. } => {
                let (l, r) = (
                    self.resolved_qualifiers(left, scope),
                    self.resolved_qualifiers(right, scope),
                );
                for a in &l {
                    for b in &r {
                        if a != b {
                            self.push_edge(*a, *b, op, constraint);
                        }
                    }
                }
            }
            Expr::Nested(e) | Expr::UnaryOp { expr: e, .. } => {
                self.predicate_edges(e, scope, op, constraint)
            }
            _ => {}
        }
    }

    /// The occurrences named by the qualifiers of every `alias.column` in an expression.
    ///
    /// ⛔ Does not descend into a nested subquery: a qualifier written inside one is resolved in
    /// that subquery's own scope when the walk reaches it, and pulling it up here would draw the
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

fn collect_qualifiers(expr: &Expr, f: &mut impl FnMut(Bytes)) {
    match expr {
        Expr::CompoundIdentifier(parts) if parts.len() >= 2 => f(ident_bytes(&parts[0])),
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
        J::FullOuter(c) => (JoinOp::FullOuter, kind(c)),
        J::Semi(c) | J::LeftSemi(c) | J::RightSemi(c) => (JoinOp::Semi, kind(c)),
        J::Anti(c) | J::LeftAnti(c) | J::RightAnti(c) => (JoinOp::Anti, kind(c)),
        J::StraightJoin(c) => (JoinOp::Straight, kind(c)),
        J::AsOf { constraint, .. } => (JoinOp::AsOf, kind(constraint)),
        J::CrossJoin => (JoinOp::Cross, ConstraintKind::None),
        J::CrossApply | J::OuterApply => (JoinOp::Apply, ConstraintKind::None),
    }
}

fn constraint_expr(op: &JoinOperator) -> Option<&Expr> {
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
        J::CrossJoin | J::CrossApply | J::OuterApply => return None,
    };
    match c {
        JoinConstraint::On(e) => Some(e),
        _ => None,
    }
}

fn ident_bytes(i: &sqlparser::ast::Ident) -> Bytes {
    Bytes::from(i.value.clone())
}

fn split_name(n: &ObjectName) -> (Option<Bytes>, Option<Bytes>) {
    let parts: Vec<Bytes> = n
        .0
        .iter()
        .map(|p| {
            let ObjectNamePart::Identifier(i) = p;
            ident_bytes(i)
        })
        .collect();
    match parts.len() {
        0 => (None, None),
        1 => (None, Some(parts[0].clone())),
        // ⚠️ Three parts is `catalog.schema.object`; the catalogue is dropped and the last two
        // kept, which is the same reading `objects()` has always taken.
        _ => (
            Some(parts[parts.len() - 2].clone()),
            Some(parts[parts.len() - 1].clone()),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlparser::dialect::MySqlDialect;
    use sqlparser::parser::Parser;

    fn graph(sql: &str) -> StatementGraph {
        StatementGraph::of(&one(sql))
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

    /// ⭐ THE CASE `objects()` CANNOT EXPRESS AT ALL. Its `BTreeSet` returns one name, and
    /// `PLAN-2026-09-22-02-fusion.md`'s T1.10 records that as `k = 1` — which is true of the set
    /// and false of the statement. Two occurrences is what the statement said.
    #[test]
    fn a_self_join_is_two_nodes() {
        let g = graph("SELECT * FROM employee e1 JOIN employee e2 ON e1.manager_id = e2.id");
        assert_eq!(ids(&g), vec!["e1", "e2"]);
        assert_eq!(g.edges.len(), 1);
        let m = g.measures();
        assert_eq!((m.nodes, m.edges, m.cycle_space), (2, 1, 0));

        // Both occurrences carry the same written name, so a reader holding a catalogue can
        // still collapse them. The collapse is theirs to make and this crate does not make it.
        let names: Vec<_> = g.occurrences.iter().map(|o| o.object_name.clone()).collect();
        assert_eq!(names[0], names[1]);
    }

    /// ⛔ A CTE NAME IS NOT A RELATION, AND `objects()` FILES IT AS ONE. The definition site is an
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

    /// ⛔ `TableFactor::Derived` CARRIES NO `ObjectName`, so `visit_relations` never sees the
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

    /// ⭐ THE BRANCH IS IN THE PREDICATE AND NOWHERE ELSE. `TableWithJoins.joins` is a flat
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

    /// ⭐⭐ THE WITNESS THE `process-modulus` CORPUS DOES NOT HAVE. `rank/composition_closure.sqlc`
    /// computes a fusion's kernel two ways and says the two "agree exactly where the descent is a
    /// tree". Every layer graph in that corpus is a forest, so the disagreeing case is unreached.
    /// `actor_info` reaches it: `film_category` and `film_actor` are each named twice, once in the
    /// outer join chain and once inside the correlated subquery, and the two correlation edges
    /// close a cycle.
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

    /// ⭐ A RELATION NAMED IN A VIEW BODY WAS NOT READ, and `objects()` spells the two the same.
    /// On the shipped fixture every multi-relation statement is a `CREATE VIEW`, so an
    /// elimination computed over "tables this statement touched" is drawn entirely from
    /// statements that touched none of them.
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
        assert!(!g.in_view_body(view.occ), "the view is not inside its own body");

        for o in g.occurrences.iter().filter(|o| o.occ != view.occ) {
            assert!(g.in_view_body(o.occ), "{:?} was named, not scanned", ids(&g));
        }
    }

    /// ⛔⛔ THE DDL THAT BLOCKS A READER NAMED NOTHING. `demand.parquet` separates `ddl` from
    /// `write` on the argument that a DDL takes `MDL_EXCLUSIVE` and blocks every reader of its
    /// table — and the only statements that reached that role were `CREATE VIEW` and
    /// `CREATE TABLE`, which name a relation that did not exist and so can block nobody. The
    /// shipped log's 32 `ALTER TABLE`s and 11 `DROP`s contributed no occurrence.
    ///
    /// ⚠️ And they are three roles rather than one, because a `CREATE` names a relation that was
    /// not there before and a `DROP` names one that is not there after.
    #[test]
    fn the_ddl_that_can_block_a_reader_names_the_table_it_locks() {
        // ⚠️ `ALTER TABLE ... DISABLE KEYS`, which is what the shipped log's 32 alters actually
        // say, is refused by `sqlparser` outright — so those rows are `invalid` and reach no
        // graph at all. The role has a witness through the forms that do parse.
        let g = graph("ALTER TABLE `actor` ADD COLUMN last_seen DATETIME");
        let o = g
            .occurrences
            .iter()
            .find(|o| o.role == RelationRole::AlterTarget)
            .expect("⛔ ALTER TABLE reached `objects()` and no artifact that has roles");
        assert_eq!(o.object_name.as_deref(), Some(b"actor".as_ref()));

        let g = graph("DROP TABLE IF EXISTS sakila.film_text, sakila.staff_list");
        let dropped: Vec<_> = g
            .occurrences
            .iter()
            .filter(|o| o.role == RelationRole::DropTarget)
            .filter_map(|o| o.object_name.clone())
            .collect();
        assert_eq!(dropped.len(), 2, "⛔ `Drop.names` is unannotated: {dropped:?}");
        assert_eq!(dropped[0].as_ref(), b"film_text");

        // ⚠️ And the schema survives, which is what lets a dropped table join a demand layer.
        let schemas: Vec<_> = g
            .occurrences
            .iter()
            .filter_map(|o| o.schema_name.clone())
            .collect();
        assert_eq!(schemas.len(), 2);
    }

    /// ⭐⭐⭐ THE LOCK THE LOG MEASURES THE WAIT FOR, AND THE STATEMENT THAT TAKES IT.
    ///
    /// `Lock_time` in a slow log is table-level and metadata lock wait. `LOCK TABLES` is how a
    /// client asks for precisely that, `mysqldump` writes one before every table it restores,
    /// and `LockTables.tables` carries no `visit_relation` annotation — so the sixteen explicit
    /// write locks in the shipped corpus reached no artifact in either crate.
    ///
    /// ⚠️ The two modes are two roles because they exclude different things: a read lock admits
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

        // ⛔ AND THE GRAMMAR CANNOT SAY IT ABOUT A QUALIFIED TABLE. `LockTable.table` is an
        // `Ident`, so `LOCK TABLES shop.invoice WRITE` — valid MySQL — is refused outright and
        // becomes an `invalid` entry with no graph. That is the grammar's regime and not the
        // server's, and the two are different claims.
        use sqlparser::dialect::MySqlDialect;
        use sqlparser::parser::Parser as SqlParser;
        assert!(SqlParser::parse_sql(&MySqlDialect {}, "LOCK TABLES shop.i WRITE").is_err());
    }

    /// ⭐ THE REST OF THE WALK, each form the reason it is here.
    ///
    /// | statement | files | because |
    /// |---|---|---|
    /// | `TRUNCATE t` | `TruncateTarget` | InnoDB drops and recreates the tablespace — `MDL_EXCLUSIVE`, not row locks |
    /// | `CREATE INDEX i ON t` | `AlterTarget` on `t` | ⭐ the index is not a relation; the table is what gets locked |
    /// | `RENAME TABLE a TO b` | `DropTarget` + `CreateTarget` | ⛔ false about the data, exact about the names |
    /// | `ALTER VIEW v` | `AlterTarget` | it redefines a relation that already exists |
    /// | `ANALYZE TABLE t` | `AnalyzeTarget` | ⚠️ single-table only — this grammar refuses MySQL's list form |
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

        // ⛔ THE SCHEMA SURVIVES WHERE THE GRAMMAR CARRIES ONE, which is what lets these join a
        // demand layer rather than degenerating to a bare name.
        let g = graph("CREATE INDEX idx_year ON shop.invoice (year)");
        assert_eq!(g.occurrences[0].schema_name.as_deref(), Some(b"shop".as_ref()));
    }

    /// ⛔ `Delete.tables` carries no `visit_relation` annotation, so MySQL's multi-table delete
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

    /// ⛔⛔ AND THE TARGETS ARE NOT RELATIONS OF THEIR OWN, which is what the count above could
    /// not see. MySQL names a multi-table delete's targets **by alias**, so
    /// `DELETE o, p FROM orders o JOIN payments p` put two relations called `o` and `p` into the
    /// graph — tables that do not exist — while recording no write against `orders` or
    /// `payments` at all. Anything asking which physical tables a statement touched got two
    /// phantoms and two reads where there were two reads and two writes.
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

        // ⭐ NON-VACUITY FROM THE OTHER SIDE: a target list written with the table names rather
        // than aliases resolves too, because then the table name IS the identity.
        let g2 = graph("DELETE t1, t2 FROM t1 JOIN t2 ON t1.id = t2.t1_id");
        assert!(g2
            .occurrences
            .iter()
            .filter(|o| o.role == RelationRole::DeleteTarget)
            .all(|o| o.resolves_to_occ.is_some()));

        // ⛔ AND A RELATION THAT NAMES ITSELF RESOLVES TO NOTHING, which is what stops this from
        // marking every occurrence as a reference. A single-table delete has no target list.
        let g3 = graph("DELETE FROM orders WHERE id = 1");
        assert!(g3.occurrences.iter().all(|o| o.resolves_to_occ.is_none()));
    }

    #[test]
    fn a_union_puts_each_side_in_its_own_scope() {
        let g = graph("SELECT a FROM t1 UNION SELECT b FROM t2");
        assert_eq!(
            g.scopes.iter().filter(|s| s.kind == ScopeKind::SetOp).count(),
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

    /// ⛔⛔ THE GUARD ON THIS MODULE'S OWN BLIND SPOT. [`Builder::walk_expr`] descends into a named
    /// list of `Expr` forms; a subquery inside a form it does not name would simply be missing,
    /// and nothing about the resulting graph would look wrong. This counts the same subqueries
    /// through `sqlparser`'s own `visit_expressions`, which shares no code with the walk.
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
                StatementGraph::nested_query_count(&s),
                "the walk and visit_expressions disagree on: {sql}"
            );
        }
    }

    /// ⭐⭐ THE READER'S MAPPING IS A QUANTITY, NOT A SETTING. Under the statement's own reading a
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

    /// The same two readings over the correlated case. ⭐ Note that the cycle survives BOTH: it is
    /// closed by the correlation edges, not by the collapse, so the one witness this corpus has
    /// for a non-tree descent does not depend on which identity a reader takes.
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

    /// ⚠️ An unparseable statement and an admin command have no graph, and that is the same
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
}
