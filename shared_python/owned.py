"""Per-person data ownership for SQLAlchemy apps: one person must never see or change another's rows.

Every table that holds a person's data gets `owner_id` by inheriting `OwnedMixin`. Then, instead of trusting every
query in the app to remember `.filter(owner_id == me)`, the filter is applied BELOW the app, to every ORM statement:

* While a request runs inside `scope(person_id)`, every SELECT, UPDATE and DELETE touching an owned table is
  filtered to that person automatically, including joins, subqueries, aggregates, relationship loads and by-id
  lookups. A route that forgets its own check cannot leak: it just finds nothing.
* With no scope at all the filter matches nothing (it fails closed), so code that runs outside a request cannot
  read anyone's data by accident.
* New rows get their owner filled in from the scope. A write that would put a row in someone else's name, move a
  row to another person, or change or delete a row that belongs to someone else raises instead of happening.
* A row may not point at another person's row (a foreign key or relationship to a category, folder, job... that is
  someone else's): that raises too, whatever id a request names.
* `unscoped()` is the explicit, greppable way out, for migrations and account administration only.

This is the second line of defence. The first is that routes ask only for the signed-in person's own things, and
each app tests every route with two people. Known limits: an object already in a session's identity map (loaded with `unscoped()` in the same session) is
returned by `session.get()` without a query, so never mix unscoped and scoped work in one session; raw SQL (`session.execute(text(...))`) and a BARE
`exists().where(Model.col == x)` (a plain subquery SQLAlchemy does not see as touching the model) are not filtered, so
apps must not use them on owned tables; write `select(Model.id).where(...).exists()` or `query.filter(...).exists()`
instead. `assert_no_raw_sql` lets a test enforce both.

Install once at start-up (`owned.install()`); it hooks SQLAlchemy's Session globally, so every session is covered.
"""
import re
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Iterable, Optional

from sqlalchemy import Column, ForeignKey, Integer, event, false, select
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.orm import MANYTOONE, Session, attributes, declared_attr, with_loader_criteria


class NoOwner(RuntimeError):
    """A row was written with no person in scope."""


class WrongOwner(RuntimeError):
    """A write that would touch a row belonging to someone else (or give a row to someone else)."""


_UNSCOPED = object()
_owner: ContextVar = ContextVar("shared_python_owner", default=None)


class OwnedMixin:
    """Put on every model whose rows belong to one person. Needs a `users` table with an integer `id`."""

    @declared_attr
    def owner_id(cls):
        return Column(Integer, ForeignKey("users.id"), nullable=False, index=True)


def current_owner() -> Optional[int]:
    """The person in scope, or None (no scope, or `unscoped()`)."""
    value = _owner.get()
    return None if value is _UNSCOPED else value


@contextmanager
def scope(owner_id: int):
    """Everything inside sees, and writes, only `owner_id`'s rows."""
    if isinstance(owner_id, bool) or not isinstance(owner_id, int):
        raise TypeError("scope() needs a person's integer id")
    token = _owner.set(owner_id)
    try:
        yield
    finally:
        _owner.reset(token)


@contextmanager
def unscoped():
    """No filtering and no write checks. Only for migrations and account administration: never for a request that
    handles a person's data."""
    token = _owner.set(_UNSCOPED)
    try:
        yield
    finally:
        _owner.reset(token)


def _filter_statements(state) -> None:
    owner = _owner.get()
    if owner is _UNSCOPED:
        return
    if not (state.is_select or state.is_update or state.is_delete):
        return
    if state.is_column_load:
        return  # refreshing columns of a row already loaded; relationship loads ARE filtered (they do not inherit it)
    if owner is None:
        criteria = lambda cls: false()  # noqa: E731 - no person in scope: no rows
    else:
        criteria = lambda cls: cls.owner_id == owner  # noqa: E731
    state.statement = state.statement.options(with_loader_criteria(OwnedMixin, criteria, include_aliases=True))


def _guard_writes(session, flush_context, instances) -> None:
    owner = _owner.get()
    if owner is _UNSCOPED:
        return
    for obj in session.new:
        if not isinstance(obj, OwnedMixin):
            continue
        if owner is None:
            raise NoOwner(f"Refusing to add a {type(obj).__name__} with no person in scope")
        if obj.owner_id is None:
            obj.owner_id = owner
        elif obj.owner_id != owner:
            raise WrongOwner(f"Refusing to add a {type(obj).__name__} owned by someone else")
    for obj in list(session.dirty):
        if not isinstance(obj, OwnedMixin) or not session.is_modified(obj, include_collections=False):
            continue
        moved = attributes.get_history(obj, "owner_id").has_changes()
        if owner is None or obj.owner_id != owner or moved:
            raise WrongOwner(f"Refusing to change a {type(obj).__name__} that is not this person's")
    for obj in session.deleted:
        if isinstance(obj, OwnedMixin) and (owner is None or obj.owner_id != owner):
            raise WrongOwner(f"Refusing to delete a {type(obj).__name__} that is not this person's")
    # Last, once every new row has its owner: nothing of this person's may POINT AT another person's row (a category,
    # folder, job... named by id in a request). Apps still answer such a request with a clean 400/404 of their own;
    # this is the backstop for the one that forgets.
    for obj in list(session.new) + [o for o in session.dirty if session.is_modified(o, include_collections=False)]:
        if isinstance(obj, OwnedMixin):
            _check_references(session, obj)


def _check_references(session, obj) -> None:
    state = sa_inspect(obj)
    mapper = state.mapper
    for fk in mapper.local_table.foreign_keys:
        parent = fk.column.table
        if fk.parent.name == "owner_id" or "owner_id" not in parent.c:
            continue
        attr = mapper.get_property_by_column(fk.parent).key
        value = getattr(obj, attr, None)
        if value is None or not (state.key is None or attributes.get_history(obj, attr).has_changes()):
            continue
        found = session.connection().execute(select(parent.c.owner_id).where(fk.column == value)).scalar()
        if found is not None and found != obj.owner_id:
            raise WrongOwner(f"Refusing to link a {type(obj).__name__} to another person's {parent.name} row")
    for rel in mapper.relationships:
        if rel.direction is not MANYTOONE:
            continue
        target = state.dict.get(rel.key)
        if isinstance(target, OwnedMixin) and target.owner_id is not None and target.owner_id != obj.owner_id:
            raise WrongOwner(f"Refusing to link a {type(obj).__name__} to another person's {type(target).__name__}")


_installed = False


def install() -> None:
    """Hook the filter and the write checks into every Session. Safe to call more than once."""
    global _installed
    if _installed:
        return
    event.listen(Session, "do_orm_execute", _filter_statements)
    event.listen(Session, "before_flush", _guard_writes)
    _installed = True


_RAW_SQL = re.compile(
    r"\b(?:session|db|self\.db|self\.session)\.execute\(\s*(?:sqlalchemy\.)?text\(|\btext\(\s*[\"']\s*(?:select|update|delete|insert)"
    r"|(?<![.\w])exists\(\s*\)\s*\.where|\.from_statement\(",
    re.I,
)


def assert_no_raw_sql(roots: Iterable[str]) -> None:
    """For a test: raise if any .py file under `roots` runs raw SQL, a bare exists(), or from_statement(), all of which
    would bypass the owner filter."""
    found = []
    for root in roots:
        for path in Path(root).rglob("*.py"):
            if "venv" in path.parts or "migrations" in path.parts or "tests" in path.parts:
                continue
            for number, line in enumerate(path.read_text().splitlines(), 1):
                if _RAW_SQL.search(line):
                    found.append(f"{path}:{number}: {line.strip()}")
    if found:
        raise AssertionError("these bypass the owner filter:\n" + "\n".join(found))
