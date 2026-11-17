"""Per-person data ownership. The point of every test here: one person can never read or change another's rows,
however the app happens to ask: by id, through a join, in an aggregate, through a relationship, in a bulk update,
or by forgetting to filter at all."""
import asyncio

import pytest
from sqlalchemy import Column, ForeignKey, Integer, String, create_engine, delete, exists, func, select, text, update
from sqlalchemy.orm import aliased, declarative_base, joinedload, relationship, selectinload, sessionmaker
from sqlalchemy.pool import StaticPool

from shared_python import owned

Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True)


class Folder(Base, owned.OwnedMixin):
    __tablename__ = "folders"
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    notes = relationship("Note", back_populates="folder")


class Note(Base, owned.OwnedMixin):
    __tablename__ = "notes"
    id = Column(Integer, primary_key=True)
    title = Column(String, nullable=False)
    amount = Column(Integer, default=0)
    folder_id = Column(Integer, ForeignKey("folders.id"), nullable=True)
    folder = relationship("Folder", back_populates="notes")


owned.install()
ALICE, BOB = 1, 2


@pytest.fixture()
def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    with owned.unscoped():
        session.add_all([User(id=ALICE, email="alice@example.com"), User(id=BOB, email="bob@example.com")])
        alice_folder = Folder(name="alice-folder", owner_id=ALICE)
        bob_folder = Folder(name="bob-folder", owner_id=BOB)
        session.add_all([alice_folder, bob_folder])
        session.flush()
        session.add_all([
            Note(title="alice-1", amount=10, owner_id=ALICE, folder_id=alice_folder.id),
            Note(title="alice-2", amount=20, owner_id=ALICE),
            Note(title="bob-1", amount=1000, owner_id=BOB, folder_id=bob_folder.id),
            Note(title="bob-2", amount=2000, owner_id=BOB),
        ])
        session.commit()
    session.expunge_all()
    yield session
    session.close()


def titles(rows):
    return sorted(r.title for r in rows)


# --- reading -------------------------------------------------------------------------------------------------------------


def test_each_person_sees_only_their_own_rows(db):
    with owned.scope(ALICE):
        assert titles(db.query(Note).all()) == ["alice-1", "alice-2"]
    with owned.scope(BOB):
        assert titles(db.query(Note).all()) == ["bob-1", "bob-2"]


def test_with_nobody_in_scope_nothing_is_visible(db):
    assert db.query(Note).all() == [] and db.query(Folder).count() == 0 and db.execute(select(Note)).all() == []


def test_unscoped_sees_everything_for_migrations_and_administration(db):
    with owned.unscoped():
        assert len(db.query(Note).all()) == 4


def _id_of(db, title):
    """Look a row's id up in a SEPARATE session, so nothing is left in the test session's identity map."""
    other = sessionmaker(bind=db.get_bind())()
    try:
        with owned.unscoped():
            return other.query(Note).filter_by(title=title).one().id
    finally:
        other.close()


def test_another_persons_row_cannot_be_fetched_by_its_id_however_the_app_asks(db):
    bobs = _id_of(db, "bob-1")
    with owned.scope(ALICE):
        assert db.get(Note, bobs) is None
        assert db.query(Note).get(bobs) is None if hasattr(db.query(Note), "get") else True
        assert db.query(Note).filter(Note.id == bobs).first() is None
        assert db.query(Note).filter_by(id=bobs).all() == []
        assert db.scalar(select(Note).where(Note.id == bobs)) is None
        assert db.query(Note).filter(Note.id.in_([bobs])).count() == 0
        assert db.query(select(Note.id).where(Note.id == bobs).exists()).scalar() is False
        assert db.query(db.query(Note).filter(Note.id == bobs).exists()).scalar() is False
        assert db.execute(select(exists(select(Note.id).where(Note.id == bobs)))).scalar() is False


def test_aggregates_and_column_queries_only_see_the_persons_own_rows(db):
    with owned.scope(ALICE):
        assert db.query(func.sum(Note.amount)).scalar() == 30
        assert db.query(func.count(Note.id)).scalar() == 2
        assert sorted(t for (t,) in db.query(Note.title).all()) == ["alice-1", "alice-2"]
        assert db.execute(select(func.max(Note.amount))).scalar() == 20


def test_joins_and_subqueries_are_filtered_on_every_side(db):
    with owned.scope(ALICE):
        rows = db.query(Note).join(Folder, Note.folder_id == Folder.id).all()
        assert titles(rows) == ["alice-1"]
        sub = select(Note.folder_id).where(Note.folder_id.is_not(None)).scalar_subquery()
        assert [f.name for f in db.query(Folder).filter(Folder.id.in_(sub)).all()] == ["alice-folder"]
        other = aliased(Note)
        assert titles(db.query(Note).join(other, other.id == Note.id).all()) == ["alice-1", "alice-2"]


def test_relationships_never_load_another_persons_rows_even_if_data_links_them(db):
    with owned.unscoped():
        alice_folder = db.query(Folder).filter_by(name="alice-folder").one()
        bobs_note = db.query(Note).filter_by(title="bob-1").one()
        bobs_note.folder_id = alice_folder.id  # corrupt data: a note of Bob's pointing at Alice's folder
        db.commit()
        db.expire_all()
    with owned.scope(ALICE):
        assert titles(db.query(Folder).one().notes) == ["alice-1"]  # lazy load
        assert titles(db.query(Folder).options(selectinload(Folder.notes)).one().notes) == ["alice-1"]
        assert titles(db.query(Folder).options(joinedload(Folder.notes)).one().notes) == ["alice-1"]
    db.expunge_all()  # a session is per request in the apps; this keeps Alice's folder out of the identity map
    with owned.scope(BOB):
        assert db.query(Note).filter_by(title="bob-1").one().folder is None  # Alice's folder is invisible to Bob


def test_a_row_loaded_in_one_scope_does_not_leak_into_another_session_scope(db):
    with owned.scope(ALICE):
        mine = db.query(Note).all()
        assert len(mine) == 2
    db.expire_all()
    with owned.scope(BOB):
        assert titles(db.query(Note).all()) == ["bob-1", "bob-2"]


# --- bulk updates and deletes -------------------------------------------------------------------------------------------------


def test_a_bulk_update_only_touches_the_persons_own_rows(db):
    with owned.scope(ALICE):
        assert db.query(Note).update({"amount": 0}) == 2
        db.commit()
    with owned.unscoped():
        assert {n.title: n.amount for n in db.query(Note).all()} == {"alice-1": 0, "alice-2": 0, "bob-1": 1000, "bob-2": 2000}


def test_a_bulk_delete_only_touches_the_persons_own_rows(db):
    with owned.scope(ALICE):
        assert db.query(Note).delete() == 2
        db.commit()
    with owned.unscoped():
        assert titles(db.query(Note).all()) == ["bob-1", "bob-2"]


def test_core_style_update_and_delete_statements_are_filtered_too(db):
    with owned.scope(BOB):
        db.execute(update(Note).values(amount=7))
        db.execute(delete(Folder))
        db.commit()
    with owned.unscoped():
        assert {n.title: n.amount for n in db.query(Note).all()}["alice-1"] == 10
        assert [f.name for f in db.query(Folder).all()] == ["alice-folder"]


# --- writing ---------------------------------------------------------------------------------------------------------------------


def test_new_rows_get_their_owner_from_the_scope(db):
    with owned.scope(ALICE):
        note = Note(title="mine")
        db.add(note)
        db.commit()
        assert note.owner_id == ALICE
    with owned.scope(BOB):
        assert "mine" not in titles(db.query(Note).all())


def test_a_row_cannot_be_created_in_someone_elses_name(db):
    with owned.scope(ALICE):
        db.add(Note(title="forged", owner_id=BOB))
        with pytest.raises(owned.WrongOwner):
            db.commit()
        db.rollback()
    with owned.unscoped():
        assert db.query(Note).filter_by(title="forged").count() == 0


def test_a_row_cannot_be_written_with_nobody_in_scope(db):
    db.add(Note(title="orphan", owner_id=ALICE))
    with pytest.raises(owned.NoOwner):
        db.commit()
    db.rollback()


def test_a_row_cannot_be_handed_to_another_person(db):
    with owned.scope(ALICE):
        note = db.query(Note).filter_by(title="alice-1").one()
        note.owner_id = BOB
        with pytest.raises(owned.WrongOwner):
            db.commit()
        db.rollback()
    with owned.unscoped():
        assert db.query(Note).filter_by(title="alice-1").one().owner_id == ALICE


def test_a_row_of_another_person_loaded_by_mistake_cannot_be_changed_or_deleted(db):
    with owned.unscoped():
        bobs = db.query(Note).filter_by(title="bob-1").one()
    with owned.scope(ALICE):
        bobs.title = "hijacked"
        with pytest.raises(owned.WrongOwner):
            db.commit()
        db.rollback()
        db.delete(bobs)
        with pytest.raises(owned.WrongOwner):
            db.commit()
        db.rollback()
    with owned.unscoped():
        assert db.query(Note).filter_by(title="bob-1").count() == 1


def test_known_limit_a_row_loaded_unscoped_in_the_same_session_is_returned_by_get(db):
    """Why apps must keep unscoped work (adopting legacy rows, account lookups) in its own session."""
    with owned.unscoped():
        bobs = db.query(Note).filter_by(title="bob-1").one()
    with owned.scope(ALICE):
        assert db.get(Note, bobs.id) is bobs  # served from the identity map without a query
        assert db.query(Note).filter_by(id=bobs.id).first() is None  # but any real query still refuses


def test_deleting_through_the_session_only_works_on_the_persons_own_rows(db):
    with owned.scope(ALICE):
        db.delete(db.query(Note).filter_by(title="alice-1").one())
        db.commit()
        assert db.query(Note).filter_by(title="bob-1").first() is None  # cannot even be found, so cannot be deleted
    with owned.unscoped():
        assert titles(db.query(Note).all()) == ["alice-2", "bob-1", "bob-2"]


def test_an_unowned_table_is_unaffected_by_scoping(db):
    assert db.query(User).count() == 2  # the accounts table is looked up with nobody in scope
    with owned.scope(ALICE):
        assert db.query(User).count() == 2


# --- the scope itself -------------------------------------------------------------------------------------------------------------


def test_scopes_nest_and_restore(db):
    with owned.scope(ALICE):
        with owned.scope(BOB):
            assert owned.current_owner() == BOB
        assert owned.current_owner() == ALICE
        with owned.unscoped():
            assert owned.current_owner() is None
        assert owned.current_owner() == ALICE
    assert owned.current_owner() is None


@pytest.mark.parametrize("bad", [None, True, "1", 1.5, [1]])
def test_a_scope_needs_a_real_person_id(bad):
    with pytest.raises(TypeError):
        with owned.scope(bad):
            pass


def test_the_scope_does_not_leak_between_concurrent_requests(db):
    seen = []

    async def request(owner, delay):
        with owned.scope(owner):
            await asyncio.sleep(delay)
            seen.append((owner, owned.current_owner()))

    async def main():
        await asyncio.gather(request(ALICE, 0.02), request(BOB, 0.01))

    asyncio.run(main())
    assert sorted(seen) == [(ALICE, ALICE), (BOB, BOB)]
    assert owned.current_owner() is None


def test_a_worker_thread_started_inside_a_scope_keeps_it_and_one_outside_has_none(db):
    import contextvars
    import threading

    results = {}
    with owned.scope(ALICE):
        ctx = contextvars.copy_context()
        t = threading.Thread(target=lambda: results.update(inside=ctx.run(owned.current_owner)))
        t.start(); t.join()
    t = threading.Thread(target=lambda: results.update(outside=owned.current_owner()))
    t.start(); t.join()
    assert results == {"inside": ALICE, "outside": None}


# --- the known limit, and the guard for it -----------------------------------------------------------------------------------------


def test_raw_sql_is_not_filtered_which_is_why_apps_must_not_use_it_on_owned_tables(db):
    with owned.scope(ALICE):
        assert len(db.execute(text("select * from notes")).all()) == 4  # the filter cannot see inside raw SQL


def test_known_limit_a_bare_exists_may_not_be_filtered_so_the_lint_rejects_it_and_the_safe_form_always_is(db):
    """SQLAlchemy 2.0 does not see a model inside a bare exists().where(Note.col == x), so it is not filtered there
    (2.1 does filter it). Apps must not depend on either, so the lint rejects the bare form (next test) and the safe
    form, which is filtered on every version, is what apps use."""
    bobs = _id_of(db, "bob-1")
    with owned.scope(ALICE):
        assert db.query(select(Note.id).where(Note.id == bobs).exists()).scalar() is False
        assert db.query(db.query(Note).filter(Note.id == bobs).exists()).scalar() is False


def test_the_lint_rejects_a_bare_exists_and_from_statement_but_not_the_safe_forms(tmp_path):
    (tmp_path / "app").mkdir()
    safe = tmp_path / "app" / "safe.py"
    safe.write_text("db.query(select(Note.id).where(Note.id == 1).exists())\nq.filter(x).exists()\nsqlalchemy.exists(select(1))\n")
    owned.assert_no_raw_sql([str(tmp_path)])
    for bad in ("db.query(exists().where(Note.id == 1))\n", "x = exists() .where(a)\n", "db.query(Note).from_statement(stmt)\n"):
        safe.write_text(bad)
        with pytest.raises(AssertionError):
            owned.assert_no_raw_sql([str(tmp_path)])


def test_the_raw_sql_check_finds_it_and_ignores_tests_and_migrations(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "ok.py").write_text("db.query(Note).all()\n")
    (tmp_path / "app" / "bad.py").write_text("rows = db.execute(text('select * from notes')).all()\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "t.py").write_text("db.execute(text('select 1'))\n")
    with pytest.raises(AssertionError, match="bad.py"):
        owned.assert_no_raw_sql([str(tmp_path)])
    (tmp_path / "app" / "bad.py").unlink()
    owned.assert_no_raw_sql([str(tmp_path)])


def test_a_row_cannot_be_taken_over_by_changing_its_owner_to_yourself(db):
    with owned.unscoped():
        bobs = db.query(Note).filter_by(title="bob-1").one()
    with owned.scope(ALICE):
        bobs.owner_id = ALICE  # looks like a legitimate owner for this scope, but it is a theft
        with pytest.raises(owned.WrongOwner):
            db.commit()
        db.rollback()
    with owned.unscoped():
        assert db.query(Note).filter_by(title="bob-1").one().owner_id == BOB


# --- nothing of one person's may point at another person's row ---------------------------------------------------------------


def _folder_id(db, name):
    other = sessionmaker(bind=db.get_bind())()
    try:
        with owned.unscoped():
            return other.query(Folder).filter_by(name=name).one().id
    finally:
        other.close()


def test_a_new_row_cannot_point_at_another_persons_row_by_id(db):
    bobs_folder = _folder_id(db, "bob-folder")
    with owned.scope(ALICE):
        db.add(Note(title="sneaky", folder_id=bobs_folder))
        with pytest.raises(owned.WrongOwner):
            db.flush()
    db.rollback()
    with owned.unscoped():
        assert db.query(Note).filter_by(title="sneaky").count() == 0


def test_an_existing_row_cannot_be_repointed_at_another_persons_row(db):
    bobs_folder = _folder_id(db, "bob-folder")
    with owned.scope(ALICE):
        note = db.query(Note).filter_by(title="alice-2").one()
        note.folder_id = bobs_folder
        with pytest.raises(owned.WrongOwner):
            db.flush()
    db.rollback()
    with owned.unscoped():
        assert db.query(Note).filter_by(title="alice-2").one().folder_id is None


def test_a_row_cannot_point_at_another_persons_object_through_a_relationship(db):
    with owned.unscoped():
        bobs = db.query(Folder).filter_by(name="bob-folder").one()
    with owned.scope(ALICE):
        db.add(Note(title="sneaky-2", folder=bobs))
        with pytest.raises(owned.WrongOwner):
            db.flush()
    db.rollback()


def test_a_row_can_point_at_the_persons_own_rows_and_at_ones_made_in_the_same_flush(db):
    alices = _folder_id(db, "alice-folder")
    with owned.scope(ALICE):
        db.add(Note(title="fine", folder_id=alices))
        db.add(Note(title="fine-too", folder=Folder(name="brand-new")))  # parent and child created together
        db.commit()
        assert titles(db.query(Note).filter(Note.title.like("fine%")).all()) == ["fine", "fine-too"]
        note = db.query(Note).filter_by(title="fine").one()
        note.folder_id = None
        note.title = "renamed"
        db.commit()
