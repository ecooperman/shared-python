"""People-with-accounts gate: who gets in, whose data they see, and that no sign-in trick makes one person into another.
The stand-in app below keeps notes per person; one route deliberately FORGETS to filter by owner, to prove the data
layer still shows each person only their own."""
import threading
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.testclient import TestClient
from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from shared_python import accounts_gate, auth, owned, settings
from shared_python.accounts_gate import Account

ISSUER = "https://login.example.com"
CLIENT = "client-123"
FRONT = "https://dashboard.example.org"
SERVICE_TOKEN = "service-secret"

Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True, nullable=False)
    status = Column(String, nullable=False, default="active")
    is_admin = Column(Integer, nullable=False, default=0)


class Note(Base, owned.OwnedMixin):
    __tablename__ = "notes"
    id = Column(Integer, primary_key=True)
    text = Column(String, nullable=False)


owned.install()


@pytest.fixture()
def world(monkeypatch, tmp_path):
    # A real file with the usual connection pool, like the apps: each request thread gets its OWN connection. (A single
    # in-memory connection shared by every thread at once is not safe in SQLite and corrupts concurrent results.)
    engine = create_engine(f"sqlite:///{tmp_path / 'world.db'}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    with owned.unscoped():
        with Session() as s:
            s.add_all([
                User(id=1, email="alice@example.com", is_admin=1), User(id=2, email="bob@example.com"),
                User(id=3, email="gone@example.com", status="removed"),
            ])
            s.flush()
            s.add_all([Note(text="alice-note", owner_id=1), Note(text="bob-note", owner_id=2)])
            s.commit()

    def account_for(email):
        with Session() as s:
            user = s.query(User).filter(User.email == email).first()
        if user is None:
            return "none"
        if user.status != "active":
            return "removed"
        return Account(id=user.id, email=user.email, is_admin=bool(user.is_admin))

    def db():
        s = Session()
        try:
            yield s
        finally:
            s.close()

    def service(request: Request):
        if request.method == "GET" and request.url.path == "/api/all-notes" and request.headers.get("x-service-token") == SERVICE_TOKEN:
            return Account(id=1, email="alice@example.com", is_admin=True)
        return None

    app = FastAPI()

    @app.get("/", )
    def page():
        return "home"

    @app.get("/public.txt")
    def public():
        return "public"

    @app.get("/api/notes")
    def mine(s=Depends(db)):
        return [n.text for n in s.query(Note).filter(Note.owner_id == accounts_gate_owner()).all()]

    def accounts_gate_owner():
        return owned.current_owner()

    @app.get("/api/all-notes")  # a forgetful route: no owner filter at all
    def all_notes(s=Depends(db)):
        return sorted(n.text for n in s.query(Note).all())

    @app.get("/api/all-notes-async")
    async def all_notes_async(s=Depends(db)):
        return sorted(n.text for n in s.query(Note).all())

    @app.post("/api/notes")
    def add(body: dict, s=Depends(db)):
        note = Note(text=body["text"])
        s.add(note)
        s.commit()
        return {"id": note.id, "owner": note.owner_id}

    @app.get("/api/notes/{note_id}")
    def one(note_id: int, s=Depends(db)):
        note = s.get(Note, note_id)
        if note is None:
            raise HTTPException(status_code=404, detail="Not found")
        return {"text": note.text}

    @app.delete("/api/notes/{note_id}")
    def remove(note_id: int, s=Depends(db)):
        note = s.get(Note, note_id)
        if note is None:
            raise HTTPException(status_code=404, detail="Not found")
        s.delete(note)
        s.commit()
        return {"ok": True}

    @app.get("/api/admin-only")
    def admin_only(account=Depends(accounts_gate.require_admin)):
        return {"admin": account.email}

    @app.get("/api/who")
    def who(account=Depends(accounts_gate.current_account)):
        return {"id": account.id, "email": account.email}

    accounts_gate.install(app, account_for=account_for, dev_user_email="dev@localhost.test", service_account=service, public_paths=("/public.txt",))
    return app


@pytest.fixture(scope="module")
def key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture()
def production(monkeypatch, key, world):
    monkeypatch.setattr(settings, "ENV", "production")
    monkeypatch.setattr(settings, "OIDC_ISSUER", ISSUER)
    monkeypatch.setattr(settings, "OIDC_AUDIENCE", CLIENT)
    monkeypatch.setattr(settings, "OIDC_LOGIN_URL", FRONT + "/auth/login")
    monkeypatch.setattr(auth, "_oidc_signing_key", lambda _t: key.public_key())
    return world


def token(key, email, aud=CLIENT, verified=True, exp_in=300, iss=ISSUER):
    return jwt.encode({"iss": iss, "aud": aud, "exp": int(time.time()) + exp_in, "email": email, "email_verified": verified}, key, algorithm="RS256")


def as_person(app, key, email, **kw):
    c = TestClient(app, base_url="https://plans.example.org", follow_redirects=False)
    c.cookies.set("oidc_session", token(key, email, **kw))
    return c


# --- who gets in ----------------------------------------------------------------------------------------------------------


def test_a_person_with_an_account_gets_in(production, key):
    assert as_person(production, key, "bob@example.com").get("/api/who").json() == {"id": 2, "email": "bob@example.com"}


def test_a_signed_out_visitor_is_sent_to_sign_in_for_a_page_and_refused_for_the_api(production):
    c = TestClient(production, base_url="https://plans.example.org", follow_redirects=False)
    assert c.get("/").status_code == 302 and c.get("/").headers["location"].startswith(FRONT + "/auth/login?next=")
    assert c.get("/api/notes").status_code == 401 and c.get("/api/all-notes").status_code == 401


def test_a_signed_in_person_with_no_account_gets_nothing_and_a_way_to_sign_out(production, key):
    c = as_person(production, key, "stranger@example.com")
    page = c.get("/")
    assert page.status_code == 403 and "have access yet" in page.text and "stranger@example.com" in page.text
    assert f'href="{FRONT}/auth/logout"' in page.text and "alice-note" not in page.text
    for path in ("/api/notes", "/api/all-notes", "/api/who", "/api/admin-only"):
        resp = c.get(path)
        assert resp.status_code == 403 and "alice-note" not in resp.text and "bob-note" not in resp.text


def test_someone_with_no_account_is_pointed_at_the_dashboard_to_ask(production, key):
    page = as_person(production, key, "stranger@example.com").get("/")
    assert f'href="{FRONT}/"' in page.text and "Ask for access" in page.text and "ask for access from your dashboard" in page.text


def test_the_ask_link_is_only_for_people_who_never_had_an_account_and_only_with_a_dashboard(production, key, monkeypatch):
    removed = as_person(production, key, "gone@example.com").get("/")
    assert "access was removed" in removed.text and "Ask for access" not in removed.text  # they ask the administrator instead
    assert "Ask for access" not in as_person(production, key, "stranger@example.com").get("/api/notes").text  # the API stays plain JSON
    monkeypatch.setattr(settings, "OIDC_LOGIN_URL", None)  # nothing in front of this app: nowhere to send them
    monkeypatch.setattr(settings, "OIDC_COOKIE", "oidc_session")  # (the session cookie still signs them in)
    page = as_person(production, key, "stranger@example.com").get("/")
    assert page.status_code == 403 and "have access yet" in page.text and "Ask for access" not in page.text


def test_a_person_whose_access_was_removed_is_told_so_and_gets_nothing(production, key):
    c = as_person(production, key, "gone@example.com")
    page = c.get("/")
    assert page.status_code == 403 and "access was removed" in page.text
    assert c.get("/api/all-notes").status_code == 403


def test_the_email_is_matched_ignoring_case_but_a_plus_alias_is_a_different_person(production, key):
    assert as_person(production, key, "Bob@Example.COM").get("/api/who").json()["id"] == 2
    assert as_person(production, key, "bob+evil@example.com").get("/api/who").status_code == 403
    assert as_person(production, key, "b.ob@example.com").get("/api/who").status_code == 403


# --- whose data they see ---------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("path", ["/api/all-notes", "/api/all-notes-async"])
def test_even_a_route_that_forgets_to_filter_shows_each_person_only_their_own(production, key, path):
    assert as_person(production, key, "alice@example.com").get(path).json() == ["alice-note"]
    assert as_person(production, key, "bob@example.com").get(path).json() == ["bob-note"]


def test_a_person_cannot_read_or_delete_anothers_row_by_its_id(production, key):
    alice, bob = as_person(production, key, "alice@example.com"), as_person(production, key, "bob@example.com")
    alices = alice.post("/api/notes", json={"text": "private"}, headers={"Sec-Fetch-Site": "same-origin"}).json()
    assert alices["owner"] == 1
    assert bob.get(f"/api/notes/{alices['id']}").status_code == 404
    assert bob.delete(f"/api/notes/{alices['id']}", headers={"Sec-Fetch-Site": "same-origin"}).status_code == 404
    assert alice.get(f"/api/notes/{alices['id']}").json() == {"text": "private"}


def test_new_rows_belong_to_whoever_made_them(production, key):
    bob = as_person(production, key, "bob@example.com")
    assert bob.post("/api/notes", json={"text": "x"}, headers={"Sec-Fetch-Site": "same-origin"}).json()["owner"] == 2


def test_concurrent_requests_from_different_people_never_see_each_others_data(production, key):
    results, errors = [], []

    def go(email, expected):
        try:
            c = as_person(production, key, email)
            for _ in range(15):
                results.append(c.get("/api/all-notes").json() == expected)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=go, args=(e, x)) for e, x in
               [("alice@example.com", ["alice-note"]), ("bob@example.com", ["bob-note"])] * 3]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert not errors and len(results) == 90 and all(results)


def test_the_scope_ends_with_the_request(production, key):
    as_person(production, key, "alice@example.com").get("/api/all-notes")
    assert owned.current_owner() is None


# --- no sign-in trick makes one person another -------------------------------------------------------------------------------


def test_a_token_signed_by_anyone_else_is_refused(production, key):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    forged = jwt.encode({"iss": ISSUER, "aud": CLIENT, "exp": int(time.time()) + 300, "email": "alice@example.com", "email_verified": True}, other, algorithm="RS256")
    c = TestClient(production, base_url="https://plans.example.org", follow_redirects=False)
    c.cookies.set("oidc_session", forged)
    assert c.get("/api/all-notes").status_code == 401


@pytest.mark.parametrize("kw", [{"aud": "another-application"}, {"verified": False}, {"exp_in": -5}, {"iss": "https://evil.example.com"}])
def test_a_token_for_the_wrong_application_issuer_unverified_or_expired_is_refused(production, key, kw):
    assert as_person(production, key, "alice@example.com", **kw).get("/api/all-notes").status_code == 401


def test_a_token_with_the_signature_stripped_or_tampered_is_refused(production, key):
    good = token(key, "bob@example.com")
    head, payload, sig = good.split(".")
    for bad in (head + "." + payload + ".", head + "." + payload + "." + sig[:-3] + "AAA", "not-a-token"):
        c = TestClient(production, base_url="https://plans.example.org", follow_redirects=False)
        c.cookies.set("oidc_session", bad)
        assert c.get("/api/all-notes").status_code == 401


def test_a_header_claiming_to_be_someone_is_never_trusted_in_production(production):
    c = TestClient(production, base_url="https://plans.example.org", follow_redirects=False)
    headers = {"Cf-Access-Authenticated-User-Email": "alice@example.com", "X-Forwarded-User": "alice@example.com"}
    assert c.get("/api/all-notes", headers=headers).status_code == 401
    assert c.get("/api/all-notes", cookies={"dev_user": "alice@example.com"}).status_code == 401


def test_a_bearer_header_is_accepted_only_if_it_is_a_valid_token(production, key):
    c = TestClient(production, base_url="https://plans.example.org", follow_redirects=False)
    assert c.get("/api/who", headers={"Authorization": f"Bearer {token(key, 'bob@example.com')}"}).json()["id"] == 2
    assert c.get("/api/who", headers={"Authorization": "Bearer nonsense"}).status_code == 401


# --- administrators, the service account, public files, forgery ---------------------------------------------------------------


def test_only_an_administrator_gets_an_admin_route(production, key):
    assert as_person(production, key, "alice@example.com").get("/api/admin-only").json() == {"admin": "alice@example.com"}
    resp = as_person(production, key, "bob@example.com").get("/api/admin-only")
    assert resp.status_code == 403 and "administrator" in resp.text


def test_the_service_account_acts_as_that_account_for_the_one_agreed_call_only(production):
    c = TestClient(production, base_url="https://plans.example.org", follow_redirects=False)
    headers = {"X-Service-Token": SERVICE_TOKEN}
    assert c.get("/api/all-notes", headers=headers).json() == ["alice-note"]  # scoped to the account it acts as
    for method, path in [("GET", "/api/notes"), ("GET", "/api/who"), ("POST", "/api/notes"), ("GET", "/")]:
        resp = c.request(method, path, headers=headers, json={"text": "x"} if method == "POST" else None)
        assert resp.status_code in (401, 302)
    assert c.get("/api/all-notes", headers={"X-Service-Token": "wrong"}).status_code == 401


def test_a_public_path_needs_no_sign_in_and_nothing_else_does(production):
    c = TestClient(production, base_url="https://plans.example.org", follow_redirects=False)
    assert c.get("/public.txt").status_code == 200
    assert c.get("/public.txt.bak").status_code == 302 and c.get("/public.txt/../api/all-notes").status_code in (302, 401, 404)


def test_a_cross_site_change_is_refused_even_with_a_valid_session(production, key):
    bob = as_person(production, key, "bob@example.com")
    for site in ("same-site", "cross-site"):
        resp = bob.post("/api/notes", json={"text": "csrf"}, headers={"Sec-Fetch-Site": site})
        assert resp.status_code == 403 and "didn't come from this app" in resp.text
    assert bob.get("/api/all-notes").json() == ["bob-note"]  # nothing was created


def test_locally_the_dev_user_is_looked_up_like_anyone(world):
    c = TestClient(world, follow_redirects=False)
    assert c.get("/api/who").status_code == 403  # dev@localhost.test has no account in this stand-in
    assert c.get("/api/who", headers={"Cf-Access-Authenticated-User-Email": "bob@example.com"}).json()["id"] == 2
