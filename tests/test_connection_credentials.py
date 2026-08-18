"""Credentials embedded in connection URIs (scheme://user:pass@host).

The vendor-prefix patterns cannot catch these — the password is arbitrary — yet
a hardcoded DSN is one of the most common places a real credential sits in
ordinary source, build output and stack traces.
"""
import pytest

from prismor.runtime.data_boundary import classify, redact_payload


def _secrets(text):
    return [m for m in classify(text, context="body")
            if m.kind == "secret" and not m.synthetic]


# ── true positives ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("dsn", [
    "postgresql://admin:hunter2pass@db.internal:5432/prod",
    "postgres://svc_api:Xk9-vv2Qz@10.0.0.4/main",
    "mysql://root:tOpS3cret99@mysql.prod.svc:3306/app",
    "mongodb+srv://appuser:aB3xY7zQ1p@cluster0.mongodb.net/test",
    "amqp://rabbit:s3cure-pw-x1@queue.internal:5672",
    "redis://default:9fJ2kdLmQ0aa@cache.internal:6379/0",
])
def test_real_credentials_are_classified(dsn):
    assert _secrets(dsn), f"missed credentials in {dsn}"


def test_only_the_credential_span_is_redacted():
    """Host and scheme survive so the line stays useful to read."""
    out = redact_payload("DSN = 'postgresql://admin:hunter2pass@db.internal:5432/prod'")
    assert "hunter2pass" not in out
    assert "admin" not in out
    assert "postgresql://" in out and "db.internal:5432/prod" in out


def test_credentials_in_a_source_file_body():
    src = ('# TODO: move to env\n'
           'FALLBACK_DSN = "postgresql://admin:hunter2pass@db.internal:5432/prod"\n')
    assert "hunter2pass" not in redact_payload(src)


# ── placeholders must survive (documentation is not a leak) ──────────────────

@pytest.mark.parametrize("dsn", [
    "postgres://user:password@example.com:5432/mydb",
    "postgresql://user:pass@host/db",
    "mysql://root:changeme@db.example.com/test",
    "postgres://admin:${DB_PASSWORD}@db.example.com/db",
    "postgres://admin:{{password}}@db.example.com/db",
    "postgres://admin:<password>@db.example.com/db",
    "postgres://admin:$PGPASSWORD@db.example.com/db",
    "postgres://app:{db_pw}@db.example.com:5432/prod",   # str.format template
])
def test_placeholder_credentials_are_synthetic(dsn):
    assert not _secrets(dsn), f"false positive on placeholder {dsn}"
    assert redact_payload(dsn) == dsn


@pytest.mark.parametrize("dsn", [
    "postgresql://prismor:prismor@localhost:5432/prismor_dev",
    "redis://default:devpassword@127.0.0.1:6379/0",
    "mysql://root:rootpw@host.docker.internal:3306/app",
])
def test_loopback_credentials_are_development_fixtures(dsn):
    """Nobody off the machine can use these, and dev scripts and compose files
    need to read back verbatim."""
    assert not _secrets(dsn), f"false positive on loopback DSN {dsn}"
    assert redact_payload(dsn) == dsn


def test_regex_literals_in_source_are_not_mangled():
    """A permissive username class matches inside regex source and corrupts the
    file the model is about to edit — a worse failure than a missed credential."""
    src = 'm = re.match(r"(?:git@|https?://|ssh://(?:git@)?)([^/:]+)[:/](.+)", url)'
    assert redact_payload(src) == src


# ── shapes that must not match at all ────────────────────────────────────────

@pytest.mark.parametrize("text", [
    "https://github.com/PrismorSec/prismor",
    "https://api.example.com:8443/v1/health",
    "git@github.com:PrismorSec/prismor.git",
    "see http://localhost:3000/admin for the console",
    "postgres://db.internal:5432/prod",          # no credentials at all
    "https://user@github.com/repo.git",          # user, no password
    "ratio is 3://4 whatever",
])
def test_no_match_without_embedded_credentials(text):
    assert not _secrets(text), f"false positive on {text}"
    assert redact_payload(text) == text


def test_url_path_colons_do_not_create_a_match():
    """A colon later in the path must not be read as a credential separator."""
    url = "https://storage.example.com/bucket/a:b@c/file.txt"
    assert redact_payload(url) == url
