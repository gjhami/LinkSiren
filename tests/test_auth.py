"""Tests for the credential / auth-flow plumbing added in 0.0.5."""

from unittest.mock import MagicMock, patch
import pytest

from linksiren.__main__ import AuthContext, Credentials, _build_auth_context, _parse_hashes
from linksiren.target import HostTarget


# ---------------------------------------------------------- AuthContext API ---


def test_credentials_alias_is_authcontext():
    """``Credentials`` is kept as an alias for backwards compatibility."""
    assert Credentials is AuthContext


def test_authcontext_defaults_are_empty():
    auth = AuthContext()
    assert auth.username == ""
    assert auth.password == ""
    assert auth.lmhash == ""
    assert auth.nthash == ""
    assert auth.aes_key == ""
    assert auth.kdc_host is None
    assert auth.use_kerberos is False
    assert auth.no_pass is False


# ----------------------------------------------------------- hash parsing ---


def test_parse_hashes_empty():
    assert _parse_hashes(None) == ("", "")
    assert _parse_hashes("") == ("", "")


def test_parse_hashes_full_pair():
    lm, nt = _parse_hashes("aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0")
    assert lm == "aad3b435b51404eeaad3b435b51404ee"
    assert nt == "31d6cfe0d16ae931b73c59d7e0c089c0"


def test_parse_hashes_bare_nthash():
    """A bare NT hash with no colon is accepted (LM left empty)."""
    lm, nt = _parse_hashes("31d6cfe0d16ae931b73c59d7e0c089c0")
    assert lm == ""
    assert nt == "31d6cfe0d16ae931b73c59d7e0c089c0"


# ----------------------------------------------- _build_auth_context (CLI) ---


def _make_args(**kwargs):
    """Build an args-like object that supports ``in`` and ``getattr``."""

    class _A:
        pass

    a = _A()
    for k, v in kwargs.items():
        setattr(a, k, v)
    # __contains__ needs to be a real method for ``'credentials' in args``.
    a.__class__ = type("_Args", (_A,), {"__contains__": lambda self, k: hasattr(self, k)})
    return a


def test_build_auth_context_password_only():
    args = _make_args(credentials="DOMAIN/user:passw0rd")
    auth = _build_auth_context(args)
    assert auth.domain == "DOMAIN"
    assert auth.username == "user"
    assert auth.password == "passw0rd"
    assert auth.lmhash == ""
    assert auth.nthash == ""
    assert auth.use_kerberos is False


def test_build_auth_context_with_hashes():
    args = _make_args(
        credentials="DOMAIN/user",
        hashes="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
    )
    auth = _build_auth_context(args)
    assert auth.username == "user"
    assert auth.lmhash == "aad3b435b51404eeaad3b435b51404ee"
    assert auth.nthash == "31d6cfe0d16ae931b73c59d7e0c089c0"


def test_build_auth_context_kerberos_flags():
    args = _make_args(
        credentials="DOMAIN/user",
        k=True,
        aesKey="cafebabe" * 8,
        dc_ip="dc01.example.local",
        no_pass=True,
    )
    auth = _build_auth_context(args)
    assert auth.use_kerberos is True
    assert auth.aes_key == "cafebabe" * 8
    assert auth.kdc_host == "dc01.example.local"
    # -no-pass without -hashes should blank the password
    assert auth.password == ""
    assert auth.no_pass is True


def test_build_auth_context_no_pass_with_hashes_keeps_password_empty():
    """-no-pass + -hashes: password was never supplied, stays empty."""
    args = _make_args(
        credentials="DOMAIN/user",
        hashes="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
        no_pass=True,
    )
    auth = _build_auth_context(args)
    assert auth.password == ""
    assert auth.nthash == "31d6cfe0d16ae931b73c59d7e0c089c0"


def test_build_auth_context_no_credentials_returns_empty():
    """``generate`` mode has no credentials arg."""
    args = _make_args(mode="generate")
    auth = _build_auth_context(args)
    assert auth == AuthContext()


# ------------------------------------ HostTarget.connect dispatches on -k ---


@pytest.fixture
def smb_connection_mock():
    return MagicMock()


@pytest.fixture
def fresh_target():
    t = HostTarget(host="example.local")
    t.connection = None
    return t


def test_connect_password_calls_login(fresh_target, smb_connection_mock, credentials):
    with patch("linksiren.target.SMBConnection", return_value=smb_connection_mock):
        fresh_target.connect(credentials)
    smb_connection_mock.login.assert_called_once_with(
        "test_user", "test_password", "test_domain", "", "", True
    )
    smb_connection_mock.kerberosLogin.assert_not_called()
    assert fresh_target.logged_in is True


def test_connect_with_hashes_forwards_hashes(fresh_target, smb_connection_mock, hash_credentials):
    with patch("linksiren.target.SMBConnection", return_value=smb_connection_mock):
        fresh_target.connect(hash_credentials)
    smb_connection_mock.login.assert_called_once_with(
        "test_user",
        "",
        "test_domain",
        "aad3b435b51404eeaad3b435b51404ee",
        "31d6cfe0d16ae931b73c59d7e0c089c0",
        True,
    )
    smb_connection_mock.kerberosLogin.assert_not_called()


def test_connect_kerberos_calls_kerberos_login(
    fresh_target, smb_connection_mock, kerberos_credentials
):
    with patch("linksiren.target.SMBConnection", return_value=smb_connection_mock):
        fresh_target.connect(kerberos_credentials)
    smb_connection_mock.login.assert_not_called()
    smb_connection_mock.kerberosLogin.assert_called_once_with(
        user="test_user",
        password="",
        domain="test_domain",
        lmhash="",
        nthash="",
        aesKey="",
        kdcHost="dc01.test_domain",
        useCache=True,
    )
    assert fresh_target.logged_in is True


def test_connect_kerberos_error_is_swallowed(fresh_target, smb_connection_mock, kerberos_credentials):
    """A failed Kerberos auth on one host must not kill the whole run."""
    smb_connection_mock.kerberosLogin.side_effect = RuntimeError("kerberos boom")
    with patch("linksiren.target.SMBConnection", return_value=smb_connection_mock):
        fresh_target.connect(kerberos_credentials)
    assert fresh_target.connection is None
    assert fresh_target.logged_in is False
