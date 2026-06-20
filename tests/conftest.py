"""Shared pytest fixtures."""

import pytest

from linksiren.__main__ import AuthContext


@pytest.fixture
def credentials():
    """A populated :class:`AuthContext` for password-based auth tests."""
    return AuthContext(
        domain="test_domain",
        username="test_user",
        password="test_password",
    )


@pytest.fixture
def hash_credentials():
    """An :class:`AuthContext` populated for Pass-the-Hash."""
    return AuthContext(
        domain="test_domain",
        username="test_user",
        password="",
        lmhash="aad3b435b51404eeaad3b435b51404ee",
        nthash="31d6cfe0d16ae931b73c59d7e0c089c0",
    )


@pytest.fixture
def kerberos_credentials():
    """An :class:`AuthContext` configured for Kerberos auth."""
    return AuthContext(
        domain="test_domain",
        username="test_user",
        password="",
        use_kerberos=True,
        kdc_host="dc01.test_domain",
    )
