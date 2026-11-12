import unittest

from tasking_manager.auth import (
    encode_session_token,
    normalize_token,
    parse_oauth_redirect,
)


REDIRECT_URI = "https://tasks.hotosm.org/authorized"


class NormalizeTokenTests(unittest.TestCase):
    def test_plain_token(self):
        self.assertEqual(normalize_token("abc123"), "abc123")

    def test_token_prefix_is_removed(self):
        self.assertEqual(normalize_token("Token abc123"), "abc123")
        self.assertEqual(normalize_token("token   abc123  "), "abc123")

    def test_none_and_empty(self):
        self.assertEqual(normalize_token(None), "")
        self.assertEqual(normalize_token("   "), "")


class EncodeSessionTokenTests(unittest.TestCase):
    def test_base64_encoding(self):
        self.assertEqual(encode_session_token("abc"), "YWJj")

    def test_round_trip(self):
        import base64

        token = "abc.def-ghi_jkl"
        encoded = encode_session_token(token)
        self.assertEqual(base64.b64decode(encoded).decode("utf-8"), token)


class ParseOAuthRedirectTests(unittest.TestCase):
    def test_code_and_state(self):
        url = f"{REDIRECT_URI}?code=abc123&state=xyz"
        self.assertEqual(parse_oauth_redirect(url, REDIRECT_URI), ("abc123", "xyz", None))

    def test_error(self):
        url = (
            f"{REDIRECT_URI}?error=access_denied"
            "&error_description=User+denied+access&state=xyz"
        )
        self.assertEqual(
            parse_oauth_redirect(url, REDIRECT_URI),
            (None, "xyz", "User denied access"),
        )

    def test_non_matching_url(self):
        url = "https://www.openstreetmap.org/login?code=abc"
        self.assertEqual(parse_oauth_redirect(url, REDIRECT_URI), (None, None, None))

    def test_trailing_slash_is_ignored(self):
        url = f"{REDIRECT_URI}/?code=abc123&state=xyz"
        self.assertEqual(parse_oauth_redirect(url, REDIRECT_URI), ("abc123", "xyz", None))


if __name__ == "__main__":
    unittest.main()
