import sys, base64, json
sys.path.insert(0, ".")
from jwt_analyzer import parse_jwt, b64d, b64e

# Sample JWT: {"alg":"HS256","typ":"JWT"}.{"sub":"1234","name":"test","admin":false}.signature
SAMPLE = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

def test_parse_jwt_structure():
    header, payload, parts = parse_jwt(SAMPLE)
    assert header["alg"] == "HS256"
    assert header["typ"] == "JWT"
    assert "sub" in payload
    assert len(parts) == 3

def test_parse_jwt_payload():
    header, payload, parts = parse_jwt(SAMPLE)
    assert payload["sub"] == "1234567890"
    assert payload["name"] == "John Doe"

def test_b64_roundtrip():
    original = b"test data 123"
    encoded = b64e(original)
    decoded = b64d(encoded)
    assert decoded == original

def test_invalid_jwt_raises():
    try:
        parse_jwt("not.a.valid.jwt.token.with.too.many.parts")
        assert False, "Should have raised"
    except Exception:
        pass

if __name__ == "__main__":
    test_parse_jwt_structure()
    test_parse_jwt_payload()
    test_b64_roundtrip()
    test_invalid_jwt_raises()
    print("All tests passed.")
