# 🔑 JWT Security Analyzer

Deep inspection and vulnerability testing of JWT tokens.

## Checks
- `alg:none` bypass
- RS256 → HS256 algorithm confusion
- Weak HMAC secret dictionary attack
- Claim validation (exp, nbf, iss, aud)
- Signature forging with known key
- `kid` injection, `jku` confusion

## Usage
```bash
pip install -r requirements.txt

python jwt_analyzer.py analyze --token "eyJ0eXAiOiJKV1Qi..."
python jwt_analyzer.py crack --token "eyJ..." --wordlist secrets.txt
python jwt_analyzer.py algnone --token "eyJ..."
python jwt_analyzer.py forge --token "eyJ..." --secret "mysecret" --claims '{"admin":true}'
```
