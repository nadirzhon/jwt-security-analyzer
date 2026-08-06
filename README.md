# 🔑 JWT Security Analyzer

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white) ![License](https://img.shields.io/badge/License-MIT-green) ![Tests](https://img.shields.io/badge/tests-passing-success) ![Status](https://img.shields.io/badge/status-active-brightgreen)

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

## Responsible use

This project is published for **defensive research, education, and authorized security testing only**.
Use it exclusively on systems you own or have explicit written permission to assess. The author
assumes no liability for misuse. See `SECURITY.md` for the disclosure policy.
