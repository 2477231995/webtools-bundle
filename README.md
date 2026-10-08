# webtools-bundle

Security advisories for **WebTools.bundle** (`ukdtom/WebTools.bundle`) — a third-party web
management plugin for **Plex Media Server**, built on the Tornado framework. The project is
**no longer maintained** and no fix is expected.

- **Vendor / project:** `ukdtom`
- **Product:** `WebTools.bundle` (Plex Media Server plugin)
- **Affected versions:** `3.0.0` and all versions up to `master` (tested: `3.0.0`)
- **Credit:** gucheNg
- **CVE IDs:** pending

## Advisories

| # | Vulnerability | CWE | CVSS 4.0 |
|---|---|---|---|
| 1 | [Predictable Tornado session signing key leads to unauthenticated authentication bypass](1.md) | CWE-330, CWE-287 | 9.3 Critical |
| 2 | [Path traversal in the logs download endpoint allows arbitrary file read](2.md) | CWE-22 | 8.7 High |

> Advisory 2 is reachable **without credentials** when chained with advisory 1.

## Repository layout

```
1.md                                  # advisory 1 - predictable session key -> auth bypass
2.md                                  # advisory 2 - logs download path traversal -> arbitrary file read
poc/webtools_cookie_forge.py          # PoC: offline enumeration + forged session cookie
poc/webtools_lfi_packets.md           # Yakit-ready raw HTTP requests (auth bypass + LFI)
```

## References

- Upstream project: <https://github.com/ukdtom/WebTools.bundle>
- Source at tag `3.0.0`: <https://github.com/ukdtom/WebTools.bundle/tree/3.0.0/Contents/Code>
- Vulnerable files:
  - [`Contents/Code/webSrv.py`](https://github.com/ukdtom/WebTools.bundle/blob/master/Contents/Code/webSrv.py)
  - [`Contents/Code/consts.py`](https://github.com/ukdtom/WebTools.bundle/blob/master/Contents/Code/consts.py)
  - [`Contents/Code/logsV3.py`](https://github.com/ukdtom/WebTools.bundle/blob/master/Contents/Code/logsV3.py)

## Disclaimer

The information and proof-of-concept code in this repository are provided for defensive and
educational purposes only, and for use in authorized security testing. Do not use it against
systems you do not own or do not have explicit permission to test.
