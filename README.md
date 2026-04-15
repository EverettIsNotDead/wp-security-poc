# WordPress XML-RPC Multicall Rate Limit Bypass (PoC)

A Proof-of-Concept demonstrating how the `system.multicall` method in WordPress XML-RPC can be abused to bypass traditional rate-limiting mechanisms and perform large-scale authentication attempts.

---

## Quick Summary

* **Component:** WordPress XML-RPC (`/xmlrpc.php`)
* **Method:** `system.multicall`
* **Vulnerability Type:** Rate Limit Bypass
* **Impact:** Large-scale brute-force attacks
* **Authentication Required:** No

---

## Vulnerability Overview

The `system.multicall` method allows multiple XML-RPC calls to be bundled into a single HTTP request.

Many systems apply rate-limiting per HTTP request rather than per authentication attempt. This allows an attacker to send hundreds of login attempts within a single request, effectively bypassing protection mechanisms.

---

## How It Works

1. Sends batched authentication attempts using `system.multicall`
2. Parses server responses to identify potential valid credentials
3. Performs a single verification request to confirm successful authentication

---

## Usage

### CLI Mode (Recommended)

```bash
./audit.sh \
  --target https://example.com/xmlrpc.php \
  --user admin \
  --wordlist passwords.txt \
  --batch 50 \
  --delay 1 \
  --timeout 10
```

### Interactive Mode

```bash
./audit.sh
```

The script will prompt for:

* Target XML-RPC endpoint
* Username
* Password wordlist
* Batch size

---

## Options

| Flag       | Description              |
| ---------- | ------------------------ |
| --target   | XML-RPC endpoint         |
| --user     | Target username          |
| --wordlist | Password list            |
| --batch    | Batch size (default: 50) |
| --delay    | Delay between batches    |
| --timeout  | Request timeout          |
| --insecure | Disable SSL verification |

insecure option is only viable for lab environments.

---

## Expected Output

```
[SUCCESS] Valid Credential: admin:password123
```

---

## Features

* Efficient batching via `system.multicall`
* Reduced network overhead
* Verification step to avoid false positives
* Configurable delay for controlled testing
* Logging support (`security_audit_log.txt`)
* CLI + Interactive usage support

---

## Responsible Disclosure

* Vulnerability identified during authorized security testing
* Reported to the affected organization
* Successfully mitigated via WAF implementation

---

## Mitigation

* Disable XML-RPC if not required
* Block or restrict `system.multicall`
* Apply rate-limiting per authentication attempt (not per request)
* Use WAF rules (e.g., OpenResty, ModSecurity)

---

## Detection

* High volume of requests to `/xmlrpc.php`
* Large XML payloads containing multiple authentication attempts
* Repeated login attempts within a single HTTP request

---

## Limitations

* Requires XML-RPC to be enabled
* May be blocked by WAF or rate limiting
* Response detection is heuristic-based

---

## ⚠️ Disclaimer

This tool is intended for educational purposes and authorized security testing only.

Unauthorized access to computer systems is illegal. The author is not responsible for any misuse of this tool.
