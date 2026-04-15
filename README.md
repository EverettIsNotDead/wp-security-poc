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

## Example Request

```http
POST /xmlrpc.php HTTP/1.1
Content-Type: text/xml

<methodCall>
  <methodName>system.multicall</methodName>
  ...
</methodCall>
```

---

## How It Works

1. Sends batched authentication attempts using `system.multicall`
2. Parses server responses to identify potential valid credentials
3. Performs a single verification request to confirm successful authentication

---

## Usage

```bash
chmod +x audit.sh

./audit.sh \
  --target http://example.com/xmlrpc.php \
  --user admin \
  --wordlist passwords.txt
```

---

## Expected Output

```
[+] Valid credentials found: admin:password123
```

---

## Features

* Efficient batching of authentication attempts
* Reduced network overhead via multicall
* Verification step to eliminate false positives
* Configurable delays for controlled testing
* Logging support for audit trails

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

## ⚠️ Disclaimer

This tool is intended for educational purposes and authorized security testing only.

Unauthorized access to computer systems is illegal. The author is not responsible for any misuse of this tool.
