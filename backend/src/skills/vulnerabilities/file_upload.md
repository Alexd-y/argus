---
name: file_upload
description: Unrestricted file upload vulnerability testing
applicable_contexts: [web, api, file_operations]
---

## File Upload Testing

### Extension Bypass Techniques

- Double extension: shell.php.jpg, shell.php.png
- Null byte (legacy): shell.php%00.jpg
- Case variation: shell.PhP, shell.pHP
- Alternative extensions: .php5, .phtml, .shtml, .phar, .inc
- Trailing characters: shell.php. or shell.php::$DATA (Windows)
- Right-to-left override: Unicode character to reverse extension display

### MIME Type Confusion

Upload executable file with image Content-Type header.
Add image magic bytes (JPEG: FF D8 FF E0) before executable code.

### SVG XSS via Upload

Upload SVG containing JavaScript in script tags or event handlers.
If SVG rendered in browser, JavaScript executes in application origin.

### Web Shell Payloads

PHP: system() or exec() with GET parameter for command.
JSP: Runtime.getRuntime().exec() for Java environments.
ASPX: Process.Start() for .NET environments.

### Path Traversal in Filename

Inject ../ sequences in the filename field of multipart upload.
URL-encode the traversal: ..%2f..%2f to bypass filters.

### Polyglot Files

Create files valid as both image and executable code.
GIF89a header followed by PHP code creates valid GIF that also executes as PHP.

### Zip Slip Attack

Create archive with relative path traversal in filenames.
When extracted server-side, files write outside intended directory.

### Validation Requirements

- Upload file that gets executed server-side or rendered in browser
- For web shells: demonstrate command execution via uploaded file
- For XSS via upload: show script execution from uploaded SVG or HTML
- Document accepted file types, storage location, and serving URL
- Check Content-Type and Content-Disposition headers on served files

### Business Impact

- Remote code execution via web shell upload
- Stored XSS through SVG or HTML file uploads
- Denial of service via large files or archive bombs
- Infrastructure compromise through configuration file overwrite
- Malware distribution from trusted domain origin
