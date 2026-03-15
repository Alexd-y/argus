# RAGNAROK - Penetration Testing Platform

A modern, cyberpunk-themed web application for security vulnerability scanning and penetration testing.

## Overview

**RAGNAROK** is a demo penetration testing platform by Svalbard Security that provides a sleek interface for security scanning with comprehensive reporting options.

## Features

### Scanning Capabilities
- **Multiple Scan Types**: Quick, Light, and Deep scans
- **Vulnerability Detection**: XSS, SQLi, CSRF, SSRF, LFI/RFI, RCE
- **Authentication Support**: Basic Auth, Bearer Token, Cookie-based
- **Advanced Options**:
  - Custom ports and port ranges
  - Rate limiting controls
  - Proxy support
  - Custom HTTP headers
  - User-Agent spoofing

### User Experience
- **Flexible Input**: Accept URLs with or without protocol (auto-adds https://)
- **Email Notifications**: Receive scan results via email
- **Real-time Progress**: Visual scan progress with 5 stages
- **Multiple Report Formats**: PDF, HTML, JSON, XML

### Reporting Tiers
1. **Basic (Free)**: Overview of discovered issues
2. **Professional ($204)**: Detailed analysis with recommendations
3. **Enterprise ($587)**: Complete audit with step-by-step remediation

## Tech Stack

- **Framework**: Next.js 16.1.6 (App Router)
- **UI**: React 19 with TypeScript
- **Styling**: Tailwind CSS v4
- **Design**: Dark cyberpunk theme with glitch effects

## Getting Started

```bash
# Install dependencies
npm install

# Run development server
npm run dev

# Build for production
npm run build

# Start production server
npm start
```

Open [http://localhost:5000](http://localhost:5000) to view the application.

## Project Structure

```
src/
├── app/
│   ├── page.tsx           # Main scanning interface
│   ├── report/
│   │   └── page.tsx       # Report selection page
│   ├── layout.tsx         # Root layout
│   └── globals.css        # Global styles & animations
```

## Visual Features

- **Glitch Effects**: Hover animations on text and buttons
- **Pulse Animations**: Status indicators
- **Progress Visualization**: Animated scan stages
- **Gradient Accents**: Purple (#A655F7) theme

## Notes

This is a **frontend-only demo**. No actual security scanning is performed - all results are mocked for demonstration purposes.

## Links

- [Svalbard Security](https://svalbard.ca)
- [Documentation](https://svalbard.ca/docs)
- [Support](https://svalbard.ca/support)

## Legal

Authorized testing only. Unauthorized access to computer systems is illegal.

---

© 2026 Svalbard Security Inc.
