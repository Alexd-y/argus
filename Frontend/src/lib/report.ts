import type { ScanRecord } from "./scans";
import { getTierConfig } from "./scan-tiers";
import type { Finding } from "./scan-results";
import { groupFindings } from "./scan-results";

// Characters outside Latin-1 that WinAnsiEncoding maps to its 0x80-0x9F block.
const WIN_ANSI_SPECIALS: Record<string, number> = {
  "\u20AC": 0x80,
  "\u201A": 0x82,
  "\u0192": 0x83,
  "\u201E": 0x84,
  "\u2026": 0x85,
  "\u2020": 0x86,
  "\u2021": 0x87,
  "\u02C6": 0x88,
  "\u2030": 0x89,
  "\u0160": 0x8a,
  "\u2039": 0x8b,
  "\u0152": 0x8c,
  "\u017D": 0x8e,
  "\u2018": 0x91,
  "\u2019": 0x92,
  "\u201C": 0x93,
  "\u201D": 0x94,
  "\u2022": 0x95,
  "\u2013": 0x96,
  "\u2014": 0x97,
  "\u02DC": 0x98,
  "\u2122": 0x99,
  "\u0161": 0x9a,
  "\u203A": 0x9b,
  "\u0153": 0x9c,
  "\u017E": 0x9e,
  "\u0178": 0x9f,
};

function pdfEscape(text: string): string {
  let out = "";
  for (const char of text) {
    if (char === "\\") out += "\\\\";
    else if (char === "(") out += "\\(";
    else if (char === ")") out += "\\)";
    else {
      const code = char.codePointAt(0) ?? 0x3f;
      if (code >= 0x20 && code <= 0x7e) out += char;
      else {
        const byte = code >= 0xa0 && code <= 0xff ? code : WIN_ANSI_SPECIALS[char];
        out += byte ? `\\${byte.toString(8).padStart(3, "0")}` : "?";
      }
    }
  }
  return out;
}

function wrap(text: string, width: number): string[] {
  const words = text.split(/\s+/);
  const lines: string[] = [];
  let current = "";
  for (const word of words) {
    const next = current ? `${current} ${word}` : word;
    if (next.length > width && current) {
      lines.push(current);
      current = word;
    } else {
      current = next;
    }
  }
  if (current) lines.push(current);
  return lines.length ? lines : [""];
}

function statusLabel(finding: Finding): string {
  return `${finding.status.toUpperCase()} / ${finding.priority.toUpperCase()}`;
}

export function buildReportPdf(scan: ScanRecord): Uint8Array {
  const tier = getTierConfig(scan.tier);
  const results = scan.results;
  const findings: Finding[] = results?.findings ?? [];

  const commands: string[] = [];
  const pageStarts: number[] = [];
  let y = 0;

  const startPage = () => {
    pageStarts.push(commands.length);
    y = 742;
    commands.push("BT");
  };

  const endPage = () => {
    commands.push("ET");
  };

  const ensureSpace = (needed: number) => {
    if (y - needed < 56) {
      endPage();
      startPage();
    }
  };

  const text = (content: string, size: number, bold: boolean, leading = size + 4) => {
    ensureSpace(leading);
    const font = bold ? "/F2" : "/F1";
    commands.push(`${font} ${size} Tf`);
    commands.push(`50 ${y} Td`);
    commands.push(`(${pdfEscape(content)}) Tj`);
    commands.push("ET BT");
    y -= leading;
  };

  const body = (content: string, size = 10) => {
    for (const line of wrap(content, 80)) {
      text(line, size, false, size + 3);
    }
  };

  startPage();
  text("RAGNARØK SECURITY SCAN REPORT", 16, true, 22);
  text("Svalbard Security — authorized testing only", 9, false, 16);
  y -= 8;
  text(`Target:    ${scan.target}`, 11, false, 15);
  text(`Report:    ${tier.name}`, 11, false, 15);
  text(`Scan ID:   ${scan.id}`, 11, false, 15);
  text(`Completed: ${scan.completedAt ?? "—"}`, 11, false, 18);

  if (results) {
    text("COMMAND BOARD", 12, true, 18);
    text(
      `Findings ${results.totalFindings}    Critical ${results.critical}    Important ${results.high}    Passed ${results.passed}`,
      10,
      false,
      16
    );
    if (scan.tier === "free") {
      body(
        `${getTierConfig("free").name} lists 1-2 critical summaries. Remaining findings are counted above and unlock on ${getTierConfig("standard").name} and ${getTierConfig("premium").name}.`
      );
    }
    if (results.technologies.length) {
      body(`Stack: ${results.technologies.join(", ")}`);
    }
    if (scan.tier === "premium") {
      if (results.subdomains && results.subdomains.length > 0) {
        body(
          `Subdomains discovered and scanned (${results.subdomains.length}): ${results.subdomains.join(", ")}`
        );
      } else {
        body("Subdomain discovery: none found under this apex. The apex host was scanned.");
      }
    }

    y -= 8;
    text("CHECK INDEX", 12, true, 18);
    for (const item of findings) {
      body(`${item.id}  ${statusLabel(item)}  ${item.name}`);
    }

    y -= 8;
    for (const group of groupFindings(findings)) {
      text(`${group.groupId}. ${group.group.toUpperCase()}`, 12, true, 20);
      for (const item of group.findings) {
        ensureSpace(80);
        text(`${item.id}  ${item.name}`, 11, true, 16);
        body(item.headline);
        if (item.access === "basic" || item.access === "full") {
          y -= 4;
          if (item.explanation) body(item.explanation);
          if (item.evidence) {
            text("Evidence", 10, true, 14);
            body(item.evidence);
          }
          if (item.probe) {
            text("Scanner output", 10, true, 14);
            body(`Port: ${item.probe.port}`);
            body(`Template Path: ${item.probe.templatePath}`);
            body(`Template ID: ${item.probe.templateId}`);
            body(`Matcher: ${item.probe.matcher}`);
            body(`Matched At: ${item.probe.matchedAt}`);
            body(`IP Address: ${item.probe.ipAddress}`);
            body(`Tags: ${item.probe.tags.join(", ")}`);
            text("Extracted Results", 10, true, 14);
            for (const result of item.probe.extractedResults) {
              body(result);
            }
          }
          if (item.remediation) {
            text(item.access === "full" ? "Step-by-step remediation" : "Remediation", 10, true, 14);
            body(item.remediation);
          }
        } else if (item.access === "summary") {
          body(
            `Summary only — full evidence and remediation are unlocked on ${getTierConfig("standard").name} and ${getTierConfig("premium").name}.`
          );
        } else {
          body("Listed in this index. Full writeup is included in a higher tier report.");
        }
        y -= 10;
      }
    }

    const leaks = scan.darkWebMonitoring ? (results.leaks ?? []) : [];
    if (leaks.length > 0) {
      text("DARK WEB EXPOSURE", 12, true, 20);
      body(
        `${leaks.length} account${leaks.length === 1 ? "" : "s"} on this domain appear in public breach dumps. Rotate these passwords and enable multi-factor authentication.`
      );
      y -= 4;
      for (const leak of leaks) {
        ensureSpace(48);
        text(`${leak.identity} (${leak.identityKind})`, 11, true, 15);
        if (leak.source) body(`Source: ${leak.source} (${leak.breachedAt})`);
        if (leak.exposed.length) body(`Exposed: ${leak.exposed.join(", ")}`);
        if (leak.access === "full") {
          body(
            `Password: ${leak.secretKind === "plaintext" ? "plaintext" : "hashed"} — ${leak.secret}${
              leak.algorithm ? ` (${leak.algorithm})` : ""
            }`
          );
        }
        y -= 8;
      }
    }
  }

  y -= 6;
  text("Need help with remediation? svalbard.ca/support", 9, false, 14);
  text("Svalbard Security Inc. — https://svalbard.ca", 9, false, 12);

  endPage();

  const pageCount = pageStarts.length;
  const contentStreams: string[] = [];
  for (let i = 0; i < pageCount; i += 1) {
    const start = pageStarts[i];
    const end = i + 1 < pageCount ? pageStarts[i + 1] : commands.length;
    contentStreams.push(commands.slice(start, end).join("\n") + "\n");
  }

  const objects: string[] = [];
  const add = (bodyText: string) => {
    objects.push(bodyText);
    return objects.length;
  };

  const fontRegular = add(
    "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"
  );
  const fontBold = add(
    "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>"
  );

  const contentIds: number[] = [];
  for (const stream of contentStreams) {
    contentIds.push(
      add(`<< /Length ${stream.length} >>\nstream\n${stream}endstream`)
    );
  }

  const pageIds: number[] = [];
  const pagesId = objects.length + pageCount + 1;

  for (let i = 0; i < pageCount; i += 1) {
    pageIds.push(
      add(
        `<< /Type /Page /Parent ${pagesId} 0 R /MediaBox [0 0 612 792] /Contents ${contentIds[i]} 0 R /Resources << /Font << /F1 ${fontRegular} 0 R /F2 ${fontBold} 0 R >> >> >>`
      )
    );
  }

  const kids = pageIds.map((id) => `${id} 0 R`).join(" ");
  add(`<< /Type /Pages /Kids [ ${kids} ] /Count ${pageCount} >>`);
  const catalogId = add(`<< /Type /Catalog /Pages ${pagesId} 0 R >>`);

  const encoder = new TextEncoder();
  const header = "%PDF-1.4\n";
  const chunks: Uint8Array[] = [encoder.encode(header)];
  let offset = header.length;
  const xref = [0];

  for (let i = 0; i < objects.length; i += 1) {
    xref.push(offset);
    const objectText = `${i + 1} 0 obj\n${objects[i]}\nendobj\n`;
    const bytes = encoder.encode(objectText);
    chunks.push(bytes);
    offset += bytes.length;
  }

  const xrefStart = offset;
  let xrefTable = `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (let i = 1; i <= objects.length; i += 1) {
    xrefTable += `${String(xref[i]).padStart(10, "0")} 00000 n \n`;
  }
  const trailer = `trailer\n<< /Size ${objects.length + 1} /Root ${catalogId} 0 R >>\nstartxref\n${xrefStart}\n%%EOF\n`;
  chunks.push(encoder.encode(xrefTable + trailer));

  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const output = new Uint8Array(total);
  let cursor = 0;
  for (const chunk of chunks) {
    output.set(chunk, cursor);
    cursor += chunk.length;
  }
  return output;
}
