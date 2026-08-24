import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import {
  isIpAddress,
  isVerificationToken,
  normalizeHostname,
  verificationFileUrl,
} from "./domain-verification";
import { isLocalIP } from "./validation";

const FETCH_TIMEOUT_MS = 5000;
const MAX_BODY_BYTES = 2048;

function isPrivateOrLocalIP(ip: string): boolean {
  const version = isIP(ip);
  if (version === 4) {
    const octets = ip.split(".").map(Number);
    if (octets.length !== 4 || octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)) {
      return true;
    }
    return isLocalIP(octets);
  }
  if (version === 6) {
    const lower = ip.toLowerCase();
    const mapped = lower.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) return isPrivateOrLocalIP(mapped[1]);
    return (
      lower === "::" ||
      lower === "::1" ||
      lower.startsWith("fe80:") ||
      lower.startsWith("fc") ||
      lower.startsWith("fd")
    );
  }
  return true;
}

async function hostIsPublic(hostname: string): Promise<boolean> {
  if (isIpAddress(hostname)) {
    return !isPrivateOrLocalIP(hostname);
  }
  try {
    const records = await lookup(hostname, { all: true });
    if (records.length === 0) return false;
    return records.every((record) => !isPrivateOrLocalIP(record.address));
  } catch {
    return false;
  }
}

function tokenFromBody(body: string, expected: string): boolean {
  return body.replace(/^\uFEFF/, "").trim() === expected;
}

export async function verifyFileToken(
  target: string,
  token: string
): Promise<{ verified: boolean; url: string; error?: string }> {
  const hostname = normalizeHostname(target);
  const url = verificationFileUrl(hostname);
  const expected = token.trim();

  if (!hostname || !expected || !isVerificationToken(expected)) {
    return { verified: false, url, error: "Invalid verification token." };
  }

  const publicHost = await hostIsPublic(hostname);
  if (!publicHost) {
    return {
      verified: false,
      url,
      error: "File verification is only available for public hostnames.",
    };
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  try {
    const response = await fetch(url, {
      method: "GET",
      redirect: "manual",
      credentials: "omit",
      signal: controller.signal,
      headers: { Accept: "text/plain, */*" },
    });

    if (response.status < 200 || response.status >= 300) {
      return {
        verified: false,
        url,
        error: `File not found at ${url}. Publish the token as plain text, then try again.`,
      };
    }

    const buffer = await response.arrayBuffer();
    if (buffer.byteLength > MAX_BODY_BYTES) {
      return { verified: false, url, error: "Verification file is larger than expected." };
    }

    const body = new TextDecoder("utf-8", { fatal: false }).decode(buffer);
    if (!tokenFromBody(body, expected)) {
      return {
        verified: false,
        url,
        error: `Token mismatch at ${url}. The file must contain only the verification value.`,
      };
    }

    return { verified: true, url };
  } catch {
    return {
      verified: false,
      url,
      error: `Could not fetch ${url}. Confirm the file is published over HTTPS.`,
    };
  } finally {
    clearTimeout(timer);
  }
}
