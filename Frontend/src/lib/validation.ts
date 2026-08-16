export type ValidationResult = {
  valid: boolean;
  type: "url" | "ip" | "invalid" | "empty";
  message: string;
};

function isLocalIP(octets: number[]): boolean {
  if (octets[0] === 10) return true;
  if (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) return true;
  if (octets[0] === 192 && octets[1] === 168) return true;
  if (octets[0] === 127) return true;
  if (octets.every((o) => o === 0)) return true;
  if (octets[0] === 169 && octets[1] === 254) return true;
  return false;
}

export function validateTarget(value: string): ValidationResult {
  if (!value.trim()) {
    return { valid: false, type: "empty", message: "" };
  }

  const urlPattern =
    /^https?:\/\/([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(\/.*)?$/;
  const ipPattern = /^https?:\/\/(\d{1,3}\.){3}\d{1,3}(:\d{1,5})?(\/.*)?$/;
  const bareIpPattern = /^(\d{1,3}\.){3}\d{1,3}(:\d{1,5})?$/;
  const bareDomainPattern =
    /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(\/.*)?$/;

  if (urlPattern.test(value)) {
    return { valid: true, type: "url", message: "Valid URL" };
  }

  if (ipPattern.test(value)) {
    const ipMatch = value.match(/(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/);
    if (ipMatch) {
      const octets = [ipMatch[1], ipMatch[2], ipMatch[3], ipMatch[4]].map(Number);
      if (octets.every((o) => o >= 0 && o <= 255)) {
        if (isLocalIP(octets)) {
          return { valid: false, type: "invalid", message: "Local/private IPs not allowed" };
        }
        return { valid: true, type: "ip", message: "Valid IP" };
      }
    }
    return { valid: false, type: "invalid", message: "Invalid IP octets (0-255)" };
  }

  if (bareIpPattern.test(value)) {
    const ipMatch = value.match(/(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/);
    if (ipMatch) {
      const octets = [ipMatch[1], ipMatch[2], ipMatch[3], ipMatch[4]].map(Number);
      if (octets.every((o) => o >= 0 && o <= 255)) {
        if (isLocalIP(octets)) {
          return { valid: false, type: "invalid", message: "Local/private IPs not allowed" };
        }
        return { valid: true, type: "ip", message: "Valid IP" };
      }
    }
    return { valid: false, type: "invalid", message: "Invalid IP address" };
  }

  if (bareDomainPattern.test(value)) {
    return { valid: true, type: "url", message: "Valid domain" };
  }

  if (value.startsWith("http://") || value.startsWith("https://")) {
    return { valid: false, type: "invalid", message: "Invalid URL format" };
  }

  return { valid: false, type: "invalid", message: "Enter a valid URL or IP address" };
}

export function normalizeTarget(value: string, selectedProtocol: string = "https"): string {
  const protocols = ["http://", "https://"];
  if (protocols.some((p) => value.startsWith(p))) {
    return value;
  }
  return selectedProtocol + "://" + value;
}

export function extractHostname(target: string, protocol: string = "https"): string {
  const normalized = normalizeTarget(target, protocol);
  return normalized.replace(/^https?:\/\//, "").split("/")[0];
}

export function isValidEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
}
