export function getEmailDomain(email: string): string {
  return email.split("@")[1]?.toLowerCase().trim() ?? "";
}

export function normalizeHostname(host: string): string {
  const hostname = host.replace(/^https?:\/\//, "").split("/")[0].split(":")[0].toLowerCase();
  return hostname.replace(/^www\./, "");
}

export function isIpAddress(host: string): boolean {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(normalizeHostname(host));
}

export function emailMatchesTarget(email: string, target: string): boolean {
  const emailDomain = getEmailDomain(email);
  const targetHost = normalizeHostname(target);

  if (!emailDomain || !targetHost) return false;
  if (isIpAddress(targetHost)) return false;

  if (emailDomain === targetHost) return true;
  if (targetHost.endsWith(`.${emailDomain}`)) return true;
  if (emailDomain.endsWith(`.${targetHost}`)) return true;

  return false;
}
