export const VERIFICATION_TXT_PREFIX = "ragnarok-verify=";
export const VERIFICATION_RELATIVE_HOST = "_ragnarok-verify";
export const VERIFICATION_FILE_PATH = "/.well-known/ragnarok-verify.txt";

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

export function verificationRecordHost(target: string): string {
  return `${VERIFICATION_RELATIVE_HOST}.${normalizeHostname(target)}`;
}

export function verificationFileUrl(target: string): string {
  return `https://${normalizeHostname(target)}${VERIFICATION_FILE_PATH}`;
}

/** DNS name queried for the ownership TXT record. */
export function verificationDnsNames(target: string): string[] {
  const host = normalizeHostname(target);
  if (!host || isIpAddress(host)) return [];
  return [`${VERIFICATION_RELATIVE_HOST}.${host}`];
}

export function dnsNameBelongsToTarget(dnsName: string, target: string): boolean {
  const host = normalizeHostname(target);
  const name = dnsName.replace(/\.$/, "").toLowerCase();
  if (!host || !name || isIpAddress(host)) return false;
  return name === host || name.endsWith(`.${host}`);
}

export function isVerificationToken(token: string): boolean {
  return token.startsWith(VERIFICATION_TXT_PREFIX) && token.length > VERIFICATION_TXT_PREFIX.length;
}
