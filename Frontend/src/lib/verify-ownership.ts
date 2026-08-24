import { verifyDnsTxtToken } from "./dns-lookup";
import { verifyFileToken } from "./file-verification";

export async function verifyOwnershipToken(
  target: string,
  token: string
): Promise<{
  verified: boolean;
  method: "dns" | "file" | null;
  checkedNames: string[];
  fileUrl: string;
  error?: string;
}> {
  const [dns, file] = await Promise.all([
    verifyDnsTxtToken(target, token),
    verifyFileToken(target, token),
  ]);

  if (dns.verified) {
    return {
      verified: true,
      method: "dns",
      checkedNames: dns.checkedNames,
      fileUrl: file.url,
    };
  }

  if (file.verified) {
    return {
      verified: true,
      method: "file",
      checkedNames: dns.checkedNames,
      fileUrl: file.url,
    };
  }

  const names = dns.checkedNames.join(" or ");
  return {
    verified: false,
    method: null,
    checkedNames: dns.checkedNames,
    fileUrl: file.url,
    error: names
      ? `Ownership not verified. Add the TXT record at ${names}, or publish the token at ${file.url}.`
      : (file.error ?? "Ownership not verified."),
  };
}
