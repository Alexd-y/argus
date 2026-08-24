import { Resolver } from "node:dns/promises";
import {
  dnsNameBelongsToTarget,
  isVerificationToken,
  verificationDnsNames,
} from "./domain-verification";

const PUBLIC_DNS_SERVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"];

function createPublicResolver(): Resolver {
  const resolver = new Resolver();
  resolver.setServers(PUBLIC_DNS_SERVERS);
  return resolver;
}

export async function resolvePublicTxt(name: string): Promise<string[]> {
  const resolver = createPublicResolver();
  try {
    const records = await resolver.resolveTxt(name);
    return records.map((parts) => parts.join("")).map((value) => value.trim());
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (
      code === "ENODATA" ||
      code === "ENOTFOUND" ||
      code === "NXDOMAIN" ||
      code === "SERVFAIL" ||
      code === "ETIMEOUT" ||
      code === "ECONNREFUSED"
    ) {
      return [];
    }
    throw error;
  }
}

export async function verifyDnsTxtToken(
  target: string,
  token: string
): Promise<{
  verified: boolean;
  matchedName: string | null;
  checkedNames: string[];
}> {
  const expected = token.trim();
  const checkedNames = verificationDnsNames(target).filter((name) =>
    dnsNameBelongsToTarget(name, target)
  );

  if (!expected || !isVerificationToken(expected) || checkedNames.length === 0) {
    return { verified: false, matchedName: null, checkedNames };
  }

  const lookups = await Promise.all(
    checkedNames.map(async (name) => {
      const values = await resolvePublicTxt(name);
      return { name, found: values.includes(expected) };
    })
  );

  const match = lookups.find((result) => result.found);
  return {
    verified: Boolean(match),
    matchedName: match?.name ?? null,
    checkedNames,
  };
}
