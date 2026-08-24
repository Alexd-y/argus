import { getTierConfig } from "@/lib/scan-tiers";

interface SubdomainsSectionProps {
  target: string;
  subdomains: string[] | null;
  included: boolean;
  anchor: string;
}

export function SubdomainsSection({
  target,
  subdomains,
  included,
  anchor,
}: SubdomainsSectionProps) {
  if (!included) {
    return (
      <section id={anchor} className="scroll-mt-6 border border-neutral-800 bg-neutral-900 rounded-sm overflow-hidden">
        <div className="border-b border-neutral-800 bg-neutral-950 px-4 sm:px-6 py-3 sm:py-4">
          <h2 className="text-base sm:text-lg text-white">Subdomain discovery</h2>
          <p className="text-neutral-500 text-xs mt-1">
            Find related hosts under {target} and scan them with the same checks.
          </p>
        </div>
        <div className="px-4 sm:px-6 py-5">
          <p className="text-xs text-neutral-500">
            Included on <span className="text-[#E3CAFE]">{getTierConfig("premium").name}</span> only.
          </p>
        </div>
      </section>
    );
  }

  const hosts = subdomains ?? [];

  return (
    <section id={anchor} className="scroll-mt-6 border border-neutral-800 bg-neutral-900 rounded-sm overflow-hidden">
      <div className="border-b border-neutral-800 bg-neutral-950 px-4 sm:px-6 py-3 sm:py-4">
        <h2 className="text-base sm:text-lg text-white">Discovered subdomains</h2>
        <p className="text-neutral-500 text-xs mt-1">
          {hosts.length === 0
            ? `No subdomains found under ${target}. The apex host was scanned.`
            : `${hosts.length} host${hosts.length === 1 ? "" : "s"} under ${target} discovered and included in this assessment.`}
        </p>
      </div>
      {hosts.length > 0 && (
        <ul className="divide-y divide-neutral-800">
          {hosts.map((host) => (
            <li
              key={host}
              className="flex items-center justify-between gap-3 px-4 sm:px-6 py-3 text-xs"
            >
              <span className="text-neutral-200 break-all font-mono">{host}</span>
              <span className="text-[10px] uppercase tracking-wider text-emerald-400/80 flex-shrink-0">
                Scanned
              </span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
