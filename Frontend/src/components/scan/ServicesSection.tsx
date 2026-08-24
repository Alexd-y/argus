interface ServicesSectionProps {
  target: string;
  critical: number;
  important: number;
}

export function ServicesSection({ target, critical, important }: ServicesSectionProps) {
  const supportHref = `https://svalbard.ca/support?target=${encodeURIComponent(target)}&critical=${critical}&important=${important}`;

  return (
    <div className="border border-neutral-800 bg-neutral-900 rounded-sm overflow-hidden">
      <div className="border-b border-neutral-800 bg-neutral-950 px-4 sm:px-6 py-3 sm:py-4">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-[10px] uppercase tracking-wider border border-neutral-700 text-neutral-400 px-1.5 py-0.5 rounded-sm">
            Humans, not the scanner
          </span>
          <h2 className="text-base sm:text-lg text-white">Want people to fix these?</h2>
        </div>
        <p className="text-neutral-500 text-xs mt-1.5">
          {critical} critical / {important} important on {target}.
        </p>
      </div>
      <div className="p-4 sm:p-6">
        <p className="text-xs text-neutral-500 leading-relaxed mb-6">
          Ragnarøk scanning is automated. Remediation is not: the Svalbard Security team can fix the
          findings from this scan by hand and then retest them. That is separate work, quoted per
          engagement — not part of your scan subscription.
        </p>
        <div className="text-center">
          <a
            href={supportHref}
            className="inline-block bg-[#A655F7] text-white px-8 py-3 rounded text-sm font-medium hover:bg-[#b875f8] cursor-pointer"
          >
            Talk to the Svalbard team
          </a>
        </div>
      </div>
    </div>
  );
}
