export function ServicesSection() {
  const services = [
    {
      title: "Consultation",
      description: "Expert review of your specific situation and security posture.",
      icon: (
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth={2}
          d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z"
        />
      ),
    },
    {
      title: "Remediation Service",
      description: "Our team fixes discovered vulnerabilities on your behalf.",
      icon: (
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth={2}
          d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z M15 12a3 3 0 11-6 0 3 3 0 016 0z"
        />
      ),
    },
    {
      title: "Retainer",
      description: "Ongoing security monitoring, scanning, and expert support.",
      icon: (
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth={2}
          d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"
        />
      ),
    },
    {
      title: "Post-Fix Audit",
      description: "Verification that all remediations were applied correctly.",
      icon: (
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth={2}
          d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"
        />
      ),
    },
  ];

  return (
    <div className="border border-neutral-800 bg-neutral-900 rounded-lg overflow-hidden">
      <div className="border-b border-neutral-800 bg-neutral-950 px-4 sm:px-6 py-3 sm:py-4">
        <h2 className="text-base sm:text-lg text-white">Need Help With Remediation?</h2>
        <p className="text-neutral-500 text-xs mt-1">Our experts can help fix all discovered issues</p>
      </div>
      <div className="p-4 sm:p-6">
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 sm:gap-6 mb-6">
          {services.map((service) => (
            <div key={service.title} className="flex gap-4">
              <div className="flex-shrink-0 w-12 h-12 flex items-center justify-center">
                <svg className="w-8 h-8 text-[#A655F7]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  {service.icon}
                </svg>
              </div>
              <div>
                <h4 className="text-white text-sm font-medium mb-1">{service.title}</h4>
                <p className="text-xs text-neutral-500 leading-relaxed">{service.description}</p>
              </div>
            </div>
          ))}
        </div>
        <div className="text-center">
          <a
            href="https://svalbard.ca/support"
            className="inline-block bg-[#A655F7] text-white px-8 py-3 rounded text-sm font-medium hover:bg-[#b875f8] glitch-hover cursor-pointer"
          >
            Contact Us
          </a>
        </div>
      </div>
    </div>
  );
}
