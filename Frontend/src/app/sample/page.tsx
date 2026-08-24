import type { Metadata } from "next";
import { Header } from "@/components/Header";
import { Footer } from "@/components/Footer";
import { SampleReport } from "@/components/scan/SampleReport";
import { getTierConfig } from "@/lib/scan-tiers";

export const metadata: Metadata = {
  title: "Sample report | Ragnarøk",
  description:
    "See a complete Full Surface report before you subscribe: subdomain discovery, every finding with evidence, scanner output, step-by-step fixes, and dark web exposure.",
};

export default function SamplePage() {
  return (
    <div className="flex min-h-screen flex-col bg-neutral-950 font-mono text-sm">
      <Header wide />
      <main className="flex flex-1 px-4 sm:px-6 py-6 sm:py-10">
        <div className="mx-auto w-full max-w-5xl">
          <div className="mb-5 sm:mb-6 border border-[#A655F7]/50 bg-[#A655F7]/[0.08] rounded-sm px-4 py-4 sm:px-5">
            <div className="flex flex-wrap items-center gap-2 mb-1.5">
              <span className="text-[10px] uppercase tracking-wider bg-[#A655F7] text-white px-2 py-0.5 rounded-sm">
                Sample
              </span>
              <p className="text-sm text-white">
                This is what a {getTierConfig("premium").name} report looks like
              </p>
            </div>
            <p className="text-xs text-neutral-300 leading-relaxed">
              A complete report for the demo domain <span className="text-[#E3CAFE]">example.com</span>:
              subdomain discovery and testing, every finding with evidence, scanner output, step-by-step
              fixes, and dark web exposure. The numbers here are illustrative — scan your own domain to
              get yours, free, before you decide anything.
            </p>
          </div>
          <SampleReport />
        </div>
      </main>
      <Footer wide />
    </div>
  );
}
