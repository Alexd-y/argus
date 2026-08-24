"use client";

import { useEffect, useState, useCallback, Suspense } from "react";
import Link from "next/link";
import { useParams, useSearchParams } from "next/navigation";
import type { ScanData } from "@/lib/scan-types";
import { Header } from "@/components/Header";
import { Footer } from "@/components/Footer";
import { ScanRunning } from "@/components/scan/ScanRunning";
import { ScanSuccess } from "@/components/scan/ScanSuccess";
import { ScanFailed } from "@/components/scan/ScanFailed";

const POLL_INTERVAL_MS = 5000;

function ScanPageContent() {
  const params = useParams();
  const searchParams = useSearchParams();
  const id = params.id as string;
  const [scan, setScan] = useState<ScanData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const canceled = searchParams.get("canceled") === "true";
  const justUnlocked = searchParams.get("unlocked") === "true";
  const extraCredits = searchParams.get("credits") === "1";

  const fetchScan = useCallback(async () => {
    try {
      const res = await fetch(`/api/scans/${id}`);
      if (!res.ok) {
        if (res.status === 404) {
          setError("Scan not found");
        } else {
          setError("Failed to load scan");
        }
        return;
      }
      const data: ScanData = await res.json();
      setScan(data);
      setError(null);
    } catch {
      setError("Failed to load scan");
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      try {
        const res = await fetch(`/api/scans/${id}`);
        if (cancelled) return;
        if (!res.ok) {
          setError(res.status === 404 ? "Scan not found" : "Failed to load scan");
          return;
        }
        const data: ScanData = await res.json();
        if (cancelled) return;
        setScan(data);
        setError(null);
      } catch {
        if (!cancelled) setError("Failed to load scan");
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    void load();
    return () => {
      cancelled = true;
    };
  }, [id, justUnlocked]);

  // Drop ?unlocked=true from the URL once we've confirmed payment server-side
  useEffect(() => {
    if (!justUnlocked || !scan?.paid || scan.tier === "free") return;
    window.history.replaceState({}, "", `/scan/${id}`);
  }, [justUnlocked, scan?.paid, scan?.tier, id]);

  useEffect(() => {
    if (!extraCredits) return;
    window.history.replaceState({}, "", `/scan/${id}`);
  }, [extraCredits, id]);

  const showUnlockedBanner =
    justUnlocked && scan?.paid === true && scan.tier !== "free";

  useEffect(() => {
    if (!scan || (scan.status !== "pending" && scan.status !== "running")) {
      return;
    }

    const interval = setInterval(fetchScan, POLL_INTERVAL_MS);
    return () => clearInterval(interval);
  }, [scan, fetchScan]);

  const baseUrl = typeof window !== "undefined" ? window.location.origin : "";
  const scanUrl = `${baseUrl}/scan/${id}`;

  return (
    <div className="flex min-h-screen flex-col bg-neutral-950 font-mono text-sm">
      <Header wide />

      <main className="flex flex-1 px-4 sm:px-6 py-6 sm:py-10">
        <div className="mx-auto w-full max-w-5xl">
          {canceled && (
            <div className="mb-4 border border-amber-500/30 bg-amber-500/5 rounded p-3 text-xs text-amber-300">
              Checkout was canceled. Your scan results are still available to unlock.
            </div>
          )}

          {showUnlockedBanner && scan.quota && (
            <div className="mb-4 border border-emerald-500/30 bg-emerald-500/5 rounded p-3 text-xs text-emerald-300">
              Subscription active. Full results are now unlocked — {scan.quota.remaining} of{" "}
              {scan.quota.capacity} scans remaining this period.
            </div>
          )}

          {extraCredits && (
            <div className="mb-4 border border-emerald-500/30 bg-emerald-500/5 rounded p-3 text-xs text-emerald-300">
              Extra scan added. You can retest this target now.
            </div>
          )}

          {loading && (
            <div className="text-center py-16 text-neutral-500">Loading scan...</div>
          )}

          {error && !loading && (
            <div className="text-center py-16">
              <p className="text-red-400 mb-4">{error}</p>
              <Link href="/" className="text-[#A655F7] hover:text-[#b875f8] underline text-xs">
                Back to home
              </Link>
            </div>
          )}

          {scan && !error && (
            <>
              {(scan.status === "pending" || scan.status === "running") && (
                <div className="max-w-xl mx-auto border border-neutral-800 bg-neutral-900 rounded">
                  <div className="flex items-center justify-between border-b border-neutral-800 px-4 py-3">
                    <div className="flex items-center gap-2">
                      <div className="h-2 w-2 rounded-full bg-amber-400 pulse-glow" />
                      <span className="text-white truncate">{scan.target}</span>
                    </div>
                    <span className="text-xs text-neutral-600">{scan.status}</span>
                  </div>
                  <div className="p-5">
                    <ScanRunning scan={scan} scanUrl={scanUrl} />
                  </div>
                </div>
              )}

              {scan.status === "complete" && <ScanSuccess scan={scan} />}

              {scan.status === "failed" && (
                <div className="max-w-xl mx-auto border border-neutral-800 bg-neutral-900 rounded">
                  <div className="p-5">
                    <ScanFailed scan={scan} />
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </main>

      <Footer wide />
    </div>
  );
}

export default function ScanPage() {
  return (
    <Suspense
      fallback={
        <div className="flex min-h-screen items-center justify-center bg-neutral-950 text-neutral-400">
          Loading...
        </div>
      }
    >
      <ScanPageContent />
    </Suspense>
  );
}
