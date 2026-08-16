"use client";

import { useCallback, useEffect, useState } from "react";

import { labApi } from "@/lib/lab/labApi";
import type { NucleiReleaseRecord } from "@/lib/lab/types";

const SHA256_RE = /^[0-9a-f]{64}$/;

export function NucleiReleasePanel() {
  const [releases, setReleases] = useState<NucleiReleaseRecord[]>([]);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [version, setVersion] = useState("");
  const [digest, setDigest] = useState("");
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback(() => {
    void labApi
      .listNucleiReleases()
      .then((payload) => {
        setReleases(payload.releases);
        setActiveId(payload.active_release_id);
        setError(null);
      })
      .catch((err: unknown) => {
        setError(err instanceof Error ? err.message : "releases_failed");
      });
  }, []);

  useEffect(() => {
    reload();
  }, [reload]);

  async function register() {
    const trimmedDigest = digest.trim().toLowerCase();
    if (!version.trim() || !SHA256_RE.test(trimmedDigest)) {
      setError("version and 64-char sha256 digest required");
      return;
    }
    try {
      await labApi.registerNucleiRelease({
        version: version.trim(),
        digest_sha256: trimmedDigest,
      });
      setVersion("");
      setDigest("");
      reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : "register_failed");
    }
  }

  return (
    <section className="rounded border border-neutral-800 p-4" data-testid="nuclei-release-panel">
      <h2 className="mb-2 font-medium text-white">Nuclei releases</h2>
      <div className="mb-3 flex flex-wrap gap-2">
        <input
          className="rounded border border-neutral-700 bg-neutral-950 px-2 py-1 text-sm text-white"
          placeholder="version"
          value={version}
          onChange={(event) => setVersion(event.target.value)}
          data-testid="nuclei-release-version"
        />
        <input
          className="min-w-[16rem] flex-1 rounded border border-neutral-700 bg-neutral-950 px-2 py-1 font-mono text-sm text-white"
          placeholder="digest sha256"
          value={digest}
          onChange={(event) => setDigest(event.target.value)}
          data-testid="nuclei-release-digest"
        />
        <button
          type="button"
          className="rounded bg-indigo-700 px-3 py-1 text-sm text-white"
          onClick={() => void register()}
          data-testid="nuclei-release-register"
        >
          Register
        </button>
      </div>
      {error ? (
        <p className="mb-2 text-xs text-red-400" data-testid="nuclei-release-error">
          {error}
        </p>
      ) : null}
      <ul className="space-y-1" data-testid="nuclei-release-list">
        {releases.map((release) => (
          <li
            key={release.release_id}
            className="flex flex-wrap items-center justify-between gap-2 rounded border border-neutral-800 px-2 py-1 text-xs"
            data-active={release.release_id === activeId}
          >
            <span className="font-mono text-neutral-200">
              {release.version} · {release.status}
              {release.release_id === activeId ? " · ACTIVE" : ""}
            </span>
            <span className="flex gap-1">
              <button
                type="button"
                className="rounded border border-emerald-700 px-2 py-0.5 text-emerald-200"
                onClick={() =>
                  void labApi.activateNucleiRelease(release.release_id).then(reload)
                }
              >
                Activate
              </button>
              <button
                type="button"
                className="rounded border border-amber-700 px-2 py-0.5 text-amber-200"
                onClick={() =>
                  void labApi.rollbackNucleiRelease(release.release_id).then(reload)
                }
              >
                Rollback
              </button>
            </span>
          </li>
        ))}
      </ul>
    </section>
  );
}
