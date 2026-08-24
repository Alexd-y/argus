import Link from "next/link";

export function Header({ wide = false }: { wide?: boolean }) {
  return (
    <header className="sticky top-0 z-50 border-b border-neutral-800 bg-neutral-900">
      <div
        className={`mx-auto flex h-12 items-center justify-between px-4 sm:px-6 ${
          wide ? "max-w-5xl" : "max-w-3xl"
        }`}
      >
        <div className="flex items-center gap-2">
          <Link
            href="/"
            className="glitch-text text-white font-semibold tracking-wide cursor-pointer"
            data-text="RAGNARØK"
          >
            RAGNARØK
          </Link>
          <span className="text-neutral-500 text-xs hidden sm:inline">by</span>
          <a
            href="https://svalbard.ca"
            className="text-neutral-400 text-xs hover:text-[#E3CAFE] cursor-pointer hidden sm:inline"
          >
            Svalbard Security
          </a>
        </div>
        <nav className="flex items-center gap-1 text-xs">
          <Link
            href="/sample"
            className="cursor-pointer px-2 sm:px-3 py-1.5 text-neutral-400 hover:text-[#E3CAFE] hover:bg-[#393A84]/20 rounded"
          >
            Sample
          </Link>
          <a
            href="https://svalbard.ca/docs"
            className="cursor-pointer px-2 sm:px-3 py-1.5 text-neutral-400 hover:text-[#E3CAFE] hover:bg-[#393A84]/20 rounded"
          >
            Docs
          </a>
          <a
            href="https://svalbard.ca/support"
            className="cursor-pointer px-2 sm:px-3 py-1.5 text-neutral-400 hover:text-[#E3CAFE] hover:bg-[#393A84]/20 rounded"
          >
            Support
          </a>
        </nav>
      </div>
    </header>
  );
}
