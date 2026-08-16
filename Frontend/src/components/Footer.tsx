export function Footer({ wide = false }: { wide?: boolean }) {
  return (
    <footer className="border-t border-neutral-800 bg-neutral-900">
      <div className={`mx-auto px-4 sm:px-6 py-4 ${wide ? "max-w-5xl" : "max-w-3xl"}`}>
        <div className="flex flex-col sm:flex-row sm:flex-wrap items-center justify-between gap-2 sm:gap-4 text-xs">
          <div className="flex items-center gap-2 sm:gap-4">
            <span className="text-neutral-400">Svalbard Security Inc.</span>
            <span className="text-neutral-700 hidden sm:inline">|</span>
            <a href="mailto:info@svalbard.ca" className="cursor-pointer text-neutral-500 hover:text-[#E3CAFE]">
              info@svalbard.ca
            </a>
          </div>
          <div className="flex items-center gap-3 sm:gap-4 text-neutral-500">
            <a href="https://svalbard.ca/terms" target="_blank" rel="noopener noreferrer" className="cursor-pointer hover:text-[#E3CAFE]">
              Terms
            </a>
            <a href="https://svalbard.ca/privacy" target="_blank" rel="noopener noreferrer" className="cursor-pointer hover:text-[#E3CAFE]">
              Privacy
            </a>
            <span suppressHydrationWarning>© {new Date().getFullYear()}</span>
          </div>
        </div>
        <p className="mt-3 text-xs text-neutral-600 leading-relaxed text-center sm:text-left">
          Authorized testing only. Unauthorized access to computer systems is illegal.
        </p>
      </div>
    </footer>
  );
}
