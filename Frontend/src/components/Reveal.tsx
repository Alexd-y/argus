"use client";

import { useEffect, useRef, type ReactNode } from "react";

/** One observer for the whole page: a long report can hold dozens of reveals. */
let sharedObserver: IntersectionObserver | null = null;
const pending = new Map<Element, () => void>();

function getObserver(): IntersectionObserver {
  if (!sharedObserver) {
    sharedObserver = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (!entry.isIntersecting) continue;
          const show = pending.get(entry.target);
          pending.delete(entry.target);
          sharedObserver?.unobserve(entry.target);
          show?.();
        }
      },
      // Small inset so the animation starts just after the element clears the
      // bottom edge. Keep it small: anything inside this band never reveals
      // once the document cannot scroll any further.
      { rootMargin: "0px 0px -32px 0px" }
    );
  }
  return sharedObserver;
}

interface RevealProps {
  children: ReactNode;
  className?: string;
  /** Stagger offset applied once the element enters the viewport. */
  delay?: number;
}

export function Reveal({ children, className = "", delay = 0 }: RevealProps) {
  const ref = useRef<HTMLDivElement | null>(null);
  const revealed = useRef(false);

  // The reveal swaps classes on the node itself rather than through state, so
  // scrolling past a long report never re-renders the report.
  useEffect(() => {
    const node = ref.current;
    if (!node || revealed.current) return;

    const show = () => {
      revealed.current = true;
      if (delay > 0) node.style.animationDelay = `${delay}ms`;
      node.classList.remove("reveal-idle");
      node.classList.add("reveal-in");
    };

    if (typeof IntersectionObserver === "undefined") {
      show();
      return;
    }

    const observer = getObserver();
    pending.set(node, show);
    observer.observe(node);

    return () => {
      pending.delete(node);
      observer.unobserve(node);
    };
  }, [delay]);

  return (
    <div ref={ref} className={`reveal-idle${className ? ` ${className}` : ""}`}>
      {children}
    </div>
  );
}
