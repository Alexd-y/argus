"use client";

import type { ReactNode } from "react";

interface CollapseProps {
  open: boolean;
  children: ReactNode;
  /** Applied to the content box, which keeps padding and borders out of the clipped track. */
  className?: string;
}

export function Collapse({ open, children, className = "" }: CollapseProps) {
  return (
    <div className="collapse-region" data-open={open}>
      <div className="collapse-clip">
        <div className={className} inert={!open}>
          {children}
        </div>
      </div>
    </div>
  );
}
