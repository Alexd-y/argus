import type { Metadata } from "next";
import type { ReactNode } from "react";
import { AdminLayoutClient } from "./AdminLayoutClient";

export const metadata: Metadata = {
  title: "ARGUS · Admin",
  description: "ARGUS administration console",
};

export default function AdminLayout({ children }: { children: ReactNode }) {
  return <AdminLayoutClient>{children}</AdminLayoutClient>;
}
