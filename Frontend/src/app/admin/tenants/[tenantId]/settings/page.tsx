import { notFound } from "next/navigation";

import { getTenant } from "@/app/admin/tenants/actions";

import { TenantSettingsClient } from "./TenantSettingsClient";

type PageProps = { params: Promise<{ tenantId: string }> };

export default async function TenantSettingsPage({ params }: PageProps) {
  const { tenantId } = await params;
  const tenant = await getTenant(tenantId);
  if (!tenant) notFound();
  return <TenantSettingsClient tenantId={tenantId} initial={tenant} />;
}
