import { notFound } from "next/navigation";

import { getTenant } from "@/app/admin/tenants/actions";
import { listScopeTargets } from "@/app/admin/tenants/[tenantId]/scopes/actions";

import { TenantScopesClient } from "./TenantScopesClient";

type PageProps = { params: Promise<{ tenantId: string }> };

export default async function TenantScopesPage({ params }: PageProps) {
  const { tenantId } = await params;
  const tenant = await getTenant(tenantId);
  if (!tenant) notFound();
  const targets = await listScopeTargets(tenantId);
  return (
    <TenantScopesClient
      tenantId={tenantId}
      tenantName={tenant.name}
      initialTargets={targets}
    />
  );
}
