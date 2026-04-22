/**
 * Tenant settings shared client-safe types and constants.
 *
 * Lives outside ``actions.ts`` because Next.js Server Actions files
 * (``"use server"``) may only export async functions. Both this module
 * and ``actions.ts`` re-export the types via a single canonical name so
 * client components can import them without crossing the server boundary.
 */

/**
 * Closed taxonomy mirroring the backend ``Tenant.pdf_archival_format``
 * column (B6-T02 / T48 / D-4) and the Pydantic ``Literal`` on
 * ``TenantPatch.pdf_archival_format``. Adding a new format requires:
 *
 * 1. Add the literal here.
 * 2. Extend ``PDF_ARCHIVAL_FORMAT_VALUES`` in ``backend/src/db/models.py``.
 * 3. Update the Alembic 029 ``CHECK`` constraint (or ship a follow-up
 *    migration).
 * 4. Add a translation in ``PDF_ARCHIVAL_FORMAT_LABELS`` below.
 */
export const PDF_ARCHIVAL_FORMAT_VALUES = ["standard", "pdfa-2u"] as const;
export type PdfArchivalFormat = (typeof PDF_ARCHIVAL_FORMAT_VALUES)[number];

/**
 * UI labels for the PDF archival format selector (English + short
 * Russian). Keep the keys exhaustive: TypeScript will error on any
 * missing format the day a new value is added to
 * ``PDF_ARCHIVAL_FORMAT_VALUES``.
 */
export const PDF_ARCHIVAL_FORMAT_LABELS: Record<
  PdfArchivalFormat,
  { en: string; ru: string; descriptionEn: string; descriptionRu: string }
> = {
  standard: {
    en: "Standard PDF",
    ru: "Стандартный PDF",
    descriptionEn:
      "Default deterministic PDF rendering. Suitable for ad-hoc audits and short-term sharing.",
    descriptionRu:
      "Стандартный детерминированный PDF. Подходит для оперативных аудитов и краткосрочного хранения.",
  },
  "pdfa-2u": {
    en: "PDF/A-2u (long-term archival)",
    ru: "PDF/A-2u (долгосрочное хранение)",
    descriptionEn:
      "ISO 19005-2u archival profile with embedded ICC profile and XMP metadata. Required for compliance audits where long-term reproducibility matters.",
    descriptionRu:
      "Архивный профиль ISO 19005-2u с встроенным ICC-профилем и XMP-метаданными. Используется для долгосрочного хранения и соответствия требованиям комплаенс-аудитов.",
  },
};

/**
 * Default value for back-compat (mirrors the server-side default of the
 * Alembic 029 column). New tenants land on ``"standard"`` until an admin
 * explicitly opts in to PDF/A-2u.
 */
export const PDF_ARCHIVAL_FORMAT_DEFAULT: PdfArchivalFormat = "standard";

export function isPdfArchivalFormat(value: unknown): value is PdfArchivalFormat {
  return (
    typeof value === "string" &&
    (PDF_ARCHIVAL_FORMAT_VALUES as readonly string[]).includes(value)
  );
}
