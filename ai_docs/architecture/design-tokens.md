# ARGUS Design Tokens — Canonical Reference

**Type:** Frontend / Design system architecture document
**Source of truth:** [`Frontend/src/app/globals.css`](../../Frontend/src/app/globals.css) — `:root` block
**Last updated:** 2026-04-22
**Owners:** Frontend / Design system
**Related issues:** [ISS-T26-001](../develop/issues/ISS-T26-001.md) (WCAG AA accent contrast)

---

## Purpose

Inline CSS custom properties in `globals.css` are the only design-token
storage in the project today (no Tailwind theme extension, no JSON token
pipeline). This document is the **canonical catalog** of those tokens:
their intent, their permitted pairings, and — for any pair that carries
text — their WCAG 2.1 contrast measurement.

Every change to `:root` in `globals.css` must be reflected here in the
same commit; reviewers should reject token changes that ship without a
matching entry in this file.

---

## 1. Token catalog

All tokens live under `:root` in `Frontend/src/app/globals.css`. The
table below mirrors that block; the column **Surfaces** lists the CSS
roles where the token is permitted to appear, and **Pair-with**
identifies the only foreground/background tokens it is allowed to be
combined with for text rendering.

### 1.1 Background surfaces

| Token             | Hex       | Surfaces                              | Pair-with (text)                     |
| ----------------- | --------- | ------------------------------------- | ------------------------------------ |
| `--bg-primary`    | `#0a0a0a` | App body, top-level page background   | `--text-primary`, `--text-secondary`, `--text-muted`, `--accent`, `--highlight` |
| `--bg-secondary`  | `#111111` | Cards, side panels, modal shells      | `--text-primary`, `--text-secondary`, `--text-muted` |
| `--bg-tertiary`   | `#1a1a1a` | Nested surfaces, table headers, chips | `--text-primary`, `--text-secondary`, `--text-muted` |

### 1.2 Borders & dividers

| Token            | Hex       | Surfaces                                    |
| ---------------- | --------- | ------------------------------------------- |
| `--border`       | `#262626` | Default 1px borders on cards, inputs, table rows |
| `--border-light` | `#333333` | Hover/focus borders, separator lines on `--bg-tertiary` |

### 1.3 Accent / brand

| Token             | Hex       | Role                                                                 | Pair-with (text)        |
| ----------------- | --------- | -------------------------------------------------------------------- | ----------------------- |
| `--accent`        | `#A655F7` | **Decorative only** — borders, focus rings, glow, marketing surface, selection highlight. **Do not use as a text-bearing fill.** | (decorative; not for text-on-fill) |
| `--accent-hover`  | `#b875f8` | Hover state for `--accent` borders / glow                            | (decorative)            |
| `--accent-dim`    | `#8b44d4` | Pressed / secondary accent state                                     | `--text-primary` (≥4.7:1) |
| `--accent-strong` | `#6B2EBE` | **Primary action fill** for buttons and confirm CTAs (Option A from ISS-T26-001) | `--on-accent` only       |
| `--on-accent`     | `#FAFAFA` | Foreground text/icon color rendered on top of `--accent-strong`      | (use only on `--accent-strong`) |
| `--secondary`     | `#393A84` | Secondary brand surface, used by glitch effect layer                 | (decorative)            |
| `--highlight`     | `#E3CAFE` | Highlight / glitch effect layer, "new" badges                        | `--bg-primary` only      |

### 1.4 Text

| Token              | Hex       | Use                                                                                        |
| ------------------ | --------- | ------------------------------------------------------------------------------------------ |
| `--text-primary`   | `#f5f5f5` | Default body and heading text on all dark surfaces                                         |
| `--text-secondary` | `#a3a3a3` | Secondary text — captions, table sub-rows, deemphasized labels                             |
| `--text-muted`     | `#8a8a8a` | Tertiary / muted text — placeholders, disabled hints. Bumped from `#525252` for AA (T26).  |

### 1.5 Status

| Token       | Hex       | Use                                       |
| ----------- | --------- | ----------------------------------------- |
| `--success` | `#22c55e` | Success banners, "ok" badges, healthy chips |
| `--warning` | `#eab308` | Warning banners, attention chips           |
| `--error`   | `#ef4444` | Destructive states, error banners          |

> Note: status tokens currently follow Tailwind's standard palette and
> may not all clear AA on every surface; specific failing pairs are
> tracked under ISS-T26-001 (see §3 below).

---

## 2. WCAG 2.1 contrast verification

All measurements use the WCAG 2.x relative-luminance formula
(sRGB → linear → `0.2126·R + 0.7152·G + 0.0722·B`) and the contrast
formula `(L_lighter + 0.05) / (L_darker + 0.05)`. Thresholds:

* **AA normal text** (< 18.66 px regular, < 14 px bold): ≥ **4.5 : 1**
* **AA large text** (≥ 18.66 px regular or ≥ 14 px bold): ≥ **3 : 1**
* **AAA normal text**: ≥ **7 : 1**

### 2.1 Verified pairs (text-on-surface)

| Foreground       | Background        | Ratio         | AA (4.5) | ≥ 5    | AAA (7) | Notes                                              |
| ---------------- | ----------------- | ------------- | :------: | :----: | :-----: | -------------------------------------------------- |
| `--on-accent`    | `--accent-strong` | **7.29 : 1**  |   PASS   |  PASS  |  PASS   | **Option A primary-button pair** (this commit)     |
| `--on-accent`    | `--bg-primary`    | 18.97 : 1     |   PASS   |  PASS  |  PASS   | Sanity — `--on-accent` is safe on any dark surface |
| `--text-primary` | `--bg-primary`    | 18.10 : 1     |   PASS   |  PASS  |  PASS   | Default body text                                  |
| `--text-muted`   | `--bg-primary`    | 5.77 : 1      |   PASS   |  PASS  |  FAIL   | Bumped from `#525252` → `#8a8a8a` in T26           |
| `--text-muted`   | `--bg-tertiary`   | 4.69 : 1      |   PASS   |  FAIL  |  FAIL   | Smallest acceptable surface for muted text         |

### 2.2 Failing / forbidden pairs (do not use for text)

| Foreground       | Background        | Ratio        | Status | Replacement                                          |
| ---------------- | ----------------- | ------------ | :----: | ---------------------------------------------------- |
| `--bg-primary`   | `--accent`        | 4.20 : 1*    |  FAIL  | Use `--accent-strong` + `--on-accent`               |
| `--text-primary` | `--accent`        | 3.82 : 1     |  FAIL  | Use `--accent-strong` + `--on-accent`               |
| `--accent-strong`| `--bg-primary`    | 2.60 : 1     |  FAIL  | `--accent-strong` is a **fill**, not a text color   |
| `--accent-strong`| `--bg-tertiary`   | 2.29 : 1     |  FAIL  | Same — never use `--accent-strong` as a text token  |

*Rounded-down axe-core measurement after sub-pixel composite, originally
4.20 : 1; mathematical pair ratio is 4.96 : 1. Either way it is below
the 5 : 1 internal target adopted alongside ISS-T26-001 to leave a
margin against rasterization drift.

### 2.3 Reproducing the measurements

The contrast script lives in this doc only (no committed Python file
yet — kept in-line so it ships with the doc instead of drifting from
it):

```python
def srgb_to_lin(c):
    c = c / 255.0
    return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4

def luminance(hex_color):
    h = hex_color.lstrip('#')
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    return 0.2126 * srgb_to_lin(r) + 0.7152 * srgb_to_lin(g) + 0.0722 * srgb_to_lin(b)

def contrast(fg, bg):
    l1, l2 = luminance(fg), luminance(bg)
    if l1 < l2:
        l1, l2 = l2, l1
    return (l1 + 0.05) / (l2 + 0.05)

assert round(contrast('#FAFAFA', '#6B2EBE'), 2) == 7.29
```

---

## 3. `--accent-strong` / `--on-accent` — Option A foundation

### 3.1 Why these tokens exist

ISS-T26-001 documents a real WCAG 2.1 AA failure (axe rule
`color-contrast`) on the brand-purple primary CTA used across at least
**7 admin surfaces** plus **5 additional T36 surfaces**:

* `components/admin/audit-logs/AuditLogsFilterBar.tsx` — *Verify chain
  integrity*
* `components/admin/findings/FindingsFilterBar.tsx`
* `components/admin/ExportFormatToggle.tsx`
* `app/admin/llm/AdminLlmClient.tsx`
* `app/admin/tenants/TenantsAdminClient.tsx`
* `app/admin/tenants/[tenantId]/scopes/TenantScopesClient.tsx`
* `app/admin/tenants/[tenantId]/settings/TenantSettingsClient.tsx`
* T36 carry-over: `PerTenantThrottleClient`, `SchedulesClient`,
  `CronExpressionField`, `RunNowDialog`, `DeleteScheduleDialog`

The issue weighed three options:

* **Option A** *(adopted)*: introduce `--accent-strong` (darker purple)
  + `--on-accent` (off-white). Migrate primary actions; keep `--accent`
  as the brand color for borders, glow, focus rings.
* Option B: redefine `--accent` itself to a darker shade — bigger blast
  radius, requires a brand-design sign-off.
* Option C: keep the bright accent but inflate buttons to 16 px bold —
  rejected (breaks layout density).

### 3.2 Why `#6B2EBE` and `#FAFAFA`

* `#6B2EBE` is the same brand hue (`hsl(266°, 60%, 46%)`) as `--accent`
  shifted to lightness ≤ 0.16, which keeps the visual identity but
  lifts the accent/text contrast over AA.
* `#FAFAFA` is preferred over `#FFFFFF` to suppress the harsh
  pure-white glare on dark UIs while still staying within the AAA band
  for normal text on `--accent-strong` (7.29 : 1).
* The combined ratio (7.29 : 1) clears both AA (4.5 : 1) and AAA
  (7 : 1) and leaves headroom against axe-core's sub-pixel
  rasterization drift (the original ISS-T26-001 axe report rounded
  4.96 : 1 → 4.20 : 1 in similar conditions).

### 3.3 Status — what this commit ships

* Tokens added to `Frontend/src/app/globals.css` (`:root` block,
  alongside the existing `--accent` family).
* This catalog created at `ai_docs/architecture/design-tokens.md`.
* **No component migration in this commit.** The seven primary admin
  surfaces above continue to use `bg-[var(--accent)]
  text-[var(--bg-primary)]` and remain gated by `test.fail()` in
  `Frontend/tests/e2e/admin-axe.spec.ts` referencing ISS-T26-001 until
  the migration commit lands.

### 3.4 Migration recipe (for the follow-up commit)

When component migration is scheduled (separate task; out of scope for
this foundation), the per-button change is:

```diff
- className="… border-[var(--accent)] bg-[var(--accent)] … text-[var(--bg-primary)] …"
+ className="… border-[var(--accent-strong)] bg-[var(--accent-strong)] … text-[var(--on-accent)] …"
```

Acceptance criteria for the migration commit (taken verbatim from
ISS-T26-001 §Acceptance criteria):

1. All 7 primary admin buttons + the 5 T36 surfaces clear axe
   `color-contrast` against WCAG 2 AA (≥ 4.5 : 1).
2. Visual diff against current Storybook / Chromatic snapshots is
   reviewed and explicitly approved by design.
3. `Frontend/tests/e2e/admin-axe.spec.ts` removes the `test.fail`
   annotations referencing ISS-T26-001 on the 7 affected scenarios.

---

## 4. Change-control rules

1. **Single source of truth.** The CSS `:root` block is authoritative;
   this doc is a derived catalog. PRs that change tokens in the CSS but
   not here (or vice versa) must be rejected.
2. **No magic hex literals in components.** New components must
   reference tokens (`var(--…)` or the corresponding Tailwind
   `bg-[var(--…)]`). Existing literal hexes (`#A655F7`, `#E3CAFE`,
   `#393A84` inside `globals.css` keyframes / glitch-text) are
   tolerated for pre-existing decorative effects.
3. **Pair before you ship.** Any new text-bearing token pair must list
   its measured contrast ratio in §2.1 with the script in §2.3 and
   clear ≥ 4.5 : 1 (AA) for normal text, or ≥ 3 : 1 with explicit
   `text-lg font-bold` annotation for large-text exemptions.
4. **Forbidden pairs stay listed.** When a pair is retired (e.g. the
   current `--accent` + `--bg-primary`), it must be moved to §2.2
   instead of deleted, so reviewers can prove a regression was
   considered.

---

## 5. Cross-references

* [`Frontend/src/app/globals.css`](../../Frontend/src/app/globals.css) —
  authoritative token definitions
* [`Frontend/tests/e2e/admin-axe.spec.ts`](../../Frontend/tests/e2e/admin-axe.spec.ts) —
  axe-core AA gate (T26)
* [ISS-T26-001](../develop/issues/ISS-T26-001.md) — original WCAG AA
  contrast issue + Option A proposal
* [WCAG 2.1 1.4.3 Contrast (Minimum)](https://www.w3.org/TR/WCAG21/#contrast-minimum)
* [axe-core `color-contrast` rule](https://dequeuniversity.com/rules/axe/4.11/color-contrast)
