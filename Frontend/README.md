# Ragnarøk

Security scan demo by Svalbard Security.

## Setup

```bash
pnpm install
cp .env.example .env.local
```

## Stripe

1. Create a [Stripe](https://dashboard.stripe.com) account and copy your **test** secret key into `.env.local`:

   ```
   STRIPE_SECRET_KEY=sk_test_...
   NEXT_PUBLIC_BASE_URL=http://localhost:3000
   ```

2. Create products in Stripe Dashboard, each with a recurring monthly price:
   - Continuous (`standard`) — CA$1,891/month
   - Full Surface (`premium`) — CA$2,947/month

   Add the Product IDs (`prod_...`). The env var names keep their original suffixes: `ASGARD` is Continuous, `VALHALLA` is Full Surface.

   ```
   STRIPE_PRODUCT_ASGARD=prod_...
   STRIPE_PRODUCT_VALHALLA=prod_...
   ```

   Checkout looks up each product's default price. Optional one-time extra-scan products after the monthly quota is used:

   ```
   STRIPE_PRODUCT_ASGARD_EXTRA=prod_...
   STRIPE_PRODUCT_VALHALLA_EXTRA=prod_...
   ```

3. **Webhooks** (keeps unlock state reliable if the user closes the browser after payment):

   ```bash
   stripe listen --forward-to localhost:3000/api/webhooks/stripe
   ```

   Copy the webhook signing secret:

   ```
   STRIPE_WEBHOOK_SECRET=whsec_...
   ```

## Run

```bash
pnpm dev
```

## Flow

- Start a scan at `/` → progress at `/scan/[id]`
- Free Overview: download report immediately
- Paid tiers: scan runs free → **Unlock** via Stripe subscription → download report
- Subscription includes **4 scans per month** of the same target. Retest from the report while scans remain, or buy up to **3 extra scans** when the month is used up.
