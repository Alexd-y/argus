# Ragnarok

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

2. **(Recommended)** Create two recurring products/prices in Stripe Dashboard:
   - Asgard — CA$1,891/month
   - Valhalla — CA$2,947/month

   Add their Price IDs:

   ```
   STRIPE_PRICE_ASGARD=price_...
   STRIPE_PRICE_VALHALLA=price_...
   ```

   If omitted, checkout uses inline `price_data` from the app (fine for testing).

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
- Free Midgard: download report immediately
- Paid tiers: scan runs free → **Buy Report** unlocks via Stripe subscription → download report
