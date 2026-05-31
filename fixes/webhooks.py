from pathlib import Path


EXPRESS_WEBHOOK = """// Stripe webhook verification middleware (auto-generated)
// Install: npm install stripe
// Usage:
//   const webhookHandler = require('./middleware/webhook');
//   app.post('/webhook/stripe', express.raw({type: 'application/json'}), webhookHandler);

const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

async function handleWebhook(req, res) {
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    event = stripe.webhooks.constructEvent(
      req.body,
      sig,
      process.env.STRIPE_WEBHOOK_SECRET
    );
  } catch (err) {
    console.error('Webhook signature verification failed:', err.message);
    return res.status(400).json({ error: 'Invalid signature' });
  }

  // Idempotency check
  const processed = req.app.get('processedEvents') || new Map();
  if (processed.has(event.id)) {
    return res.json({ received: true, duplicate: true });
  }
  processed.set(event.id, Date.now());
  req.app.set('processedEvents', processed);

  // Handle event types
  switch (event.type) {
    case 'payment_intent.succeeded':
      console.log('Payment succeeded:', event.data.object.id);
      break;
    case 'invoice.payment_failed':
      console.error('Payment failed:', event.data.object.id);
      break;
    case 'customer.subscription.deleted':
      console.log('Subscription deleted:', event.data.object.id);
      break;
    case 'customer.subscription.past_due':
      console.warn('Subscription past due:', event.data.object.id);
      break;
    default:
      console.log('Unhandled event type:', event.type);
  }

  res.json({ received: true });
}

module.exports = handleWebhook;
"""

FASTAPI_WEBHOOK = """# Stripe webhook verification (auto-generated)
# Install: pip install stripe
# Usage:
#   from middleware.webhook import stripe_webhook
#   @app.post("/webhook/stripe")
#   async def webhook(request: Request):
#       return await stripe_webhook(request)

import stripe
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse

processed_events = set()


async def stripe_webhook(request: Request):
    stripe.api_key = request.app.state.STRIPE_SECRET_KEY
    payload = await request.body()
    sig = request.headers.get("stripe-signature")

    if not sig:
        raise HTTPException(status_code=400, detail="Missing stripe-signature header")

    try:
        event = stripe.Webhook.construct_event(
            payload, sig, request.app.state.STRIPE_WEBHOOK_SECRET
        )
    except (ValueError, stripe.error.SignatureVerificationError) as e:
        raise HTTPException(status_code=400, detail=f"Invalid signature: {e}")

    # Idempotency
    if event.id in processed_events:
        return JSONResponse(content={"received": True, "duplicate": True})
    processed_events.add(event.id)

    handlers = {
        "payment_intent.succeeded": lambda e: print(f"Payment: {e.data.object.id}"),
        "invoice.payment_failed": lambda e: print(f"Failed: {e.data.object.id}"),
        "customer.subscription.deleted": lambda e: print(f"Deleted: {e.data.object.id}"),
        "customer.subscription.past_due": lambda e: print(f"Past due: {e.data.object.id}"),
    }

    handler = handlers.get(event.type)
    if handler:
        handler(event)

    return JSONResponse(content={"received": True})
"""


def fix_webhooks(target, framework, dry_run=False, verbose=False):
    target = Path(target)
    outcome = {"fixed": [], "created": [], "warnings": [], "message": ""}
    src_dir = target / (framework.get("src_dir") or ".")

    if framework["has_express"] or framework["has_next"]:
        mw_dir = src_dir / "middleware" if src_dir != target else target / "middleware"
        if not mw_dir.exists():
            if not dry_run:
                mw_dir.mkdir(parents=True, exist_ok=True)
        wh_file = mw_dir / "webhook.js"
        if not wh_file.exists():
            if not dry_run:
                wh_file.write_text(EXPRESS_WEBHOOK)
            outcome["created"].append("middleware/webhook.js")
            outcome["warnings"].append("Install: npm install stripe")
            outcome["warnings"].append("Set STRIPE_SECRET_KEY and STRIPE_WEBHOOK_SECRET in .env")
        else:
            outcome["fixed"].append("middleware/webhook.js already exists")

    elif framework["has_fastapi"]:
        mw_dir = src_dir / "middleware" if src_dir != target else target / "middleware"
        if not mw_dir.exists():
            if not dry_run:
                mw_dir.mkdir(parents=True, exist_ok=True)
        wh_file = mw_dir / "webhook.py"
        if not wh_file.exists():
            if not dry_run:
                wh_file.write_text(FASTAPI_WEBHOOK)
            outcome["created"].append("middleware/webhook.py")
            outcome["warnings"].append("Install: pip install stripe")
            outcome["warnings"].append("Set STRIPE_SECRET_KEY and STRIPE_WEBHOOK_SECRET in .env")
        else:
            outcome["fixed"].append("middleware/webhook.py already exists")

    else:
        outcome["message"] = "Verify Stripe webhook signature using stripe.Webhook.construct_event() on every request"

    return outcome
