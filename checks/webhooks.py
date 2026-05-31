from pathlib import Path
from scanner import iter_source_files, relative_to
import re


STRIPE_PATTERNS = [
    (r'stripe', 'Stripe reference'),
    (r'construct_event', 'Stripe webhook signature verification [GOOD]'),
    (r'webhookSecret', 'Webhook secret config'),
    (r'webhook', 'Webhook endpoint'),
    (r'payment_intent\.succeeded', 'Payment success handler'),
    (r'invoice\.payment_failed', 'Payment failure handler'),
    (r'customer\.subscription\.deleted', 'Subscription cancellation handler'),
    (r'customer\.subscription\.past_due', 'Past due subscription handler'),
    (r'idempotency', 'Idempotency handling [GOOD]'),
    (r'idempotency_key', 'Idempotency key [GOOD]'),
    (r'stripe-webhook', 'Stripe webhook middleware'),
    (r'endpointSecret', 'Webhook endpoint secret'),
]

VERIFICATION_PATTERNS = ['construct_event', 'verifyEvent', 'verify_signature', 'verifyWebhook']
IDEMPOTENCY_PATTERNS = ['idempotency', 'idempotency_key', 'processed_events', 'event_processed']


def check_payment_webhooks(target, verbose=False):
    target = Path(target)
    details = []
    findings = []
    severity = "LOW"

    has_stripe = False
    has_verification = False
    has_idempotency = False
    handles_events = []
    stripe_files = []

    for fpath in iter_source_files(target):
        try:
            text = fpath.read_text(errors='ignore')
            rel = relative_to(fpath, target)

            for pattern, desc in STRIPE_PATTERNS:
                if re.search(pattern, text, re.IGNORECASE):
                    if '[GOOD]' in desc:
                        if 'signature' in desc:
                            has_verification = True
                        if 'idempotency' in desc:
                            has_idempotency = True
                    else:
                        stripe_files.append((rel, desc))
                        if 'payment' in desc.lower() or 'subscription' in desc.lower():
                            handles_events.append(desc)

            if re.search(r'stripe', text, re.IGNORECASE):
                has_stripe = True

            if any(vp in text for vp in VERIFICATION_PATTERNS):
                has_verification = True
            if any(ip in text for ip in IDEMPOTENCY_PATTERNS):
                has_idempotency = True

        except (PermissionError, UnicodeDecodeError):
            continue

    if not has_stripe:
        details.append("[PASS] No Stripe/payment references found (N/A)")
        summary = "No payment processing detected — N/A"
        return {
            "id": "PAYMENT_WEBHOOKS",
            "name": "Payment Webhooks",
            "status": "PASS",
            "severity": "LOW",
            "summary": summary,
            "details": details,
            "findings": [],
        }

    details.append(f"[INFO] Stripe/payment references found in {len(stripe_files)} file(s)")

    if has_verification:
        details.append("[PASS] Webhook signature verification detected")
    else:
        findings.append("No webhook signature verification detected")
        details.append("[FAIL] Stripe webhook missing signature verification")
        severity = "CRITICAL"

    if has_idempotency:
        details.append("[PASS] Idempotency handling detected")
    else:
        findings.append("No idempotency handling detected")
        details.append("[WARN] No webhook idempotency handling detected")
        if severity != "CRITICAL":
            severity = "HIGH"

    event_types = set(h for h in handles_events)
    details.append(f"[INFO] Event handlers: {', '.join(event_types) if event_types else 'none detected'}")

    summary = f"Found {len(findings)} webhook issue(s)" if findings else "Payment webhooks appear secure"
    return {
        "id": "PAYMENT_WEBHOOKS",
        "name": "Payment Webhooks",
        "status": "FAIL" if findings else "PASS",
        "severity": severity,
        "summary": summary,
        "details": details,
        "findings": findings,
    }
