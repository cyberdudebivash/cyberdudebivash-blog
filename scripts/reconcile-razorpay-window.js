#!/usr/bin/env node
'use strict';

/**
 * Read-only Razorpay reconciliation for a time window.
 *
 * Lists every Razorpay order created in [from, to] and classifies it:
 *   TEST_UNPAID     known canary identity, never paid
 *   REAL_UNPAID     not paid (abandoned / never opened)
 *   REAL_CAPTURED   paid and not refunded
 *   REAL_REFUNDED   paid and fully refunded
 *   UNKNOWN         paid but the payment state could not be read
 * and attributes ownership from server-set notes:
 *   BLOG_PLAN (retired blog plan checkout), INTEL_FACTORY_PREMIUM,
 *   OTHER (e.g. Sentinel APEX platform subscriptions).
 *
 * Emails are masked in all output. Nothing is written anywhere; migrating a
 * captured blog-plan buyer is a separate, manual, audited operator action
 * (docs/audits/PLAN-CUTOVER-PAYMENT-RECONCILIATION.md).
 *
 *   RAZORPAY_KEY_ID=... RAZORPAY_KEY_SECRET=... \
 *     node scripts/reconcile-razorpay-window.js 2026-10-01T11:40:00Z 2026-10-01T12:50:00Z
 */

const CANARY_EMAILS = new Set(['razorpay-canary@cyberdudebivash.com']);
const API = 'https://api.razorpay.com/v1';

function maskEmail(email) {
  const e = String(email || '');
  const at = e.indexOf('@');
  if (at < 1) return e ? '***' : '';
  return `${e[0]}***@${e.slice(at + 1)}`;
}

function ownership(notes = {}) {
  if (notes.platform === 'CYBERDUDEBIVASH_INTEL_FACTORY' || notes.commerce === 'premium_intelligence') return 'INTEL_FACTORY_PREMIUM';
  if (notes.platform === 'CYBERDUDEBIVASH_SENTINEL_APEX' && notes.planType) return 'BLOG_PLAN';
  return 'OTHER';
}

/** order: Razorpay order entity; payments: its payments (or null if unreadable). */
function classify(order, payments) {
  const notes = order.notes || {};
  const email = String(notes.email || '').toLowerCase();
  const paid = order.status === 'paid' || Number(order.amount_paid) > 0;
  let state;
  if (!paid) state = CANARY_EMAILS.has(email) ? 'TEST_UNPAID' : 'REAL_UNPAID';
  else if (!Array.isArray(payments)) state = 'UNKNOWN';
  else {
    const captured = payments.filter(p => p.status === 'captured' || p.status === 'refunded');
    const refunded = captured.length > 0 && captured.every(p => p.status === 'refunded' || Number(p.amount_refunded) >= Number(p.amount));
    state = captured.length === 0 ? 'UNKNOWN' : refunded ? 'REAL_REFUNDED' : 'REAL_CAPTURED';
  }
  return {
    order: order.id,
    created_at: new Date(Number(order.created_at) * 1000).toISOString(),
    owner: ownership(notes),
    state,
    amount_minor: Number(order.amount),
    currency: order.currency,
    plan: notes.planType || notes.sku || notes.report_id || null,
    email: maskEmail(email),
  };
}

async function rzp(path, auth) {
  const res = await fetch(`${API}${path}`, { headers: { Authorization: `Basic ${auth}` } });
  if (!res.ok) throw new Error(`Razorpay ${path.split('?')[0]} HTTP ${res.status}`);
  return res.json();
}

async function main() {
  const [fromIso, toIso] = process.argv.slice(2);
  const from = Math.floor(Date.parse(fromIso) / 1000);
  const to = Math.floor(Date.parse(toIso) / 1000);
  if (!from || !to || to <= from) { console.error('usage: reconcile-razorpay-window.js <fromISO> <toISO>'); process.exit(2); }
  const id = process.env.RAZORPAY_KEY_ID || '';
  const secret = process.env.RAZORPAY_KEY_SECRET || '';
  if (!id || !secret) { console.error('RAZORPAY_KEY_ID / RAZORPAY_KEY_SECRET not set'); process.exit(2); }
  const auth = Buffer.from(`${id}:${secret}`).toString('base64');

  const rows = [];
  for (let skip = 0; skip < 1000; skip += 100) {
    const page = await rzp(`/orders?from=${from}&to=${to}&count=100&skip=${skip}`, auth);
    for (const order of page.items || []) {
      let payments = null;
      if (order.status === 'paid' || Number(order.amount_paid) > 0) {
        try { payments = (await rzp(`/orders/${order.id}/payments`, auth)).items || []; } catch (_) { payments = null; }
      }
      rows.push(classify(order, payments));
    }
    if (!page.items || page.items.length < 100) break;
  }

  console.log('| Order | Created (UTC) | Owner | Payment State | Amount | Plan / SKU | Email |');
  console.log('|---|---|---|---|---:|---|---|');
  for (const r of rows) {
    console.log(`| ${r.order} | ${r.created_at} | ${r.owner} | ${r.state} | ${(r.amount_minor / 100).toFixed(2)} ${r.currency} | ${r.plan || ''} | ${r.email} |`);
  }
  const blogCaptured = rows.filter(r => r.owner === 'BLOG_PLAN' && r.state === 'REAL_CAPTURED');
  console.log(`\n${rows.length} order(s); BLOG_PLAN captured needing migration: ${blogCaptured.length}`);
}

if (require.main === module) main().catch(e => { console.error(e.message); process.exit(1); });

module.exports = { classify, ownership, maskEmail };
