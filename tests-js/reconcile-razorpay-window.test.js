'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { classify, maskEmail } = require('../scripts/reconcile-razorpay-window.js');

const base = { id: 'order_X', created_at: 1790855660, amount: 149900, currency: 'INR' };
const blogNotes = (email) => ({ platform: 'CYBERDUDEBIVASH_SENTINEL_APEX', planType: 'pro', email });

test('known canary orders that were never paid are TEST_UNPAID, not sales', () => {
  const r = classify({ ...base, status: 'created', notes: blogNotes('razorpay-canary@cyberdudebivash.com') }, null);
  assert.strictEqual(r.state, 'TEST_UNPAID');
  assert.strictEqual(r.owner, 'BLOG_PLAN');
  assert.strictEqual(r.email, 'r***@cyberdudebivash.com');
});

test('paid blog plan orders are REAL_CAPTURED unless every payment was refunded', () => {
  const order = { ...base, status: 'paid', amount_paid: 149900, notes: blogNotes('buyer@example.com') };
  assert.strictEqual(classify(order, [{ status: 'captured', amount: 149900, amount_refunded: 0 }]).state, 'REAL_CAPTURED');
  assert.strictEqual(classify(order, [{ status: 'refunded', amount: 149900, amount_refunded: 149900 }]).state, 'REAL_REFUNDED');
  assert.strictEqual(classify(order, null).state, 'UNKNOWN', 'unreadable payments are never assumed captured');
});

test('unpaid real orders and ownership attribution', () => {
  assert.strictEqual(classify({ ...base, status: 'attempted', notes: blogNotes('a@b.com') }, null).state, 'REAL_UNPAID');
  assert.strictEqual(classify({ ...base, status: 'created', notes: { platform: 'CYBERDUDEBIVASH_INTEL_FACTORY', sku: 'r1' } }, null).owner, 'INTEL_FACTORY_PREMIUM');
  assert.strictEqual(classify({ ...base, status: 'created', notes: {} }, null).owner, 'OTHER');
});

test('emails are always masked', () => {
  assert.strictEqual(maskEmail('someone@example.com'), 's***@example.com');
  assert.strictEqual(maskEmail(''), '');
});
