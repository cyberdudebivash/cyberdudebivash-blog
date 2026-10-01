/**
 * CYBERDUDEBIVASH SENTINEL APEX — Payment Flow Module
 * Self-contained payment state machine. Include this script on any page,
 * then call: ApexPaymentFlow.startUpgrade('pro') or .startUpgrade('enterprise')
 *
 * Injects its own modal HTML + CSS on first call. No dependencies.
 * API: POST /api/v1/billing?action=create-razorpay-order / verify-razorpay-payment
 *      (manual create-intent was retired 2026-10-01; submit-payment and the
 *      status poller remain only for sessions restored from before that date)
 *      GET  /api/v1/billing?action=status
 */
(function (global) {
  'use strict';

  /* ── Config ──────────────────────────────────────────────────── */
  const API_BASE    = '/api/v1';
  const POLL_MS     = 10000;
  const SESSION_KEY = 'apex_pf_state';

  /* Fallback only — used if action=plans hasn't resolved yet (or fails) by
     the time a user clicks upgrade. The real source of truth is the backend
     (api/_lib/payment-utils.js); this must be kept in sync with it as a
     last-resort, not treated as authoritative. See docs/PRICING.md. */
  let PLANS = {
    starter:    { name: 'API Starter',     price: '₹999',    amount: 999,   currency: 'INR' },
    pro:        { name: 'SOC Pro',         price: '₹1,499',  amount: 1499,  currency: 'INR' },
    team:       { name: 'Sentinel Team',   price: '₹20,699', amount: 20699, currency: 'INR' },
    enterprise: { name: 'Enterprise Apex', price: '₹82,999', amount: 82999, currency: 'INR' },
  };

  /* Fetched once at script load and cached — the actual source of truth for
     every price this module displays. Fires immediately so it has almost
     always resolved by the time a user reaches the upgrade button. */
  const _plansReady = fetch(`${API_BASE}/billing?action=plans`)
    .then(r => r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`)))
    .then(data => {
      const fetched = data.plans || data.data?.plans;
      if (!fetched) return;
      const merged = {};
      for (const [key, p] of Object.entries(fetched)) {
        merged[key] = { name: p.label, amount: p.amount, currency: p.currency,
          price: `${p.currency === 'INR' ? '₹' : '$'}${p.amount.toLocaleString('en-IN')}` };
      }
      PLANS = merged;
    })
    .catch(e => console.warn('[ApexPF] Could not load canonical plans, using fallback:', e.message));

  const FEATURES = {
    starter:    ['5,000 API calls/day', 'Weekly threat intel digest', 'Full-text search (unrestricted)', 'Single API key'],
    pro:        ['50 live threat items per request', 'Complete IOC feed access', 'SIGMA + Yara detection rules', 'Unlimited full-text search', '25,000 API calls/day'],
    enterprise: ['Unlimited threat items', 'Unlimited API calls/day', 'STIX 2.1 bundle export', 'Bulk CSV/JSON export', 'Pre-disclosure CVE reports', 'All Pro features included'],
  };

  /* ── State ───────────────────────────────────────────────────── */
  let S = {
    plan: null, email: null, intentId: null,
    transactionId: null, step: 1,
    pollTimer: null, cdTimer: null,
  };
  let _injected = false;

  /* ══════════════════════════════════════════════════════════════
     DOM INJECTION
  ══════════════════════════════════════════════════════════════ */
  function _inject() {
    if (_injected) return;
    _injected = true;

    /* ── CSS ── */
    const style = document.createElement('style');
    style.id = 'apex-pf-css';
    style.textContent = `
      #apex-pf-overlay{position:fixed;inset:0;z-index:99999;background:rgba(0,0,0,.78);
        backdrop-filter:blur(10px);display:flex;align-items:center;justify-content:center;
        padding:1rem;opacity:0;pointer-events:none;transition:opacity .2s}
      #apex-pf-overlay.open{opacity:1;pointer-events:all}
      #apex-pf-modal{background:#0f1520;border:1px solid rgba(0,255,224,.18);border-radius:16px;
        width:100%;max-width:470px;max-height:90vh;overflow-y:auto;padding:1.75rem;
        transform:translateY(20px);transition:transform .2s}
      #apex-pf-overlay.open #apex-pf-modal{transform:translateY(0)}
      .pf-mhdr{display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:1.25rem}
      .pf-mtitle{font-size:1.15rem;font-weight:700;color:#e0e8f0}
      .pf-msub{font-size:.78rem;color:#7a8fa6;margin-top:3px}
      .pf-mclose{background:none;border:none;color:#7a8fa6;font-size:1.4rem;
        cursor:pointer;line-height:1;padding:0 4px;flex-shrink:0}
      .pf-mclose:hover{color:#e0e8f0}
      .pf-dots{display:flex;gap:8px;margin-bottom:1.5rem}
      .pf-dot{height:4px;border-radius:2px;flex:1;background:rgba(0,255,224,.12);transition:background .3s}
      .pf-dot.active{background:#00ffe0}
      .pf-dot.done{background:rgba(0,255,224,.38)}
      .pf-step{display:none}
      .pf-step.show{display:block}
      .pf-plan-sum{background:#141c2b;border:1px solid rgba(0,255,224,.12);border-radius:8px;
        padding:11px 15px;display:flex;justify-content:space-between;align-items:center;margin-bottom:1.15rem}
      .pf-plan-name{font-size:.85rem;font-weight:700;color:#e0e8f0}
      .pf-plan-note{font-size:.72rem;color:#7a8fa6}
      .pf-plan-price{font-size:.9rem;font-weight:800;color:#00ffe0}
      .pf-label{display:block;font-size:.78rem;font-weight:600;color:#7a8fa6;
        margin-bottom:6px;letter-spacing:.04em}
      .pf-input{width:100%;padding:10px 13px;background:#141c2b;
        border:1px solid rgba(0,255,224,.15);border-radius:8px;
        color:#e0e8f0;font-size:.9rem;outline:none;transition:border-color .2s;
        font-family:inherit;box-sizing:border-box}
      .pf-input:focus{border-color:#00ffe0}
      .pf-input.err{border-color:#ff3b3b}
      .pf-ferr{font-size:.73rem;color:#ff3b3b;margin-top:4px;display:none}
      .pf-ferr.show{display:block}
      .pf-fg{margin-bottom:1.15rem}
      .pf-btn{width:100%;padding:12px;border-radius:8px;
        background:#00ffe0;color:#0a0d14;font-weight:700;font-size:.9rem;
        border:none;cursor:pointer;transition:all .2s;margin-top:.4rem;
        position:relative}
      .pf-btn:hover:not(:disabled){background:#00e6ca}
      .pf-btn:disabled{opacity:.45;cursor:not-allowed}
      .pf-btn.loading::after{content:'';position:absolute;right:13px;top:50%;
        transform:translateY(-50%);width:13px;height:13px;border:2px solid rgba(0,0,0,.2);
        border-top-color:#0a0d14;border-radius:50%;animation:pf-spin .7s linear infinite}
      .pf-btn2{width:100%;padding:9px;border-radius:8px;
        background:transparent;border:1px solid rgba(0,255,224,.18);
        color:#7a8fa6;font-size:.83rem;cursor:pointer;transition:all .2s;margin-top:.4rem}
      .pf-btn2:hover{border-color:#00ffe0;color:#00ffe0}
      .pf-intent{background:rgba(0,255,224,.07);border:1px solid rgba(0,255,224,.28);
        border-radius:8px;padding:10px 14px;margin:0 0 1rem;font-size:.78rem;color:#00ffe0}
      .pf-intent strong{display:block;margin-bottom:4px;color:#e0e8f0;font-size:.82rem}
      .pf-intent-id{font-family:monospace;font-size:.84rem;color:#00ffe0;word-break:break-all;margin-top:4px}
      .pf-tabs{display:flex;gap:7px;margin-bottom:.85rem}
      .pf-tab{flex:1;padding:8px;border-radius:7px;background:#141c2b;
        border:1px solid rgba(0,255,224,.12);color:#7a8fa6;
        font-size:.8rem;font-weight:600;cursor:pointer;transition:all .2s;text-align:center}
      .pf-tab.active{border-color:#00ffe0;color:#00ffe0;background:rgba(0,255,224,.07)}
      .pf-panel{display:none}
      .pf-panel.show{display:block}
      .pf-qr{text-align:center;margin:.85rem 0}
      .pf-qr img{border-radius:8px;border:3px solid #141c2b}
      .pf-upi-row{background:#141c2b;border:1px solid rgba(0,255,224,.12);border-radius:7px;
        padding:9px 13px;display:flex;align-items:center;justify-content:space-between;margin-bottom:.6rem}
      .pf-upi-val{font-size:.83rem;color:#00ffe0;font-family:monospace}
      .pf-copy{background:none;border:1px solid rgba(0,255,224,.2);border-radius:4px;
        color:#7a8fa6;font-size:.72rem;cursor:pointer;padding:2px 8px;transition:all .2s}
      .pf-copy:hover{color:#00ffe0;border-color:#00ffe0}
      .pf-bank-row{display:flex;justify-content:space-between;align-items:flex-start;
        padding:7px 0;border-bottom:1px solid rgba(0,255,224,.08);font-size:.82rem}
      .pf-bank-row:last-child{border-bottom:none}
      .pf-bk{color:#7a8fa6}
      .pf-bv{color:#e0e8f0;font-family:monospace;text-align:right;max-width:210px;word-break:break-all}
      .pf-stat-wrap{text-align:center;padding:.75rem 0}
      .pf-stat-icon{font-size:2.8rem;margin-bottom:.75rem}
      .pf-stat-title{font-size:1.05rem;font-weight:700;margin-bottom:.4rem}
      .pf-stat-sub{font-size:.82rem;color:#7a8fa6;margin-bottom:1.25rem}
      .pf-txn{background:#141c2b;border:1px solid rgba(0,255,224,.12);border-radius:7px;
        padding:9px 13px;font-size:.76rem;color:#7a8fa6;word-break:break-all;margin-bottom:1.25rem}
      .pf-txn span{color:#e0e8f0;font-family:monospace}
      .pf-badge{display:inline-flex;align-items:center;gap:5px;
        padding:3px 11px;border-radius:20px;font-size:.72rem;font-weight:700}
      .pf-badge.pending{background:rgba(255,215,0,.1);color:#ffd700;border:1px solid rgba(255,215,0,.3)}
      .pf-badge.approved{background:rgba(0,255,224,.1);color:#00ffe0;border:1px solid rgba(0,255,224,.3)}
      .pf-badge.rejected{background:rgba(255,59,59,.1);color:#ff3b3b;border:1px solid rgba(255,59,59,.3)}
      .pf-cdbar{background:#141c2b;border-radius:7px;padding:7px 13px;
        font-size:.77rem;color:#7a8fa6;margin-bottom:.75rem}
      .pf-bar-wrap{height:4px;background:rgba(0,255,224,.1);border-radius:2px;overflow:hidden;margin-bottom:1.25rem}
      .pf-bar-fill{height:100%;background:#00ffe0;border-radius:2px;transition:width 1s linear}
      .pf-ok-wrap{text-align:center;padding:.75rem 0}
      .pf-ok-icon{font-size:3.5rem;margin-bottom:.75rem}
      .pf-ok-title{font-size:1.3rem;font-weight:800;color:#00ffe0;margin-bottom:.4rem}
      .pf-ok-sub{font-size:.87rem;color:#7a8fa6;margin-bottom:1.5rem}
      .pf-unlock{background:#141c2b;border:1px solid rgba(0,255,224,.2);
        border-radius:9px;padding:1.1rem;text-align:left;margin-bottom:1.25rem}
      .pf-unlock h4{font-size:.75rem;color:#00ffe0;margin-bottom:.65rem;
        text-transform:uppercase;letter-spacing:.08em}
      .pf-ul-item{font-size:.83rem;color:#e0e8f0;padding:3px 0;display:flex;gap:7px}
      .pf-hint{font-size:.75rem;color:#7a8fa6;text-align:center;margin-top:.6rem}
      /* Toast */
      #apex-pf-toasts{position:fixed;top:68px;right:14px;z-index:999999;
        display:flex;flex-direction:column;gap:7px;pointer-events:none}
      .pf-toast{background:#0f1520;border-radius:8px;padding:9px 13px 9px 11px;
        display:flex;align-items:flex-start;gap:9px;min-width:240px;max-width:320px;
        box-shadow:0 4px 20px rgba(0,0,0,.45);border-left:3px solid #00ffe0;
        animation:pf-in .25s ease;pointer-events:all}
      .pf-toast.err{border-left-color:#ff3b3b}
      .pf-toast.warn{border-left-color:#ffd700}
      .pf-toast-ico{font-size:.95rem;flex-shrink:0;margin-top:1px}
      .pf-toast-body{flex:1}
      .pf-toast-title{font-size:.8rem;font-weight:700;color:#e0e8f0}
      .pf-toast-msg{font-size:.75rem;color:#7a8fa6;margin-top:2px}
      .pf-toast-x{background:none;border:none;color:#7a8fa6;cursor:pointer;
        font-size:.95rem;padding:0 2px;flex-shrink:0;pointer-events:all}
      @keyframes pf-spin{to{transform:translateY(-50%) rotate(360deg)}}
      @keyframes pf-in{from{transform:translateX(16px);opacity:0}to{transform:translateX(0);opacity:1}}
      @keyframes pf-out{to{transform:translateX(10px);opacity:0}}
    `;
    document.head.appendChild(style);

    /* ── Modal HTML ── */
    const wrap = document.createElement('div');
    wrap.innerHTML = `
      <div id="apex-pf-overlay">
        <div id="apex-pf-modal">
          <div class="pf-mhdr">
            <div>
              <div class="pf-mtitle" id="pf-title">Upgrade Your Plan</div>
              <div class="pf-msub"  id="pf-sub">Complete payment to activate your tier</div>
            </div>
            <button class="pf-mclose" id="pf-close">×</button>
          </div>
          <div class="pf-dots">
            <div class="pf-dot" id="pfd1"></div><div class="pf-dot" id="pfd2"></div>
            <div class="pf-dot" id="pfd3"></div><div class="pf-dot" id="pfd4"></div>
            <div class="pf-dot" id="pfd5"></div>
          </div>

          <!-- STEP 1: Email -->
          <div class="pf-step" id="pfs1">
            <div class="pf-plan-sum">
              <div><div class="pf-plan-name" id="pf-s1name">SOC Pro</div>
                <div class="pf-plan-note">Billed monthly · Activate after verification</div></div>
              <div class="pf-plan-price" id="pf-s1price">₹1,499/mo</div>
            </div>
            <div class="pf-fg">
              <label class="pf-label" for="pf-email">Your Email Address</label>
              <input type="email" class="pf-input" id="pf-email" placeholder="you@company.com" autocomplete="email">
              <div class="pf-ferr" id="pf-email-err">Please enter a valid email address.</div>
            </div>
            <p style="font-size:.76rem;color:#7a8fa6;margin-bottom:.9rem">
              Use the email linked to (or intended for) your API key. Your tier upgrade is tied to this email.
            </p>
            <button class="pf-btn" id="pf-btn1">Continue →</button>
          </div>

          <!-- STEP 2: Payment details -->
          <div class="pf-step" id="pfs2">
            <button class="pf-btn" id="pf-instant-btn" style="margin-bottom:.4rem;background:linear-gradient(135deg,#00ffe0,#00b8a3)" onclick="ApexPaymentFlow._payInstant()">⚡ Pay Instantly — Card / UPI / Wallet</button>
            <p class="pf-hint" id="pf-instant-hint" style="margin:0 0 1rem">Instant activation via Razorpay — no waiting for manual review.</p>
            <div class="pf-intent">
              <strong>Manual UPI / bank transfer has been retired</strong>
              Payments are taken through secure online checkout only. If checkout is unavailable, email
              <a href="mailto:bivash@cyberdudebivash.com?subject=Sentinel%20APEX%20plan%20purchase" style="color:#00ffe0">bivash@cyberdudebivash.com</a> to purchase.
            </div>
            <button class="pf-btn2" onclick="ApexPaymentFlow._go(1)">← Back</button>
          </div>

          <!-- STEP 3: UTR submission -->
          <div class="pf-step" id="pfs3">
            <div class="pf-intent">
              <strong>Submit Your Transaction Reference</strong>
              Enter the UTR / reference number from your payment confirmation.
            </div>
            <div class="pf-fg">
              <label class="pf-label" for="pf-utr">UTR / Transaction Reference Number</label>
              <input type="text" class="pf-input" id="pf-utr" placeholder="e.g. 123456789012" maxlength="64">
              <div class="pf-ferr" id="pf-utr-err">UTR must be 12–64 alphanumeric characters.</div>
            </div>
            <div class="pf-fg">
              <label class="pf-label" for="pf-email2">Confirm Email</label>
              <input type="email" class="pf-input" id="pf-email2" placeholder="same email as step 1" autocomplete="email">
              <div class="pf-ferr" id="pf-email2-err">Must match the email you entered in step 1.</div>
            </div>
            <p style="font-size:.74rem;color:#7a8fa6;margin-bottom:.85rem">
              Find your UTR in your UPI app's transaction history or bank SMS. Usually 12–22 digits.
            </p>
            <button class="pf-btn" id="pf-btn3">Submit for Verification →</button>
            <button class="pf-btn2" onclick="ApexPaymentFlow._go(2)">← Back to Payment</button>
          </div>

          <!-- STEP 4: Polling -->
          <div class="pf-step" id="pfs4">
            <div class="pf-stat-wrap">
              <div class="pf-stat-icon" id="pf-poll-icon">⏳</div>
              <div class="pf-stat-title" id="pf-poll-title">Payment Under Review</div>
              <p class="pf-stat-sub" id="pf-poll-sub">Our team is verifying your transaction. This typically takes 2–4 hours during business hours.</p>
              <div class="pf-txn">Transaction ID: <span id="pf-txn-id">—</span></div>
              <div style="margin-bottom:.6rem;display:flex;justify-content:center">
                <span class="pf-badge pending" id="pf-status-badge">● Pending Review</span>
              </div>
              <div class="pf-cdbar" id="pf-cd">Next check in 10s…</div>
              <div class="pf-bar-wrap"><div class="pf-bar-fill" id="pf-fill" style="width:100%"></div></div>
              <p style="font-size:.75rem;color:#7a8fa6;margin-bottom:1rem">
                Keep this open to get notified instantly, or check later at <a href="/api-dashboard.html" style="color:#00ffe0">API Dashboard</a>.
              </p>
              <button class="pf-btn2" style="max-width:220px;margin:0 auto" onclick="ApexPaymentFlow._poll()">🔄 Check Now</button>
            </div>
          </div>

          <!-- STEP 5: Success -->
          <div class="pf-step" id="pfs5">
            <div class="pf-ok-wrap">
              <div class="pf-ok-icon">🎉</div>
              <div class="pf-ok-title" id="pf-ok-title">Pro Tier Activated!</div>
              <p class="pf-ok-sub" id="pf-ok-sub">Your API key now has full access. Same key — more power.</p>
              <div class="pf-unlock" id="pf-unlock">
                <h4>🔓 Unlocked Features</h4>
              </div>
              <button class="pf-btn" onclick="window.location.href='/api-dashboard.html'">Go to API Dashboard →</button>
              <button class="pf-btn2" onclick="ApexPaymentFlow.close()">Close</button>
            </div>
          </div>
        </div>
      </div>
      <div id="apex-pf-toasts"></div>
    `;
    document.body.appendChild(wrap);

    /* ── Event listeners ── */
    document.getElementById('pf-close').addEventListener('click', () => ApexPaymentFlow.close());
    document.getElementById('apex-pf-overlay').addEventListener('click', (e) => {
      if (e.target === document.getElementById('apex-pf-overlay')) ApexPaymentFlow.close();
    });
    document.getElementById('pf-btn1').addEventListener('click', () => ApexPaymentFlow._emailSubmit());
    document.getElementById('pf-btn3').addEventListener('click', () => ApexPaymentFlow._submitUtr());
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape') ApexPaymentFlow.close(); });
  }

  /* ══════════════════════════════════════════════════════════════
     PUBLIC API
  ══════════════════════════════════════════════════════════════ */
  const ApexPaymentFlow = {

    async startUpgrade(plan) {
      await _plansReady; // resolves near-instantly if already loaded; never blocks more than one fetch
      if (!PLANS[plan]) { console.warn('[ApexPF] Unknown plan:', plan); return; }
      _inject();
      S.plan = plan;

      // Try to restore in-progress session
      try {
        const saved = JSON.parse(sessionStorage.getItem(SESSION_KEY) || 'null');
        if (saved && saved.plan === plan && saved.step >= 4 && saved.transactionId) {
          Object.assign(S, saved);
          this._open();
          this._go(S.step);
          return;
        }
      } catch (_) {}

      // Fresh flow
      S.email = null; S.intentId = null; S.transactionId = null;
      const p = PLANS[plan];
      _set('pf-title', `Upgrade to ${p.name}`);
      _set('pf-sub', `${p.price}/month · Activates after payment verification`);
      _set('pf-s1name', p.name);
      _set('pf-s1price', `${p.price}/mo`);

      // Pre-fill email from localStorage
      try { const e = localStorage.getItem('apex_email'); if (e) _val('pf-email', e); } catch (_) {}
      this._open();
      this._go(1);
    },

    close() {
      _stopPolling();
      const ov = document.getElementById('apex-pf-overlay');
      if (ov) ov.classList.remove('open');
      document.body.style.overflow = '';
    },

    _open() {
      const ov = document.getElementById('apex-pf-overlay');
      if (ov) { ov.classList.add('open'); document.body.style.overflow = 'hidden'; }
    },

    _go(n) {
      for (let i = 1; i <= 5; i++) {
        _cls(`pfs${i}`, 'show', i === n);
        const d = _el(`pfd${i}`);
        if (d) {
          d.className = 'pf-dot' + (i < n ? ' done' : i === n ? ' active' : '');
        }
      }
      S.step = n;
      _save();
    },

    _tab(t) {
      _cls('pf-tupi',  'active', t === 'upi');
      _cls('pf-tbank', 'active', t === 'bank');
      _cls('pf-pupi',  'show',   t === 'upi');
      _cls('pf-pbank', 'show',   t === 'bank');
    },

    _copy(text) {
      if (!text || text === '—') return;
      navigator.clipboard.writeText(text).then(
        () => _toast('info', 'Copied!', text.length > 30 ? text.slice(0, 30) + '…' : text),
        () => _toast('warn', 'Copy failed', 'Please copy manually.')
      );
    },

    async _emailSubmit() {
      const emailEl = _el('pf-email');
      const email   = emailEl.value.trim().toLowerCase();
      _cls('pf-email-err', 'show', false);
      _cls('pf-email', 'err', false);
      if (!email || !/^[^@\s]{1,64}@[^@\s]{1,253}\.[^@\s]{2,}$/.test(email)) {
        _cls('pf-email-err', 'show', true); _cls('pf-email', 'err', true); return;
      }
      // Manual payment intents were retired on 2026-10-01; checkout goes
      // straight to Razorpay, which only needs the email and plan.
      S.email    = email;
      S.intentId = null;
      _storeEmail(email);
      this._go(2);
    },

    async _submitUtr() {
      const utrEl    = _el('pf-utr');
      const emailEl  = _el('pf-email2');
      const utr      = utrEl.value.trim();
      const emailVal = emailEl.value.trim().toLowerCase();
      let ok = true;
      _cls('pf-utr-err',    'show', false); _cls('pf-utr',    'err', false);
      _cls('pf-email2-err', 'show', false); _cls('pf-email2', 'err', false);
      if (!utr || !/^[a-zA-Z0-9]{12,64}$/.test(utr)) {
        _cls('pf-utr-err', 'show', true); _cls('pf-utr', 'err', true); ok = false;
      }
      if (!emailVal || emailVal !== S.email) {
        _cls('pf-email2-err', 'show', true); _cls('pf-email2', 'err', true); ok = false;
      }
      if (!ok) return;
      const btn = _el('pf-btn3');
      _btnLoad(btn, true, 'Submitting…');
      try {
        const data = await _post(`${API_BASE}/billing?action=submit-payment`, {
          intent_id: S.intentId, utr_number: utr,
          email: S.email, payment_method: 'upi',
        });
        if (!data._ok) {
          const code = data.error?.code || '';
          const msgs = {
            DUPLICATE_TRANSACTION: 'This UTR was already submitted. Each transaction can only be submitted once.',
            INTENT_NOT_FOUND:      'Payment intent expired. Please restart the upgrade flow.',
            EMAIL_MISMATCH:        'Email does not match the intent. Use the email from Step 1.',
            INVALID_UTR:           'Invalid UTR format. Must be 12–64 alphanumeric characters.',
            RATE_LIMIT_EXCEEDED:   'Too many submissions. Please wait before retrying.',
          };
          throw new Error(msgs[code] || data.error?.message || 'Submission failed');
        }
        S.transactionId = data.transaction_id || data.data?.transaction_id;
        _set('pf-txn-id', S.transactionId || '—');
        _save();
        this._go(4);
        _startPolling();
      } catch (e) {
        _toast('err', 'Submission Failed', e.message);
      } finally {
        _btnLoad(btn, false, 'Submit for Verification →');
      }
    },

    async _poll() { await _doPoll(); },

    async _payInstant() {
      if (!S.email) {
        // Step 2 is only reachable after step 1 sets the email — guard defensively.
        _toast('err', 'Error', 'Please complete Step 1 first.');
        return;
      }
      const btn = _el('pf-instant-btn');
      _btnLoad(btn, true, 'Opening secure checkout…');
      try {
        await _loadRazorpayScript();
        const data = await _post(`${API_BASE}/billing?action=create-razorpay-order`, {
          email: S.email, plan_type: S.plan,
        });
        if (!data._ok) {
          if (data.error?.code === 'RAZORPAY_UNAVAILABLE') {
            _toast('warn', 'Online checkout unavailable', 'Please email bivash@cyberdudebivash.com to purchase.');
            return;
          }
          throw new Error(data.error?.message || 'Could not start instant checkout.');
        }
        const order = data.order || data.data?.order;
        if (!order || !order.order_id || !order.key_id) throw new Error('Malformed order response.');

        const rzp = new window.Razorpay({
          key:      order.key_id,
          amount:   order.amount,
          currency: order.currency,
          name:     'CYBERDUDEBIVASH SENTINEL APEX',
          description: `${order.plan_label || S.plan} — monthly subscription`,
          order_id: order.order_id,
          prefill:  { email: S.email },
          theme:    { color: '#00ffe0' },
          handler: async (resp) => {
            _btnLoad(btn, true, 'Verifying payment…');
            try {
              const verify = await _post(`${API_BASE}/billing?action=verify-razorpay-payment`, {
                email: S.email, plan_type: S.plan,
                razorpay_order_id:   resp.razorpay_order_id,
                razorpay_payment_id: resp.razorpay_payment_id,
                razorpay_signature:  resp.razorpay_signature,
              });
              if (!verify._ok) throw new Error(verify.error?.message || 'Payment verification failed.');
              try { sessionStorage.removeItem(SESSION_KEY); } catch (_) {}
              _showSuccess();
            } catch (e) {
              _toast('err', 'Verification Failed', e.message || 'Contact support with your payment ID.');
            } finally {
              _btnLoad(btn, false, '⚡ Pay Instantly — Card / UPI / Wallet');
            }
          },
          modal: {
            ondismiss: () => { _btnLoad(btn, false, '⚡ Pay Instantly — Card / UPI / Wallet'); },
          },
        });
        rzp.open();
      } catch (e) {
        _toast('err', 'Error', e.message || 'Could not start online checkout. Email bivash@cyberdudebivash.com to purchase.');
        _btnLoad(btn, false, '⚡ Pay Instantly — Card / UPI / Wallet');
      }
    },
  };

  /* ══════════════════════════════════════════════════════════════
     PRIVATE HELPERS
  ══════════════════════════════════════════════════════════════ */
  let _rzpScriptPromise = null;
  function _loadRazorpayScript() {
    if (window.Razorpay) return Promise.resolve();
    if (_rzpScriptPromise) return _rzpScriptPromise;
    _rzpScriptPromise = new Promise((resolve, reject) => {
      const s = document.createElement('script');
      s.src = 'https://checkout.razorpay.com/v1/checkout.js';
      s.onload  = () => resolve();
      s.onerror = () => { _rzpScriptPromise = null; reject(new Error('Could not load secure checkout.')); };
      document.head.appendChild(s);
    });
    return _rzpScriptPromise;
  }

  function _startPolling() {
    _stopPolling();
    _doPoll();
    S.pollTimer = setInterval(_doPoll, POLL_MS);
    _startCd();
  }

  function _stopPolling() {
    if (S.pollTimer)  { clearInterval(S.pollTimer);  S.pollTimer = null; }
    if (S.cdTimer)    { clearInterval(S.cdTimer);    S.cdTimer   = null; }
  }

  function _startCd() {
    let secs  = POLL_MS / 1000;
    const cd  = _el('pf-cd');
    const bar = _el('pf-fill');
    if (S.cdTimer) clearInterval(S.cdTimer);
    if (bar) { bar.style.transition = 'none'; bar.style.width = '100%'; }
    setTimeout(() => {
      if (bar) { bar.style.transition = `width ${POLL_MS}ms linear`; bar.style.width = '0%'; }
    }, 60);
    S.cdTimer = setInterval(() => {
      secs--;
      if (cd) cd.textContent = secs > 0 ? `Next check in ${secs}s…` : 'Checking…';
      if (secs <= 0) {
        clearInterval(S.cdTimer);
        if (bar) { bar.style.transition = 'none'; bar.style.width = '100%'; }
        setTimeout(() => {
          if (bar) { bar.style.transition = `width ${POLL_MS}ms linear`; bar.style.width = '0%'; }
        }, 60);
        secs = POLL_MS / 1000;
      }
    }, 1000);
  }

  async function _doPoll() {
    if (!S.transactionId || !S.email) return;
    try {
      const url = `${API_BASE}/billing?action=status&transaction_id=${encodeURIComponent(S.transactionId)}&email=${encodeURIComponent(S.email)}`;
      const res = await fetch(url);
      if (!res.ok) return;
      const data = await res.json();
      if (!data.success) return;
      const status = data.status || data.data?.status || 'pending_review';
      _updateBadge(status);
      if (status === 'approved') {
        _stopPolling();
        try { sessionStorage.removeItem(SESSION_KEY); } catch (_) {}
        _showSuccess();
      } else if (status === 'rejected') {
        _stopPolling();
        const reason = data.rejection_reason || 'Contact support with your Intent ID.';
        _updateBadge('rejected');
        _set('pf-poll-sub', reason);
        _toast('err', 'Payment Rejected', reason, 8000);
      }
    } catch (_) { /* retry next tick */ }
  }

  function _updateBadge(status) {
    const el = _el('pf-status-badge');
    if (!el) return;
    el.className = `pf-badge ${status === 'approved' ? 'approved' : status === 'rejected' ? 'rejected' : 'pending'}`;
    el.textContent = { pending_review: '● Pending Review', approved: '✓ Approved', rejected: '✗ Rejected' }[status] || status;
  }

  function _showSuccess() {
    const p     = PLANS[S.plan] || {};
    const feats = FEATURES[S.plan] || [];
    _set('pf-ok-title', `${p.name || 'Pro'} Tier Activated!`);
    _set('pf-ok-sub', `Your API key now has full ${p.name} access. No changes needed — same key, more power.`);
    const ul = _el('pf-unlock');
    if (ul) ul.innerHTML = '<h4>🔓 Unlocked Features</h4>' +
      feats.map(f => `<div class="pf-ul-item"><span>✓</span><span>${_esc(f)}</span></div>`).join('');
    ApexPaymentFlow._go(5);
    _toast('info', '🎉 Upgrade Complete!', `API key is now ${p.name}. Full access activated.`, 7000);
  }

  /* ── DOM utils ── */
  function _el(id)         { return document.getElementById(id); }
  function _set(id, v)     { const e = _el(id); if (e) e.textContent = v; }
  function _val(id, v)     { const e = _el(id); if (e) e.value = v; }
  function _cls(id, c, on) { const e = _el(id); if (!e) return; on ? e.classList.add(c) : e.classList.remove(c); }
  function _esc(s)         { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
  function _storeEmail(e)  { try { localStorage.setItem('apex_email', e); } catch (_) {} }
  function _save()         { try { sessionStorage.setItem(SESSION_KEY, JSON.stringify({ plan:S.plan, email:S.email, intentId:S.intentId, transactionId:S.transactionId, step:S.step })); } catch (_) {} }

  function _btnLoad(btn, on, label) {
    if (!btn) return;
    btn.disabled = on;
    btn.textContent = label;
    on ? btn.classList.add('loading') : btn.classList.remove('loading');
  }

  async function _post(url, body) {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    let data;
    try { data = await res.json(); } catch (_) { data = {}; }
    data._ok = res.ok;
    return data;
  }

  /* ── Toast ── */
  let _tid = 0;
  function _toast(type, title, msg, ms = 5000) {
    if (!_el('apex-pf-toasts')) return;
    const id = ++_tid;
    const ico = { info:'✅', err:'❌', warn:'⚠️' }[type] || 'ℹ️';
    const t = document.createElement('div');
    t.className = `pf-toast ${type !== 'info' ? type : ''}`;
    t.id = `pft${id}`;
    t.innerHTML = `<span class="pf-toast-ico">${ico}</span>
      <div class="pf-toast-body">
        <div class="pf-toast-title">${_esc(title)}</div>
        ${msg ? `<div class="pf-toast-msg">${_esc(msg)}</div>` : ''}
      </div>
      <button class="pf-toast-x" onclick="document.getElementById('pft${id}').remove()">×</button>`;
    _el('apex-pf-toasts').appendChild(t);
    setTimeout(() => { const el = _el(`pft${id}`); if (el) { el.style.animation = 'pf-out .25s forwards'; setTimeout(() => el.remove(), 240); } }, ms);
  }

  /* ── Export ── */
  global.ApexPaymentFlow = ApexPaymentFlow;

})(typeof window !== 'undefined' ? window : global);
