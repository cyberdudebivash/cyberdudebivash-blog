/**
 * CYBERDUDEBIVASH — SECURITY ENGINE v1.0
 * XSS prevention · Input sanitization · CSP · CSRF tokens · Rate limiting
 * Runs before all other engines — load FIRST in <head>
 */

(function() {
  'use strict';

  // ─────────────────────────────────────────────
  // § 1. CONTENT SECURITY POLICY (meta tag)
  // ─────────────────────────────────────────────
  (function injectCSP() {
    // Only inject if no CSP meta exists yet
    if (document.querySelector('meta[http-equiv="Content-Security-Policy"]')) return;

    var csp = [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' https://js.stripe.com https://www.googletagmanager.com https://www.google-analytics.com https://connect.facebook.net https://cdn.jsdelivr.net https://api.convertkit.com",
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "font-src 'self' https://fonts.gstatic.com",
      "img-src 'self' data: https: blob:",
      "connect-src 'self' https://www.google-analytics.com https://analytics.google.com https://stats.g.doubleclick.net https://formsubmit.co https://api.stripe.com https://api.convertkit.com",
      "frame-src https://js.stripe.com https://hooks.stripe.com https://calendly.com",
      "object-src 'none'",
      "base-uri 'self'",
      "form-action 'self' https://formsubmit.co"
    ].join('; ');

    var meta = document.createElement('meta');
    meta.setAttribute('http-equiv', 'Content-Security-Policy');
    meta.setAttribute('content', csp);
    if (document.head) {
      document.head.insertBefore(meta, document.head.firstChild);
    }
  })();

  // ─────────────────────────────────────────────
  // § 2. INPUT SANITIZER
  // ─────────────────────────────────────────────
  var SANITIZE = {
    // Strip dangerous HTML tags and attributes
    html: function(input) {
      if (typeof input !== 'string') return '';
      return input
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;')
        .replace(/\//g, '&#x2F;')
        .replace(/`/g, '&#x60;')
        .replace(/=/g, '&#x3D;');
    },

    // Allow safe inline HTML (removes script/onclick/etc.)
    safeHtml: function(input) {
      if (typeof input !== 'string') return '';
      // Remove script tags and event handlers
      return input
        .replace(/<script[\s\S]*?<\/script>/gi, '')
        .replace(/<iframe[\s\S]*?>/gi, '')
        .replace(/<object[\s\S]*?>/gi, '')
        .replace(/<embed[\s\S]*?>/gi, '')
        .replace(/on\w+\s*=\s*["'][^"']*["']/gi, '')
        .replace(/on\w+\s*=\s*[^\s>]*/gi, '')
        .replace(/javascript\s*:/gi, '')
        .replace(/data\s*:/gi, '');
    },

    // Email validation
    email: function(input) {
      if (typeof input !== 'string') return '';
      var clean = input.trim().toLowerCase().substring(0, 320);
      return /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/.test(clean) ? clean : '';
    },

    // Alphanumeric + safe chars only
    alphanumeric: function(input, allowedExtra) {
      if (typeof input !== 'string') return '';
      var safe = allowedExtra || '';
      return input.replace(new RegExp('[^a-zA-Z0-9\\s' + safe.replace(/./g, '\\$&') + ']', 'g'), '').substring(0, 500);
    },

    // URL validation
    url: function(input) {
      if (typeof input !== 'string') return '';
      try {
        var u = new URL(input);
        if (u.protocol === 'http:' || u.protocol === 'https:') return u.href;
      } catch(e) {}
      return '';
    },

    // Integer only
    int: function(input, min, max) {
      var n = parseInt(input, 10);
      if (isNaN(n)) return 0;
      if (min !== undefined && n < min) n = min;
      if (max !== undefined && n > max) n = max;
      return n;
    }
  };

  // ─────────────────────────────────────────────
  // § 3. CSRF TOKEN
  // ─────────────────────────────────────────────
  var CSRF = {
    key: 'cdb_csrf_token',

    generate: function() {
      var arr = new Uint8Array(32);
      if (window.crypto && window.crypto.getRandomValues) {
        window.crypto.getRandomValues(arr);
      } else {
        for (var i = 0; i < 32; i++) arr[i] = Math.floor(Math.random() * 256);
      }
      var token = Array.from(arr).map(function(b) { return b.toString(16).padStart(2,'0'); }).join('');
      try { sessionStorage.setItem(this.key, token); } catch(e) {}
      return token;
    },

    get: function() {
      try {
        var t = sessionStorage.getItem(this.key);
        if (t) return t;
      } catch(e) {}
      return this.generate();
    },

    injectIntoForms: function() {
      var token = this.get();
      var forms = document.querySelectorAll('form');
      for (var i = 0; i < forms.length; i++) {
        if (!forms[i].querySelector('[name=_csrf]')) {
          var inp = document.createElement('input');
          inp.type = 'hidden';
          inp.name = '_csrf';
          inp.value = token;
          forms[i].appendChild(inp);
        }
      }
    }
  };

  // ─────────────────────────────────────────────
  // § 4. RATE LIMITER (form submissions)
  // ─────────────────────────────────────────────
  var RATE_LIMIT = {
    key: 'cdb_rate_limits',
    limits: {
      form_submit:    { window: 60000, max: 3 },    // 3 per 60s
      email_capture:  { window: 300000, max: 2 },   // 2 per 5min
      api_request:    { window: 10000, max: 10 }    // 10 per 10s
    },

    check: function(action) {
      try {
        var store = JSON.parse(localStorage.getItem(this.key)) || {};
        var now   = Date.now();
        var limit = this.limits[action] || { window: 60000, max: 5 };

        if (!store[action]) store[action] = [];
        // Remove expired timestamps
        store[action] = store[action].filter(function(ts) { return now - ts < limit.window; });

        if (store[action].length >= limit.max) {
          localStorage.setItem(this.key, JSON.stringify(store));
          return false; // Rate limited
        }

        store[action].push(now);
        localStorage.setItem(this.key, JSON.stringify(store));
        return true; // Allowed
      } catch(e) {
        return true; // Allow on error
      }
    }
  };

  // ─────────────────────────────────────────────
  // § 5. FORM SECURITY INTERCEPTOR
  // ─────────────────────────────────────────────
  var FORM_SECURITY = {
    init: function() {
      if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', this.attach.bind(this));
      } else {
        this.attach();
      }
    },

    attach: function() {
      CSRF.injectIntoForms();

      document.addEventListener('submit', function(e) {
        var form = e.target;

        // Rate limit check
        if (!RATE_LIMIT.check('form_submit')) {
          e.preventDefault();
          FORM_SECURITY.showError(form, 'Too many submissions. Please wait a moment before trying again.');
          return;
        }

        // Sanitize all text inputs
        var inputs = form.querySelectorAll('input[type=text], input[type=email], textarea, input:not([type])');
        for (var i = 0; i < inputs.length; i++) {
          var inp = inputs[i];
          var name = inp.name || '';

          if (inp.type === 'email' || name === 'email') {
            var cleanEmail = SANITIZE.email(inp.value);
            if (!cleanEmail && inp.value.trim()) {
              e.preventDefault();
              FORM_SECURITY.showError(form, 'Please enter a valid email address.');
              return;
            }
            inp.value = cleanEmail;
          } else {
            inp.value = SANITIZE.alphanumeric(inp.value, '@._-+/ ');
          }
        }

        // Sanitize textareas
        var textareas = form.querySelectorAll('textarea');
        for (var j = 0; j < textareas.length; j++) {
          textareas[j].value = SANITIZE.safeHtml(textareas[j].value).substring(0, 2000);
        }

      }, true); // Use capture phase
    },

    showError: function(form, msg) {
      var existing = form.querySelector('.security-error');
      if (existing) existing.remove();
      var div = document.createElement('div');
      div.className = 'security-error';
      div.style.cssText = 'background:#2d1515;border:1px solid #ff4444;color:#ff6666;padding:10px 14px;border-radius:6px;font-size:0.88em;margin-top:8px;';
      div.textContent = msg;
      form.appendChild(div);
      setTimeout(function() { div.remove(); }, 5000);
    }
  };

  // ─────────────────────────────────────────────
  // § 6. XSS URL PARAM PROTECTION
  // ─────────────────────────────────────────────
  (function protectURLParams() {
    // Detect XSS in URL parameters and reject
    var dangerous = /<script|javascript:|onerror=|onload=|alert\(|document\.|eval\(/i;
    var search = window.location.search + window.location.hash;
    if (dangerous.test(decodeURIComponent(search))) {
      // Redirect to clean URL without dangerous params
      window.location.replace(window.location.pathname);
    }
  })();

  // ─────────────────────────────────────────────
  // § 7. CLICKJACKING PREVENTION (frame check)
  // ─────────────────────────────────────────────
  (function preventClickjacking() {
    if (window.top !== window.self) {
      // We're in a frame — verify it's allowed (e.g. Calendly widget)
      try {
        var parentHost = window.top.location.host;
        // If we can read parent host, we're same-origin — OK
      } catch(e) {
        // Cross-origin frame — bust it
        window.top.location = window.self.location;
      }
    }
  })();

  // ─────────────────────────────────────────────
  // § 8. SECURITY HEADERS (via meta tags where possible)
  // ─────────────────────────────────────────────
  (function injectSecurityMetas() {
    var metas = [
      { 'http-equiv': 'X-Content-Type-Options', content: 'nosniff' },
      { 'http-equiv': 'Referrer-Policy',         content: 'strict-origin-when-cross-origin' },
      { 'http-equiv': 'Permissions-Policy',      content: 'geolocation=(), microphone=(), camera=()' }
    ];
    metas.forEach(function(m) {
      if (!document.querySelector('meta[http-equiv="' + m['http-equiv'] + '"]')) {
        var el = document.createElement('meta');
        el.setAttribute('http-equiv', m['http-equiv']);
        el.setAttribute('content', m.content);
        if (document.head) document.head.appendChild(el);
      }
    });
  })();

  // ─────────────────────────────────────────────
  // § 9. API INPUT VALIDATION HELPERS
  // ─────────────────────────────────────────────
  var VALIDATE = {
    required: function(val) { return val !== null && val !== undefined && String(val).trim().length > 0; },
    minLength: function(val, min) { return String(val || '').length >= min; },
    maxLength: function(val, max) { return String(val || '').length <= max; },
    pattern:   function(val, regex) { return regex.test(String(val || '')); },

    form: function(form, rules) {
      var errors = [];
      Object.keys(rules).forEach(function(field) {
        var el    = form.querySelector('[name="' + field + '"]');
        var val   = el ? el.value : '';
        var rule  = rules[field];
        if (rule.required && !VALIDATE.required(val)) {
          errors.push(rule.label + ' is required');
        } else if (val) {
          if (rule.min && !VALIDATE.minLength(val, rule.min)) errors.push(rule.label + ' is too short');
          if (rule.max && !VALIDATE.maxLength(val, rule.max)) errors.push(rule.label + ' is too long');
          if (rule.email && !SANITIZE.email(val)) errors.push('Invalid email address');
          if (rule.pattern && !VALIDATE.pattern(val, rule.pattern)) errors.push(rule.label + ' format is invalid');
        }
      });
      return errors;
    }
  };

  // ─────────────────────────────────────────────
  // § 10. INIT & PUBLIC API
  // ─────────────────────────────────────────────
  FORM_SECURITY.init();

  window.SE = {
    sanitize:   SANITIZE,
    csrf:       CSRF,
    rateLimit:  RATE_LIMIT,
    validate:   VALIDATE
  };

  // Re-inject CSRF tokens after DOM changes (for dynamically added forms)
  var _observer = new MutationObserver(function(mutations) {
    mutations.forEach(function(m) {
      m.addedNodes.forEach(function(node) {
        if (node.nodeType === 1 && (node.tagName === 'FORM' || node.querySelector('form'))) {
          CSRF.injectIntoForms();
        }
      });
    });
  });
  if (document.body) {
    _observer.observe(document.body, { childList: true, subtree: true });
  } else {
    document.addEventListener('DOMContentLoaded', function() {
      _observer.observe(document.body, { childList: true, subtree: true });
    });
  }

})();
