/**
 * CYBERDUDEBIVASH — EMAIL ENGINE v1.0
 * Mailchimp / ConvertKit integration + lead capture + drip config
 * Replace YOUR_MAILCHIMP_* or YOUR_CONVERTKIT_* with real values
 */

(function() {
  'use strict';

  // ─────────────────────────────────────────────
  // § 1. CONFIGURATION
  // ─────────────────────────────────────────────
  var CONFIG = {
    // Choose provider: 'mailchimp' | 'convertkit' | 'formsubmit'
    provider: 'formsubmit',

    mailchimp: {
      // Get from: Mailchimp → Audience → Signup Forms → Embedded Form
      action_url: 'YOUR_MAILCHIMP_FORM_ACTION_URL',  // https://xxx.us1.list-manage.com/subscribe/post
      u:          'YOUR_MAILCHIMP_U',
      id:         'YOUR_MAILCHIMP_LIST_ID',
      // Tags (Mailchimp groups) for segmentation
      tags: {
        soc_analyst: 'YOUR_TAG_SOC',
        developer:   'YOUR_TAG_DEV',
        enterprise:  'YOUR_TAG_ENT',
        general:     'YOUR_TAG_GEN'
      }
    },

    convertkit: {
      // Get from: ConvertKit → Grow → Landing Pages & Forms → your form → Embed
      form_id: 'YOUR_CONVERTKIT_FORM_ID',
      api_key: 'YOUR_CONVERTKIT_API_KEY'
    },

    formsubmit: {
      // Used as fallback — already configured
      email: 'bivash@cyberdudebivash.com'
    },

    // Drip sequence subject lines (for preview display on leads.html)
    drip: [
      { day: 0,  subject: '🎯 Your Threat Intel Pack is ready — download now',         type: 'delivery' },
      { day: 1,  subject: '🔍 50,000+ IOCs you can load into your SIEM right now',     type: 'value' },
      { day: 3,  subject: '⚡ How our API cuts CVE triage time by 87%',                 type: 'education' },
      { day: 5,  subject: '🛡 500 Sigma Rules vs. your current detection coverage',      type: 'comparison' },
      { day: 7,  subject: '🚀 Exclusive: Pro plan at 40% off — today only',             type: 'offer' },
      { day: 10, subject: '📊 Q2 2026 Threat Report: top 10 CVEs attacking your sector', type: 'report' },
      { day: 14, subject: '🤖 Your personalized threat profile is ready',                type: 'personalized' }
    ],

    storageKey: 'cdb_email_leads',
    maxLocalLeads: 200
  };

  // ─────────────────────────────────────────────
  // § 2. LEAD STORAGE (local backup regardless of provider)
  // ─────────────────────────────────────────────
  var LEADS = {
    store: function(lead) {
      try {
        var leads = JSON.parse(localStorage.getItem(CONFIG.storageKey)) || [];
        lead.ts       = Date.now();
        lead.page     = window.location.pathname;
        lead.segment  = lead.segment || (window.AIM && window.AIM.INTENT ? window.AIM.INTENT.classify().top : 'unknown');
        lead.referrer = document.referrer || 'direct';

        // Deduplicate by email
        var existing = leads.findIndex(function(l) { return l.email === lead.email; });
        if (existing >= 0) {
          leads[existing] = Object.assign(leads[existing], lead);
        } else {
          leads.push(lead);
          if (leads.length > CONFIG.maxLocalLeads) leads = leads.slice(-CONFIG.maxLocalLeads);
        }

        localStorage.setItem(CONFIG.storageKey, JSON.stringify(leads));

        // Update lead counter for admin dashboard
        var counters = JSON.parse(localStorage.getItem('cdb_counters')) || {};
        counters.email_signup = (counters.email_signup || 0) + 1;
        counters._leads_total  = leads.length;
        localStorage.setItem('cdb_counters', JSON.stringify(counters));

      } catch(e) {}
    },

    getAll: function() {
      try { return JSON.parse(localStorage.getItem(CONFIG.storageKey)) || []; } catch(e) { return []; }
    },

    count: function() { return this.getAll().length; }
  };

  // ─────────────────────────────────────────────
  // § 3. MAILCHIMP SUBMISSION
  // ─────────────────────────────────────────────
  var MAILCHIMP = {
    submit: function(email, segment, cb) {
      if (CONFIG.mailchimp.action_url.startsWith('YOUR_')) { if(cb) cb(false, 'not_configured'); return; }

      // Mailchimp JSONP submission
      var tag    = CONFIG.mailchimp.tags[segment] || CONFIG.mailchimp.tags.general || '';
      var callbackName = 'mc_cb_' + Date.now();
      var url = CONFIG.mailchimp.action_url + '?u=' + CONFIG.mailchimp.u +
                '&id=' + CONFIG.mailchimp.id +
                '&EMAIL=' + encodeURIComponent(email) +
                (tag ? '&tags=' + encodeURIComponent(tag) : '') +
                '&c=' + callbackName + '&output=json';

      window[callbackName] = function(data) {
        delete window[callbackName];
        if (data && data.result === 'success') {
          if (cb) cb(true, 'subscribed');
        } else {
          if (cb) cb(false, data ? data.msg : 'error');
        }
        try { document.head.removeChild(script); } catch(e) {}
      };

      var script = document.createElement('script');
      script.src = url;
      script.onerror = function() { if(cb) cb(false, 'network_error'); };
      document.head.appendChild(script);
    }
  };

  // ─────────────────────────────────────────────
  // § 4. CONVERTKIT SUBMISSION
  // ─────────────────────────────────────────────
  var CONVERTKIT = {
    submit: function(email, firstName, cb) {
      if (CONFIG.convertkit.form_id.startsWith('YOUR_')) { if(cb) cb(false, 'not_configured'); return; }

      fetch('https://api.convertkit.com/v3/forms/' + CONFIG.convertkit.form_id + '/subscribe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json; charset=utf-8' },
        body: JSON.stringify({
          api_key:    CONFIG.convertkit.api_key,
          email:      email,
          first_name: firstName || ''
        })
      })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        if (cb) cb(data.subscription ? true : false, data);
      })
      .catch(function() { if(cb) cb(false, 'network_error'); });
    }
  };

  // ─────────────────────────────────────────────
  // § 5. FORMSUBMIT FALLBACK
  // ─────────────────────────────────────────────
  var FORMSUBMIT = {
    buildUrl: function() {
      return 'https://formsubmit.co/' + CONFIG.formsubmit.email;
    }
  };

  // ─────────────────────────────────────────────
  // § 6. UNIFIED SUBSCRIBE FUNCTION
  // ─────────────────────────────────────────────
  function subscribe(opts, cb) {
    if (!opts || !opts.email) { if(cb) cb(false, 'no_email'); return; }

    // Always store locally first
    LEADS.store({ email: opts.email, name: opts.name || '', segment: opts.segment || '' });

    // Fire analytics
    if (window.trackEvent) {
      window.trackEvent({ category: 'conversion', action: 'email_signup', label: opts.source || 'form', value: 0 });
    }
    if (window.AE) {
      window.AE.track({ category: 'conversion', action: 'email_signup', label: opts.source || 'form' });
    }

    // Submit to provider
    switch(CONFIG.provider) {
      case 'mailchimp':
        MAILCHIMP.submit(opts.email, opts.segment, cb);
        break;
      case 'convertkit':
        CONVERTKIT.submit(opts.email, opts.name, cb);
        break;
      default:
        // formsubmit — form must have correct action set
        if (cb) cb(true, 'formsubmit_mode');
        break;
    }
  }

  // ─────────────────────────────────────────────
  // § 7. EMAIL CAPTURE FORM AUTO-WIRING
  // ─────────────────────────────────────────────
  var FORM_WIRER = {
    init: function() {
      if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', this.wire.bind(this));
      } else {
        this.wire();
      }
    },

    wire: function() {
      var forms = document.querySelectorAll('[data-email-capture]');
      for (var i = 0; i < forms.length; i++) {
        (function(form) {
          if (form.getAttribute('data-ee-wired')) return;
          form.setAttribute('data-ee-wired', '1');

          form.addEventListener('submit', function(e) {
            e.preventDefault();
            var emailInput = form.querySelector('[type=email]') || form.querySelector('[name=email]');
            var nameInput  = form.querySelector('[name=name]') || form.querySelector('[name=fname]');
            var submitBtn  = form.querySelector('[type=submit]') || form.querySelector('button');
            var segment    = form.getAttribute('data-segment') || 'general';
            var source     = form.getAttribute('data-source') || window.location.pathname;

            if (!emailInput || !emailInput.value) return;

            if (submitBtn) { submitBtn.disabled = true; submitBtn.textContent = 'Subscribing...'; }

            subscribe({
              email:   emailInput.value,
              name:    nameInput ? nameInput.value : '',
              segment: segment,
              source:  source
            }, function(success, msg) {
              if (success || msg === 'formsubmit_mode') {
                FORM_WIRER.showSuccess(form, submitBtn);
              } else {
                // Fallback to formsubmit action
                form.action = FORMSUBMIT.buildUrl();
                form.method = 'POST';
                if (submitBtn) { submitBtn.disabled = false; submitBtn.textContent = 'Get Access'; }
                // Try native submit
                var clone = form.cloneNode(true);
                clone.removeAttribute('data-ee-wired');
                form.parentNode.replaceChild(clone, form);
                clone.submit();
              }
            });
          });
        })(forms[i]);
      }
    },

    showSuccess: function(form, btn) {
      var successMsg = form.getAttribute('data-success') ||
        '✅ You\'re in! Check your email for your download link.';
      var container = form.closest('[data-capture-container]') || form;
      container.innerHTML = '<div style="text-align:center;padding:24px;">' +
        '<div style="font-size:3em;margin-bottom:12px;">🎯</div>' +
        '<h3 style="color:#00ff88;margin-bottom:8px;">You\'re In!</h3>' +
        '<p style="color:#aaa;">' + successMsg + '</p>' +
        '</div>';
    }
  };

  // ─────────────────────────────────────────────
  // § 8. NEWSLETTER WIDGET INJECTOR
  // ─────────────────────────────────────────────
  var NEWSLETTER_WIDGET = {
    inject: function() {
      var targets = document.querySelectorAll('[data-newsletter-widget]');
      for (var i = 0; i < targets.length; i++) {
        targets[i].innerHTML = NEWSLETTER_WIDGET.html();
      }
      FORM_WIRER.wire();
    },

    html: function() {
      return '<div style="background:linear-gradient(135deg,#0d1117,#111827);border:1px solid #1a2535;border-radius:12px;padding:28px;margin:24px 0;">' +
        '<h3 style="color:#00ff88;margin:0 0 6px;font-size:1.1em;">🛡 Weekly Threat Intelligence Digest</h3>' +
        '<p style="color:#aaa;font-size:0.9em;margin:0 0 16px;">CVE alerts, IOC packs, and detection rules — every Tuesday.</p>' +
        '<form data-email-capture data-segment="general" data-source="newsletter_widget" ' +
        'action="https://formsubmit.co/bivash@cyberdudebivash.com" method="POST" ' +
        'style="display:flex;gap:8px;flex-wrap:wrap;">' +
        '<input type="hidden" name="_subject" value="Newsletter Signup">' +
        '<input type="hidden" name="_next" value="' + window.location.href + '?subscribed=1">' +
        '<input type="email" name="email" placeholder="your@email.com" required ' +
        'style="flex:1;min-width:200px;padding:10px 14px;background:#0a0e1a;border:1px solid #1a2535;' +
        'border-radius:6px;color:#e0e0e0;font-size:0.95em;">' +
        '<button type="submit" ' +
        'style="background:#00ff88;color:#000;border:none;padding:10px 20px;border-radius:6px;' +
        'font-weight:700;cursor:pointer;white-space:nowrap;">Subscribe Free</button>' +
        '</form></div>';
    }
  };

  // ─────────────────────────────────────────────
  // § 9. DRIP SEQUENCE DISPLAY (for leads.html)
  // ─────────────────────────────────────────────
  var DRIP_DISPLAY = {
    render: function(containerId) {
      var el = document.getElementById(containerId);
      if (!el) return;

      var html = '<div class="drip-timeline">';
      CONFIG.drip.forEach(function(item) {
        var icon = item.type === 'delivery' ? '📦' : item.type === 'value' ? '💡' :
                   item.type === 'education' ? '🎓' : item.type === 'offer' ? '🔥' :
                   item.type === 'report' ? '📊' : item.type === 'personalized' ? '🤖' : '📧';
        html += '<div class="drip-item" style="display:flex;align-items:flex-start;gap:12px;padding:12px 0;border-bottom:1px solid #1a2535;">' +
          '<div style="background:#0d1117;border:1px solid #1a2535;border-radius:8px;padding:8px 12px;min-width:60px;text-align:center;">' +
          '<div style="color:#00ff88;font-size:0.7em;font-weight:700;">DAY</div>' +
          '<div style="color:#e0e0e0;font-weight:700;font-size:1.1em;">' + item.day + '</div></div>' +
          '<div><span style="font-size:1.1em;">' + icon + '</span> ' +
          '<span style="color:#e0e0e0;font-size:0.9em;">' + item.subject + '</span></div>' +
          '</div>';
      });
      html += '</div>';
      el.innerHTML = html;
    }
  };

  // ─────────────────────────────────────────────
  // § 10. INIT
  // ─────────────────────────────────────────────
  FORM_WIRER.init();

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function() {
      NEWSLETTER_WIDGET.inject();
      DRIP_DISPLAY.render('drip-sequence-display');
    });
  } else {
    NEWSLETTER_WIDGET.inject();
    DRIP_DISPLAY.render('drip-sequence-display');
  }

  // Handle ?subscribed=1 parameter
  if (new URLSearchParams(window.location.search).get('subscribed') === '1') {
    if (window.trackEvent) window.trackEvent({ category: 'conversion', action: 'email_signup', label: 'form_redirect' });
    if (window.AE) window.AE.track({ category: 'conversion', action: 'email_signup', label: 'form_redirect' });
  }

  // Public API
  window.EE = {
    subscribe:        subscribe,
    leads:            LEADS,
    drip:             CONFIG.drip,
    newsletterWidget: NEWSLETTER_WIDGET,
    dripDisplay:      DRIP_DISPLAY,
    config:           CONFIG
  };

})();
