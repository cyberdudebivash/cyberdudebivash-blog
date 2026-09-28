/**
 * SENTINEL APEX — Authenticated Customer Assurance Export
 * GET /api/v1/customer/assurance
 * GET /api/v1/customer/assurance?download=1
 */
'use strict';

const { authenticate } = require('../../_lib/middleware');
const sec = require('../../_lib/security');

const PUBLIC_BASE = 'https://blog.cyberdudebivash.in';

function packageFor(user) {
  return {
    schema_version: '1.0',
    generated_at: new Date().toISOString(),
    service: 'CYBERDUDEBIVASH SENTINEL APEX',
    customer_scope: {
      user_id: String(user.userId || ''),
      tier: String(user.tier || 'free'),
      authenticated: true
    },
    assurance_status: 'SOC_2_ALIGNED_OPERATIONAL_EVIDENCE_NOT_CERTIFIED',
    soc2_certified: false,
    soc2_attestation_published: false,
    truth_boundary: 'SOC 2-aligned operational evidence; not SOC 2 certified.',
    controls: {
      exact_commit_deployment: true,
      allowlisted_public_assets: true,
      dependency_audit_gate: true,
      secret_exposure_gate: true,
      workflow_security_gate: true,
      production_smoke_test: true,
      live_customer_journey_certification: true,
      customer_scoped_authentication: true,
      synthetic_customer_activity_metrics: false
    },
    availability: {
      evidence_model: 'current_state_and_release_certification',
      historical_uptime_percentage: null,
      contractual_sla: 'CUSTOMER_SPECIFIC_IF_EXECUTED'
    },
    cti_delivery: {
      source_bound_evidence: true,
      runtime_derived_freshness: true,
      fixed_zero_delay_claim: false,
      pre_disclosure_claim: false,
      acceptance_profile: PUBLIC_BASE + '/api/intel/cti-delivery-acceptance.json'
    },
    incident_response: {
      security_contact: 'security@cyberdudebivash.in',
      customer_production_contact: 'contact@cyberdudebivash.in',
      security_disclosure: PUBLIC_BASE + '/security-disclosure.html',
      security_txt: PUBLIC_BASE + '/.well-known/security.txt',
      customer_incident_response: PUBLIC_BASE + '/customer-incident-response.html',
      incident_response_profile: PUBLIC_BASE + '/api/intel/customer-incident-response.json',
      credential_handling: 'Do not transmit API keys or secrets by email or support ticket.'
    },
    resources: {
      customer_assurance: PUBLIC_BASE + '/customer-assurance.html',
      service_assurance: PUBLIC_BASE + '/service-status.html',
      enterprise_onboarding: PUBLIC_BASE + '/enterprise-onboarding.html',
      delivery_acceptance: PUBLIC_BASE + '/cti-delivery-acceptance.html',
      customer_incident_response: PUBLIC_BASE + '/customer-incident-response.html',
      machine_readable_assurance: PUBLIC_BASE + '/api/intel/customer-assurance.json',
      service_assurance_json: PUBLIC_BASE + '/api/intel/service-assurance.json',
      customer_api_dashboard: PUBLIC_BASE + '/api-dashboard.html'
    },
    contractual_note: 'SLA, audit rights, DPA terms, data residency, support commitments, and compliance obligations apply only where explicitly executed with the customer.'
  };
}

module.exports = async (req, res) => {
  const guarded = await sec.guardRequest(req, res, { allowedMethods: ['GET', 'OPTIONS'], maxBodyBytes: 0 });
  if (!guarded) return;
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (!(await sec.globalIpRateLimit(req, res))) return;

  const user = await authenticate(req, res);
  if (!user) return;

  const body = packageFor(user);
  sec.applySecurityHeaders(res);
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Type', 'application/json; charset=UTF-8');
  if (String((req.query && req.query.download) || '') === '1') {
    const safeUser = String(user.userId || 'customer').replace(/[^a-z0-9_.-]/gi, '_').slice(0, 80) || 'customer';
    res.setHeader('Content-Disposition', 'attachment; filename="sentinel-apex-assurance-' + safeUser + '.json"');
  }
  return res.status(200).json({
    success: true,
    data: body,
    meta: { platform: 'CYBERDUDEBIVASH SENTINEL APEX v4.0', timestamp: new Date().toISOString() }
  });
};

module.exports.packageFor = packageFor;
