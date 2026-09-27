(function () {
  'use strict';
  var VALID_STATUS = new Set(['CONFIRMED','REPORTED','CORROBORATED','ASSESSED','HYPOTHESIS','UNKNOWN','NOT_ASSESSED','NOT_APPLICABLE','DISPUTED']);
  var VALID_CORROBORATION = new Set(['SINGLE_SOURCE','MULTI_SOURCE_INDEPENDENT','MULTI_SOURCE_DEPENDENT','UNCORROBORATED']);
  function text(el, value) { el.textContent = value == null || value === '' ? 'Not established' : String(value); }
  function make(tag, cls, value) { var el=document.createElement(tag); if(cls) el.className=cls; if(value!==undefined) text(el,value); return el; }
  function validContract(c) {
    return c && c.schema === 'cdb.soc-evidence.v1' && typeof c.report_id === 'string' &&
      Array.isArray(c.claims) && Array.isArray(c.sources) && Array.isArray(c.evidence) &&
      c.claims.every(function(x){return x && typeof x.claim_id==='string' && VALID_STATUS.has(x.status) && VALID_CORROBORATION.has(x.corroboration_state);});
  }
  function safeSourceUrl(raw) {
    try {
      var u = new URL(String(raw || '').trim());
      if (u.protocol !== 'https:' || u.username || u.password) return null;
      return u.href;
    } catch (e) { return null; }
  }
  function reviewLabel(review) {
    if (!review) return 'Not human reviewed';
    if (review.is_test_only_fixture) return 'Test-only review fixture — not production review';
    if (review.decision === 'APPROVE') return 'Human review: APPROVE';
    if (review.decision === 'REJECT') return 'Human review: REJECT';
    if (review.decision === 'REQUEST_CHANGES') return 'Human review: REQUEST_CHANGES';
    return 'Human review state unavailable';
  }
  function indexBy(list,key){var out=Object.create(null); list.forEach(function(x){if(x&&typeof x[key]==='string')out[x[key]]=x;});return out;}
  function row(label,value){var r=make('div','evidence-row');r.append(make('span','evidence-label',label),make('span','evidence-value',value));return r;}
  function render(container, contract) {
    container.replaceChildren();
    if (!validContract(contract)) {
      container.setAttribute('data-evidence-state','UNAVAILABLE');
      container.append(make('div','evidence-error','Evidence unavailable — canonical ReportX contract validation failed. No inferred provenance is displayed.'));
      return false;
    }
    container.setAttribute('data-evidence-state','VERIFIED_CONTRACT');
    var sourceIndex=indexBy(contract.sources,'source_id'), evidenceIndex=indexBy(contract.evidence,'evidence_id');
    var head=make('div','evidence-head');
    head.append(make('strong','', 'Evidence & Claim Inspector'),make('span','evidence-schema',contract.schema));
    container.append(head);
    contract.claims.forEach(function(claim){
      var card=make('details','evidence-claim');
      var summary=make('summary','evidence-summary');
      summary.append(make('span','evidence-status',claim.status),make('span','evidence-type',claim.claim_type),make('span','evidence-claim-id',claim.claim_id));
      card.append(summary,row('Claim',claim.text),row('Corroboration',claim.corroboration_state),row('Confidence',claim.confidence),row('Scope',claim.observed_vs_context),row('Temporal scope',claim.temporal_scope));
      if ((claim.contradictions||[]).length) card.append(row('Contradictions',claim.contradictions.join(', ')));
      var refs=make('div','evidence-refs');
      (claim.evidence_refs||[]).forEach(function(id){
        var ev=evidenceIndex[id]; if(!ev){refs.append(row('Evidence '+id,'Referenced evidence unavailable'));return;}
        refs.append(row('Evidence '+id,ev.excerpt));
        var src=sourceIndex[ev.source_id];
        if(src){
          var s=make('div','evidence-source');
          s.append(row('Publisher',src.publisher),row('Source type',src.source_type),row('Source date',src.source_date),row('Retrieved',src.retrieved_at),row('Reliability',src.reliability),row('SHA-256',src.content_sha256));
          var safeUrl=safeSourceUrl(src.url); if(safeUrl){var a=make('a','evidence-source-link','Open cited source');a.href=safeUrl;a.target='_blank';a.rel='noopener noreferrer';s.append(a);}
          refs.append(s);
        }
      });
      card.append(refs); container.append(card);
    });
    var review=contract.review;
    container.append(row('Human review',reviewLabel(review)));
    return true;
  }

  function renderAuthRequired(container, detail) {
    container.replaceChildren();
    container.setAttribute('data-evidence-state','AUTH_REQUIRED');
    var card=make('div','evidence-auth-required');
    card.append(
      make('strong','', 'Canonical evidence requires authentication'),
      row('Report ID', detail && detail.reportId || 'Not established'),
      row('Access state','Entitlement-bound')
    );
    var p=make('p','evidence-auth-copy','The selected record is linked to a canonical report, but claim-level evidence is available only through authenticated product access.');
    card.append(p);
    if (detail && detail.reportUrl) {
      var reportLink=make('a','evidence-source-link','Open canonical public report');
      reportLink.href=detail.reportUrl;reportLink.rel='noopener noreferrer';card.append(reportLink);
    }
    var authLink=make('a','evidence-source-link','Open authenticated API dashboard');
    authLink.href='/api-dashboard.html';card.append(authLink);
    container.append(card);
  }

  function bindController() {
    var container=document.getElementById('soc-evidence-drawer');
    if(!container)return;
    document.addEventListener('cdb:soc-record-selected',function(ev){
      var detail=ev&&ev.detail||{};
      if(!detail.reportId){
        container.setAttribute('data-evidence-state','UNAVAILABLE');
        container.replaceChildren(make('div','evidence-error','Canonical evidence unavailable for this rendered record. No report identity is inferred from title, CVE text, URL, or DOM content.'));
        return;
      }
      renderAuthRequired(container,detail);
    });
  }

  window.CDBSocEvidenceDrawer=Object.freeze({render:render,validate:validContract,renderAuthRequired:renderAuthRequired});
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',bindController);else bindController();
})();