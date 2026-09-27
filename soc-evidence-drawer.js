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
          if(/^https:\/\//i.test(src.url||'')){var a=make('a','evidence-source-link','Open cited source');a.href=src.url;a.target='_blank';a.rel='noopener noreferrer';s.append(a);}
          refs.append(s);
        }
      });
      card.append(refs); container.append(card);
    });
    var review=contract.review;
    container.append(row('Human review',review ? (review.decision || review.status || 'Recorded') : 'Not recorded'));
    return true;
  }
  window.CDBSocEvidenceDrawer=Object.freeze({render:render,validate:validContract});
})();