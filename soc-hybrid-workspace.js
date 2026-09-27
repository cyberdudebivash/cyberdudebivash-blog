(function(){
'use strict';
var selected=null;
function reportId(card){var id=String(card&&card.getAttribute('data-report-id')||'').trim();return /^[A-Za-z0-9][A-Za-z0-9._:-]{0,179}$/.test(id)?id:null;}
function setSelectionActions(root,card){var id=reportId(card);root.querySelectorAll('[data-requires-selection]').forEach(function(a){var evidenceOnly=a.hasAttribute('data-requires-report-id');var enabled=!!card&&(!evidenceOnly||!!id);if(enabled)a.removeAttribute('aria-disabled');else a.setAttribute('aria-disabled','true');});txt(root,'[data-selected-evidence]',id?'Canonical report ID available':'Browser-derived record · canonical evidence ID unavailable');}
function txt(root,sel,v){var e=root.querySelector(sel);if(e)e.textContent=String(v);}
function cards(root){var sel=root.getAttribute('data-workspace-feed')||'#intel-feed';var feed=document.querySelector(sel);return feed?[].slice.call(feed.querySelectorAll('.intel-post')):[];}
function severity(card){var e=card.querySelector('.severity-chip');return e?String(e.textContent||'').trim().toUpperCase():'NOT ASSESSED';}
function ensureSelect(card){
 if(card.querySelector('.soc-record-select'))return;
 var row=card.querySelector('.post-meta-row');if(!row)return;
 var b=document.createElement('button');b.type='button';b.className='soc-record-select';b.textContent='Select for analysis';
 b.addEventListener('click',function(){selectCard(card);});row.appendChild(b);
}
function selectCard(card){
 if(selected)selected.classList.remove('soc-selected-record');selected=card;card.classList.add('soc-selected-record');
 var title=card.querySelector('.post-title');var root=document.querySelector('.soc-workspace');if(!root)return;
 txt(root,'[data-selected-record]',title?title.textContent.trim():'Selected intelligence record');
 setSelectionActions(root,card);
 document.dispatchEvent(new CustomEvent('cdb:soc-record-selected',{detail:{card:card}}));
}
function update(root){
 var list=cards(root);list.forEach(ensureSelect);
 var critical=list.filter(function(c){return severity(c)==='CRITICAL';}).length;
 var high=list.filter(function(c){return severity(c)==='HIGH';}).length;
 var exploited=list.filter(function(c){return !!c.querySelector('.badge-exploit');}).length;
 txt(root,'[data-ws-visible]',list.filter(function(c){return !c.hidden;}).length);
 txt(root,'[data-ws-critical]',critical);txt(root,'[data-ws-high]',high);txt(root,'[data-ws-exploited]',exploited);
 var state=document.getElementById('soc-runtime-state');txt(root,'[data-ws-runtime]',state?state.textContent:'VERIFYING');
}
function bindEvidence(root){
 var drawer=document.getElementById('soc-evidence-drawer');if(!drawer)return;
 function sync(){
  var s=drawer.getAttribute('data-evidence-state')||'UNAVAILABLE';txt(root,'[data-ws-evidence]',s.replace(/_/g,' '));
  var claims=drawer.querySelectorAll('.evidence-claim');txt(root,'[data-ws-claims]',claims.length);
  txt(root,'[data-ws-confirmed]',drawer.querySelectorAll('.evidence-status').length?[].filter.call(drawer.querySelectorAll('.evidence-status'),function(x){return x.textContent==='CONFIRMED';}).length:0);
 }
 new MutationObserver(sync).observe(drawer,{childList:true,subtree:true,attributes:true,attributeFilter:['data-evidence-state']});sync();
}
function init(root){
 var feed=document.querySelector(root.getAttribute('data-workspace-feed')||'#intel-feed');
 root.querySelectorAll('[data-requires-selection]').forEach(function(a){a.setAttribute('aria-disabled','true');a.addEventListener('click',function(e){if(a.getAttribute('aria-disabled')==='true')e.preventDefault();});});setSelectionActions(root,null);
 if(feed&&window.MutationObserver)new MutationObserver(function(){update(root);}).observe(feed,{childList:true,subtree:true,attributes:true,attributeFilter:['hidden']});
 var state=document.getElementById('soc-runtime-state');if(state&&window.MutationObserver)new MutationObserver(function(){update(root);}).observe(state,{childList:true,attributes:true});
 bindEvidence(root);update(root);
}
function boot(){document.querySelectorAll('.soc-workspace').forEach(init);}
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',boot);else boot();
})();