(function(){
'use strict';
var selected=null;
var SESSION_KEY='cdb_soc_selected_record_v1';
function reportId(card){var id=String(card&&card.getAttribute('data-report-id')||'').trim();return /^[A-Za-z0-9][A-Za-z0-9._:-]{0,179}$/.test(id)?id:null;}
function recordId(card){var id=String(card&&card.getAttribute('data-record-id')||'').trim();return /^[A-Za-z0-9][A-Za-z0-9._:-]{0,179}$/.test(id)?id:null;}
function remember(card){try{var id=recordId(card);if(id)sessionStorage.setItem(SESSION_KEY,id);else sessionStorage.removeItem(SESSION_KEY);}catch(e){}}
function remembered(){try{return sessionStorage.getItem(SESSION_KEY)||'';}catch(e){return '';}}
function entityContext(card){
 if(!card)return null;
 var id=recordId(card);
 var cve=card.querySelector('.cve-badge');
 if(cve && /^CVE-\d{4}-\d{4,7}$/i.test(String(cve.textContent||'').trim())) id=String(cve.textContent||'').trim().toUpperCase();
 if(/^CVE-\d{4}-\d{4,7}$/i.test(String(id||'')))return {type:'cve',id:String(id).toUpperCase()};
 if(/^campaign:/i.test(String(id||'')))return {type:'campaign',id:String(id)};
 return id?{type:null,id:String(id)}:null;
}
function setActionHref(root,action,href,enabled){
 var a=root.querySelector('[data-soc-action="'+action+'"]');if(!a)return;
 if(href)a.setAttribute('href',href);
 if(enabled){a.removeAttribute('aria-disabled');a.removeAttribute('title');}
 else{a.setAttribute('aria-disabled','true');a.setAttribute('title','This action requires a dossier-supported CVE or campaign record.');}
}
function syncActionTargets(root,card){
 var ctx=entityContext(card);
 var supported=!!(ctx&&ctx.type&&ctx.id);
 if(supported){
  var base='/dossier.html?type='+encodeURIComponent(ctx.type)+'&id='+encodeURIComponent(ctx.id);
  setActionHref(root,'investigate',base+'&focus=overview',true);
  setActionHref(root,'hunt',base+'&focus=attack',true);
  setActionHref(root,'detect',base+'&focus=detections',true);
  setActionHref(root,'watch',base+'&focus=watch',true);
  setActionHref(root,'export',base+'&focus=export',true);
 }else{
  ['investigate','hunt','detect','watch','export'].forEach(function(action){setActionHref(root,action,'/api.html',false);});
 }
}
function setSelectionActions(root,card){var id=reportId(card);root.querySelectorAll('[data-requires-selection]').forEach(function(a){var evidenceOnly=a.hasAttribute('data-requires-report-id');var enabled=!!card&&(!evidenceOnly||!!id);if(enabled)a.removeAttribute('aria-disabled');else a.setAttribute('aria-disabled','true');});syncActionTargets(root,card);txt(root,'[data-selected-evidence]',id?'Canonical report ID available':'Browser-derived record · canonical evidence ID unavailable');}
function txt(root,sel,v){var e=root.querySelector(sel);if(e)e.textContent=String(v);}
function all(root,sel,v){root.querySelectorAll(sel).forEach(function(e){e.textContent=String(v);});}
function position(card,list){var visible=list.filter(function(c){return !c.hidden&&c.style.display!=='none';});var i=visible.indexOf(card);return i<0?'—':String(i+1)+' / '+String(visible.length);}
function cards(root){var sel=root.getAttribute('data-workspace-feed')||'#intel-feed';var feed=document.querySelector(sel);return feed?[].slice.call(feed.querySelectorAll('.intel-post')):[];}
function severity(card){var e=card.querySelector('.severity-chip');return e?String(e.textContent||'').trim().toUpperCase():'NOT ASSESSED';}
function ensureSelect(card){
 if(card.querySelector('.soc-record-select'))return;
 var row=card.querySelector('.post-meta-row');if(!row)return;
 var b=document.createElement('button');b.type='button';b.className='soc-record-select';b.textContent='Select for analysis';b.setAttribute('aria-label','Select intelligence record for SOC analysis');b.setAttribute('aria-pressed','false');
 b.addEventListener('click',function(){selectCard(card);});row.appendChild(b);
}
function selectCard(card){
 if(selected){selected.classList.remove('soc-selected-record');var prev=selected.querySelector('.soc-record-select');if(prev)prev.setAttribute('aria-pressed','false');}selected=card;card.classList.add('soc-selected-record');var active=card.querySelector('.soc-record-select');if(active)active.setAttribute('aria-pressed','true');
 var title=card.querySelector('.post-title');var root=document.querySelector('.soc-workspace');if(!root)return;
 txt(root,'[data-selected-record]',title?title.textContent.trim():'Selected intelligence record');all(document,'[data-case-record]',title?title.textContent.trim():'Selected intelligence record');all(document,'[data-case-position]',position(card,cards(root)));all(document,'[data-case-evidence]',reportId(card)?'ELIGIBLE':'UNAVAILABLE');
 setSelectionActions(root,card);remember(card);
 var preview=document.getElementById('selected-record-preview');
 if(preview){var sev=severity(card);var src=card.querySelector('.source-chip');var cv=card.querySelector('.cve-badge');preview.innerHTML='<div class="ioc-sample"><strong>Record</strong><br>'+String(recordId(card)||'—').replace(/[&<>]/g,function(x){return {'&':'&amp;','<':'&lt;','>':'&gt;'}[x];})+'</div><div class="ioc-sample"><strong>Severity</strong><br>'+sev+'</div><div class="ioc-sample"><strong>Source</strong><br>'+String(src?src.textContent.trim():'—').replace(/[&<>]/g,function(x){return {'&':'&amp;','<':'&lt;','>':'&gt;'}[x];})+'</div><div class="ioc-sample"><strong>Canonical report</strong><br>'+String(reportId(card)||'Not bound').replace(/[&<>]/g,function(x){return {'&':'&amp;','<':'&lt;','>':'&gt;'}[x];})+'</div>'+(cv?'<div class="ioc-sample"><strong>CVE pivot</strong><br>'+cv.textContent.trim()+'</div>':'');}

 document.dispatchEvent(new CustomEvent('cdb:soc-record-selected',{detail:{card:card,reportId:reportId(card),recordId:recordId(card),reportUrl:String(card.getAttribute('data-report-url')||'')}}));
}
function update(root){
 var list=cards(root);list.forEach(ensureSelect);
 if(selected && (selected.hidden || selected.style.display==='none' || !document.documentElement.contains(selected))){selected.classList.remove('soc-selected-record');var active=selected.querySelector('.soc-record-select');if(active)active.setAttribute('aria-pressed','false');selected=null;remember(null);txt(root,'[data-selected-record]','No visible intelligence record selected.');all(document,'[data-case-record]','No record selected');all(document,'[data-case-position]','—');all(document,'[data-case-evidence]','UNAVAILABLE');setSelectionActions(root,null);}
 var critical=list.filter(function(c){return severity(c)==='CRITICAL';}).length;
 var high=list.filter(function(c){return severity(c)==='HIGH';}).length;
 var exploited=list.filter(function(c){return !!c.querySelector('.badge-exploit');}).length;
 txt(root,'[data-ws-visible]',list.filter(function(c){return !c.hidden;}).length);
 txt(root,'[data-ws-critical]',critical);txt(root,'[data-ws-high]',high);txt(root,'[data-ws-exploited]',exploited);
 var state=document.getElementById('soc-runtime-state');var runtime=state?state.textContent:'VERIFYING';txt(root,'[data-ws-runtime]',runtime);var rt=root.querySelector('[data-ws-runtime]');if(rt){rt.setAttribute('data-state',runtime);rt.setAttribute('aria-label','Runtime state '+runtime);}all(document,'[data-case-runtime]',runtime);
 if(!selected){var saved=remembered();if(saved){var match=list.find(function(card){return recordId(card)===saved&&!card.hidden&&card.style.display!=='none';});if(match)selectCard(match);}}
}
function bindEvidence(root){
 var drawer=document.getElementById('soc-evidence-drawer');if(!drawer)return;
 function sync(){
  var s=drawer.getAttribute('data-evidence-state')||'UNAVAILABLE';txt(root,'[data-ws-evidence]',s.replace(/_/g,' '));var evs=root.querySelector('[data-ws-evidence]');if(evs)evs.setAttribute('aria-label','Evidence contract state '+s.replace(/_/g,' '));
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