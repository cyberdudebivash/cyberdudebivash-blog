(function(){
'use strict';

function cards(){
  var feed=document.getElementById('intel-feed');
  return feed?[].slice.call(feed.querySelectorAll('.intel-post')):[];
}
function matches(card,query){
  var text=String(card.textContent||'').toLowerCase();
  var groups=String(query||'').toLowerCase().split('|').map(function(x){return x.trim();}).filter(Boolean);
  if(!groups.length)return false;
  return groups.some(function(group){
    return group.split(/\s+/).filter(Boolean).every(function(token){return text.indexOf(token)>=0;});
  });
}
function updatePivot(el){
  var query=el.getAttribute('data-filter-query')||'';
  var count=cards().filter(function(card){return matches(card,query);}).length;
  var state=el.querySelector('[data-pivot-state]');
  if(state)state.textContent=count?count+' current matching record'+(count===1?'':'s'):'No current match in rendered feed';
  el.setAttribute('data-match-count',String(count));
}
function applyPivot(el){
  var input=document.querySelector('[data-triage-search]');
  if(!input)return;
  var query=el.getAttribute('data-filter-query')||'';
  input.value=query.split('|')[0].trim();
  input.dispatchEvent(new Event('input',{bubbles:true}));
  document.querySelectorAll('[data-intel-pivot]').forEach(function(x){x.classList.toggle('intel-pivot-active',x===el);});
  var triage=document.querySelector('.soc-triage');
  if(triage)triage.scrollIntoView({behavior:'smooth',block:'start'});
}
function bind(el){
  if(el.getAttribute('data-pivot-bound')==='1')return;
  el.setAttribute('data-pivot-bound','1');
  el.setAttribute('role','button');
  el.setAttribute('tabindex','0');
  el.addEventListener('click',function(){applyPivot(el);});
  el.addEventListener('keydown',function(e){
    if(e.key==='Enter'||e.key===' '){e.preventDefault();applyPivot(el);}
  });
  updatePivot(el);
}
function refresh(){
  document.querySelectorAll('[data-intel-pivot]').forEach(function(el){bind(el);updatePivot(el);});
}
function boot(){
  refresh();
  var feed=document.getElementById('intel-feed');
  if(feed&&window.MutationObserver)new MutationObserver(refresh).observe(feed,{childList:true,subtree:true});
  document.addEventListener('cdb:soc-filters-applied',refresh);
}
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',boot);else boot();
})();