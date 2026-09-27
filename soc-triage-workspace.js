(function(){
'use strict';
function norm(v){return String(v||'').toLowerCase();}
function stateFor(card){
 var s=norm(card.querySelector('.severity-chip')&&card.querySelector('.severity-chip').textContent);
 var exploited=!!card.querySelector('.badge-exploit');
 var time=norm(card.querySelector('.time-chip')&&card.querySelector('.time-chip').textContent);
 return {severity:s,exploited:exploited,time:time,text:norm(card.textContent)};
}
function apply(root){
 var q=norm(root.querySelector('[data-triage-search]')?.value);
 var sev=root.querySelector('[data-triage-severity]')?.value||'all';
 var exploit=root.querySelector('[data-triage-exploit]')?.checked;
 var cards=[].slice.call(document.querySelectorAll('.intel-post'));
 var visible=0;
 cards.forEach(function(card){var x=stateFor(card);var ok=(!q||x.text.indexOf(q)>=0)&&(sev==='all'||x.severity.indexOf(sev)>=0)&&(!exploit||x.exploited);card.hidden=!ok;if(ok)visible++;});
 var count=root.querySelector('[data-triage-count]');if(count)count.textContent=String(visible);
 var empty=root.querySelector('[data-triage-empty]');if(empty)empty.hidden=visible!==0;
}
function init(){
 document.querySelectorAll('.soc-triage').forEach(function(root){
   root.addEventListener('input',function(){apply(root);});
   root.addEventListener('change',function(){apply(root);});
   root.querySelector('[data-triage-reset]')?.addEventListener('click',function(){root.querySelector('[data-triage-search]').value='';root.querySelector('[data-triage-severity]').value='all';root.querySelector('[data-triage-exploit]').checked=false;apply(root);});
   apply(root);
 });
}
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init);else init();
})();