(function(){
'use strict';
function norm(v){return String(v||'').toLowerCase();}
function stateFor(card){
 var s=norm(card.querySelector('.severity-chip')&&card.querySelector('.severity-chip').textContent);
 var exploited=!!card.querySelector('.badge-exploit');
 return {severity:s,exploited:exploited,text:norm(card.textContent)};
}
function feedFor(root){
 var selector=root.getAttribute('data-triage-feed')||'#intel-feed';
 try{return document.querySelector(selector);}catch(e){return null;}
}
function apply(root){
 var feed=feedFor(root);
 var q=norm(root.querySelector('[data-triage-search]')?.value);
 var sev=root.querySelector('[data-triage-severity]')?.value||'all';
 var exploit=!!root.querySelector('[data-triage-exploit]')?.checked;
 var cards=feed?[].slice.call(feed.querySelectorAll('.intel-post')):[];
 var visible=0;
 cards.forEach(function(card){
   var x=stateFor(card);
   var ok=(!q||x.text.indexOf(q)>=0)&&(sev==='all'||x.severity===sev)&&(!exploit||x.exploited);
   card.hidden=!ok;if(ok)visible++;
 });
 var count=root.querySelector('[data-triage-count]');if(count)count.textContent=String(visible);
 var empty=root.querySelector('[data-triage-empty]');if(empty)empty.hidden=cards.length===0||visible!==0;
}
function initRoot(root){
 var feed=feedFor(root);
 root.addEventListener('input',function(){apply(root);});
 root.addEventListener('change',function(){apply(root);});
 root.querySelector('[data-triage-reset]')?.addEventListener('click',function(){
   root.querySelector('[data-triage-search]').value='';
   root.querySelector('[data-triage-severity]').value='all';
   root.querySelector('[data-triage-exploit]').checked=false;
   apply(root);
 });
 if(feed&&window.MutationObserver){
   var scheduled=false;
   new MutationObserver(function(){
     if(scheduled)return;scheduled=true;
     window.requestAnimationFrame(function(){scheduled=false;apply(root);});
   }).observe(feed,{childList:true,subtree:true});
 }
 apply(root);
}
function init(){document.querySelectorAll('.soc-triage').forEach(initRoot);}
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init);else init();
})();