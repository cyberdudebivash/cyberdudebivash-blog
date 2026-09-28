'use strict';
(function(){
  function q(sel,root){return Array.from((root||document).querySelectorAll(sel));}
  function hasName(el){
    if(el.getAttribute('aria-label')||el.getAttribute('aria-labelledby')) return true;
    if(el.id && document.querySelector('label[for="'+CSS.escape(el.id)+'"]')) return true;
    return !!el.closest('label');
  }
  function deriveName(el){
    return (el.getAttribute('placeholder')||el.getAttribute('name')||el.id||el.textContent||'').trim().replace(/[-_]+/g,' ');
  }
  function enhance(){
    var main=document.querySelector('main,[role="main"],#main-content');
    if(main && !main.id) main.id='main-content';
    if(main && !document.querySelector('.cx-skip-link')){
      var skip=document.createElement('a');skip.className='cx-skip-link';skip.href='#'+main.id;skip.textContent='Skip to main content';document.body.prepend(skip);
    }
    q('input,select,textarea').forEach(function(el){
      if(!hasName(el)){var n=deriveName(el);if(n)el.setAttribute('aria-label',n);}
      if(el.required){el.setAttribute('aria-required','true');var lab=el.id&&document.querySelector('label[for="'+CSS.escape(el.id)+'"]');if(lab)lab.classList.add('cx-required');}
    });
    q('[onclick]').forEach(function(el){
      if(/^(A|BUTTON|INPUT|SELECT|TEXTAREA)$/.test(el.tagName))return;
      if(!el.hasAttribute('tabindex'))el.tabIndex=0;
      if(!el.hasAttribute('role'))el.setAttribute('role','button');
      el.classList.add('cx-interactive');
      if(!el.dataset.cxKey){
        el.dataset.cxKey='1';
        el.addEventListener('keydown',function(e){if(e.key==='Enter'||e.key===' '){e.preventDefault();el.click();}});
      }
    });
    q('button').forEach(function(b){if(!b.hasAttribute('type')&&!b.closest('form'))b.type='button';});
    q('a[target="_blank"]').forEach(function(a){var rel=new Set((a.rel||'').split(/\s+/).filter(Boolean));rel.add('noopener');rel.add('noreferrer');a.rel=Array.from(rel).join(' ');});
    q('.alert-error,.error,[data-state="error"]').forEach(function(el){if(!el.hasAttribute('role'))el.setAttribute('role','alert');});
    q('.alert-success,.success,[data-state="success"],[id$="-status"],[id$="-alert"]').forEach(function(el){if(!el.hasAttribute('role'))el.setAttribute('role','status');el.setAttribute('aria-live','polite');});
    q('[disabled]').forEach(function(el){el.setAttribute('aria-disabled','true');});
    q('svg').forEach(function(el){if(!el.hasAttribute('role')&&!el.hasAttribute('aria-label'))el.setAttribute('aria-hidden','true');});
  }
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',enhance,{once:true});else enhance();
})();