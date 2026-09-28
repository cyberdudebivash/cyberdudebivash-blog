'use strict';
(function(){
  var scheduled=false;

  function q(sel,root){
    var base=root&&root.querySelectorAll?root:document;
    return Array.from(base.querySelectorAll(sel));
  }
  function labelFor(el){
    if(!el.id)return null;
    return q('label').find(function(l){return l.htmlFor===el.id;})||null;
  }
  function hasName(el){
    if(el.getAttribute('aria-label')||el.getAttribute('aria-labelledby')) return true;
    if(labelFor(el)) return true;
    return !!el.closest('label');
  }
  function deriveName(el){
    return (el.getAttribute('placeholder')||el.getAttribute('name')||el.id||el.textContent||'').trim().replace(/[-_]+/g,' ');
  }
  function ensureInteractive(el){
    if(/^(A|BUTTON|INPUT|SELECT|TEXTAREA)$/.test(el.tagName))return;
    if(!el.hasAttribute('tabindex'))el.tabIndex=0;
    if(!el.hasAttribute('role'))el.setAttribute('role','button');
    el.classList.add('cx-interactive');
    if(!el.dataset.cxKey){
      el.dataset.cxKey='1';
      el.addEventListener('keydown',function(e){
        if(e.key==='Enter'||e.key===' '){e.preventDefault();el.click();}
      });
    }
  }
  function syncTabs(){
    q('.tabs,.sub-tabs').forEach(function(list){
      if(!list.hasAttribute('role'))list.setAttribute('role','tablist');
      var tabs=Array.from(list.querySelectorAll('.tab,.sub-tab'));
      tabs.forEach(function(tab,index){
        tab.setAttribute('role','tab');
        var active=tab.classList.contains('active');
        tab.setAttribute('aria-selected',active?'true':'false');
        tab.tabIndex=active?0:-1;
        if(!tab.dataset.cxTabKeys){
          tab.dataset.cxTabKeys='1';
          tab.addEventListener('keydown',function(e){
            if(!['ArrowRight','ArrowLeft','Home','End'].includes(e.key))return;
            e.preventDefault();
            var current=tabs.indexOf(tab);
            var next=current;
            if(e.key==='ArrowRight')next=(current+1)%tabs.length;
            if(e.key==='ArrowLeft')next=(current-1+tabs.length)%tabs.length;
            if(e.key==='Home')next=0;
            if(e.key==='End')next=tabs.length-1;
            var target=tabs[next];
            if(target){target.focus();target.click();}
          });
        }
      });
    });
  }
  function enhance(){
    var main=document.querySelector('main,[role="main"],#main-content');
    if(main && !main.id) main.id='main-content';
    if(main && !document.querySelector('.cx-skip-link')){
      var skip=document.createElement('a');
      skip.className='cx-skip-link';
      skip.href='#'+main.id;
      skip.textContent='Skip to main content';
      document.body.prepend(skip);
    }

    q('input,select,textarea').forEach(function(el){
      if(!hasName(el)){var n=deriveName(el);if(n)el.setAttribute('aria-label',n);}
      if(el.required){
        el.setAttribute('aria-required','true');
        var lab=labelFor(el);
        if(lab)lab.classList.add('cx-required');
      }
    });

    q('[onclick]').forEach(ensureInteractive);
    q('.clickable,[data-type="investigation"],[data-type="graph_entity"]').forEach(ensureInteractive);

    q('button').forEach(function(b){
      if(!b.hasAttribute('type')&&!b.closest('form'))b.type='button';
      if(b.disabled)b.setAttribute('aria-disabled','true');
    });

    q('a[target="_blank"]').forEach(function(a){
      var rel=new Set((a.rel||'').split(/\s+/).filter(Boolean));
      rel.add('noopener');rel.add('noreferrer');a.rel=Array.from(rel).join(' ');
    });

    q('.alert-error,.error,[data-state="error"]').forEach(function(el){
      if(!el.hasAttribute('role'))el.setAttribute('role','alert');
      el.setAttribute('aria-live','assertive');
    });
    q('.alert-success,.success,[data-state="success"],[id$="-status"],[id$="-alert"]').forEach(function(el){
      if(!el.hasAttribute('role'))el.setAttribute('role','status');
      if(el.getAttribute('role')!=='alert')el.setAttribute('aria-live','polite');
    });

    q('[disabled]').forEach(function(el){el.setAttribute('aria-disabled','true');});
    q('svg').forEach(function(el){
      if(!el.hasAttribute('role')&&!el.hasAttribute('aria-label')&&!el.querySelector('title'))el.setAttribute('aria-hidden','true');
    });

    syncTabs();
  }
  function scheduleEnhance(){
    if(scheduled)return;
    scheduled=true;
    requestAnimationFrame(function(){scheduled=false;enhance();});
  }
  function start(){
    enhance();
    if(document.body && 'MutationObserver' in window){
      new MutationObserver(scheduleEnhance).observe(document.body,{childList:true,subtree:true});
    }
  }
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',start,{once:true});else start();
})();