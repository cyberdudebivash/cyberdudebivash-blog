'use strict';
(function(){
  function q(sel,root){return Array.from((root||document).querySelectorAll(sel));}
  function text(el){return String((el&&el.textContent)||'').replace(/\s+/g,' ').trim();}
  function labelFor(el){
    if(!el||!el.id)return null;
    return q('label').find(function(label){return label.htmlFor===el.id;})||null;
  }
  function hasName(el){
    if(el.getAttribute('aria-label')||el.getAttribute('aria-labelledby')) return true;
    if(labelFor(el)) return true;
    return !!el.closest('label');
  }
  function deriveName(el){
    return (el.getAttribute('placeholder')||el.getAttribute('name')||el.id||el.getAttribute('title')||text(el)||'').trim().replace(/[-_]+/g,' ');
  }
  function announce(message){
    var live=document.getElementById('cx-live-region');
    if(!live){
      live=document.createElement('div');
      live.id='cx-live-region';
      live.className='cx-live-region';
      live.setAttribute('aria-live','polite');
      live.setAttribute('aria-atomic','true');
      document.body.appendChild(live);
    }
    live.textContent='';
    requestAnimationFrame(function(){live.textContent=message;});
  }
  function externalToPlatform(a){
    try{
      if(!a.href)return false;
      var u=new URL(a.href,location.href);
      return /^https?:$/.test(u.protocol)&&u.origin!==location.origin;
    }catch(_){return false;}
  }
  function visible(el){
    if(!el||el.hidden)return false;
    var cs=getComputedStyle(el);
    return cs.display!=='none'&&cs.visibility!=='hidden';
  }
  function enhanceMain(){
    var main=document.querySelector('main,[role="main"],#main-content');
    if(main && !main.id) main.id='main-content';
    if(main && !document.querySelector('.cx-skip-link')){
      var skip=document.createElement('a');
      skip.className='cx-skip-link';
      skip.href='#'+main.id;
      skip.textContent='Skip to main content';
      document.body.prepend(skip);
    }
    if(!document.getElementById('cx-live-region')){
      var live=document.createElement('div');
      live.id='cx-live-region';
      live.className='cx-live-region';
      live.setAttribute('aria-live','polite');
      live.setAttribute('aria-atomic','true');
      document.body.appendChild(live);
    }
  }
  function enhanceControls(){
    q('input,select,textarea').forEach(function(el){
      if(!hasName(el)){var n=deriveName(el);if(n)el.setAttribute('aria-label',n);}
      if(el.required){
        el.setAttribute('aria-required','true');
        var lab=labelFor(el);
        if(lab)lab.classList.add('cx-required');
      }
      if(el.type!=='hidden'&&!el.hasAttribute('autocomplete')){
        var key=(el.name||el.id||'').toLowerCase();
        if(/email/.test(key))el.setAttribute('autocomplete','email');
        else if(/name/.test(key)&&!/username/.test(key))el.setAttribute('autocomplete','name');
        else if(/company|organi[sz]ation/.test(key))el.setAttribute('autocomplete','organization');
      }
    });
    q('button').forEach(function(b){
      if(!text(b)&&!b.getAttribute('aria-label')&&!b.getAttribute('title')){
        var n=deriveName(b);if(n)b.setAttribute('aria-label',n);
      }
      if(!b.hasAttribute('type')&&!b.closest('form'))b.type='button';
      if(b.disabled)b.setAttribute('aria-disabled','true');
    });
    q('[onclick]').forEach(function(el){
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
    });
    q('[disabled]').forEach(function(el){el.setAttribute('aria-disabled','true');});
  }
  function enhanceLinks(){
    q('a').forEach(function(a){
      var href=(a.getAttribute('href')||'').trim();
      if(!href)return;
      if(a.target==='_blank'){
        var rel=new Set((a.rel||'').split(/\s+/).filter(Boolean));
        rel.add('noopener');rel.add('noreferrer');a.rel=Array.from(rel).join(' ');
      }
      if(externalToPlatform(a)){
        a.classList.add('cx-external-link');
        if(!a.getAttribute('aria-label')){
          var label=text(a)||a.getAttribute('title')||'External link';
          a.setAttribute('aria-label',label+' (opens external site'+(a.target==='_blank'?' in a new tab':'')+')');
        }
      }
      var label=text(a)||a.getAttribute('aria-label')||a.getAttribute('title');
      if(!label){
        var path='';
        try{path=new URL(a.href,location.href).pathname;}catch(_){}
        var derived=(path.split('/').filter(Boolean).pop()||'link').replace(/[-_.]+/g,' ');
        a.setAttribute('aria-label',derived);
        a.classList.add('cx-link-icon-only');
      }
      if(href.charAt(0)==='#'&&href.length>1){
        var target=document.getElementById(decodeURIComponent(href.slice(1)));
        if(target)target.classList.add('cx-anchor-target');
      }
    });
  }
  function enhanceForms(){
    q('form').forEach(function(form){
      if(!form.getAttribute('aria-label')&&!form.getAttribute('aria-labelledby')){
        var heading=form.querySelector('h1,h2,h3,legend');
        if(heading&&text(heading))form.setAttribute('aria-label',text(heading));
        else form.setAttribute('aria-label','Customer form');
      }
      q('input,select,textarea',form).forEach(function(el){
        if(!el.dataset.cxValidity){
          el.dataset.cxValidity='1';
          el.addEventListener('invalid',function(){
            el.setAttribute('aria-invalid','true');
            el.classList.add('cx-invalid-control');
            var message=el.validationMessage||'Please review this field.';
            announce(message);
          });
          el.addEventListener('input',function(){
            if(el.validity&&el.validity.valid){
              el.removeAttribute('aria-invalid');
              el.classList.remove('cx-invalid-control');
            }
          });
          el.addEventListener('change',function(){
            if(el.validity&&el.validity.valid){
              el.removeAttribute('aria-invalid');
              el.classList.remove('cx-invalid-control');
            }
          });
        }
      });
      if(!form.dataset.cxSubmit){
        form.dataset.cxSubmit='1';
        form.addEventListener('submit',function(){
          if(!form.checkValidity())return;
          form.setAttribute('aria-busy','true');
          q('button[type="submit"],input[type="submit"]',form).forEach(function(b){
            b.setAttribute('aria-busy','true');
          });
          announce('Submitting form.');
          setTimeout(function(){
            if(document.contains(form)){
              form.removeAttribute('aria-busy');
              q('[aria-busy="true"]',form).forEach(function(b){b.removeAttribute('aria-busy');});
            }
          },12000);
        });
      }
    });
  }
  function enhanceTables(){
    q('table').forEach(function(table){
      if(table.closest('.cx-scroll-region'))return;
      var parent=table.parentElement;
      if(!parent)return;
      var overflow=table.scrollWidth>parent.clientWidth;
      if(!overflow&&window.innerWidth>820)return;
      if(parent.children.length===1&&parent.tagName!=='BODY'){
        parent.classList.add('cx-scroll-region');
        parent.tabIndex=parent.tabIndex>=0?parent.tabIndex:0;
        if(!parent.getAttribute('role'))parent.setAttribute('role','region');
        if(!parent.getAttribute('aria-label'))parent.setAttribute('aria-label','Scrollable data table');
      }
    });
    q('pre').forEach(function(pre){
      pre.classList.add('cx-scroll-region');
      if(!pre.hasAttribute('tabindex'))pre.tabIndex=0;
      if(!pre.getAttribute('aria-label'))pre.setAttribute('aria-label','Scrollable code or text block');
    });
  }
  function enhanceStatus(){
    q('.alert-error,.error,[data-state="error"]').forEach(function(el){
      if(!el.hasAttribute('role'))el.setAttribute('role','alert');
    });
    q('.alert-success,.success,[data-state="success"],[id$="-status"],[id$="-alert"]').forEach(function(el){
      if(!el.hasAttribute('role'))el.setAttribute('role','status');
      el.setAttribute('aria-live','polite');
    });
    q('svg').forEach(function(el){
      if(!el.hasAttribute('role')&&!el.hasAttribute('aria-label'))el.setAttribute('aria-hidden','true');
    });
  }
  function enhanceDialogs(){
    q('[role="dialog"],dialog,[aria-modal="true"]').forEach(function(d){
      if(!d.getAttribute('aria-label')&&!d.getAttribute('aria-labelledby')){
        var h=d.querySelector('h1,h2,h3,[data-dialog-title]');
        if(h&&text(h)){
          if(!h.id)h.id='cx-dialog-title-'+Math.random().toString(36).slice(2,9);
          d.setAttribute('aria-labelledby',h.id);
        }
      }
    });
  }
  function markSections(){
    q('section,article,.card,.panel,.box,.surface').forEach(function(el){
      if(!visible(el))return;
      if(el.id)el.classList.add('cx-anchor-target');
    });
  }
  function enhance(){
    enhanceMain();
    enhanceControls();
    enhanceLinks();
    enhanceForms();
    enhanceTables();
    enhanceStatus();
    enhanceDialogs();
    markSections();
  }
  var resizeTimer;
  function onResize(){
    clearTimeout(resizeTimer);
    resizeTimer=setTimeout(enhanceTables,140);
  }
  var mutationTimer;
  function observeDynamicUi(){
    if(!window.MutationObserver||!document.body)return;
    var observer=new MutationObserver(function(records){
      var relevant=records.some(function(r){return r.addedNodes&&r.addedNodes.length;});
      if(!relevant)return;
      clearTimeout(mutationTimer);
      mutationTimer=setTimeout(enhance,120);
    });
    observer.observe(document.body,{childList:true,subtree:true});
  }
  function boot(){
    enhance();
    observeDynamicUi();
  }
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',boot,{once:true});else boot();
  window.addEventListener('resize',onResize,{passive:true});
  window.addEventListener('orientationchange',onResize,{passive:true});
})();