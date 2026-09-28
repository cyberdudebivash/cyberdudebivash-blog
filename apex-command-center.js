/* SENTINEL APEX — live Hybrid SOC 2 + CTI command center */
(function(){
  'use strict';
  var root=document.getElementById('cdb-live-command-center');
  if(!root) return;

  var $=function(id){return document.getElementById(id);};
  var fmt=new Intl.NumberFormat('en-US');
  var state={feed:null,assurance:null,service:null,acceptance:null};

  function safeText(v,fallback){return (v===0||v)?String(v):fallback;}
  function escapeText(v){return String(v==null?'':v).replace(/[&<>"']/g,function(c){return({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]);});}
  function age(iso){
    var t=Date.parse(iso||''); if(!Number.isFinite(t)) return {label:'UNKNOWN',minutes:null,iso:null};
    var mins=Math.max(0,Math.floor((Date.now()-t)/60000));
    var label=mins<60?mins+'m':mins<1440?Math.floor(mins/60)+'h '+(mins%60)+'m':Math.floor(mins/1440)+'d '+Math.floor((mins%1440)/60)+'h';
    return {label:label,minutes:mins,iso:new Date(t).toISOString()};
  }
  function setRuntime(kind,label,meta){
    var pill=$('cdb-runtime-pill'),txt=$('cdb-runtime-text'),detail=$('cdb-runtime-detail');
    if(pill) pill.dataset.state=kind;if(txt)txt.textContent=label;if(detail)detail.textContent=meta||'';
  }
  function setKpi(id,value,note){
    var v=$(id),n=$(id+'-note');if(v)v.textContent=value;if(n)n.textContent=note||'';
  }
  function feedStamp(feed){return feed.generatedAt||feed.lastUpdated||(feed.metadata&&feed.metadata.lastPipelineRun)||(feed.metadata&&feed.metadata.generatedAt)||null;}
  function normalizeSeverity(item){
    var s=String(item.threatLevel||'').toUpperCase();
    if(['CRITICAL','HIGH','MEDIUM','LOW'].indexOf(s)>=0)return s;
    var cv=Number(item.cvss);
    if(Number.isFinite(cv)){if(cv>=9)return'CRITICAL';if(cv>=7)return'HIGH';if(cv>=4)return'MEDIUM';return'LOW';}
    return 'LOW';
  }
  function renderFeed(feed){
    var items=Array.isArray(feed.items)?feed.items.slice():[];
    items.sort(function(a,b){return (Number(b.priority)||0)-(Number(a.priority)||0)||Date.parse(b._addedAt||b.pubDate||0)-Date.parse(a._addedAt||a.pubDate||0);});
    var top=items.slice(0,7),box=$('cdb-triage-feed');
    if(box){
      if(!top.length){box.innerHTML='<div class="cdb-feed-row"><div></div><div><div class="cdb-feed-title">No current records available</div><div class="cdb-feed-sub">Feed returned no intelligence rows.</div></div></div>';}
      else box.innerHTML=top.map(function(it){
        var sev=normalizeSeverity(it),cls=sev.toLowerCase(),href=it.link||('/search.html?q='+encodeURIComponent(it.id||it.title||'')),when=it._addedAt||it.pubDate||'';
        var a=age(when),flags=[];if(it.cisaKev)flags.push('CISA KEV');if(it.exploited)flags.push('EXPLOITED');if(it.ransomware)flags.push('RANSOMWARE');if(Number(it.iocCount)>0)flags.push(it.iocCount+' IOC');
        return '<a class="cdb-feed-row" href="'+escapeText(href)+'"><span class="cdb-sev '+cls+'">'+sev+'</span><span><span class="cdb-feed-title">'+escapeText(it.title||it.id||'Intelligence record')+'</span><span class="cdb-feed-sub">'+escapeText([it.id,it.source].concat(flags).filter(Boolean).join(' · '))+'</span></span><span class="cdb-feed-time">'+escapeText(a.iso?a.label:String(when||''))+'</span></a>';
      }).join('');
    }
    state.feedItems=top;
    drawFabric(top);
  }
  function renderMetrics(feed){
    var stats=feed.stats||{},stamp=feedStamp(feed),fresh=age(stamp);
    setKpi('cdb-total',fmt.format(Number(feed.totalPublished)||0),'Published first-party intelligence');
    setKpi('cdb-critical',fmt.format(Number(stats.critical)||0),'Feed records labelled critical');
    setKpi('cdb-kev',fmt.format(Number(stats.cisaKev)||0),'CISA KEV-confirmed records');
    setKpi('cdb-exploited',fmt.format(Number(stats.exploited)||0),'Records with exploitation evidence');
    setKpi('cdb-ransomware',fmt.format(Number(stats.ransomware)||0),'Ransomware-associated records');
    setKpi('cdb-sources',fmt.format(Number(stats.sources)||0),'Attributed pipeline sources');
    var freshEl=$('cdb-freshness');if(freshEl)freshEl.textContent=fresh.label;
    var timeEl=$('cdb-feed-time');if(timeEl)timeEl.textContent=fresh.iso||'timestamp unavailable';
    if(fresh.minutes==null)setRuntime('warn','FEED TIMESTAMP UNKNOWN','First-party feed reachable; freshness timestamp unavailable.');
    else if(fresh.minutes<=360)setRuntime('live','PRODUCTION DATA LIVE','First-party feed age '+fresh.label+'.');
    else setRuntime('warn','PRODUCTION DATA STALE','First-party feed age '+fresh.label+'; freshness review required.');
  }
  function renderAssurance(a,s,acc){
    var soc=$('cdb-soc2-state');if(soc)soc.textContent=a&&a.soc2_certified===false?'ALIGNED · NOT CERTIFIED':'VERIFY';
    var integrity=$('cdb-integrity-state');if(integrity)integrity.textContent=a&&a.cti_controls&&a.cti_controls.source_bound_evidence?'SOURCE-BOUND':'VERIFY';
    var synth=$('cdb-synthetic-state');if(synth)synth.textContent=a&&a.cti_controls&&a.cti_controls.synthetic_customer_activity_metrics===false?'DISABLED':'VERIFY';
    var sla=$('cdb-sla-state');if(sla)sla.textContent=s&&s.contractual_sla&&s.contractual_sla.status==='CUSTOMER_SPECIFIC_IF_EXECUTED'?'BY CONTRACT':'VERIFY';
    var ac=$('cdb-accept-state');if(ac)ac.textContent=acc&&acc.automatic_acceptance===false?'CUSTOMER-OWNED':'VERIFY';
  }
  function drawFabric(items){
    var canvas=$('cdbSignalCanvas');if(!canvas||!canvas.getContext)return;
    var ctx=canvas.getContext('2d'),dpr=Math.min(window.devicePixelRatio||1,2),rect=canvas.getBoundingClientRect();
    var w=Math.max(320,rect.width),h=Math.max(240,rect.height);canvas.width=Math.floor(w*dpr);canvas.height=Math.floor(h*dpr);ctx.setTransform(dpr,0,0,dpr,0,0);
    var nodes=(items||[]).map(function(it,i){
      var p=(Number(it.priority)||50)/100,ang=(i/(Math.max(1,items.length)))*Math.PI*2-.7;
      return {x:w*.5+Math.cos(ang)*w*(.18+.17*(i%3)/2),y:h*.5+Math.sin(ang)*h*(.20+.15*((i+1)%3)/2),r:3+5*p,sev:normalizeSeverity(it),phase:i*.9};
    });
    nodes.unshift({x:w*.5,y:h*.5,r:8,sev:'CORE',phase:0});
    var reduce=window.matchMedia&&window.matchMedia('(prefers-reduced-motion: reduce)').matches,raf;
    function frame(ts){
      ctx.clearRect(0,0,w,h);
      var grd=ctx.createRadialGradient(w*.5,h*.5,10,w*.5,h*.5,Math.max(w,h)*.48);grd.addColorStop(0,'rgba(33,230,255,.07)');grd.addColorStop(1,'rgba(3,9,15,0)');ctx.fillStyle=grd;ctx.fillRect(0,0,w,h);
      for(var i=1;i<nodes.length;i++){var n=nodes[i];ctx.beginPath();ctx.moveTo(nodes[0].x,nodes[0].y);ctx.quadraticCurveTo(w*.5+(n.x-w*.5)*.35,h*.5-(n.y-h*.5)*.18,n.x,n.y);ctx.strokeStyle='rgba(50,145,205,.18)';ctx.lineWidth=1;ctx.stroke();}
      nodes.forEach(function(n,i){
        var pulse=reduce?0:Math.sin((ts||0)/650+n.phase)*1.7;
        var color=n.sev==='CRITICAL'?'255,73,106':n.sev==='HIGH'?'255,145,96':n.sev==='MEDIUM'?'255,200,87':n.sev==='CORE'?'33,230,255':'62,230,208';
        ctx.beginPath();ctx.arc(n.x,n.y,n.r+5+Math.max(0,pulse),0,Math.PI*2);ctx.fillStyle='rgba('+color+',.08)';ctx.fill();
        ctx.beginPath();ctx.arc(n.x,n.y,n.r,0,Math.PI*2);ctx.fillStyle='rgba('+color+',.88)';ctx.fill();
      });
      if(!reduce)raf=requestAnimationFrame(frame);
    }
    if(raf)cancelAnimationFrame(raf);frame(0);
  }
  function fetchJson(url){return fetch(url,{cache:'no-store',headers:{'Accept':'application/json'}}).then(function(r){if(!r.ok)throw new Error(url+' '+r.status);return r.json();});}
  Promise.allSettled([
    fetchJson('/live-intel.json'),fetchJson('/api/intel/customer-assurance.json'),fetchJson('/api/intel/service-assurance.json'),fetchJson('/api/intel/cti-delivery-acceptance.json')
  ]).then(function(results){
    if(results[0].status==='fulfilled'){state.feed=results[0].value;renderMetrics(state.feed);renderFeed(state.feed);}else setRuntime('bad','DATA UNAVAILABLE','First-party live-intel.json could not be verified.');
    if(results[1].status==='fulfilled')state.assurance=results[1].value;
    if(results[2].status==='fulfilled')state.service=results[2].value;
    if(results[3].status==='fulfilled')state.acceptance=results[3].value;
    renderAssurance(state.assurance,state.service,state.acceptance);
    var ok=results.filter(function(x){return x.status==='fulfilled';}).length;
    var e=$('cdb-evidence-count');if(e)e.textContent=ok+'/4 assurance feeds verified';
  });
  var refresh=$('cdb-refresh');
  if(refresh)refresh.addEventListener('click',function(){window.location.reload();});
  window.addEventListener('resize',function(){if(state.feedItems)drawFabric(state.feedItems);},{passive:true});
})();