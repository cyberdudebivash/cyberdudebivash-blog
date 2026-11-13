'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {selectLiveWindow}=require('../fetch-live-intel.js');
const RS=require('../runtime-state.js');
const NOW=Date.parse('2026-11-13T18:00:00Z');
const hoursAgo=h=>new Date(NOW-h*3600000).toISOString();
const rec=(id,ingestedH,publishedH,priority)=>({
 id,title:id,_addedAt:hoursAgo(ingestedH),
 pubDate:hoursAgo(publishedH),priority,source:'nvd'
});

test('P0 a new low-severity verified report cannot be evicted by 150 archival high-severity CVEs',()=>{
 const historic=Array.from({length:150},(_,i)=>rec('ARCHIVE-'+i,24*40,24*40,100));
 const newReport=rec('NEW-LOW-SEVERITY',1,1,5);
 const out=selectLiveWindow([...historic,newReport],150,NOW);
 assert.equal(out.length,150);
 assert.equal(out[0].id,'NEW-LOW-SEVERITY');
 assert(out.some(x=>x.id==='NEW-LOW-SEVERITY'));
 assert(out.every(x=>x.id==='NEW-LOW-SEVERITY'||x.id.startsWith('ARCHIVE-')));
 assert.equal(RS.selectLiveRecords(out,NOW).items[0].id,'NEW-LOW-SEVERITY');
});

test('P0 recent reports precede historical filler and are sorted by original ingestion before priority',()=>{
 const items=[
  rec('OLD-CRITICAL',24*20,24*20,100),
  rec('FRESH-HIGH',2,2,99),rec('FRESH-NEWER-LOW',1,1,15),
  rec('OLD-NEWLY-INGESTED',0.5,24*40,100)
 ];
 const out=selectLiveWindow(items,4,NOW);
 assert.deepEqual(out.slice(0,2).map(x=>x.id),['FRESH-NEWER-LOW','FRESH-HIGH']);
 assert.equal(RS.isLiveRecord(out[2],NOW),false);
 assert.equal(RS.isLiveRecord(out[3],NOW),false);
});

test('P0 missing, future or zone-less source timestamps cannot obtain live priority',()=>{
 const bad=[
  {...rec('NO-SOURCE-DATE',0.1,0.1,100),pubDate:null},
  {...rec('FUTURE',0.1,0.1,100),pubDate:new Date(NOW+6*60000).toISOString()},
  {...rec('ZONELESS',0.1,0.1,100),_addedAt:'2026-11-13T17:50:00'},
 ];
 const known=rec('VERIFIED-CURRENT',1,1,1);
 assert.equal(selectLiveWindow([...bad,known],2,NOW)[0].id,known.id);
 assert.equal(RS.selectLiveRecords(selectLiveWindow([...bad,known],4,NOW),NOW).items.length,1);
});

test('P0 bounded window validates input and preserves original source records unchanged',()=>{
 assert.throws(()=>selectLiveWindow(null,150,NOW),/LIVE_WINDOW_INPUT_INVALID/);
 assert.throws(()=>selectLiveWindow([],0,NOW),/LIVE_WINDOW_INPUT_INVALID/);
 assert.throws(()=>selectLiveWindow([],5001,NOW),/LIVE_WINDOW_INPUT_INVALID/);
 const records=[rec('CURRENT',0.5,0.5,20)];
 const original=JSON.stringify(records);
 assert.deepEqual(selectLiveWindow(records,1,NOW),records);
 assert.equal(JSON.stringify(records),original);
});

test('P0 publisher no longer fabricates original publication date from its own wall clock',()=>{
 const engine=fs.readFileSync(path.join(__dirname,'..','fetch-live-intel.js'),'utf8');
 const start=engine.indexOf('function writeLiveIntel(');
 const end=engine.indexOf('// ── VALIDATION REPORT',start);
 const source=engine.slice(start,end);
 assert.match(source,/pubDate: item\.pubDate\|\|null/);
 assert.doesNotMatch(source,/pubDate:\s*item\.pubDate\s*\|\|\s*isoNow\(/);
 assert.match(source,/selectLiveWindow\(merged,CFG\.liveRollingWindow \|\| 150,Date\.now\(\)\)/);
});
