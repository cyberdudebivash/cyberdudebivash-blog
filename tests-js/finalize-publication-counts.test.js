'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {assessPublicationCounts, finalizePublicationCounts} = require('../scripts/finalize-publication-counts.cjs');
const state = (total=6533, generated=6) => ({totalPublished:total,lastIngestion:{reportsGenerated:generated}});
const widget = (total=6527) => ({generatedAt:'2026-10-26T05:51:59Z',totalPublished:total,metadata:{lastPipelineRun:'2026-10-26T05:52:12Z'},items:[{id:'CVE-A'}]});
const api = (total=6527) => ({generated:'2026-10-26T05:51:59Z',total_published:total,items:[{id:'CVE-B'}]});
function files(w=widget(),a=api()) {
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'apex-final-'));
  const wp=path.join(dir,'live-intel.json'),ap=path.join(dir,'api-live.json');
  fs.writeFileSync(wp,JSON.stringify(w));fs.writeFileSync(ap,JSON.stringify(a));
  return {wp,ap,read:()=>[JSON.parse(fs.readFileSync(wp)),JSON.parse(fs.readFileSync(ap))],clean:()=>fs.rmSync(dir,{recursive:true,force:true})};
}
test('existing report file updates dedup only, never increments cumulative count or invents report freshness',()=>{
 const { acknowledgeExistingPost }=require('../fetch-live-intel.js');
 const s={totalPublished:6996,lastRun:'2026-11-03T11:44:01Z',
   lastReportGeneratedAt:'2026-11-03T11:44:01Z',
   published:[{id:'CVE-EXISTING',slug:'old',date:'2026-05-01',title:'Old'},
     {id:'CVE-OTHER',slug:'other',date:'2026-11-02',title:'Other'}]};
 const item={id:'CVE-EXISTING',slug:'existing-cve',title:'Existing CVE'};
 assert.deepEqual(acknowledgeExistingPost(s,item),{status:'EXISTING_FILE_DEDUP_ONLY',total:6996});
 assert.equal(s.totalPublished,6996);
 assert.equal(s.lastRun,'2026-11-03T11:44:01Z');
 assert.equal(s.lastReportGeneratedAt,'2026-11-03T11:44:01Z');
 assert.equal(s.published.filter(p=>p.id===item.id).length,1);
 assert.equal(s.published[0].slug,'existing-cve');
 assert.equal(s.published[1].id,'CVE-OTHER');
 acknowledgeExistingPost(s,item);
 assert.equal(s.totalPublished,6996);
 assert.equal(s.published.filter(p=>p.id===item.id).length,1);
 for(const malformed of [{...s,totalPublished:-1},{...s,published:null},null])
   assert.throws(()=>acknowledgeExistingPost(malformed,item),/EXISTING_POST_DEDUP_INVALID/);
 for(const invalid of [{...item,id:''},{...item,slug:''},{...item,title:''}])
   assert.throws(()=>acknowledgeExistingPost(s,invalid),/EXISTING_POST_DEDUP_INVALID/);
 const sixNew={totalPublished:s.totalPublished+6,lastIngestion:{reportsGenerated:6}};
 assert.equal(assessPublicationCounts(sixNew,widget(6996),api(6996)).status,'RECONCILE');
});

test('publisher differentiates previously existing post from a genuinely new report',()=>{
 const engine=fs.readFileSync(path.join(__dirname,'..','fetch-live-intel.js'),'utf8');
 const preexisting=engine.match(/if \(fs\.existsSync\(filePath\)\) \{([\s\S]*?)\n        \}/);
 assert.ok(preexisting,'post-exists decision is missing');
 assert.match(preexisting[1],/acknowledgeExistingPost\(state,/);
 assert.doesNotMatch(preexisting[1],/markPublished\(state,/);
 assert.match(engine,/safeWriteSync\(filePath, html, 'utf8'\);[\s\S]{0,300}markPublished\(state,/);
 assert.match(engine,/state\.lastIngestion\.reportsGenerated = newSlugs\.length/);
});
test('reconciles six genuinely generated reports without rewriting timestamps or items',()=>{
 const f=files();try{assert.deepEqual(finalizePublicationCounts(state(),f.wp,f.ap),{status:'RECONCILED',total:6533});
 const [w,a]=f.read();assert.equal(w.totalPublished,6533);assert.equal(a.total_published,6533);
 assert.equal(w.generatedAt,widget().generatedAt);assert.deepEqual(w.items,widget().items);assert.deepEqual(a.items,api().items);
 assert.equal(w.metadata.lastPipelineRun,widget().metadata.lastPipelineRun);assert.equal(a.generated,api().generated);}finally{f.clean();}
});
test('already finalized is idempotent and byte-preserving',()=>{
 const f=files(widget(6533),api(6533));try{const before=[fs.readFileSync(f.wp,'utf8'),fs.readFileSync(f.ap,'utf8')];
 assert.equal(finalizePublicationCounts(state(),f.wp,f.ap).status,'ALREADY_FINAL');
 assert.deepEqual([fs.readFileSync(f.wp,'utf8'),fs.readFileSync(f.ap,'utf8')],before);}finally{f.clean();}
});
test('zero new reports requires matching counts, not a fabricated heartbeat',()=>{
 assert.equal(assessPublicationCounts(state(6527,0),widget(),api()).status,'ALREADY_FINAL');
 assert.throws(()=>assessPublicationCounts(state(6533,0),widget(),api()),/SOURCE_FEED_COUNT_DRIFT/);
});
test('wrong six-report delta fails closed without changing either file',()=>{
 const f=files(widget(6528),api());try{const before=[fs.readFileSync(f.wp,'utf8'),fs.readFileSync(f.ap,'utf8')];
 assert.throws(()=>finalizePublicationCounts(state(),f.wp,f.ap),/SOURCE_FEED_COUNT_DRIFT/);
 assert.deepEqual([fs.readFileSync(f.wp,'utf8'),fs.readFileSync(f.ap,'utf8')],before);}finally{f.clean();}
});
test('one feed already ahead fails closed',()=>{
 assert.throws(()=>assessPublicationCounts(state(),widget(6533),api()),/SOURCE_FEED_COUNT_DRIFT/);
});
test('invalid ledgers and invalid feed shapes reject',()=>{
 for(const s of [{totalPublished:-1,lastIngestion:{reportsGenerated:0}},state(6533,6534),state(6533,0.5),{}])
  assert.throws(()=>assessPublicationCounts(s,widget(),api()),/REPORT_LEDGER_INVALID/);
 assert.throws(()=>assessPublicationCounts(state(),{totalPublished:6527,items:null},api()),/SOURCE_FEED_SHAPE_INVALID/);
 assert.throws(()=>assessPublicationCounts(state(),widget(),{total_published:6527,items:null}),/SOURCE_FEED_SHAPE_INVALID/);
});
test('malformed JSON and missing feed fail closed',()=>{
 const f=files();try{fs.writeFileSync(f.ap,'not json');assert.throws(()=>finalizePublicationCounts(state(),f.wp,f.ap),SyntaxError);
 fs.unlinkSync(f.wp);assert.throws(()=>finalizePublicationCounts(state(),f.wp,f.ap),/ENOENT/);}finally{f.clean();}
});
test('publisher invokes count finalization after state save in both branches',()=>{
 const engine=fs.readFileSync(path.join(__dirname,'..','fetch-live-intel.js'),'utf8');
 const matches=engine.match(/saveState\(state\);\s*finalizePublicationCounts\(state, CFG\.liveJsonPath, path\.join\(CFG\.apiDir, 'live\.json'\)\);/g)||[];
 assert.equal(matches.length,2);
});

test('P0 prior-run receipt repairs exact 6-report interruption before next generator',()=>{
 const f=files();
 try {
  const before=f.read(),first=finalizePublicationCounts(state(),f.wp,f.ap);
  assert.equal(first.status,'RECONCILED');
  const [widgetAfter,apiAfter]=f.read();
  assert.equal(widgetAfter.totalPublished,6533);
  assert.equal(apiAfter.total_published,6533);
  assert.deepEqual(widgetAfter.items,before[0].items);
  assert.deepEqual(apiAfter.items,before[1].items);
  assert.equal(widgetAfter.generatedAt,before[0].generatedAt);
  assert.equal(apiAfter.generated,before[1].generated);
  assert.equal(finalizePublicationCounts(state(),f.wp,f.ap).status,'ALREADY_FINAL');
 }finally{f.clean();}
});
test('P0 read-only assertion refuses real six-report ledger drift and does not reset freshness',()=>{
 const {check}=require('../scripts/assert-publication-ledger.cjs');
 const s={...state(),lastRun:'2026-10-26T05:51:59.280Z',
   lastReportGeneratedAt:'2026-10-26T05:51:59.280Z'};
 assert(check({state:s,widget:widget(),api:api()}).codes.includes('UNFINALIZED_REPORT_COUNT'));
 const attestedWidget=widget(6533),attestedApi=api(6533);
 attestedWidget.metadata.lastReportGeneratedAt=s.lastReportGeneratedAt;
 attestedApi.lastReportGeneratedAt=s.lastReportGeneratedAt;
 assert.equal(check({state:s,widget:attestedWidget,api:attestedApi}).status,'PASS');
 const bad={...widget(6533),generatedAt:'2026-10-23T04:58:15Z'};
 assert(check({state:s,widget:bad,api:api(6533)}).codes.includes('SOURCE_FEED_RUN_DIVERGENCE'));
});
test('P0 publisher recovery executes before run mutations and CI prevents unfinalized commits',()=>{
 const engine=fs.readFileSync(path.join(__dirname,'..','fetch-live-intel.js'),'utf8');
 const workflow=fs.readFileSync(path.join(__dirname,'..','.github/workflows/sentinel-apex.yml'),'utf8');
 const s=engine.indexOf('const state      = loadState();');
 const recovery=engine.indexOf('const recovery = finalizePublicationCounts(');
 const tier1=engine.indexOf('const tier1Batches = await runTier(');
 assert(s>=0&&recovery>s&&tier1>recovery);
 const pre=workflow.indexOf('name: "P0 fail-closed finalized report ledger and both source feeds"');
 const stage=workflow.indexOf('name: "Commit and push intel (always commit for heartbeat)"');
 assert(pre>0&&pre<stage);
 assert(workflow.includes('node scripts/assert-publication-ledger.cjs'));
 assert(workflow.indexOf('node scripts/assert-publication-ledger.cjs',stage)>stage);
});

test('P0 finalizer publishes genuine report receipt to both public feeds after state is persisted',()=>{
 const f=files(widget(6533),api(6533));
 const report='2026-10-26T05:51:55Z';
 const ledger={...state(),lastRun:'2026-10-26T05:52:00Z',lastReportGeneratedAt:report};
 try{
   assert.deepEqual(finalizePublicationCounts(ledger,f.wp,f.ap),
     {status:'REPORT_PROVENANCE_FINALIZED',total:6533});
   const [w,a]=f.read();
   assert.equal(w.metadata.lastReportGeneratedAt,report);
   assert.equal(a.lastReportGeneratedAt,report);
   assert.equal(w.generatedAt,widget().generatedAt);
   assert.equal(a.generated,api().generated);
   const before=[fs.readFileSync(f.wp,'utf8'),fs.readFileSync(f.ap,'utf8')];
   // A heartbeat without a new report does not manufacture a new receipt.
   ledger.lastRun='2026-10-26T06:00:00Z';
   ledger.lastIngestion.reportsGenerated=0;
   assert.equal(finalizePublicationCounts(ledger,f.wp,f.ap).status,'ALREADY_FINAL');
   assert.deepEqual([fs.readFileSync(f.wp,'utf8'),fs.readFileSync(f.ap,'utf8')],before);
   assert.equal(require('../scripts/assert-publication-ledger.cjs').check({state:ledger,widget:w,api:a}).status,'PASS');
 }finally{f.clean();}
});

test('P0 invalid or impossible real report receipt cannot be stamped as current',()=>{
 const f=files(widget(6533),api(6533));
 try{
   const make=v=>({...state(),lastRun:'2026-10-26T05:52:00Z',lastReportGeneratedAt:v});
   for(const bad of ['not-an-iso','2026-10-27T05:52:00Z','2026-10-26T05:52:00']){
     assert.throws(()=>finalizePublicationCounts(make(bad),f.wp,f.ap),/REAL_REPORT_RECEIPT_/);
   }
   assert.equal(require('../scripts/assert-publication-ledger.cjs').check({
     state:make('2026-10-26T05:51:55Z'),widget:widget(6533),api:api(6533)
   }).codes.includes('PUBLIC_REPORT_RECEIPT_DIVERGENCE'),true);
 }finally{f.clean();}
});
