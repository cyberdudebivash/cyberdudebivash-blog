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
