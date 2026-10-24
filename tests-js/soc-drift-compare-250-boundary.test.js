'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const p=require('../scripts/production-drift-policy.cjs');
const base='a'.repeat(40),head='b'.repeat(40);
const oldSha='c'.repeat(40),newSha='d'.repeat(40),blob='e'.repeat(40);
const patterns=Array.from({length:20},(_,i)=>'known/path'+i+'.html');
const compare={
  status:'ahead',base_commit:{sha:base,commit:{tree:{sha:oldSha}}},
  merge_base_commit:{sha:base},ahead_by:250,total_commits:250,behind_by:0,
  commits:[{sha:'f'.repeat(40),commit:{tree:{sha:'f'.repeat(40)}}}],
};
const old={sha:oldSha,truncated:false,tree:[{path:'same.txt',type:'blob',mode:'100644',sha:blob}]};
const newer={sha:newSha,truncated:false,tree:[{path:'same.txt',type:'blob',mode:'100644',sha:blob}]};
const anchor={sha:head,commit:{tree:{sha:newSha}}};

test('P0 #433: 250+ compare accepts independently anchored, unchanged immutable trees',()=>{
  const r=p.classifyVerifiedGitTrees(compare,base,head,patterns,old,newer,anchor);
  assert.equal(r.state,'nonproduction_only');
  assert.equal(r.comparison_source,'verified_full_git_trees');
});
test('P0 #433: missing independent head anchor remains blocked',()=>{
  const r=p.classifyVerifiedGitTrees(compare,base,head,patterns,old,newer);
  assert.equal(r.state,'blocked');
});
test('P0 #433: mismatched independent head commit is rejected',()=>{
  const r=p.classifyVerifiedGitTrees(compare,base,head,patterns,old,newer,{...anchor,sha:'0'.repeat(40)});
  assert.equal(r.state,'blocked');
});
test('P0 #433: diverged lineage cannot be accepted with matching tree',()=>{
  const r=p.classifyVerifiedGitTrees({...compare,merge_base_commit:{sha:'0'.repeat(40)}},base,head,patterns,old,newer,anchor);
  assert.equal(r.state,'blocked');
});
test('P0 #433: altered tree identity cannot be accepted',()=>{
  const r=p.classifyVerifiedGitTrees(compare,base,head,patterns,old,{...newer,sha:'0'.repeat(40)},anchor);
  assert.equal(r.state,'blocked');
});
test('P0 #433: truncated tree payload cannot become a false success',()=>{
  const r=p.classifyVerifiedGitTrees(compare,base,head,patterns,old,{...newer,truncated:true},anchor);
  assert.equal(r.state,'blocked');
});
