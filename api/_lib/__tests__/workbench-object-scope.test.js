'use strict';
const {
  isInternalLead, isValidObjectId, canAccessInvestigation, canAssignInvestigation
} = require('../workbench-object-scope');

test('P0 only explicit internal SOC lead roles inherit shared queue visibility',()=>{
  expect(isInternalLead({id:'lead',role:'lead_analyst'})).toBe(true);
  expect(isInternalLead({id:'lead',role:'soc_admin'})).toBe(true);
  for(const role of ['analyst','customer','admin','enterprise',null,undefined]){
    expect(isInternalLead({id:'u',role})).toBe(false);
  }
  expect(isInternalLead({role:'soc_admin'})).toBe(false);
});
test('P0 object IDs must be bounded and reject delimiters/key injection',()=>{
  for(const id of ['inv-123','abc123','ABC_123'])expect(isValidObjectId(id)).toBe(true);
  for(const id of ['',null,{},[], 'a'.repeat(101),'../admin','case:admin','a/b','x\nsecret']){
    expect(isValidObjectId(id)).toBe(false);
  }
});
test('P0 analyst ownership, missing owner and corrupt records fail closed',()=>{
  const alice={id:'alice',role:'analyst'};
  const inv={id:'inv123',assignee:'alice'};
  expect(canAccessInvestigation(alice,inv)).toBe(true);
  for(const record of [{id:'inv123',assignee:'bob'},{id:'inv123'},null,{assignee:'alice'}]){
    expect(canAccessInvestigation(alice,record)).toBe(false);
  }
  expect(canAccessInvestigation({id:'bob',role:'customer'},inv)).toBe(false);
  expect(canAccessInvestigation(null,inv)).toBe(false);
});
test('P0 ordinary analyst cannot delegate investigations, only verified internal lead',()=>{
  expect(canAssignInvestigation({id:'alice',role:'analyst'},'alice')).toBe(true);
  expect(canAssignInvestigation({id:'alice',role:'analyst'},'bob')).toBe(false);
  expect(canAssignInvestigation({id:'lead',role:'lead_analyst'},'bob')).toBe(true);
  expect(canAssignInvestigation({id:'lead',role:'soc_admin'},'bob')).toBe(true);
  expect(canAssignInvestigation({id:'lead',role:'soc_admin'},'../admin')).toBe(false);
});
