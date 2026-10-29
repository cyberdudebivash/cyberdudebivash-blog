'use strict';

/**
 * P0 #462 — atomic closure for the internal SOC workbench only.
 * Requires a server-authenticated internal lead, never a client-asserted role.
 * Redis EVAL performs record CAS, old/current status-index transition and
 * audit append as one server-side operation. Historical index reconciliation,
 * customer tenant control and native Upstash verification remain independent.
 */
const {isInternalLead,isValidObjectId}=require('./workbench-object-scope');

const CLOSE_INVESTIGATION_SCRIPT=[
  "local recordType=redis.call('TYPE',KEYS[1]).ok",
  "local oldType=redis.call('TYPE',KEYS[2]).ok",
  "local newType=redis.call('TYPE',KEYS[3]).ok",
  "local auditType=redis.call('TYPE',KEYS[4]).ok",
  "if recordType~='hash' then return {'HOLD_RECORD_TYPE'} end",
  "if (oldType~='zset' and oldType~='none') or (newType~='zset' and newType~='none') or (auditType~='zset' and auditType~='none') then return {'HOLD_INDEX_TYPE'} end",
  "local record=redis.call('HMGET',KEYS[1],'status','version','assignee')",
  "if not record[1] or not record[2] or not record[3] then return {'HOLD_INCOMPLETE_RECORD'} end",
  "if record[1]~=ARGV[1] or record[2]~=ARGV[2] or record[3]~=ARGV[3] then return {'HOLD_STALE_RECORD'} end",
  "if record[1]=='closed' or record[1]=='archived' then return {'HOLD_TERMINAL_RECORD'} end",
  "if record[1]~='open' and record[1]~='in_progress' and record[1]~='pending_review' then return {'HOLD_INVALID_STATUS'} end",
  "redis.call('HSET',KEYS[1],'status','closed','closedAt',ARGV[4],'closureReason',ARGV[5],'recommendations',ARGV[6],'updatedAt',ARGV[4],'version',ARGV[7])",
  "redis.call('ZREM',KEYS[2],ARGV[8])",
  "redis.call('ZADD',KEYS[3],ARGV[9],ARGV[8])",
  "redis.call('ZADD',KEYS[4],ARGV[9],ARGV[10])",
  "return {'OK',ARGV[7]}"
].join('\n');

async function atomicCloseInvestigation({redis,investigation,closureReason,recommendations,caller,now=new Date()}={}){
  if(!isInternalLead(caller)||!isValidObjectId(caller.id)){
    throw new Error('SOC_INVESTIGATION_CLOSE_AUTHORIZATION_REQUIRED');
  }
  if(!redis||typeof redis.eval!=='function'){
    throw new Error('SOC_INVESTIGATION_CLOSE_ATOMIC_REDIS_UNAVAILABLE');
  }
  if(!investigation||!isValidObjectId(investigation.id)||
     !isValidObjectId(investigation.assignee)||
     !['open','in_progress','pending_review'].includes(investigation.status)||
     !Number.isSafeInteger(investigation.version)||investigation.version<1||
     investigation.version===Number.MAX_SAFE_INTEGER){
    throw new Error('SOC_INVESTIGATION_CLOSE_INVALID_RECORD');
  }
  if(typeof closureReason!=='string'||!closureReason.trim()||closureReason.length>2048){
    throw new Error('SOC_INVESTIGATION_CLOSE_INVALID_REASON');
  }
  if(recommendations!==undefined&&
    (!Array.isArray(recommendations)||recommendations.length>64||
     recommendations.some(x=>typeof x!=='string'||!x.trim()||x.length>4096))){
    throw new Error('SOC_INVESTIGATION_CLOSE_INVALID_RECOMMENDATIONS');
  }
  if(!(now instanceof Date)||!Number.isFinite(now.getTime())||
     !Number.isSafeInteger(now.getTime())){
    throw new Error('SOC_INVESTIGATION_CLOSE_INVALID_TIME');
  }
  const timestamp=now.toISOString(),version=investigation.version+1;
  const audit=JSON.stringify({
    action:'CLOSE',actor:caller.id,
    metadata:{closureReason,recommendations:recommendations||[]},
    timestamp,version
  });
  const keys=[
    'investigation:'+investigation.id,
    'investigations:by:status:'+investigation.status,
    'investigations:by:status:closed',
    'investigation:audit:'+investigation.id
  ];
  const args=[
    investigation.status,String(investigation.version),investigation.assignee,
    timestamp,closureReason,JSON.stringify(recommendations||[]),String(version),
    investigation.id,String(now.getTime()),audit
  ];
  // Ambiguous timeout/error never triggers a second write automatically.
  const result=await redis.eval(CLOSE_INVESTIGATION_SCRIPT,keys,args);
  if(!Array.isArray(result)||result[0]!=='OK'||
     String(result[1])!==String(version)){
    throw new Error('SOC_INVESTIGATION_CLOSE_NOT_COMMITTED');
  }
  return {closed:true,investigationId:investigation.id,version,closedAt:timestamp};
}

module.exports={atomicCloseInvestigation,CLOSE_INVESTIGATION_SCRIPT};
