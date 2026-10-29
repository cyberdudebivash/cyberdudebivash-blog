'use strict';
/**
 * P0 #455 — atomic internal-only investigation reassignment.
 *
 * One Upstash EVAL compares the stored owner, version and status before
 * changing the hash, removing the old owner index, writing the new owner
 * index and committing the audit event. A pipeline is NOT atomic.
 *
 * Never expose this helper directly through HTTP; the caller is an already
 * verified internal analyst identity from requireAnalyst, checked again here.
 * Legacy data/index reconciliation and native production canary remain open.
 */
const {isInternalLead,isValidObjectId}=require('./workbench-object-scope');

// Every key touched by the script is explicitly listed in KEYS. Preflight
// types before writing: Redis Lua is atomic against interleaving commands,
// but runtime errors do not roll back previous Lua writes.
const REASSIGN_SCRIPT = [
"local v = redis.call('HMGET', KEYS[1], 'assignee', 'version', 'status')",
"if not v[1] or not v[2] or not v[3] then return {'HOLD_MISSING_RECORD'} end",
"if v[1] ~= ARGV[1] or v[2] ~= ARGV[3] or v[3] ~= ARGV[4] then return {'HOLD_STALE_RECORD'} end",
"if v[3] == 'closed' or v[3] == 'archived' then return {'HOLD_TERMINAL_CASE'} end",
"local recType = redis.call('TYPE', KEYS[1]).ok",
"local oldType = redis.call('TYPE', KEYS[2]).ok",
"local newType = redis.call('TYPE', KEYS[3]).ok",
"local auditType = redis.call('TYPE', KEYS[4]).ok",
"if recType ~= 'hash' or (oldType ~= 'zset' and oldType ~= 'none') or (newType ~= 'zset' and newType ~= 'none') or (auditType ~= 'zset' and auditType ~= 'none') then return {'HOLD_INDEX_TYPE'} end",
"redis.call('HSET', KEYS[1], 'assignee', ARGV[2], 'updatedAt', ARGV[5], 'version', ARGV[6])",
"if ARGV[9] == '1' then redis.call('HSET', KEYS[1], 'title', ARGV[10]) end",
"if ARGV[12] == '1' then redis.call('HSET', KEYS[1], 'description', ARGV[13]) end",
"if ARGV[1] ~= 'unassigned' then redis.call('ZREM', KEYS[2], ARGV[7]) end",
"if ARGV[2] ~= 'unassigned' then redis.call('ZADD', KEYS[3], ARGV[8], ARGV[7]) end",
"redis.call('ZADD', KEYS[4], ARGV[8], ARGV[11])",
"return {'OK', ARGV[6]}"
].join('\n');

async function atomicReassign({redis,investigation,updates,caller,now=new Date()}={}){
  if(!isInternalLead(caller) || !isValidObjectId(caller.id)) {
    throw new Error('SOC_INVESTIGATION_REASSIGNMENT_NOT_READY');
  }
  if(!redis || typeof redis.eval !== 'function') {
    throw new Error('SOC_INVESTIGATION_ATOMIC_REDIS_NOT_AVAILABLE');
  }
  if(!investigation || !isValidObjectId(investigation.id) ||
     !isValidObjectId(investigation.assignee) ||
     !isValidObjectId(updates?.assignee) ||
     !Number.isSafeInteger(investigation.version) || investigation.version < 1 ||
     !['open','in_progress','pending_review'].includes(investigation.status)) {
    throw new Error('SOC_INVESTIGATION_INVALID_REASSIGNMENT');
  }
  if(updates.assignee === investigation.assignee) {
    throw new Error('SOC_INVESTIGATION_REASSIGNMENT_NOT_CHANGED');
  }
  const hasTitle=updates.title!==undefined,hasDescription=updates.description!==undefined;
  if((hasTitle && (typeof updates.title !== 'string' || updates.title.length > 4096)) ||
     (hasDescription && (typeof updates.description !== 'string' || updates.description.length > 16384))) {
    throw new Error('SOC_INVESTIGATION_REASSIGNMENT_INVALID_METADATA');
  }
  if(!(now instanceof Date) || !Number.isFinite(now.getTime())) {
    throw new Error('SOC_INVESTIGATION_REASSIGNMENT_INVALID_TIME');
  }
  const nowIso=now.toISOString();
  const version=investigation.version+1;
  const audit=JSON.stringify({
    action:'REASSIGN', actor:caller.id,
    metadata:{from:investigation.assignee,to:updates.assignee},
    timestamp:nowIso, version
  });
  const keys=[
    'investigation:'+investigation.id,
    'investigations:assigned:'+investigation.assignee,
    'investigations:assigned:'+updates.assignee,
    'investigation:audit:'+investigation.id
  ];
  const args=[
    investigation.assignee,updates.assignee,
    String(investigation.version),investigation.status,
    nowIso,String(version),investigation.id,String(now.getTime()),
    hasTitle?'1':'0',hasTitle?updates.title:'',
    audit,hasDescription?'1':'0',hasDescription?updates.description:''
  ];
  const result=await redis.eval(REASSIGN_SCRIPT,keys,args);
  if(!Array.isArray(result) || result[0]!=='OK' ||
     String(result[1])!==String(version)) {
    throw new Error('SOC_INVESTIGATION_ATOMIC_REASSIGNMENT_NOT_COMMITTED');
  }
  return {...investigation,
    assignee:updates.assignee,
    ...(hasTitle?{title:updates.title}:{}),
    ...(hasDescription?{description:updates.description}:{}),
    updatedAt:nowIso,version
  };
}
module.exports={atomicReassign,REASSIGN_SCRIPT};
