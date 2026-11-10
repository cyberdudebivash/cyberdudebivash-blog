'use strict';
/**
 * P0 SOC: atomic investigation creation with complete worklist indexes.
 *
 * Redis Lua is atomic against other Redis commands, but it does NOT roll back
 * writes on script runtime errors. Preflight record and every index type,
 * validate JS arguments and keep the mutation sequence deterministic.
 *
 * This fixes split HSET/EXPIRE/ZADD audit writes for a single creation attempt.
 * It does not claim exactly-once HTTP retries or certify customer tenancy.
 */
const {isValidObjectId}=require('./workbench-object-scope');

const CREATE_SCRIPT=[
  "if redis.call('TYPE',KEYS[1]).ok~='none' then return {'HOLD_RECORD_EXISTS'} end",
  "for i=2,6 do local t=redis.call('TYPE',KEYS[i]).ok",
  " if t~='none' and t~='zset' then return {'HOLD_INDEX_TYPE'} end end",
  "local fields=cjson.decode(ARGV[1])",
  "if type(fields)~='table' or #fields==0 or (#fields%2)~=0 then return {'HOLD_INVALID_FIELDS'} end",
  "redis.call('HSET',KEYS[1],unpack(fields))",
  "redis.call('EXPIRE',KEYS[1],31536000)",
  "redis.call('ZADD',KEYS[2],ARGV[2],ARGV[3])",
  "redis.call('ZADD',KEYS[3],ARGV[2],ARGV[3])",
  "redis.call('ZADD',KEYS[4],ARGV[2],ARGV[3])",
  "if ARGV[5]=='1' then redis.call('ZADD',KEYS[5],ARGV[2],ARGV[3]) end",
  "redis.call('ZADD',KEYS[6],ARGV[2],ARGV[4])",
  "return {'OK',ARGV[3]}"
].join('\n');

async function atomicCreateInvestigation({redis,investigation,now=new Date()}={}){
  if(!redis || typeof redis.eval!=='function'){
    throw new Error('SOC_INVESTIGATION_CREATE_ATOMIC_REDIS_UNAVAILABLE');
  }
  const x=investigation;
  if(!x || typeof x!=='object' ||
     typeof x.id!=='string' || !/^[0-9a-f]{32}$/.test(x.id) ||
     typeof x.title!=='string' || !x.title.trim() || x.title.length>4096 ||
     typeof x.description!=='string' || x.description.length>16384 ||
     !Number.isSafeInteger(x.priority) || x.priority<1 || x.priority>5 ||
     x.status!=='open' ||
     !isValidObjectId(x.assignee) || !isValidObjectId(x.createdBy) ||
     x.version!==1 || x.caseCount!==0 || x.evidenceCount!==0 || x.noteCount!==0 ||
     typeof x.createdAt!=='string' || typeof x.updatedAt!=='string' ||
     x.createdAt!==x.updatedAt ||
     typeof x.linkedIntelligence!=='string' ||
     typeof x.linkedEntities!=='string'){
    throw new Error('SOC_INVESTIGATION_CREATE_INVALID_RECORD');
  }
  let intel,entities;
  try{intel=JSON.parse(x.linkedIntelligence);entities=JSON.parse(x.linkedEntities);}
  catch{throw new Error('SOC_INVESTIGATION_CREATE_INVALID_LINKS');}
  if(!Array.isArray(intel) || intel.length>100 ||
     intel.some(id=>typeof id!=='string'||id.length>256||!id.trim()) ||
     !Array.isArray(entities) || entities.length!==0){
    throw new Error('SOC_INVESTIGATION_CREATE_INVALID_LINKS');
  }
  if(!(now instanceof Date) || !Number.isSafeInteger(now.getTime()) ||
     now.toISOString()!==x.createdAt){
    throw new Error('SOC_INVESTIGATION_CREATE_INVALID_CLOCK');
  }
  const fields=Object.entries(x).flatMap(([field,value])=>[field,String(value)]);
  const audit=JSON.stringify({
    action:'CREATE',actor:x.createdBy,
    metadata:{title:x.title,priority:x.priority,assignee:x.assignee},
    timestamp:x.createdAt,version:1
  });
  const keys=[
    'investigation:'+x.id,'investigations:all',
    'investigations:by:status:open',
    'investigations:by:priority:'+x.priority,
    'investigations:assigned:'+x.assignee,
    'investigation:audit:'+x.id
  ];
  const args=[
    JSON.stringify(fields),String(now.getTime()),x.id,audit,
    x.assignee==='unassigned'?'0':'1'
  ];
  // Do not retry an ambiguous transport/EVAL result: a second creation
  // would use a different random ID and could duplicate a customer case.
  const result=await redis.eval(CREATE_SCRIPT,keys,args);
  if(!Array.isArray(result)||result[0]!=='OK'||result[1]!==x.id){
    throw new Error('SOC_INVESTIGATION_CREATE_NOT_COMMITTED');
  }
  return x;
}
module.exports={atomicCreateInvestigation,CREATE_SCRIPT};
