#!/usr/bin/env node
'use strict';
/**
 * Zero-I/O outcome classifier. Never interprets green queue processing as
 * proof of a delivered customer notification / end-to-end pilot canary.
 * Dead-letter and unresolved provider/D1 transitions require investigation.
 */
const MAX_PENDING_AGE_SEC=60*60;
const COUNTERS=Object.freeze([
  'records_processed','claimed','skipped_claimed_elsewhere','cancelled',
  'attempts','delivered','retried','dead_lettered','unresolved'
]);
function assessDeliveryHealth(result,oldestPendingAgeSeconds) {
  const errors=[];
  if(!result || typeof result!=='object'||Array.isArray(result)) {
    return {healthy:false,status:'MONITOR_ERROR',codes:['DELIVERY_COUNTERS_UNAVAILABLE'],customerReceiptVerified:false};
  }
  for(const key of COUNTERS) if(!Number.isSafeInteger(result[key])||result[key]<0)
    errors.push('COUNTER_INVALID_'+key.toUpperCase());
  if(oldestPendingAgeSeconds!==null&&
    (!Number.isSafeInteger(oldestPendingAgeSeconds)||oldestPendingAgeSeconds<0))
    errors.push('BACKLOG_AGE_INVALID');
  if(errors.length) return {healthy:false,status:'MONITOR_ERROR',codes:errors,customerReceiptVerified:false};
  // Every attempted delivery must have exactly one recorded disposition.
  // Under-counted outcomes are ambiguous, not successful processing.
  if(result.delivered+result.retried+result.dead_lettered+result.unresolved!==result.attempts)
    errors.push('DISPOSITION_TOTAL_MISMATCH');
  if(result.delivered>result.claimed||result.attempts>result.claimed)
    errors.push('IMPOSSIBLE_ATTEMPT_CLAIM_TOTAL');
  if(errors.length)return {healthy:false,status:'MONITOR_ERROR',codes:errors,customerReceiptVerified:false};
  if(result.dead_lettered>0)errors.push('DEAD_LETTERED_DELIVERIES');
  if(result.unresolved>0)errors.push('AMBIGUOUS_DELIVERY_STATE');
  if(oldestPendingAgeSeconds!==null&&oldestPendingAgeSeconds>MAX_PENDING_AGE_SEC)
    errors.push('PENDING_BACKLOG_OLDER_THAN_60_MIN');
  const noEligible=result.attempts===0;
  return {
    healthy:errors.length===0,status:errors.length?'DELIVERY_PROCESSING_DEGRADED':
      noEligible?'NO_ELIGIBLE_DELIVERIES':'PROCESSING_COMPLETED_NOT_CUSTOMER_CANARY',
    codes:errors,
    customerReceiptVerified:false,
    attempts:result.attempts,delivered:result.delivered,retried:result.retried,
    deadLettered:result.dead_lettered,unresolved:result.unresolved,
    oldestPendingAgeSeconds
  };
}
module.exports={assessDeliveryHealth,MAX_PENDING_AGE_SEC,COUNTERS};
