'use strict';

/**
 * SOURCE ONLY — authoritative per-tenant/connector evidence-read admission.
 *
 * A primary-consistent D1 session runs ONE conditional UPSERT SELECT RETURNING
 * statement per attempted source read. No in-process counters, replicas, KV
 * or read-then-write races. The statement checks both ACTIVE tenant and
 * APPROVED connector and atomically rejects an exceeded fixed-window budget.
 *
 * This gate limits provider/network reads, NOT user-facing HTTP requests.
 * It must run AFTER revocation-aware analyst authorization and BEFORE
 * resolving a provider token or making an outbound request.
 */
const TENANT=/^[a-z0-9_-]{3,64}$/;
const CONNECTOR=/^[A-Za-z0-9_.:-]{1,128}$/;
const SOURCE=/^[A-Za-z0-9_.:-]{1,128}$/;
const WINDOW_SECONDS=300;

const ADMIT_SQL=[
  'INSERT INTO soc_evidence_read_windows',
  '(tenant_id,connector_id,window_start_epoch,consumed,last_admitted_epoch)',
  'SELECT c.tenant_id,c.connector_id,?,1,?',
  'FROM soc_connectors c',
  'JOIN soc_tenants t ON t.tenant_id=c.tenant_id',
  'WHERE c.tenant_id=? AND c.connector_id=?',
  "AND c.state='APPROVED' AND t.status='ACTIVE'",
  'ON CONFLICT(tenant_id,connector_id,window_start_epoch)',
  'DO UPDATE SET consumed=soc_evidence_read_windows.consumed+1,',
  'last_admitted_epoch=excluded.last_admitted_epoch',
  'WHERE soc_evidence_read_windows.consumed < ?',
  'RETURNING consumed',
].join(' ');

class SocEvidenceReadBudgetError extends Error {
  constructor(code) {super(code);this.name='SocEvidenceReadBudgetError';this.code=code;}
}
function deny(code){throw new SocEvidenceReadBudgetError(code);}

function createSocEvidenceReadBudget({
  nativeD1,now=()=>Date.now(),limitPerWindow=12,
}={}) {
  if(!nativeD1||typeof nativeD1.withSession!=='function'||
      typeof now!=='function'||
      !Number.isSafeInteger(limitPerWindow)||
      limitPerWindow<1||limitPerWindow>60)
    deny('SOURCE_BUDGET_NOT_CONFIGURED');

  async function admitRead({tenantId,connectorId,sourceEventId}={}) {
    if(typeof tenantId!=='string'||!TENANT.test(tenantId)||
       typeof connectorId!=='string'||!CONNECTOR.test(connectorId)||
       typeof sourceEventId!=='string'||!SOURCE.test(sourceEventId))
      deny('SOURCE_BUDGET_SCOPE_INVALID');

    const seconds=Math.floor(now()/1000);
    if(!Number.isSafeInteger(seconds)||seconds<0)
      deny('SOURCE_BUDGET_CLOCK_UNAVAILABLE');
    const start=Math.floor(seconds/WINDOW_SECONDS)*WINDOW_SECONDS;
    let session;
    try{session=nativeD1.withSession('first-primary');}
    catch(_){deny('SOURCE_BUDGET_UNAVAILABLE');}
    if(!session||typeof session.prepare!=='function')
      deny('SOURCE_BUDGET_UNAVAILABLE');

    let row;
    try{row=await session.prepare(ADMIT_SQL)
      .bind(start,seconds,tenantId,connectorId,limitPerWindow).first();}
    catch(_){deny('SOURCE_BUDGET_UNAVAILABLE');}
    if(!row)deny('SOURCE_BUDGET_DENIED');
    const used=Number(row.consumed);
    if(!Number.isSafeInteger(used)||used<1||used>limitPerWindow)
      deny('SOURCE_BUDGET_UNAVAILABLE');
    return Object.freeze({
      admitted:true,windowStartEpoch:start,
      remaining:limitPerWindow-used,
    });
  }

  return Object.freeze({admitRead});
}
module.exports={createSocEvidenceReadBudget,SocEvidenceReadBudgetError,ADMIT_SQL};
