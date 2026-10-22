'use strict';
const {createSocEvidenceReadBudget,ADMIT_SQL}=require('../soc-evidence-read-budget');
const BASE={tenantId:'acme',connectorId:'siem',sourceEventId:'source-20261022-001'};
const NOW=Date.parse('2026-10-22T10:02:00.000Z');

function fixture({perWindow=2,active=true,crash=false,now=()=>NOW}={}){
  const counters=new Map(),calls=[];
  const first=jest.fn(async function(){
    if(crash)throw Error('sensitive D1 error: credentials were leaked');
    const [start,seconds,tenant,connector,limit]=calls.at(-1).params;
    if(!active || tenant!=='acme'||connector!=='siem')return null;
    const id=JSON.stringify([tenant,connector,start]);
    const used=counters.get(id)||0;
    if(used>=limit)return null;
    counters.set(id,used+1);
    return {consumed:used+1};
  });
  const nativeD1={withSession:jest.fn(mode=>{
    if(mode!=='first-primary')throw Error('stale D1 session forbidden');
    return {
      prepare:jest.fn(sql=>{
        return {bind:(...params)=>{
          calls.push({sql,params});return {first};
        }};
      }),
    };
  })};
  const budget=createSocEvidenceReadBudget({
    nativeD1,limitPerWindow:perWindow,now,
  });
  return {budget,counters,calls,nativeD1,first};
}

describe('SENTINEL APEX durable D1 evidence source-read quota',()=>{
  test('configuration must have authoritative primary database and bounded quota',()=>{
    expect(()=>createSocEvidenceReadBudget()).toThrow('SOURCE_BUDGET_NOT_CONFIGURED');
    expect(()=>createSocEvidenceReadBudget({
      nativeD1:{withSession:()=>{}},limitPerWindow:0,
    })).toThrow('SOURCE_BUDGET_NOT_CONFIGURED');
    expect(()=>createSocEvidenceReadBudget({
      nativeD1:{withSession:()=>{}},limitPerWindow:61,
    })).toThrow('SOURCE_BUDGET_NOT_CONFIGURED');
  });
  test('returns safe remaining quota and denies third request in the same window',async()=>{
    const h=fixture();
    const a=await h.budget.admitRead(BASE);
    expect(a).toEqual({
      admitted:true,windowStartEpoch:Math.floor(NOW/300000)*300,
      remaining:1,
    });
    const b=await h.budget.admitRead(BASE);
    expect(b.remaining).toBe(0);
    await expect(h.budget.admitRead(BASE))
      .rejects.toMatchObject({code:'SOURCE_BUDGET_DENIED'});
    expect(h.calls).toHaveLength(3);
    expect(h.calls[0].sql).toBe(ADMIT_SQL);
    expect(h.nativeD1.withSession).toHaveBeenCalledWith('first-primary');
    expect(h.calls[0].params).toEqual([
      Math.floor(NOW/300000)*300,
      Math.floor(NOW/1000),'acme','siem',2,
    ]);
  });
  test('new five-minute window receives fresh quota, older window retained',async()=>{
    let now=NOW;
    const h=fixture({perWindow:1,now:()=>now});
    await h.budget.admitRead(BASE);
    await expect(h.budget.admitRead(BASE))
      .rejects.toMatchObject({code:'SOURCE_BUDGET_DENIED'});
    now+=300000;
    expect((await h.budget.admitRead(BASE)).remaining).toBe(0);
    expect(h.counters.size).toBe(2);
  });
  test('disabled connector and missing scope deny source read',async()=>{
    const h=fixture({active:false});
    await expect(h.budget.admitRead(BASE))
      .rejects.toMatchObject({code:'SOURCE_BUDGET_DENIED'});
    expect(h.counters.size).toBe(0);
  });
  test('invalid tenant, event paths and connector IDs fail before D1 access',async()=>{
    const h=fixture();
    for(const bad of [
      {...BASE,tenantId:'../acme'},
      {...BASE,connectorId:'..\\siem'},
      {...BASE,sourceEventId:'https://evil.example/event'},
      {...BASE,sourceEventId:'../../secrets'},
      {...BASE,sourceEventId:''},
    ])await expect(h.budget.admitRead(bad)).rejects.toMatchObject({
      code:'SOURCE_BUDGET_SCOPE_INVALID',
    });
    expect(h.nativeD1.withSession).not.toHaveBeenCalled();
  });
  test('D1 outage never becomes success or reveals backend details',async()=>{
    const h=fixture({crash:true});
    let error;
    try{await h.budget.admitRead(BASE);}catch(e){error=e;}
    expect(error.code).toBe('SOURCE_BUDGET_UNAVAILABLE');
    expect(error.message).not.toContain('credentials');
  });
  test('clock invalidity never creates an accounting entry',async()=>{
    const h=fixture({now:()=>NaN});
    await expect(h.budget.admitRead(BASE))
      .rejects.toMatchObject({code:'SOURCE_BUDGET_CLOCK_UNAVAILABLE'});
    expect(h.nativeD1.withSession).not.toHaveBeenCalled();
  });
  test('returned quota grant is frozen and contains no event, key or tenant secret',async()=>{
    const h=fixture();
    const x=await h.budget.admitRead(BASE);
    expect(Object.isFrozen(x)).toBe(true);
    expect(Object.keys(x)).toEqual(['admitted','windowStartEpoch','remaining']);
    expect(JSON.stringify(x)).not.toContain(BASE.sourceEventId);
  });
  test('atomic D1 expression is a single SELECT guarded UPSERT with RETURNING',()=>{
    expect(ADMIT_SQL).toMatch(/INSERT INTO soc_evidence_read_windows/);
    expect(ADMIT_SQL).toMatch(/ON CONFLICT\(tenant_id,connector_id,window_start_epoch\)/);
    expect(ADMIT_SQL).toMatch(/c\.state='APPROVED'/);
    expect(ADMIT_SQL).toMatch(/t\.status='ACTIVE'/);
    expect(ADMIT_SQL).toMatch(/RETURNING consumed/);
    expect(ADMIT_SQL).not.toMatch(/DELETE FROM|INSERT OR REPLACE|SELECT \*/);
  });
});
