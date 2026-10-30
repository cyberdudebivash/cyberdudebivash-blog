'use strict';

jest.mock('../d1', () => ({query: jest.fn(), run: jest.fn(), runMutationWithChanges: jest.fn()}));
const {createSocIncidentService,SocServiceError} = require('../soc-incident-service');

const UUID = '00000000-0000-4000-8000-000000000001';
const ID = 'inc_' + UUID;
const TIME = '2026-10-21T15:00:00Z';
const REQUEST = 'req-1234567890123456';

function harness({
  role = 'ANALYST',
  member = true,
  identity = {verified:true,issuer:'https://idp.example',subject:'analyst-sub'},
} = {}) {
  const row = {
    tenant_id:'acme',incident_id:ID,title:'Real investigation',severity:'HIGH',
    state:'TRIAGE',owner_id:'analyst',version:2,created_at:TIME,updated_at:TIME,
    audit_actor_id:'internal',audit_request_id:'secret',
  };
  const db = {
    query:jest.fn(async (sql,params) => {
      if (sql.includes('FROM soc_principals')) {
        // The actual owner query must not confuse existence/foreign tenancy
        // with ACTIVE, write-capable membership in the requested tenant.
        if (sql.includes('WHERE tenant_id=? AND principal_id=?')) {
          if (params[0] !== 'acme') return [];
          if (params[1] === 'analyst' || params[1] === 'lead-active')
            return [{principal_id:params[1]}];
          return []; // revoked, read-only, foreign, unknown
        }
        return member ? [{tenant_id:params[0],principal_id:'analyst',role}] : [];
      }
      if (sql.includes('FROM soc_incidents')) {
        if (sql.includes('incident_id=?')) return params[0] === 'acme' ? [row] : [];
        return params[0] === 'acme' ? [row] : [];
      }
      throw Error('Unexpected query');
    }),
    run:jest.fn(async () => ({success:true})),
    runMutationWithChanges:jest.fn(async () => 1),
  };
  const verifyIdentity=jest.fn(async () => identity);
  const service = createSocIncidentService({
    db,verifyIdentity,now:()=>TIME,randomUUID:()=>UUID,
  });
  return {service,db,verifyIdentity,row};
}

const ctx = {accessToken:'opaque-verified-by-external-adapter',tenantId:'acme'};

describe('SOC incident service: identity and tenant authorization',() => {
  test('cannot initialize without a verified identity adapter',() => {
    expect(() => createSocIncidentService({db:{}})).toThrow('OIDC_VERIFIER_REQUIRED');
  });
  test('denies unverified claims before reading D1',async () => {
    const {service,db}=harness({identity:{issuer:'https://idp.example',subject:'analyst-sub'}});
    await expect(service.list(ctx)).rejects.toMatchObject({code:'UNAUTHENTICATED',status:401});
    expect(db.query).not.toHaveBeenCalled();
  });
  test('rejects invalid access token when verifier throws',async () => {
    const t=harness();
    t.verifyIdentity.mockRejectedValue(new Error('bad signature'));
    await expect(t.service.get({...ctx,id:ID})).rejects.toMatchObject({code:'UNAUTHENTICATED'});
    expect(t.db.query).not.toHaveBeenCalled();
  });
  test('rejects missing membership even if token claims are marked verified',async () => {
    const {service,db}=harness({member:false});
    await expect(service.get({...ctx,id:ID})).rejects.toMatchObject({code:'FORBIDDEN',status:403});
    expect(db.query).toHaveBeenCalledTimes(1);
  });
  test('never trusts a caller role and uses D1 membership role',async () => {
    const t=harness({role:'READ_ONLY'});
    await expect(t.service.create({...ctx,requestId:REQUEST,input:{title:'New',severity:'HIGH',role:'ADMIN'}}))
      .rejects.toMatchObject({code:'FORBIDDEN'});
    await expect(t.service.update({...ctx,id:ID,expectedVersion:2,requestId:REQUEST,changes:{state:'INVESTIGATING'}}))
      .rejects.toMatchObject({code:'FORBIDDEN'});
    expect(t.db.run).not.toHaveBeenCalled();
    expect(t.db.runMutationWithChanges).not.toHaveBeenCalled();
  });
  test('tenant identity and D1 membership are checked on every request',async () => {
    const t=harness();
    await t.service.get({...ctx,id:ID});
    await t.service.list(ctx);
    expect(t.db.query.mock.calls.filter(([sql])=>sql.includes('FROM soc_principals'))).toHaveLength(2);
  });
  test('requires canonical tenant ID',async () => {
    const t=harness();
    await expect(t.service.list({...ctx,tenantId:'../contoso'})).rejects.toMatchObject({code:'INVALID_TENANT'});
    expect(t.db.query).not.toHaveBeenCalled();
  });
  test('foreign tenant object returns NOT_FOUND, never an object from a global index',async () => {
    const t=harness();
    await expect(t.service.get({...ctx,tenantId:'contoso',id:ID}))
      .rejects.toMatchObject({code:'NOT_FOUND',status:404});
    const [sql,params]=t.db.query.mock.calls.at(-1);
    expect(sql).toMatch(/WHERE tenant_id=\? AND incident_id=\?/);
    expect(params).toEqual(['contoso',ID]);
  });
});

describe('SOC incident service: bounded query and mutation contract',() => {
  test('read projections exclude internal audit request and actor',async () => {
    const t=harness();
    const item=await t.service.get({...ctx,id:ID});
    expect(item).toMatchObject({tenantId:'acme',incidentId:ID,title:'Real investigation',version:2});
    expect(JSON.stringify(item)).not.toContain('internal');
    expect(JSON.stringify(item)).not.toContain('secret');
  });
  test('all list queries have a tenant predicate and bounded limit',async () => {
    const t=harness();
    const results=await t.service.list({...ctx,limit:20,state:'TRIAGE'});
    expect(results).toHaveLength(1);
    const [sql,params]=t.db.query.mock.calls.at(-1);
    expect(sql).toMatch(/WHERE tenant_id=\? AND state=\?/);
    expect(params).toEqual(['acme','TRIAGE',20]);
    await expect(t.service.list({...ctx,limit:5000})).rejects.toMatchObject({code:'INVALID_PAGE_LIMIT'});
  });
  test('create generates server-owned incident ID and audit actor',async () => {
    const t=harness();
    const result=await t.service.create({...ctx,requestId:REQUEST,input:{title:'Real event',severity:'HIGH'}});
    expect(result.incidentId).toBe(ID);
    const [sql,params]=t.db.runMutationWithChanges.mock.calls[0];
    expect(sql).toContain('audit_actor_id');
    expect(sql).toContain('audit_request_id');
    expect(params).toEqual(['acme',ID,'Real event','HIGH',null,'analyst',REQUEST,TIME,TIME,null,'acme',null]);
  });
  test('extra mutation fields and injected tenant/actor are rejected',async () => {
    const t=harness();
    await expect(t.service.create({...ctx,requestId:REQUEST,input:{title:'Real',severity:'HIGH',tenantId:'contoso'}}))
      .rejects.toMatchObject({code:'UNEXPECTED_INPUT'});
    await expect(t.service.update({...ctx,id:ID,expectedVersion:2,requestId:REQUEST,changes:{actor:'admin'}}))
      .rejects.toMatchObject({code:'UNEXPECTED_INPUT'});
    expect(t.db.run).not.toHaveBeenCalled();
  });
  test('update uses tenant+ID+expectedVersion and DB actor',async () => {
    const t=harness();
    const result=await t.service.update({...ctx,id:ID,expectedVersion:2,requestId:REQUEST,changes:{state:'INVESTIGATING'}});
    expect(result.incidentId).toBe(ID);
    const [sql,params]=t.db.runMutationWithChanges.mock.calls[0];
    expect(sql).toMatch(/WHERE tenant_id=\? AND incident_id=\? AND version=\?/);
    expect(params.slice(-3)).toEqual(['acme',ID,2]);
    expect(params.slice(0,4)).toEqual(['Real investigation','HIGH','INVESTIGATING','analyst']);
    expect(params[5]).toBe('analyst');
  });
  test('stale version and database write failures stop mutation',async () => {
    const t=harness();
    await expect(t.service.update({...ctx,id:ID,expectedVersion:1,requestId:REQUEST,changes:{state:'INVESTIGATING'}}))
      .rejects.toMatchObject({code:'VERSION_CONFLICT',status:409});
    t.db.runMutationWithChanges.mockRejectedValue(new Error('tenant FK violation secret'));
    await expect(t.service.update({...ctx,id:ID,expectedVersion:2,requestId:REQUEST,changes:{state:'INVESTIGATING'}}))
      .rejects.toMatchObject({code:'INCIDENT_WRITE_REJECTED',status:409});
  });
  test('rejects malformed request ID before sending write',async () => {
    const t=harness();
    await expect(t.service.create({...ctx,requestId:'bad',input:{title:'Real',severity:'HIGH'}}))
      .rejects.toMatchObject({code:'INVALID_REQUEST_ID'});
    expect(t.db.run).not.toHaveBeenCalled();
  });
  test('does not mistake write affected=0 for success',async () => {
    const t=harness();
    t.db.runMutationWithChanges.mockResolvedValue(0);
    await expect(t.service.update({...ctx,id:ID,expectedVersion:2,requestId:REQUEST,changes:{state:'INVESTIGATING'}}))
      .rejects.toMatchObject({code:'VERSION_CONFLICT'});
  });
});

describe('P0: server-side SOC incident owner assignment tenant and lifecycle gate',() => {
  test('creation permits an explicitly ACTIVE same-tenant analyst and checks D1 before writing',async () => {
    const t=harness();
    await t.service.create({...ctx,requestId:REQUEST,input:{
      title:'Customer-originated signal',severity:'HIGH',ownerId:'lead-active',
    }});
    expect(t.db.query.mock.calls.some(([sql,params]) =>
      sql.includes('FROM soc_principals') && sql.includes('principal_id=?') &&
      params[0]==='acme' && params[1]==='lead-active')).toBe(true);
    expect(t.db.runMutationWithChanges).toHaveBeenCalledTimes(1);
    expect(t.db.runMutationWithChanges.mock.calls[0][1][5]).toBe('analyst');
  });

  test.each(['foreign-tenant-owner','revoked-owner','invited-owner','read-only-owner','unknown'])
    ('creation rejects %s before any incident write',async ownerId => {
      const t=harness();
      await expect(t.service.create({...ctx,requestId:REQUEST,input:{
        title:'Sensitive customer incident',severity:'CRITICAL',ownerId,
      }})).rejects.toMatchObject({code:'INVALID_INCIDENT_OWNER',status:403});
      expect(t.db.run).not.toHaveBeenCalled();
      expect(t.db.runMutationWithChanges).not.toHaveBeenCalled();
    });

  test.each(['foreign-tenant-owner','revoked-owner','invited-owner','read-only-owner','unknown'])
    ('reassignment to %s is forbidden without mutating incident version or audit',async ownerId => {
      const t=harness();
      await expect(t.service.update({...ctx,id:ID,expectedVersion:2,
        requestId:REQUEST,changes:{ownerId}}))
        .rejects.toMatchObject({code:'INVALID_INCIDENT_OWNER',status:403});
      expect(t.db.runMutationWithChanges).not.toHaveBeenCalled();
    });

  test('reassignment to active same-tenant operator is authorized and tenant predicate remains',async () => {
    const t=harness();
    await t.service.update({...ctx,id:ID,expectedVersion:2,
      requestId:REQUEST,changes:{ownerId:'lead-active'}});
    const owner=t.db.query.mock.calls.find(([sql]) =>
      sql.includes('WHERE tenant_id=? AND principal_id=?'));
    expect(owner[1]).toEqual(['acme','lead-active']);
    expect(t.db.runMutationWithChanges).toHaveBeenCalledTimes(1);
    expect(t.db.runMutationWithChanges.mock.calls[0][1][3]).toBe('lead-active');
  });

  test('existing legitimate owner does not trigger an unnecessary owner-enumeration query',async () => {
    const t=harness();
    await t.service.update({...ctx,id:ID,expectedVersion:2,
      requestId:REQUEST,changes:{state:'INVESTIGATING'}});
    expect(t.db.query.mock.calls.filter(([sql]) =>
      sql.includes('WHERE tenant_id=? AND principal_id=?'))).toHaveLength(0);
    expect(t.db.runMutationWithChanges).toHaveBeenCalledTimes(1);
  });

  test('clearing an assignee is permitted; cross-tenant owner names are never returned',async () => {
    const t=harness();
    await t.service.update({...ctx,id:ID,expectedVersion:2,
      requestId:REQUEST,changes:{ownerId:null}});
    expect(t.db.runMutationWithChanges.mock.calls[0][1][3]).toBeNull();
  });

  test('principal lookup outage fails before mutation rather than pretending owner is eligible',async () => {
    const t=harness();
    const original=t.db.query.getMockImplementation();
    t.db.query.mockImplementation((sql,params)=>{
      if (sql.includes('WHERE tenant_id=? AND principal_id=?'))
        throw new Error('D1 permission or connection failure');
      return original(sql,params);
    });
    await expect(t.service.update({...ctx,id:ID,expectedVersion:2,
      requestId:REQUEST,changes:{ownerId:'lead-active'}})).rejects.toThrow();
    expect(t.db.runMutationWithChanges).not.toHaveBeenCalled();
  });
});

describe('P0 commit-time SOC assignee authorization: SQLite statement receipts', () => {
  test('INSERT is an atomic SELECT gated by a live principal and has exact tenant parameters',async () => {
    const t=harness();
    await t.service.create({...ctx,requestId:REQUEST,input:{
      title:'Investigate attempted compromise',severity:'HIGH',ownerId:'lead-active',
    }});
    const [sql,params]=t.db.runMutationWithChanges.mock.calls[0];
    expect(sql).toMatch(/INSERT INTO soc_incidents/);
    expect(sql).toMatch(/SELECT \?,\?,\?,\?,'OPEN'/);
    expect(sql).toMatch(/WHERE \? IS NULL OR EXISTS/);
    expect(sql).toMatch(/WHERE tenant_id=\? AND principal_id=\?/);
    expect(sql).toMatch(/status='ACTIVE'/);
    expect(sql).toMatch(/'ANALYST','LEAD_ANALYST','TENANT_ADMIN'/);
    expect(params.slice(-3)).toEqual(['lead-active','acme','lead-active']);
    expect(t.db.run).not.toHaveBeenCalled();
  });

  test('a revoked owner between preflight and INSERT cannot be reported as created',async () => {
    const t=harness();
    // Preflight's mocked principal lookup succeeds; commit-time SQL receipt
    // returns zero because a native DB would see the intervening revocation.
    t.db.runMutationWithChanges.mockResolvedValue(0);
    await expect(t.service.create({...ctx,requestId:REQUEST,input:{
      title:'Denied after revocation',severity:'HIGH',ownerId:'lead-active',
    }})).rejects.toMatchObject({code:'INCIDENT_WRITE_REJECTED',status:409});
    expect(t.db.runMutationWithChanges).toHaveBeenCalledTimes(1);
    expect(t.db.run).not.toHaveBeenCalled();
  });

  test('a revoked owner between preflight and UPDATE cannot receive the incident',async () => {
    const t=harness();
    t.db.runMutationWithChanges.mockResolvedValue(0);
    await expect(t.service.update({...ctx,id:ID,expectedVersion:2,
      requestId:REQUEST,changes:{ownerId:'lead-active'}}))
      .rejects.toMatchObject({code:'VERSION_CONFLICT',status:409});
    const [sql,params]=t.db.runMutationWithChanges.mock.calls[0];
    expect(sql).toMatch(/WHERE tenant_id=\? AND incident_id=\? AND version=\?/);
    expect(sql).toMatch(/AND EXISTS \(SELECT 1 FROM soc_principals/);
    expect(sql).toMatch(/status='ACTIVE'/);
    expect(params.slice(-5)).toEqual(['acme',ID,2,'acme','lead-active']);
  });

  test('unassigned and unchanged-owner edits remain available without reassigning revoked legacy principals',async () => {
    const t=harness();
    await t.service.create({...ctx,requestId:REQUEST,input:{
      title:'No owner yet',severity:'MEDIUM',
    }});
    expect(t.db.runMutationWithChanges.mock.calls[0][1].slice(-3))
      .toEqual([null,'acme',null]);
    t.db.runMutationWithChanges.mockClear();
    await t.service.update({...ctx,id:ID,expectedVersion:2,
      requestId:REQUEST,changes:{state:'INVESTIGATING'}});
    const [sql,params]=t.db.runMutationWithChanges.mock.calls[0];
    expect(sql).not.toMatch(/AND EXISTS \(SELECT 1 FROM soc_principals/);
    expect(params.slice(-3)).toEqual(['acme',ID,2]);
  });

  test('native DB adapter rejection prevents a false successful incident receipt',async () => {
    const t=harness();
    t.db.runMutationWithChanges.mockRejectedValue(new Error('D1_WRITE_UNAVAILABLE'));
    await expect(t.service.create({...ctx,requestId:REQUEST,input:{
      title:'Unaudited incident must not exist',severity:'CRITICAL',ownerId:'lead-active',
    }})).rejects.toMatchObject({code:'INCIDENT_WRITE_REJECTED',status:409});
  });
});
