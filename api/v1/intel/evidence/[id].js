'use strict';

const { authenticate } = require('../../../_lib/middleware');
const service = require('../../../_lib/premium-commerce-service');
const sec = require('../../../_lib/security');

function fail(res,status,code,message){
  sec.applySecurityHeaders(res);
  res.setHeader('Cache-Control','private, no-store, max-age=0');
  return res.status(status).json({success:false,error:{code,message},meta:{platform:'CYBERDUDEBIVASH SENTINEL APEX v4.0',timestamp:new Date().toISOString()}});
}
function reportId(req){
  const raw=String((req.query&&req.query.id)||'').trim();
  return /^[A-Za-z0-9][A-Za-z0-9._:-]{0,179}$/.test(raw)?raw:null;
}
module.exports=async function evidence(req,res){
  const guarded=await sec.guardRequest(req,res,{allowedMethods:['GET','OPTIONS'],maxBodyBytes:0});
  if(!guarded)return;
  if(req.method==='OPTIONS')return res.status(204).end();
  if(!(await sec.globalIpRateLimit(req,res)))return;
  const user=await authenticate(req,res);if(!user)return;
  const id=reportId(req);if(!id)return fail(res,400,'INVALID_REPORT_ID','A valid report ID is required.');
  try{
    const evidence=await service.getEvidenceContract({user,reportId:id});
    sec.applySecurityHeaders(res);
    res.setHeader('Cache-Control','private, no-store, max-age=0');
    res.setHeader('Content-Type','application/json; charset=utf-8');
    return res.status(200).json({success:true,data:{evidence},meta:{platform:'CYBERDUDEBIVASH SENTINEL APEX v4.0',timestamp:new Date().toISOString()}});
  }catch(err){
    if(err&&err.code==='ENTITLEMENT_NOT_FOUND')return fail(res,404,'REPORT_NOT_FOUND','Report not found.');
    if(err&&['EVIDENCE_UNAVAILABLE','EVIDENCE_INTEGRITY_ERROR','EVIDENCE_INVALID','EVIDENCE_CERTIFICATION_INVALID'].includes(err.code))return fail(res,503,'EVIDENCE_UNAVAILABLE','Canonical evidence is temporarily unavailable.');
    return fail(res,503,'EVIDENCE_UNAVAILABLE','Canonical evidence is temporarily unavailable.');
  }
};