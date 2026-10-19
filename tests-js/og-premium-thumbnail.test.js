'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const crypto=require('node:crypto');
const ROOT=path.resolve(__dirname,'..');
const ASSETS=[
  {
    file:'og-sentinel-apex-threat-intel-v1.jpg',
    sha256:'6ada2be0740ecc1336ab966103cb140039bf7370c32f9e6c80d390c88698b073',
  },{
    file:'og-sentinel-apex-intel-factory-v1.jpg',
    sha256:'73f095f7cbd8dfdc2cea9e162141c1aa816d047e902b388c2b3a6a9fed170b2a',
  },
];
// Decode JPEG dimensions from SOF; no paid image dependency or build IO.
function jpegSize(bytes){
  if(bytes.length<4||bytes[0]!==0xff||bytes[1]!==0xd8)throw Error('Not JPEG');
  let i=2;
  while(i+8<bytes.length){
    while(bytes[i]===0xff)i++;
    const marker=bytes[i++];
    if(marker===0xd9||marker===0xda)break;
    if(i+2>bytes.length)break;
    const len=bytes.readUInt16BE(i);
    if(len<2||i+len>bytes.length)throw Error('Truncated JPEG');
    if([0xc0,0xc1,0xc2,0xc3,0xc5,0xc6,0xc7,0xc9,0xca,0xcb,0xcd,0xce,0xcf].includes(marker)){
      return {width:bytes.readUInt16BE(i+5),height:bytes.readUInt16BE(i+3)};
    }
    i+=len;
  }
  throw Error('Missing JPEG SOF');
}
test('approved CTI and Intel Factory social assets are present, exact and 1200x630',()=>{
  for(const asset of ASSETS){
    const file=path.join(ROOT,asset.file);
    assert.ok(fs.existsSync(file),'Missing approved binary image '+asset.file+'; run the asset-import PowerShell release script before review');
    const raw=fs.readFileSync(file);
    assert.deepEqual(jpegSize(raw),{width:1200,height:630});
    assert.equal(crypto.createHash('sha256').update(raw).digest('hex'),asset.sha256,'Wrong artwork or binary compression: '+asset.file);
    assert.ok(raw.length>=80000 && raw.length<800000,'Social-card JPG outside bounded web-size budget');
  }
});
test('Intel Factory home OG and Twitter point to the hosted Intel Factory asset',()=>{
  const html=fs.readFileSync(path.join(ROOT,'index.html'),'utf8');
  const url='https://blog.cyberdudebivash.in/og-sentinel-apex-intel-factory-v1.jpg';
  assert.ok(html.includes('<meta property="og:image" content="'+url+'">'));
  assert.ok(html.includes('<meta property="og:image:secure_url" content="'+url+'">'));
  assert.ok(html.includes('<meta name="twitter:image" content="'+url+'">'));
  assert.ok(html.includes('<meta name="twitter:card" content="summary_large_image">'));
  assert.ok(html.includes('<meta property="og:image:type" content="image/jpeg">'));
  assert.ok(html.includes('<meta property="og:image:width" content="1200">'));
  assert.ok(html.includes('<meta property="og:image:height" content="630">'));
});
test('new binaries are actually allowlisted for the asset build and deployment trigger',()=>{
  const script=fs.readFileSync(path.join(ROOT,'scripts/build-cloudflare-assets.js'),'utf8');
  const workflow=fs.readFileSync(path.join(ROOT,'.github/workflows/cloudflare-production-deploy.yml'),'utf8');
  for(const asset of ASSETS){
    assert.ok(script.includes("'"+asset.file+"'"));
    assert.ok(workflow.includes("'"+asset.file+"'"));
  }
});
