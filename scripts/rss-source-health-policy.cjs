#!/usr/bin/env node
'use strict';
/** Offline RSS transport/document validity, not report publication proof. */
const VERIFIED_RSS_URLS=Object.freeze({
  talos:'https://blog.talosintelligence.com/rss/',
  rapid7:'https://www.rapid7.com/blog/rss/'
});
const TERMINAL=new Set([400,401,403,404,405,410,422,429]);
function mayRetry(e){
  const m=/^HTTP (\d{3})\b/.exec(String(e?.message||e||''));
  return !m||!TERMINAL.has(Number(m[1]));
}
function verifyRssPayload(raw,parsed){
  if(typeof raw!=='string'||!raw.length||raw.length>8*1024*1024)throw Error('RSS_PAYLOAD_MISSING_OR_OVERSIZED');
  if(!/<(?:rss|feed|rdf:RDF)(?:\s|>)/i.test(raw) || /<html(?:\s|>)/i.test(raw.slice(0,1000)))
    throw Error('RSS_ROOT_INVALID');
  if(!Array.isArray(parsed))throw Error('RSS_PARSER_RESULT_INVALID');
  if(parsed.length===0&&/<(?:item|entry)(?:\s|>)/i.test(raw))throw Error('RSS_ENTRIES_UNPARSEABLE');
  return parsed;
}
module.exports={VERIFIED_RSS_URLS,mayRetry,verifyRssPayload};
