/** Independent ECMAScript implementation of the restricted canonical/input model. */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
export function canonical(value) {
  if (value===null) return 'null';
  if (typeof value==='boolean') return value?'true':'false';
  if (typeof value==='number') { if (!Number.isSafeInteger(value)) throw Error('unsafe/nonintegral number'); return String(value); }
  if (typeof value==='string') { for (const ch of value) if(ch.length===1 && ch.charCodeAt(0)>=0xd800 && ch.charCodeAt(0)<=0xdfff)throw Error('lone surrogate'); return JSON.stringify(value); }
  if (Array.isArray(value)) return '['+value.map(canonical).join(',')+']';
  if (typeof value==='object') return '{'+Object.keys(value).sort().map(key=>canonical(key)+':'+canonical(value[key])).join(',')+'}';
  throw Error('unsupported type');
}
export function input(contractId,payload,registry,options={}) {
  const contract=registry.contracts.find(x=>x.contract_id===contractId);if(!contract)throw Error('unknown contract');
  const allowed=new Set([...contract.included_fields,...contract.excluded_fields]);
  if(Object.keys(payload).some(x=>!allowed.has(x)) || contract.required_fields.some(x=>!(x in payload)) || payload.schema_version!==contract.payload_schema_version)throw Error('contract shape');
  const purpose=options.purpose||'digest';if(!['digest','signature'].includes(purpose))throw Error('purpose');
  const algorithm=options.signature_algorithm||null, profile=options.profile_ref||null;
  if(purpose==='signature' && (!algorithm || !profile || !profile.includes('@')))throw Error('signature context');
  if(purpose==='digest' && (algorithm || profile))throw Error('signature metadata in digest context');
  const header={contract_id:contractId,contract_version:'1.0.0',serialization_scheme:'e2eesa-jcs-integer-v1',digest_scheme:'e2eesa-sha256-domain-v1',purpose,signature_algorithm:algorithm,profile_ref:profile};
  const selected=Object.fromEntries(contract.included_fields.filter(x=>x in payload).map(x=>[x,payload[x]]));
  return Buffer.concat([Buffer.from('E2EESA\0'),Buffer.from(canonical(header)),Buffer.from([0]),Buffer.from(canonical(selected))]);
}
if (process.argv[2]) {
  const value=JSON.parse(readFileSync(0,'utf8'));
  if(process.argv[2]==='canonical')process.stdout.write(Buffer.from(canonical(value)).toString('hex'));
  else {const registry=JSON.parse(readFileSync(process.argv[2],'utf8'));process.stdout.write(input(value.contract_id,value.payload,registry,value.options).toString('hex'));}
}
