/** Independent Node.js group update canonical SHA256 for AUD-23 vectors. */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { canonical } from './canonical.mjs';

const domain = {
  members: 'E2EESA-GROUP-MEMBERS-v1',
  receipt: 'E2EESA-GROUP-APPLIED-COMMIT-v1',
};
const kind = process.argv[2];
if (!(kind in domain)) throw Error('unsupported group update vector kind');
const data = JSON.parse(readFileSync(0, 'utf8'));
let selected;
if (kind === 'members') {
  if (!Array.isArray(data) || data.length===0 ||
      !data.every(x=>typeof x==='string' && /^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(x)) ||
      new Set(data).size!==data.length)
    throw Error('malformed membership vector');
  selected = [...data].sort();
} else {
  if (!data || Array.isArray(data) || typeof data!=='object' ||
      typeof data.commit_digest!=='string' || Object.keys(data).length!==14)
    throw Error('malformed applied update receipt');
  const {commit_digest,...rest}=data;
  selected = rest;
}
const digest = createHash('sha256').update(domain[kind], 'utf8')
  .update(Buffer.from([0])).update(canonical(selected),'utf8').digest('hex');
process.stdout.write('sha256:'+digest+'\n');
