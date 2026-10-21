// Exercises the pure helpers embedded in FileVault.html.
// Run from the repo root: node tests/page_logic_test.mjs
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const html = readFileSync(join(root, 'FileVault.html'), 'utf8');
const match = html.match(/\/\/ BEGIN TESTABLE\n([\s\S]*?)\/\/ END TESTABLE/);
if (!match) {
  console.error('FileVault.html is missing the BEGIN TESTABLE / END TESTABLE helpers');
  process.exit(2);
}
const api = new Function(`${match[1]}\nreturn { escH, createHasher, hashBlob, planFileOp };`)();

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

function checkEscape() {
  const breakout = 'x" onmouseover="alert(1)';
  const esc = api.escH(breakout);
  assert(!esc.includes('"') && !esc.includes("'") && !esc.includes('<'), 'quotes or < survived: ' + esc);
  assert(esc === 'x&quot; onmouseover=&quot;alert(1)', 'unexpected escape: ' + esc);
  const tag = api.escH('<img src=x onerror=alert(1)>');
  assert(tag.startsWith('&lt;img'), tag);
  assert(!tag.includes('<'), tag);
  const fragment = `<span title="${esc}">${tag}</span>`;
  const tags = fragment.match(/<\/?[a-zA-Z]/g) || [];
  assert(tags.length === 2, 'attribute breakout created extra tags: ' + fragment);
  const ext = api.escH('png"><img src=x onerror=alert(1)>');
  assert(!ext.includes('<') && !ext.includes('"'), ext);
}

function checkPlan() {
  const same = api.planFileOp(true, true);
  assert(same.ok === false && /already in this folder/i.test(same.error), JSON.stringify(same));
  const taken = api.planFileOp(false, true);
  assert(taken.ok === false && /already exists/i.test(taken.error), JSON.stringify(taken));
  const free = api.planFileOp(false, false);
  assert(free.ok === true, JSON.stringify(free));
}

function checkHash(algo, nodeName, parts) {
  const hasher = api.createHasher(algo);
  const oracle = createHash(nodeName);
  for (const part of parts) {
    const bytes = typeof part === 'string' ? Buffer.from(part) : part;
    hasher.update(bytes);
    oracle.update(bytes);
  }
  const got = hasher.hex();
  const expect = oracle.digest('hex');
  assert(got === expect, `${algo} ${got} != ${expect} (parts=${parts.length})`);
}

function patterns() {
  const empty = [Buffer.alloc(0)];
  const abc = ['abc'];
  const split = ['a', 'b', 'c'];
  const boundary55 = [Buffer.alloc(55, 0x61)];
  const boundary56 = [Buffer.alloc(56, 0x62)];
  const blocks = [Buffer.alloc(64, 1), Buffer.alloc(64, 2), Buffer.alloc(3, 3)];
  const odd = [];
  let rest = Buffer.alloc(1000);
  for (let i = 0; i < rest.length; i++) rest[i] = (i * 17) & 0xff;
  for (let off = 0; off < rest.length; off += 100) odd.push(rest.subarray(off, off + 100));
  return [empty, abc, split, boundary55, boundary56, blocks, odd];
}

async function checkBlob() {
  const size = 2 * 1024 * 1024 + 123;
  const buf = Buffer.alloc(size);
  for (let i = 0; i < size; i += 4096) buf[i] = i & 0xff;
  const blob = new Blob([buf]);
  const hex = await api.hashBlob(blob, 'SHA-256');
  const expect = createHash('sha256').update(buf).digest('hex');
  assert(hex === expect, 'hashBlob mismatch');
  const empty = await api.hashBlob(new Blob([]), 'MD5');
  assert(empty === createHash('md5').update(Buffer.alloc(0)).digest('hex'), 'empty md5');
}

const algos = [
  ['MD5', 'md5'],
  ['SHA-1', 'sha1'],
  ['SHA-256', 'sha256'],
  ['SHA-512', 'sha512'],
];

checkEscape();
checkPlan();
for (const [algo, nodeName] of algos) {
  for (const parts of patterns()) checkHash(algo, nodeName, parts);
}
await checkBlob();
console.log('page logic ok');
