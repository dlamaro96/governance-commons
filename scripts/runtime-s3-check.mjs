// SPDX-License-Identifier: Apache-2.0
// Executed through stdin in the existing API container. Credentials come only
// from its established environment; never emit headers, response bodies or keys.
import { createHash, createHmac, randomBytes, randomUUID } from 'node:crypto';
const { S3_ENDPOINT, S3_ACCESS_KEY_ID, S3_SECRET_ACCESS_KEY } = process.env;
const region = process.env.S3_REGION || 'us-east-1';
const readiness = process.argv.includes('--readiness');
const checks = [];
const requests = [];
const hash = value => createHash('sha256').update(value).digest('hex');
const hmac = (key, value) => createHmac('sha256', key).update(value).digest();
class CheckFailure extends Error {}
function verify(condition, check) {
  if (!condition) throw new CheckFailure(check);
  checks.push(check);
}
async function request(method, path, body = '', authentication = 'valid') {
  const url = new URL(path, S3_ENDPOINT);
  const date = new Date().toISOString().replace(/[:-]|\.\d{3}/g, '');
  const day = date.slice(0, 8);
  const payloadHash = hash(body);
  const headers = { 'x-amz-date': date, 'x-amz-content-sha256': payloadHash };
  if (authentication !== 'anonymous') {
    const names = 'host;x-amz-content-sha256;x-amz-date';
    const canonical = [method, url.pathname, '', `host:${url.host}\nx-amz-content-sha256:${payloadHash}\nx-amz-date:${date}\n`, names, payloadHash].join('\n');
    const scope = `${day}/${region}/s3/aws4_request`;
    const secret = authentication === 'invalid' ? randomUUID() : S3_SECRET_ACCESS_KEY;
    const key = hmac(hmac(hmac(hmac(`AWS4${secret}`, day), region), 's3'), 'aws4_request');
    const signature = createHmac('sha256', key).update(`AWS4-HMAC-SHA256\n${date}\n${scope}\n${hash(canonical)}`).digest('hex');
    headers.Authorization = `AWS4-HMAC-SHA256 Credential=${S3_ACCESS_KEY_ID}/${scope}, SignedHeaders=${names}, Signature=${signature}`;
  }
  const response = await fetch(url, { method, headers, body: ['PUT', 'POST'].includes(method) ? body : undefined, signal: AbortSignal.timeout(20000), redirect: 'error' });
  requests.push({ method, resource: path === '/' ? 'root' : path.endsWith('/synthetic.txt') ? 'object' : 'bucket', authentication, status: response.status });
  return response;
}
let bucket, object, failure, cleanupFailure;
try {
  verify(Boolean(S3_ENDPOINT && S3_ACCESS_KEY_ID && S3_SECRET_ACCESS_KEY), 'S3 configuration present');
  verify((await request('GET', '/')).status === 200, 'signed ListBuckets succeeds');
  verify((await request('GET', '/', '', 'anonymous')).status === 403, 'anonymous ListBuckets denied');
  verify((await request('GET', '/', '', 'invalid')).status === 403, 'invalid signature denied');
  if (!readiness) {
    bucket = `/gc-qualification-${randomUUID()}`;
    const create = await request('PUT', bucket);
    verify(create.status === 200, 'synthetic isolated bucket created');
    object = `${bucket}/synthetic.txt`;
    // Exceeds filer inline thresholds, exercising actual volume object bytes.
    const content = randomBytes(64 * 1024);
    verify((await request('PUT', object, content)).status === 200, 'signed synthetic object write succeeds');
    const read = await request('GET', object);
    verify(read.status === 200 && Buffer.from(await read.arrayBuffer()).equals(content), 'signed object read matches bytes');
    verify((await request('GET', object, '', 'anonymous')).status === 403, 'anonymous object read denied');
    verify((await request('GET', object, '', 'invalid')).status === 403, 'invalid object signature denied');
  }
} catch (error) {
  // Own assertion messages are bounded static text. Network details are omitted.
  failure = error instanceof CheckFailure ? error.message : 'S3 request failed (' + (/^[A-Za-z]{1,32}$/.test(error?.name) ? error.name : 'Error') + ')';
} finally {
  for (const [path, check] of [[object, 'synthetic object removed'], [bucket, 'synthetic bucket removed']]) {
    if (!path) continue;
    try {
      const response = await request('DELETE', path);
      verify(response.status === 204 || (path === bucket && response.status === 404), check);
    } catch {
      cleanupFailure = true;
      failure = failure || 'S3 cleanup failed; inspect the synthetic qualification bucket';
    }
  }
}
console.log(JSON.stringify({ suite: readiness ? 's3-authenticated-readiness' : 's3-object-roundtrip', result: failure ? 'failed' : 'passed', checks, requests, qualification_object_bytes: readiness ? 0 : 64 * 1024, cleanup_failed: Boolean(cleanupFailure), error: failure || null, node_version: process.version, architecture: process.arch }));
process.exitCode = failure ? 1 : 0;
