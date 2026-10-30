import test, { before, after, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { analyzeUrl } from '../server/url-analysis.js';
import { parseEml } from '../server/eml-parser.js';
import { scenarios, scoreTraining } from '../server/training.js';
import { analyzeEmail, createServer } from '../server/app.js';
import { makePdf, reportObject } from '../server/report.js';

test('URL checks are static and cover malformed, IP, @, IDN, encoding and mismatch clues', () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = () => { throw new Error('URL analyzer must not fetch'); };
  try {
    assert.equal(analyzeUrl('https://192.0.2.3/path').findings[0].id, 'url.ip-host');
    assert.ok(analyzeUrl('https://trusted.example@evil.example').findings.some(x => x.id === 'url.userinfo'));
    assert.ok(analyzeUrl('https://xn--bcher-kva.example').findings.some(x => x.id === 'url.punycode'));
    assert.ok(analyzeUrl('https://example.test/%2f%40').findings.some(x => x.id === 'url.encoding'));
    assert.ok(analyzeUrl('https://evil.example', 'https://bank.example').findings.some(x => x.id === 'url.mismatch'));
    assert.equal(analyzeUrl('not a URL %').normalized, null);
    assert.ok(analyzeUrl('https://example.test').normalized.startsWith('https://'));
  } finally { globalThis.fetch = originalFetch; }
});

test('EML parser unfolds headers, decodes subject, sanitizes HTML and lists attachments as metadata', () => {
  const eml = [
    'From: Sender <a@example.test>', 'To: person@example.test', 'Subject: =?UTF-8?Q?Hello_=E2=9C=93?=',
    'Authentication-Results: mx.example.test; spf=pass', 'Content-Type: multipart/mixed; boundary="b"', '',
    '--b', 'Content-Type: text/html; charset=utf-8', '', '<p>Hello</p><a href="https://evil.example">official portal</a><script>alert(1)</script>', '--b',
    'Content-Type: application/pdf; name="invoice.pdf"', 'Content-Disposition: attachment; filename="invoice.pdf"', '', 'aW5zZW5zaXRpdmU=', '--b--', ''
  ].join('\r\n');
  const result = parseEml(eml);
  assert.match(result.subject, /Hello/);
  assert.match(result.body, /Hello/);
  assert.doesNotMatch(result.body, /script|alert/);
  assert.match(result.body,/https:\/\/evil\.example/);
  assert.equal(result.attachments[0].name, 'invoice.pdf');
  assert.equal(result.authenticationResults.length, 1);
  assert.throws(() => parseEml('no separator'), /separator/);
  assert.throws(() => parseEml('x'.repeat(1_000_001)), /1 MB/);
});

test('training examples are separate from deterministic rule output and scoring is stable', () => {
  assert.ok(scenarios.length >= 12);
  const scenario = scenarios.find(x => x.expected === 'Safe' && /password|verify|suspended/i.test(x.body) === false);
  const independent = analyzeEmail(scenario);
  assert.equal(independent.risk, 'Low'); assert.equal(scenario.expected, 'Safe');
  assert.deepEqual(scoreTraining([{correct:true},{correct:true},{correct:false},{correct:true}]), {correct:3,total:4,accuracy:75,bestStreak:2,points:30});
});

test('risk score is capped, metadata findings explain attachments and output is deterministic apart from date', () => {
  const email = {sender:'finance@example.test',subject:'urgent invoice payment today',body:'enter your password and authentication code immediately',rawHeaders:'Authentication-Results: dmarc=fail',attachments:[{name:'file.zip'}]};
  const a=analyzeEmail(email),b=analyzeEmail(email);
  assert.equal(a.score,100); assert.equal(a.risk,'Critical');
  assert.deepEqual(a.findings,b.findings);
  assert.ok(a.findings.some(x=>x.id==='attachment-metadata'));
});

test('email body link labels are compared to their actual destination',()=>{
  const result=analyzeEmail({sender:'notices@bank.example',subject:'Review',body:'https://bank.example -> https://attacker.example/login'});
  assert.ok(result.findings.some(x=>x.ruleId==='link-text-mismatch'));
});

test('JSON schema and generated PDF paginate long reports', () => {
  const analysis={id:4,email:{sender:'a@example.test',subject:'Review',body:''},score:22,risk:'Medium',summary:'Review carefully',findings:Array.from({length:100},(_,i)=>({id:`r${i}`,title:`Finding ${i}`,severity:'Medium',evidence:'Evidence '.repeat(15),why:'Explanation '.repeat(12),points:4})),createdAt:new Date().toISOString()};
  const json=reportObject(analysis), pdf=makePdf(analysis).toString('ascii');
  assert.equal(json.schemaVersion,'1.0'); assert.equal(json.reportId,'CG-4');
  assert.ok(pdf.startsWith('%PDF-1.4')); assert.ok(Number(pdf.match(/\/Count (\d+)/)?.[1]) > 1); assert.ok(pdf.endsWith('%%EOF'));
});

describe('feature API persistence',()=>{
  let server,base,temp;
  before(async()=>{temp=fs.mkdtempSync(path.join(os.tmpdir(),'cg-features-'));server=createServer({dbPath:path.join(temp,'db.sqlite3')});await new Promise(r=>server.listen(0,'127.0.0.1',r));base=`http://127.0.0.1:${server.address().port}`;});
  after(async()=>{await new Promise(r=>server.close(r));fs.rmSync(temp,{recursive:true,force:true});});
  test('dashboard uses persisted rows, URL analysis is saved, training completes and reports export locally',async()=>{
    const call=async(url,method='GET',body)=>{const r=await fetch(`${base}${url}`,{method,headers:body?{'Content-Type':'application/json'}:undefined,body:body?JSON.stringify(body):undefined});return {r,data:await r.json()};};
    const created=await call('/api/analyze','POST',{sender:'a@example.test',subject:'Routine meeting',body:'Please see you at noon.'});
    const id=created.data.id;
    const dashboard=await call('/api/dashboard'); assert.equal(dashboard.data.total,1); assert.equal(dashboard.data.distribution.Low,1);
    const linked=await call('/api/analyze','POST',{sender:'alerts@example.test',subject:'Review this link',body:'Please review https://192.0.2.44/login'});
    const related=(await call('/api/url/history')).data.items.find(x=>x.analysisId===linked.data.id); assert.ok(related);
    const urls=await call('/api/url/analyze','POST',{urls:['https://192.0.2.5']}); assert.equal(urls.data.items.length,1);
    assert.equal((await call('/api/url/history')).data.items.length,2);
    const urlJson=await fetch(`${base}/api/url/reports/${urls.data.items[0].id}.json`);assert.equal((await urlJson.json()).inputType,'url');
    const urlPdf=await fetch(`${base}/api/url/reports/${urls.data.items[0].id}.pdf`);assert.match(urlPdf.headers.get('content-type'),/application\/pdf/);
    const selected=scenarios.slice(0,2).map(x=>({id:x.id,answer:x.expected}));
    const session=await call('/api/training/sessions','POST',{difficulty:'All',answers:selected}); assert.equal(session.data.score.correct,2);
    assert.equal((await call('/api/training/stats')).data.sessions,1);
    const json=await fetch(`${base}/api/reports/${linked.data.id}.json`); assert.equal(json.status,200); const report=await json.json();assert.equal(report.schemaVersion,'1.0');assert.equal(report.urls.length,1);
    const pdf=await fetch(`${base}/api/reports/${id}.pdf`); assert.match(pdf.headers.get('content-type'),/application\/pdf/); assert.equal((await pdf.text()).slice(0,8),'%PDF-1.4');
    const parsed=await call('/api/eml/parse','POST',{content:'From: sender@example.test\nSubject: Test\n\nPlain text body'});assert.equal(parsed.data.sender,'sender@example.test');assert.equal(parsed.data.body,'Plain text body');
  });
});
