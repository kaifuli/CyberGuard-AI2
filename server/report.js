function ascii(value) {
  return String(value ?? '').normalize('NFKD').replace(/[^\x20-\x7e]/g, '?').replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)');
}
export function reportObject(analysis, urls=[]) {
  const rawHeaders=analysis.email.rawHeaders||'';
  return { schemaVersion:'1.0', product:'CyberGuard AI', reportId:`CG-${analysis.id}`, generatedAt:new Date().toISOString(), inputType:'email', subject:analysis.email.subject, sender:analysis.email.sender, risk:{ score:analysis.score, severity:analysis.risk }, summary:analysis.summary, findings:analysis.findings, urls, recommendations:analysis.risk==='Low'?['Verify unexpected requests through a known channel.']:['Avoid links and attachments until independently verified.','Verify the request through a trusted channel.','Report concerns to your security contact.'], authentication:rawHeaders.match(/authentication-results:/i)?{ status:'Authentication-Results header supplied; not independently validated.', evidence:rawHeaders.split(/\r?\n/).filter(x=>/authentication-results:/i.test(x)).slice(0,3) }:{ status:'Unavailable; no authentication header evidence provided.' }, limitations:['Local deterministic heuristics only; not independently verified.','Automated analysis can produce false positives and false negatives.'] };
}
export function urlReportObject(item) {
  return { schemaVersion:'1.0', product:'CyberGuard AI', reportId:`CG-URL-${item.id}`, generatedAt:new Date().toISOString(), inputType:'url', originalUrl:item.result.original, normalizedUrl:item.result.normalized, hostname:item.result.hostname, risk:{score:item.result.score,severity:item.result.risk}, findings:item.result.findings, recommendations:['Do not open links based only on this heuristic report. Verify the destination through an independently trusted channel.'], limitations:['Static structural heuristics only; no reputation lookup, DNS request, HTTP request, or redirect following.','Automated analysis can produce false positives and false negatives.'] };
}
export function makeUrlPdf(item) {
  const data=urlReportObject(item), analysis={id:data.reportId,email:{sender:'URL analysis',subject:data.originalUrl,body:''},score:data.risk.score,risk:data.risk.severity,label:'Structural URL assessment',summary:`Parsed host: ${data.hostname||'unavailable'}. This is not a reputation verdict.`,findings:data.findings.map(f=>({title:f.title,severity:f.severity,evidence:f.explanation,why:'Structural indicator only.',points:0})),createdAt:data.generatedAt};
  return makePdf(analysis);
}
export function makePdf(analysis, urls=[]) {
  const report=reportObject(analysis,urls), lines=[
    'CyberGuard AI | LOCAL EMAIL SECURITY REPORT',`Report: ${report.reportId}`,`Date: ${report.generatedAt}`,'',
    'ASSESSMENT',`Risk: ${report.risk.severity} (${report.risk.score}/100)`,`Subject: ${report.subject}`,`Sender: ${report.sender}`,
    '', 'SUMMARY', report.summary, '', 'DETECTED INDICATORS',
    ...(report.findings.length?report.findings.flatMap(f=>[`[${f.severity}] ${f.title} (+${f.points})`,f.evidence,f.why,'']):['No configured indicators matched.']),
    ...(urls.length?['','RELATED URL FINDINGS',...urls.flatMap(u=>[`${u.risk} · ${u.score}/100 · ${u.original}`,...u.findings.map(f=>f.title+': '+f.explanation)])]:[]),
    'RECOMMENDED ACTIONS',...report.recommendations.map(x=>`- ${x}`),'','AUTHENTICATION EVIDENCE',report.authentication.status||String(report.authentication),
    '','LIMITATIONS','Heuristic analysis can produce false positives and false negatives. This report is not a verdict.'
  ];
  const pages=[]; let page=[];
  for(const line of lines){const chunks=line.match(/.{1,88}(?:\s|$)|.{1,88}/g)||[''];for(const chunk of chunks){if(page.length>=48){pages.push(page);page=[];}page.push(chunk.trimEnd());}}
  if(page.length)pages.push(page);
  const objects=[]; const add=x=>(objects.push(x),objects.length);
  const catalog=add(''); const pagesObj=add(''); const font=add('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>');
  const pageIds=[];
  for(let p=0;p<pages.length;p++){
    const commands=['BT','/F1 10 Tf','48 754 Td','13 TL',...pages[p].flatMap((line,i)=>[(i? 'T*':'') ,`(${ascii(line)}) Tj`]).filter(Boolean),'ET',`BT /F1 9 Tf 500 28 Td (${p+1} / ${pages.length}) Tj ET`].join('\n');
    const streamId=add(`<< /Length ${Buffer.byteLength(commands)} >>\nstream\n${commands}\nendstream`);
    const pageId=add(`<< /Type /Page /Parent ${pagesObj} 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 ${font} 0 R >> >> /Contents ${streamId} 0 R >>`);pageIds.push(pageId);
  }
  objects[catalog-1]=`<< /Type /Catalog /Pages ${pagesObj} 0 R >>`;
  objects[pagesObj-1]=`<< /Type /Pages /Kids [${pageIds.map(x=>`${x} 0 R`).join(' ')}] /Count ${pageIds.length} >>`;
  let pdf='%PDF-1.4\n', offsets=[0];
  objects.forEach((obj,i)=>{offsets.push(Buffer.byteLength(pdf));pdf+=`${i+1} 0 obj\n${obj}\nendobj\n`;});
  const xref=Buffer.byteLength(pdf);pdf+=`xref\n0 ${objects.length+1}\n0000000000 65535 f \n${offsets.slice(1).map(x=>`${String(x).padStart(10,'0')} 00000 n \n`).join('')}trailer\n<< /Size ${objects.length+1} /Root ${catalog} 0 R >>\nstartxref\n${xref}\n%%EOF`;
  return Buffer.from(pdf,'ascii');
}
