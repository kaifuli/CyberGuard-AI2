function decodeHeader(value) {
  return value.replace(/=\?([^?]+)\?([bq])\?([^?]*)\?=/gi, (_all, charset, encoding, data) => {
    try {
      const bytes = encoding.toLowerCase() === 'b' ? Buffer.from(data, 'base64') : Buffer.from(data.replace(/_/g, ' ').replace(/=([\da-f]{2})/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16))), 'binary');
      return new TextDecoder(charset, { fatal: false }).decode(bytes);
    } catch { return data; }
  });
}
function decodeTextPart(value, headers) {
  const transfer = (headers.match(/content-transfer-encoding:\s*([^\n]+)/i)?.[1] || '').trim().toLowerCase();
  const charset = headers.match(/charset="?([^";\n]+)/i)?.[1] || 'utf-8';
  try {
    if (transfer === 'base64') return new TextDecoder(charset, { fatal:false }).decode(Buffer.from(value.replace(/\s/g,''),'base64'));
    if (transfer === 'quoted-printable') value=value.replace(/=\r?\n/g,'').replace(/=([\da-f]{2})/gi,(_,hex)=>String.fromCharCode(parseInt(hex,16)));
  } catch { /* return a best-effort safe text preview below */ }
  return value;
}
export function parseEml(raw) {
  if (typeof raw !== 'string' || Buffer.byteLength(raw) > 1_000_000) throw new Error('Email file must be text under 1 MB.');
  const normalized = raw.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  const split = normalized.match(/\n\n/);
  if (!split) throw new Error('The .eml file is missing the header/body separator.');
  const i = split.index + split[0].length;
  const headerText = normalized.slice(0, split.index).replace(/\n[ \t]+/g, ' ');
  const headers = {};
  for (const line of headerText.split('\n')) { const m = line.match(/^([^:\s]+):\s*(.*)$/); if (m) (headers[m[1].toLowerCase()] ??= []).push(decodeHeader(m[2])); }
  const bodyRaw = normalized.slice(i);
  const boundary = headers['content-type']?.[0]?.match(/boundary="?([^";]+)"?/i)?.[1];
  const attachments = [];
  let body = bodyRaw;
  if (boundary) {
    const parts = bodyRaw.split(`--${boundary}`);
    const bodies = [];
    for (const part of parts) {
      if (!part.trim() || /^--/.test(part.trim())) continue;
      const p = part.replace(/^\n|\n$/g, ''), sep = p.indexOf('\n\n'); if (sep < 0) continue;
      const ph = p.slice(0, sep), pb = p.slice(sep + 2);
      const name = ph.match(/filename\*?=(?:UTF-8''|"?)([^";\n]+)/i)?.[1];
      if (/attachment|filename=/i.test(ph)) attachments.push({ name: decodeURIComponent(name || 'unnamed attachment'), contentType: ph.match(/content-type:\s*([^;\n]+)/i)?.[1] || 'application/octet-stream', encodedSize: pb.length });
      else if (/text\/plain/i.test(ph)) bodies.push(decodeTextPart(pb,ph));
      else if (/text\/html/i.test(ph) && !bodies.length) {
        const html=decodeTextPart(pb,ph).replace(/<(script|style)\b[^>]*>[\s\S]*?<\/\1\s*>/gi, ' ');
        const links=[...html.matchAll(/<a\b[^>]*href\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a\s*>/gi)].map(m=>`${m[2].replace(/<[^>]*>/g,' ').trim()} -> ${m[1]}`);
        bodies.push(html.replace(/<[^>]*>/g, ' ').replace(/&nbsp;/gi, ' ').replace(/&amp;/gi, '&').replace(/&lt;/gi, '<').replace(/&gt;/gi, '>')+(links.length?`\nLinks: ${links.join('; ')}`:''));
      }
    }
    if (bodies.length) body = bodies.join('\n');
  }
  if(!boundary) body=decodeTextPart(body,headerText);
  const first = key => headers[key]?.[0] || '';
  return { sender: first('from'), recipient: first('to'), replyTo: first('reply-to'), returnPath: first('return-path'), subject: first('subject'), date: first('date'), messageId: first('message-id'), received: headers.received || [], authenticationResults: headers['authentication-results'] || [], authEvidence: headers['authentication-results']?.length ? 'Authentication-Results header is present; this local tool does not independently validate it.' : 'No Authentication-Results header was provided.', headers, body: body.slice(0, 50_000), attachments };
}
