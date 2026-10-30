import { domainToASCII } from 'node:url';

export function analyzeUrl(value, displayedText = '') {
  const original = String(value ?? '').trim();
  const findings = [];
  const add = (id, title, severity, explanation) => findings.push({ id, title, severity, explanation });
  if (!original || original.length > 2048) return { original, normalized: null, hostname: null, score: 0, risk: 'Low', findings: [{ id: 'url.invalid', title: 'Invalid URL', severity: 'Info', explanation: 'Enter a URL under 2,048 characters.' }] };
  let parsed;
  try {
    const candidate = /^[a-z][a-z\d+.-]*:/i.test(original) ? original : `https://${original}`;
    parsed = new URL(candidate);
  } catch {
    return { original, normalized: null, hostname: null, score: 0, risk: 'Low', findings: [{ id: 'url.malformed', title: 'Malformed URL', severity: 'Info', explanation: 'The text could not be parsed as a URL.' }] };
  }
  if (!['http:', 'https:'].includes(parsed.protocol)) add('url.scheme', 'Unexpected scheme', 'Medium', `The URL uses ${parsed.protocol}, not HTTP or HTTPS.`);
  if (parsed.username || parsed.password || original.includes('@')) add('url.userinfo', 'At sign or embedded user information', 'High', 'An @ can obscure which host a reader will visit. Do not open the link.');
  const host = parsed.hostname.toLowerCase();
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host) || host.includes(':')) add('url.ip-host', 'IP address used as host', 'Low', 'An IP address in a link is a structural caution, not proof of maliciousness.');
  if (host.startsWith('xn--') || host.split('.').some(x => x.startsWith('xn--'))) add('url.punycode', 'Internationalized hostname encoding', 'Medium', 'Punycode can represent non-Latin characters; inspect the displayed name carefully.');
  const labels = host.split('.');
  if (labels.length >= 5) add('url.subdomains', 'Many hostname labels', 'Low', `The hostname has ${labels.length} labels, which can make the registered domain harder to spot.`);
  if (parsed.port && !['80', '443'].includes(parsed.port)) add('url.port', 'Unusual port', 'Medium', `The URL specifies port ${parsed.port}.`);
  if (/%(?:2f|5c|40|25)/i.test(parsed.pathname + parsed.search)) add('url.encoding', 'Encoded URL delimiters', 'Medium', 'Encoded slashes, at signs, or nested percent signs can hide the destination structure.');
  if (/(?:bit\.ly|tinyurl\.com|t\.co|is\.gd|goo\.gl)$/i.test(host)) add('url.shortener', 'URL shortening service', 'Low', 'A shortened URL hides its eventual destination; inspect it only with an approved offline process.');
  if (displayedText && displayedText.trim() && !displayedText.includes(host)) add('url.mismatch', 'Displayed text differs from hostname', 'High', `Displayed link text does not contain the parsed hostname “${host}”.`);
  const riskScore = Math.min(100, findings.reduce((n, f) => n + ({ High: 30, Medium: 16, Low: 7 }[f.severity] || 0), 0));
  const lookalikes=[/micros[0o]ft|microsof[t1]/,/g[o0]{2}gle/,/app[1i]e/,/amaz[o0]n/,/paypa[l1]/,/netf[1i]ix/];
  if (lookalikes.some(pattern=>pattern.test(host) && !['microsoft','google','apple','amazon','paypal','netflix'].some(brand=>host.includes(brand)))) add('url.lookalike','Possible brand-like spelling','Medium','The hostname resembles a familiar brand string. This is a structural hint only; no reputation lookup was performed.');
  return { original, normalized: `${parsed.protocol}//${parsed.host}${parsed.pathname}${parsed.search}${parsed.hash}`, protocol:parsed.protocol, hostname: host, asciiHostname: domainToASCII(host), domainParts:labels, registrableDomainGuess:labels.slice(-2).join('.'), port:parsed.port||null, score: riskScore, risk: riskScore >= 65 ? 'Critical' : riskScore >= 40 ? 'High' : riskScore >= 20 ? 'Medium' : 'Low', findings };
}
