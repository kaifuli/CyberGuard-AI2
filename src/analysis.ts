export type RiskLevel = 'High' | 'Medium' | 'Low';
export type EmailInput = { sender: string; subject: string; body: string };
export type Finding = { id: string; title: string; severity: RiskLevel; evidence: string; why: string; points: number };
export type Analysis = { id: number | string; email: EmailInput; score: number; risk: RiskLevel; label: string; summary: string; findings: Finding[]; checked: string[]; createdAt: string; feedback?: 'Helpful' | 'Not Helpful' | null; feedbackText?: string };
const ruleList = ['Urgency, threats, and time pressure','Credential or account verification requests','Sender domain spoofing and brand lookalikes','Unverified links and deceptive URL patterns','Common social engineering language'];
const riskFor = (score: number): RiskLevel => score >= 65 ? 'High' : score >= 30 ? 'Medium' : 'Low';
export function analyzeEmail(email: EmailInput): Analysis {
 const text = `${email.subject}\n${email.body}`.toLowerCase(), findings: Finding[] = [];
 const add = (id:string,title:string,severity:RiskLevel,evidence:string,why:string,points:number) => findings.push({id,title,severity,evidence,why,points});
 const urgent=['urgent','immediately','within','today','suspended','suspend','expires','minutes','act now','final warning','unusual activity'].filter(x=>text.includes(x));
 if(urgent.length) add('urgency','Urgency and time pressure','High',`Time-pressure language detected: “${urgent.slice(0,3).join('”, “')}”.`,'Threats and short deadlines can pressure people into skipping normal verification.',25);
 const credential=['verify your account','verify account','enter your password','credentials','sign in','log in','confirm your account','account verification'].filter(x=>text.includes(x));
 if(credential.length) add('credentials','Account verification request','High',`The message asks the recipient to ${credential[0]}.`,'Unexpected requests to verify an account may lead to credential theft.',25);
 const sender=email.sender.toLowerCase(), brands=['microsoft','micros0ft','apple','google','amazon','paypal','netflix','bank'], brand=brands.find(b=>sender.includes(b)&&(sender.includes('support')||sender.includes('security')||sender.includes('alert')||sender.includes('0'))), domain=sender.split('@')[1]||'';
 if(brand&&(sender.includes('0')||domain.includes('example')||domain.includes('test')||domain.includes('-'))) add('sender','Possible brand impersonation','High',`The sender combines “${brand}” with a support or security cue, and uses the domain “${domain||'unknown'}”.`,'A familiar brand name in an address does not prove the sender is affiliated with that organization.',25);
 else if(domain&&(domain.includes('example')||domain.includes('test'))) add('sender-domain','Unverified sender domain','Medium',`The sender domain “${domain}” is a reserved demonstration domain.`,'The sender cannot be authenticated from the address text alone.',12);
 const urls=email.body.match(/(?:https?:\/\/|hxxps?:\/\/|www\.)[^\s<>"']+/gi)||[], suspicious=urls.filter(u=>/hxxp|example|test|login|verify|secure|account|\d{1,3}(?:\.\d{1,3}){3}/i.test(u));
 if(suspicious.length) add('link','Unverified verification link','High',`A link with a login or verification cue was found: ${suspicious[0]}`,'The link destination is unverified. Do not open it; inspect links only through approved security tools.',25);
 else if(urls.length) add('link','Link present in message','Medium',`${urls.length} link${urls.length===1?'':'s'} found in the message body.`,'Links deserve care, especially when a message unexpectedly asks you to sign in.',10);
 const manip=['click here','act now','avoid interruption','keep this confidential','payment overdue','gift card'].filter(x=>text.includes(x));
 if(manip.length) add('social','Social engineering language','Medium',`Common pressure phrase detected: “${manip[0]}”.`,'This wording can encourage a rushed response or discourage independent checks.',12);
 const score=Math.min(100,findings.reduce((n,f)=>n+f.points,0)),risk=riskFor(score);
 return {id:`${Date.now()}-${Math.random().toString(36).slice(2,7)}`,email:{...email},score,risk,label:risk==='High'?'Potential Phishing':risk==='Medium'?'Needs Review':'No Strong Warning Signs',summary:risk==='High'?'Several warning signs are present. Treat the message as untrusted and verify through a separate, trusted channel.':risk==='Medium'?'Some signals deserve a closer look. Check the sender and context before responding or following any links.':'The local rules found few common warning signs. This does not prove the message is safe.',findings,checked:ruleList,createdAt:new Date().toISOString()};
}
