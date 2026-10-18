import { ChevronRight, Clock3, Inbox, ScanLine, Trash2 } from 'lucide-react';
import type { Analysis } from './analysis';

export default function HistoryView({ history, open, remove, go }: {
  history: Analysis[];
  open: (analysis: Analysis) => void;
  remove: (analysis: Analysis) => void;
  go: () => void;
}) {
  return <>
    <div className="title-row"><div><div className="eyebrow">INVESTIGATION LOG</div><h1>Analysis History</h1><p>Review reports saved in your local SQLite database.</p></div>
      {history.length > 0 && <button className="btn primary" onClick={go}><ScanLine size={15}/> New analysis</button>}
    </div>
    {history.length ? <section className="panel history">
      <div className="history-head"><div><h2>Recent analyses</h2><p>{history.length} report{history.length === 1 ? '' : 's'} · stored locally</p></div><small>● LOCAL SQLITE</small></div>
      <div className="table-wrap"><table><thead><tr><th>MESSAGE</th><th>RISK</th><th>INDICATORS</th><th>ANALYZED</th><th>REPORT</th><th>DELETE</th></tr></thead>
        <tbody>{history.map(a => <tr key={a.id} tabIndex={0} onClick={() => open(a)} onKeyDown={e => (e.key === 'Enter' || e.key === ' ') && open(a)}>
          <td><b>{a.email.subject}</b><span>{a.email.sender}</span></td>
          <td><i className={`table-risk ${a.risk.toLowerCase()}`}>{a.risk} · {a.score}</i></td>
          <td>{a.findings.length} found</td>
          <td>{new Date(a.createdAt).toLocaleString([], { dateStyle: 'short', timeStyle: 'short' })}</td>
          <td><button className="row-action" aria-label={`Open analysis: ${a.email.subject}`} onClick={e => { e.stopPropagation(); open(a); }}><ChevronRight size={16}/></button></td>
          <td><button className="row-action delete-action" aria-label={`Delete analysis: ${a.email.subject}`} onClick={e => { e.stopPropagation(); remove(a); }}><Trash2 size={15}/></button></td>
        </tr>)}</tbody></table></div>
      <div className="history-foot"><Clock3 size={13}/> History persists on this computer in data/cyberguard.sqlite3.</div>
    </section> : <section className="panel empty"><div><Inbox size={22}/></div><h2>No analyses yet</h2><p>Completed email checks will appear here and stay available after restarting the app.</p><button className="btn primary" onClick={go}><ScanLine size={16}/> Open Email Analyzer</button></section>}
  </>;
}
