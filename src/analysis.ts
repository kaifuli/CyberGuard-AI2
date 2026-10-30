export type RiskLevel = 'Critical' | 'High' | 'Medium' | 'Low';
export type EmailInput = {
  sender: string;
  subject: string;
  body: string;
  recipient?: string;
  rawHeaders?: string;
  attachments?: { name: string; contentType?: string; size?: number }[];
};
export type Finding = {
  id: string;
  ruleId?: string;
  title: string;
  severity: RiskLevel;
  evidence: string;
  why: string;
  explanation?: string;
  nextAction?: string;
  points: number;
};
export type Analysis = {
  id: number | string;
  email: EmailInput;
  score: number;
  risk: RiskLevel;
  label: string;
  summary: string;
  findings: Finding[];
  checked: string[];
  createdAt: string;
  feedback?: 'Helpful' | 'Not Helpful' | null;
  feedbackText?: string;
  cloudReview?: { provider: string; model: string; text: string; createdAt: string };
  cloudError?: string | null;
};
