
export enum Severity {
  CRITICAL = 'CRITICAL',
  HIGH = 'HIGH',
  MEDIUM = 'MEDIUM',
  LOW = 'LOW',
  INFO = 'INFO'
}

export interface Vulnerability {
  id: string;
  title: string;
  severity: Severity;
  description: string;
  remediation: string;
  target: string;
  status: 'Open' | 'Resolved' | 'In Progress';
  detectedAt: string;
}

export interface ScanTask {
  id: string;
  name: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  progress: number;
}

export interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
  timestamp: Date;
}

export interface User {
  id: string;
  name: string;
  role: 'Beginner' | 'Professional' | 'Admin';
}
