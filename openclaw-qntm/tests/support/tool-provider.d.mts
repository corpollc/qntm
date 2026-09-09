export interface ToolPlan {
  id: string;
  action?: string;
  options?: Record<string, unknown>;
  initialStatus?: string;
  expectedStatus?: string;
  expectedCode?: string;
  single?: Record<string, unknown>;
}
export interface ToolResult {
  status: string;
  code?: string;
  reviewToken?: string;
  reviewHash?: string;
  review?: { body?: Record<string, unknown>; [key: string]: unknown };
  messageId?: string;
  sequence?: number;
  [key: string]: unknown;
}
export function createToolProvider(): Promise<{
  url: string;
  outcomes: Map<string, ToolResult[]>;
  failures: string[];
  close(): Promise<void>;
}>;
