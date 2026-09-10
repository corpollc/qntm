export interface ToolPlan {
  id: string;
  tool?: 'qntm_gateway' | 'qntm_group';
  action?: string;
  options?: Record<string, unknown>;
  initialStatus?: string;
  finishRotation?: boolean;
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
  beforePrepare: Map<string, () => Promise<void>>;
  close(): Promise<void>;
}>;
