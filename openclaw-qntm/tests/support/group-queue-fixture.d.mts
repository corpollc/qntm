export function stageGroupDelivery(config: unknown, stateDir: string, messageId: string): Promise<{
  messageId: string; queueId: string; generation: string;
}>;
export function stageAcceptedGroupSend(config: unknown, stateDir: string): Promise<{ messageId: string }>;

export function stageCompletedGroupAddition(config: unknown, stateDir: string, contact: string, ttl?: number, partial?: boolean): Promise<{
  expiry: number; original: { controls: string[]; welcomes: string[] }; currentRoot: string;
}>;

export function stageGenericGroupRefresh(config: unknown, stateDir: string, contact: string, ttl?: number, challenge?: string): Promise<{
  expiry: number; original: { welcomes: string[] }; cursor: number; currentRoot: string;
}>;
