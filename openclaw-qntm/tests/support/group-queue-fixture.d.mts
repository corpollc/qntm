export function stageGroupDelivery(config: unknown, stateDir: string, messageId: string): Promise<{
  messageId: string; queueId: string; generation: string;
}>;
export function stageAcceptedGroupSend(config: unknown, stateDir: string): Promise<{ messageId: string }>;
