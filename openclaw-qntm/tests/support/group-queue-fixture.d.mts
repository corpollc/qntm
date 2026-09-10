export function stageGroupDelivery(config: unknown, stateDir: string, messageId: string): Promise<{
  messageId: string; queueId: string; generation: string;
}>;
