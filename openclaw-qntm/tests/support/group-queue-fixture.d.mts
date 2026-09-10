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

export function stagePendingGroupRemoval(config: unknown, stateDir: string, contact: string, ttl?: number): Promise<{
  cursor: number; epoch: number; removalId: string; rekeyId: string; expiry: number; controls: string[]; target: unknown;
}>;

export function stageUncertainRemovalRepair(config: unknown, stateDir: string): Promise<{ rotation: string; rotationId: string }>;

export function stagePendingGroupRotation(config: unknown, stateDir: string): Promise<{
  messageId: string; control: string; epoch: number; expectedRoot: string; cursor: number;
}>;

export function stageAcceptedGroupRotation(config: unknown, stateDir: string): Promise<{
  messageId: string; control: string; sequence: number; epoch: number; expectedRoot: string;
}>;
