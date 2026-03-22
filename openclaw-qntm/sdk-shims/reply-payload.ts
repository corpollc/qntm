export type OutboundReplyPayload = {
  text?: string;
  mediaUrls?: string[];
  mediaUrl?: string;
  replyToId?: string;
};

export function createNormalizedOutboundDeliverer(
  handler: (payload: OutboundReplyPayload) => Promise<void>,
): (payload: unknown) => Promise<void> {
  return async (payload: unknown) => {
    const record = payload && typeof payload === "object" ? (payload as Record<string, unknown>) : {};
    await handler({
      text: typeof record.text === "string" ? record.text : undefined,
      mediaUrls: Array.isArray(record.mediaUrls)
        ? record.mediaUrls.filter((entry): entry is string => typeof entry === "string" && entry.length > 0)
        : undefined,
      mediaUrl: typeof record.mediaUrl === "string" ? record.mediaUrl : undefined,
      replyToId: typeof record.replyToId === "string" ? record.replyToId : undefined,
    });
  };
}
