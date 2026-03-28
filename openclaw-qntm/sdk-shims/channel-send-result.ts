type MaybePromise<T> = T | Promise<T>;

type SendTextParams = {
  cfg: Record<string, unknown>;
  to: string;
  text: string;
  accountId?: string | null;
};

type SendMediaParams = SendTextParams & {
  mediaUrl: string;
};

type SendResult = {
  messageId?: string;
  conversationId?: string;
  meta?: Record<string, unknown>;
  ok?: boolean;
  error?: Error;
};

export function attachChannelToResult<T extends object>(channel: string, result: T) {
  return {
    channel,
    ...result,
  };
}

export function createAttachedChannelResultAdapter(params: {
  channel: string;
  sendText?: (ctx: SendTextParams) => MaybePromise<SendResult>;
  sendMedia?: (ctx: SendMediaParams) => MaybePromise<SendResult>;
}) {
  return {
    sendText: params.sendText
      ? async (ctx: SendTextParams) => attachChannelToResult(params.channel, await params.sendText!(ctx))
      : undefined,
    sendMedia: params.sendMedia
      ? async (ctx: SendMediaParams) =>
          attachChannelToResult(params.channel, await params.sendMedia!(ctx))
      : undefined,
  };
}
