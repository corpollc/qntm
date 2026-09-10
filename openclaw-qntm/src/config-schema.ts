import { z } from "zod";
import { inviteFromURL, parseGroupLink } from "@corpollc/qntm";

const QntmConversationSchema = z
  .object({
    name: z.string().optional(),
    enabled: z.boolean().optional(),
    invite: z.string().optional(),
    groupLink: z.string().max(8192).optional(),
    groupActions: z.array(z.enum(["add", "remove", "refresh", "rekey", "retry", "open", "send"])).max(7).optional(),
    gatewayActions: z.array(z.enum(["invite", "request", "approve", "disapprove", "secret", "propose", "gov-approve", "gov-disapprove"])).max(8).optional(),
    convId: z.string().optional(),
    trigger: z.enum(["all", "mention"]).optional(),
    triggerNames: z.array(z.string()).optional(),
  })
  .strict()
  .superRefine((value, ctx) => {
    if (value.groupLink) {
      if (value.invite || value.convId || value.gatewayActions?.length) ctx.addIssue({ code: "custom", message: "groupLink cannot be combined with invite, convId or gateway actions" });
      try { parseGroupLink(value.groupLink); } catch { ctx.addIssue({ code: "custom", path: ["groupLink"], message: "invalid public group link" }); }
      return;
    }
    if (value.groupActions?.length && value.gatewayActions?.length) ctx.addIssue({ code: "custom", message: "ordinary group actions cannot be combined with gateway actions" });
    if (!value.invite?.trim()) {
      if (value.convId?.trim() && !/^[0-9a-f]{32}$/i.test(value.convId.trim())) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["convId"],
          message: "invalid qntm conversation id: expected 32 hex characters",
        });
      }
      return;
    }
    try {
      inviteFromURL(value.invite);
    } catch (error) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["invite"],
        message: `invalid qntm invite: ${String(error)}`,
      });
    }
  });

export const QntmAccountSchemaBase = z
  .object({
    name: z.string().optional(),
    enabled: z.boolean().optional(),
    relayUrl: z.string().optional(),
    identity: z.string().optional(),
    identityFile: z.string().optional(),
    identityDir: z.string().optional(),
    defaultTo: z.string().optional(),
    contacts: z.record(z.string().min(1).max(128), z.string().regex(/^(?:[0-9a-fA-F]{64}|[A-Za-z0-9_-]{43})$/)).optional(),
    conversations: z.record(z.string(), QntmConversationSchema.optional()).optional(),
  })
  .strict();

export const QntmAccountSchema = QntmAccountSchemaBase;

export const QntmConfigSchema = QntmAccountSchemaBase.extend({
  accounts: z.record(z.string(), QntmAccountSchema.optional()).optional(),
  defaultAccount: z.string().optional(),
});
