import { z } from "zod";
import { inviteFromURL } from "@corpollc/qntm";

const QntmConversationSchema = z
  .object({
    name: z.string().optional(),
    enabled: z.boolean().optional(),
    invite: z.string().optional(),
    convId: z.string().optional(),
    trigger: z.enum(["all", "mention"]).optional(),
    triggerNames: z.array(z.string()).optional(),
  })
  .strict()
  .superRefine((value, ctx) => {
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
    conversations: z.record(z.string(), QntmConversationSchema.optional()).optional(),
  })
  .strict();

export const QntmAccountSchema = QntmAccountSchemaBase;

export const QntmConfigSchema = QntmAccountSchemaBase.extend({
  accounts: z.record(z.string(), QntmAccountSchema.optional()).optional(),
  defaultAccount: z.string().optional(),
});
