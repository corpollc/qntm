import { z } from "zod";
import { inviteFromURL } from "@corpollc/qntm";

const QntmConversationSchema = z
  .object({
    name: z.string().optional(),
    enabled: z.boolean().optional(),
    invite: z.string().optional(),
  })
  .strict()
  .superRefine((value, ctx) => {
    if (!value.invite?.trim()) {
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
    defaultTo: z.string().optional(),
    conversations: z.record(z.string(), QntmConversationSchema.optional()).optional(),
  })
  .strict();

export const QntmAccountSchema = QntmAccountSchemaBase;

export const QntmConfigSchema = QntmAccountSchemaBase.extend({
  accounts: z.record(z.string(), QntmAccountSchema.optional()).optional(),
  defaultAccount: z.string().optional(),
});
