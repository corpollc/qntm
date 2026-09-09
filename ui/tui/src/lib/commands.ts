/**
 * Slash command definitions used for help text, per-command help, and composer hints.
 */

export interface CommandDef {
  name: string;
  aliases?: string[];
  usage: string;
  brief: string;
  description: string;
}

export const COMMANDS: CommandDef[] = [
  {
    name: 'invite',
    usage: '/invite [name]',
    brief: 'Create a new conversation',
    description:
      'Creates a new conversation and generates an invite token. Usage: /invite [name]. The name is optional and labels the conversation. After creating, share the token with another person so they can /join.',
  },
  {
    name: 'join',
    usage: '/join <token-or-link>',
    brief: 'Join a conversation',
    description:
      'Joins an existing conversation using an invite token or link. Usage: /join <token-or-link>. Paste a bare token or a full invite link.',
  },
  {
    name: 'approve',
    usage: '/approve <request-id-prefix>',
    brief: 'Approve an API Gateway request',
    description:
      'Reviews a verified pending API request, including its full URL, payload, signer roster and threshold. Use an unambiguous ID prefix of at least four characters. Read all review pages and /confirm to send your signed approval.',
  },
  {"name": "gate", "usage": "/gate [invite <https-url> [floor] | retry]", "brief": "Inspect or invite a gateway", "description": "Shows verified gateway state and request/proposal statuses. /gate invite <https-url> [floor] prepares a participant invitation for review. Confirmation gives the gateway conversation keys. Activation requires its signed acceptance in chat. /gate retry resends only a saved sealed bootstrap after an HTTP failure."},
  {"name": "request", "usage": "/request <json-file>", "brief": "Review an API request", "description": "Read JSON with service, endpoint, verb, targetUrl, and optional payload, recipeName, arguments, requiredApprovals, expiresInSeconds. Reviews the exact signed request before /confirm. The author starts with one approval. Requires an accepted gateway."},
  {"name": "disapprove", "usage": "/disapprove <request-id-prefix>", "brief": "Review withdrawal of your vote", "description": "Reviews a signed disapproval for a verified pending request. Withdraws your approval; does not veto others. Requires an unambiguous ID prefix of at least four characters and /confirm."},
  {"name": "secret", "usage": "/secret <json-file>", "brief": "Review a sealed credential", "description": "Read JSON with service, value, and optional headerName, headerTemplate, ttl (seconds). The value is sealed to the accepted gateway. Review shows byte length and SHA-256, never the plaintext; the source file remains on disk. Use a private file. Nothing is posted until /confirm."},
  {"name": "propose", "usage": "/propose <json-file>", "brief": "Review a governance proposal", "description": "Read JSON with proposalType (floor_change, rules_change, member_add, member_remove) and the matching proposedFloor, proposedRules, proposedMembers [{kid, publicKey}], or removedMemberKids. IDs and public keys are base64url. Optional requiredApprovals/expiresInSeconds can raise the quorum or set expiry. Review then /confirm."},
  {"name": "gov-approve", "usage": "/gov-approve <proposal-id-prefix>", "brief": "Review a governance approval", "description": "Reviews the complete verified proposal before /confirm. Requires an unambiguous ID prefix of at least four characters. Stale, expired, applied or invalidated proposals cannot be approved."},
  {"name": "gov-disapprove", "usage": "/gov-disapprove <proposal-id-prefix>", "brief": "Review withdrawal of governance vote", "description": "Reviews a signed withdrawal of your approval on a verified pending proposal. It does not veto others. Use /confirm to send."},
  {"name": "review", "usage": "/review [page]", "brief": "Read a review page", "description": "Shows the specified page of the current review (starting at 1). Every page must be viewed before /confirm. Page count updates with terminal size."},
  {"name": "confirm", "usage": "/confirm", "brief": "Send the reviewed action", "description": "Sends only the action currently reviewed for this conversation after all pages have been viewed. Rechecks gateway, roster, epoch, expiry and workflow status. If they changed, prepare the action again."},
  {"name": "cancel", "usage": "/cancel", "brief": "Close the review", "description": "Clears the pending action and closes the review without sending it."},
  {
    name: 'name',
    usage: '/name <new-name>',
    brief: 'Rename the active conversation',
    description: 'Renames the active conversation. Usage: /name <new-name>',
  },
  {
    name: 'nick',
    usage: '/nick <name>',
    brief: 'Set your display name',
    description:
      'Sets your display name shown to others. Usage: /nick <name>',
  },
  {
    name: 'alias',
    usage: '/alias <key-id-prefix> <name>',
    brief: 'Name a contact',
    description:
      'Sets a friendly name for a contact\'s Key ID. Usage: /alias <key-id-prefix> <name>',
  },
  {
    name: 'identity',
    aliases: ['id'],
    usage: '/identity',
    brief: 'Show your identity info',
    description:
      'Shows your Key ID, public key, and config directory.',
  },
  {
    name: 'conversations',
    aliases: ['convs'],
    usage: '/conversations',
    brief: 'List all conversations',
    description:
      'Lists all conversations with their type and number.',
  },
  {
    name: 'search',
    aliases: ['grep'],
    usage: '/search <query>',
    brief: 'Search message history',
    description:
      'Searches through messages in the active conversation. Shows up to 10 matching messages with surrounding context. /grep is an alias.',
  },
  {
    name: 'notifications',
    usage: '/notifications [on|off]',
    brief: 'Toggle notification bell',
    description:
      'Toggles the terminal bell for new messages. Usage: /notifications [on|off]. Without arguments, toggles the current state.',
  },
  {
    name: 'mute',
    usage: '/mute',
    brief: 'Disable notification bell',
    description:
      'Disables the terminal bell for new messages. Alias for /notifications off.',
  },
  {
    name: 'unmute',
    usage: '/unmute',
    brief: 'Enable notification bell',
    description:
      'Enables the terminal bell for new messages. Alias for /notifications on.',
  },
  {
    name: 'select',
    aliases: ['sel'],
    usage: '/select <number>',
    brief: 'Switch to conversation by number',
    description:
      'Switches to the conversation at the given number (1-9). Same as pressing the number key directly. Usage: /select <number>',
  },
  {
    name: 'settings',
    aliases: ['config'],
    usage: '/settings',
    brief: 'Show current configuration',
    description:
      'Shows current configuration including config directory, relay URL, bell notifications status, and display name.',
  },
  {
    name: 'help',
    aliases: ['h'],
    usage: '/help [command]',
    brief: 'Show help',
    description:
      'Shows available commands. Use /help <command> for details on a specific command.',
  },
  {
    name: 'quit',
    aliases: ['q'],
    usage: '/quit',
    brief: 'Exit the application',
    description: 'Exits the TUI.',
  },
];

/**
 * Look up a command definition by name or alias.
 */
export function findCommand(name: string): CommandDef | undefined {
  const lower = name.toLowerCase();
  return COMMANDS.find(
    (c) => c.name === lower || c.aliases?.includes(lower),
  );
}

/**
 * Return commands whose name or usage starts with the given prefix.
 */
export function matchCommands(prefix: string): CommandDef[] {
  const lower = prefix.toLowerCase();
  return COMMANDS.filter(
    (c) =>
      c.name.startsWith(lower) ||
      (c.aliases?.some((a) => a.startsWith(lower)) ?? false),
  );
}
