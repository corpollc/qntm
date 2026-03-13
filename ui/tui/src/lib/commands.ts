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
    usage: '/join <token>',
    brief: 'Join a conversation',
    description:
      'Joins an existing conversation using an invite token. Usage: /join <token>. Paste the full invite token you received.',
  },
  {
    name: 'approve',
    usage: '/approve <request-id-prefix>',
    brief: 'Approve an API Gateway request',
    description:
      'Approves an API Gateway request. Usage: /approve <request-id-prefix>. You can use just the first few characters of the request ID.',
  },
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
