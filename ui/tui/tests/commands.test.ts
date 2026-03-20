import { describe, expect, it } from 'vitest';
import { findCommand, matchCommands } from '../src/lib/commands.js';

describe('commands', () => {
  it('finds commands by name or alias case-insensitively', () => {
    expect(findCommand('invite')?.usage).toBe('/invite [name]');
    expect(findCommand('ID')?.name).toBe('identity');
    expect(findCommand('convs')?.name).toBe('conversations');
    expect(findCommand('missing')).toBeUndefined();
  });

  it('matches prefixes against command names and aliases', () => {
    expect(matchCommands('in').map((command) => command.name)).toEqual(['invite']);
    expect(matchCommands('gr').map((command) => command.name)).toEqual(['search']);
    expect(matchCommands('co').map((command) => command.name)).toEqual(['conversations', 'settings']);
  });
});
