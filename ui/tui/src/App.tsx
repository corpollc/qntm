/**
 * App — Main TUI layout.
 *
 * Vertical stack: header, sidebar/chat pane, status bar, composer.
 * Manages identity lifecycle, conversation state, and message polling.
 */

import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Box, Text, useApp, useInput, useStdout } from 'ink';
import { DropboxClient } from '@corpollc/qntm';

import { Store, bytesToHex, type StoredConversation, type StoredMessage } from './lib/store.js';
import { pollConversation, sendMessage } from './lib/poller.js';

import Sidebar from './components/Sidebar.js';
import ChatPane from './components/ChatPane.js';
import StatusBar from './components/StatusBar.js';
import Composer from './components/Composer.js';

import type { Identity } from '@corpollc/qntm';
import { keyIDToString } from '@corpollc/qntm';
import { COMMANDS, findCommand, matchCommands } from './lib/commands.js';
import { theme } from './lib/theme.js';

// ── Types ────────────────────────────────────────────────────────────────

interface SystemMessage {
  text: string;
  color: string;
}

interface AppProps {
  configDir: string;
  dropboxUrl: string;
}

// ── App ──────────────────────────────────────────────────────────────────

export default function App({ configDir, dropboxUrl }: AppProps) {
  const { exit } = useApp();
  const { stdout } = useStdout();

  // Core state
  const [store] = useState(() => new Store(configDir, dropboxUrl));
  const [dropbox] = useState(() => new DropboxClient(dropboxUrl));
  const [identity, setIdentity] = useState<Identity | null>(null);
  const [kidHex, setKidHex] = useState('');
  const [displayName, setDisplayName] = useState('');

  // Conversation state
  const [conversations, setConversations] = useState<StoredConversation[]>([]);
  const [activeConvId, setActiveConvId] = useState<string | null>(null);
  const [messages, setMessages] = useState<StoredMessage[]>([]);
  const [unread, setUnread] = useState<Record<string, number>>({});

  // UI state
  const [sidebarVisible, setSidebarVisible] = useState(true);
  const [scrollOffset, setScrollOffset] = useState(0);
  const [scrollMode, setScrollMode] = useState(false);
  const [systemMessages, setSystemMessages] = useState<SystemMessage[]>([]);
  const [connected, setConnected] = useState(false);

  const pollTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const terminalHeight = stdout?.rows ?? 24;

  // ── System message helper ──────────────────────────────────────────

  const addSystemMessage = useCallback((text: string, color: string = theme.system) => {
    setSystemMessages((prev) => {
      const next = [...prev, { text, color }];
      return next.length > 50 ? next.slice(-50) : next;
    });
  }, []);

  // ── Initialisation ─────────────────────────────────────────────────

  useEffect(() => {
    let id = store.loadIdentity();
    if (!id) {
      id = store.generateIdentity();
      addSystemMessage('Generated new keypair.', theme.success);
      addSystemMessage('Your keypair is ready. Use /invite to start a conversation.', theme.textDim);
    }
    setIdentity(id);
    setKidHex(bytesToHex(id.keyID));
    setDisplayName(store.getName());

    const convs = store.loadConversations();
    setConversations(convs);
    if (convs.length > 0) {
      const first = convs[0];
      setActiveConvId(first.id);
      setMessages(store.loadHistory(first.id));
    }

    addSystemMessage(`Keypair loaded: ${bytesToHex(id.keyID)}`, theme.info);
    addSystemMessage('Type /help for available commands.', theme.textDim);
  }, [store, addSystemMessage]);

  // ── Polling ────────────────────────────────────────────────────────

  useEffect(() => {
    if (!identity) return;

    const doPoll = async () => {
      const convs = store.loadConversations();
      let gotMessages = false;

      for (const conv of convs) {
        try {
          const result = await pollConversation(store, dropbox, identity, conv.id);
          if (result.messages.length > 0) {
            gotMessages = true;
            if (conv.id === activeConvId) {
              setMessages(store.loadHistory(conv.id));
              setScrollOffset(0);
            } else {
              setUnread((prev) => ({
                ...prev,
                [conv.id]: (prev[conv.id] || 0) + result.messages.length,
              }));
            }
          }
          setConnected(true);
        } catch {
          setConnected(false);
        }
      }
    };

    // Initial poll
    doPoll();

    // Poll every 3 seconds
    pollTimerRef.current = setInterval(doPoll, 3000);

    return () => {
      if (pollTimerRef.current) {
        clearInterval(pollTimerRef.current);
        pollTimerRef.current = null;
      }
    };
  }, [identity, activeConvId, store, dropbox]);

  // ── Keyboard navigation ────────────────────────────────────────────

  useInput((input, key) => {
    // Tab toggles sidebar
    if (key.tab) {
      setSidebarVisible((v) => !v);
      return;
    }

    // Escape enters transient scroll mode
    if (key.escape) {
      setScrollMode((m) => !m);
      return;
    }

    // In scroll mode: j/k scroll, anything else exits scroll mode
    if (scrollMode) {
      if (input === 'j') {
        setScrollOffset((o) => Math.max(0, o - 1));
        return;
      }
      if (input === 'k') {
        setScrollOffset((o) => o + 1);
        return;
      }
      // Any other key exits scroll mode (keystroke passes through to composer)
      setScrollMode(false);
      return;
    }

    // Number keys to switch conversations (only outside scroll mode)
    if (/^[1-9]$/.test(input)) {
      const idx = parseInt(input, 10) - 1;
      if (idx < conversations.length) {
        const conv = conversations[idx];
        setActiveConvId(conv.id);
        setMessages(store.loadHistory(conv.id));
        setScrollOffset(0);
        setUnread((prev) => ({ ...prev, [conv.id]: 0 }));
      }
      return;
    }
  });

  // ── Send message ───────────────────────────────────────────────────

  const handleSend = useCallback(async (text: string) => {
    if (!identity || !activeConvId) return;

    try {
      await sendMessage(store, dropbox, identity, activeConvId, text);
      setMessages(store.loadHistory(activeConvId));
      setScrollOffset(0);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      addSystemMessage(`Send failed: ${msg}`, theme.error);
    }
  }, [identity, activeConvId, store, dropbox, addSystemMessage]);

  // ── Slash commands ─────────────────────────────────────────────────

  const handleCommand = useCallback((cmd: string, args: string) => {
    switch (cmd.toLowerCase()) {
      case 'quit':
      case 'q':
        exit();
        break;

      case 'help':
      case 'h': {
        const helpArg = args.trim().toLowerCase().replace(/^\//, '');
        if (helpArg) {
          const def = findCommand(helpArg);
          if (def) {
            addSystemMessage(def.description, theme.info);
          } else {
            addSystemMessage(`Unknown command "${helpArg}". Type /help to see available commands.`, theme.error);
          }
        } else {
          for (const c of COMMANDS) {
            if (c.name === 'help' || c.name === 'quit') continue;
            addSystemMessage(`  ${c.usage} — ${c.brief}`, theme.info);
          }
          addSystemMessage('Navigation: Tab=sidebar, 1-9=switch conv, Esc=scroll j/k', theme.info);
          addSystemMessage('Type /help <command> for details.', theme.textDim);
        }
        break;
      }

      case 'identity':
      case 'id':
        if (identity) {
          addSystemMessage(`Key ID: ${kidHex}`, theme.info);
          addSystemMessage(`Public key: ${bytesToHex(identity.publicKey)}`, theme.info);
          addSystemMessage(`Config: ${configDir}`, theme.info);
        }
        break;

      case 'invite': {
        if (!identity) {
          addSystemMessage('No identity loaded.', theme.error);
          break;
        }
        const name = args.trim() || undefined;
        const { token, convId } = store.createInvite(identity, name);
        setConversations(store.loadConversations());
        setActiveConvId(convId);
        setMessages([]);
        setScrollOffset(0);
        addSystemMessage('Invite created! Share this token:', theme.success);
        addSystemMessage(token, theme.text);
        addSystemMessage('Share this token with your contact. They can join with: /join <token>', theme.textDim);
        break;
      }

      case 'join': {
        if (!identity) {
          addSystemMessage('No identity loaded.', theme.error);
          break;
        }
        const token = args.trim();
        if (!token) {
          addSystemMessage('Usage: /join <invite-token>', theme.error);
          break;
        }
        try {
          const convId = store.acceptInvite(identity, token);
          setConversations(store.loadConversations());
          setActiveConvId(convId);
          setMessages(store.loadHistory(convId));
          setScrollOffset(0);
          addSystemMessage(`Joined conversation ${convId.slice(0, 12)}`, theme.success);
          addSystemMessage("You're now in the conversation. Type a message to say hello!", theme.textDim);
        } catch (err: unknown) {
          const msg = err instanceof Error ? err.message : String(err);
          addSystemMessage(`Failed to join: ${msg}`, theme.error);
        }
        break;
      }

      case 'name': {
        const name = args.trim();
        if (!name) {
          addSystemMessage('Usage: /name <conversation-name>', theme.error);
          break;
        }
        if (!activeConvId) {
          addSystemMessage('No active conversation.', theme.error);
          break;
        }
        const convs = store.loadConversations();
        const conv = convs.find((c) => c.id === activeConvId);
        if (conv) {
          conv.name = name;
          store.saveConversations(convs);
          setConversations([...convs]);
          addSystemMessage(`Conversation renamed to: ${name}`, theme.success);
          addSystemMessage('Conversation renamed. Other participants will see the old name.', theme.textDim);
        }
        break;
      }

      case 'nick': {
        const name = args.trim();
        if (!name) {
          addSystemMessage('Usage: /nick <display-name>', theme.error);
          break;
        }
        store.setName(name);
        setDisplayName(name);
        addSystemMessage(`Display name set to: ${name}`, theme.success);
        addSystemMessage('Your display name is now visible to others in conversations.', theme.textDim);
        break;
      }

      case 'alias': {
        const parts = args.trim().split(/\s+/);
        if (parts.length < 2) {
          addSystemMessage('Usage: /alias <kid-prefix> <name>', theme.error);
          break;
        }
        const [kidPrefix, ...nameParts] = parts;
        const aliasName = nameParts.join(' ');
        // Find the full kid that matches the prefix
        const allConvs = store.loadConversations();
        let matchedKid = kidPrefix;
        for (const c of allConvs) {
          for (const p of c.participants) {
            if (p.startsWith(kidPrefix.toLowerCase())) {
              matchedKid = p;
              break;
            }
          }
        }
        store.setContact(matchedKid, aliasName);
        addSystemMessage(`Alias set: ${matchedKid.slice(0, 12)} -> ${aliasName}`, theme.success);
        addSystemMessage('Contact alias saved. Their messages will now show this name.', theme.textDim);
        break;
      }

      case 'conversations':
      case 'convs': {
        const convs = store.loadConversations();
        if (convs.length === 0) {
          addSystemMessage('No conversations. Use /invite to create one.', theme.warning);
        } else {
          for (const [i, c] of convs.entries()) {
            const marker = c.id === activeConvId ? '>' : ' ';
            addSystemMessage(`${marker} ${i + 1}. ${c.name || c.id.slice(0, 12)} [${c.type}]`, theme.info);
          }
        }
        break;
      }

      case 'search':
      case 'grep': {
        const query = args.trim();
        if (!query) {
          addSystemMessage('Usage: /search <query>', theme.error);
          break;
        }
        if (!activeConvId) {
          addSystemMessage('No active conversation to search.', theme.warning);
          break;
        }
        const history = store.loadHistory(activeConvId);
        const lowerQuery = query.toLowerCase();
        const matches = history.filter((m) => m.text.toLowerCase().includes(lowerQuery));
        if (matches.length === 0) {
          addSystemMessage(`No messages matching '${query}'`, theme.warning);
        } else {
          addSystemMessage(`Found ${matches.length} match${matches.length === 1 ? '' : 'es'} for '${query}':`, theme.info);
          const shown = matches.slice(0, 10);
          for (const m of shown) {
            const time = new Date(m.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
            let sender = m.sender;
            if (m.direction === 'incoming' && m.senderKey) {
              const alias = store.resolveContact(m.senderKey);
              if (alias) sender = alias;
              else sender = m.senderKey.slice(0, 12) + '..';
            }
            // Show a snippet around the match (up to 80 chars)
            const idx = m.text.toLowerCase().indexOf(lowerQuery);
            const snippetStart = Math.max(0, idx - 30);
            const snippetEnd = Math.min(m.text.length, idx + query.length + 30);
            const prefix = snippetStart > 0 ? '...' : '';
            const suffix = snippetEnd < m.text.length ? '...' : '';
            const snippet = prefix + m.text.slice(snippetStart, snippetEnd) + suffix;
            addSystemMessage(`  [${time}] ${sender}: ${snippet}`, theme.text);
          }
          if (matches.length > 10) {
            addSystemMessage(`  ...and ${matches.length - 10} more`, theme.textDim);
          }
        }
        break;
      }

      case 'approve': {
        const reqId = args.trim();
        if (!reqId) {
          addSystemMessage('Usage: /approve <request-id-prefix>', theme.error);
          break;
        }
        addSystemMessage(`API Gateway approval for ${reqId} — not yet implemented in TUI`, theme.warning);
        break;
      }

      case '_no_conv':
        addSystemMessage('No active conversation. Use /invite or /join first.', theme.warning);
        break;

      default: {
        const suggestions = matchCommands(cmd.toLowerCase());
        if (suggestions.length > 0) {
          const names = suggestions.map((c) => `/${c.name}`).join(', ');
          addSystemMessage(`Unknown command: /${cmd}. Did you mean ${names}?`, theme.error);
        } else {
          // Try substring match as fallback
          const lower = cmd.toLowerCase();
          const substringMatch = COMMANDS.find(
            (c) => c.name.includes(lower) || (c.aliases?.some((a) => a.includes(lower)) ?? false),
          );
          if (substringMatch) {
            addSystemMessage(`Unknown command: /${cmd}. Did you mean /${substringMatch.name}?`, theme.error);
          } else {
            addSystemMessage(`Unknown command: /${cmd}. Type /help for commands.`, theme.error);
          }
        }
        break;
      }
    }
  }, [identity, kidHex, activeConvId, configDir, store, addSystemMessage, exit]);

  // ── Last message per conversation ─────────────────────────────────

  const lastMessages = useMemo(() => {
    const result: Record<string, StoredMessage> = {};
    for (const conv of conversations) {
      const history = store.loadHistory(conv.id);
      if (history.length > 0) {
        result[conv.id] = history[history.length - 1];
      }
    }
    return result;
    // Re-derive when messages change (active conv) or conversations list changes
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [conversations, messages, store]);

  // ── Active conversation name ───────────────────────────────────────

  const activeConvName =
    conversations.find((c) => c.id === activeConvId)?.name ||
    (activeConvId ? activeConvId.slice(0, 12) : '');

  // ── Merged message list (chat + system) ────────────────────────────

  // We show system messages as part of the chat pane by converting them
  const allMessages: StoredMessage[] = [
    ...messages,
    ...systemMessages.map((sm, i) => ({
      id: `sys-${i}`,
      conversationId: activeConvId || '',
      direction: 'incoming' as const,
      sender: 'system',
      senderKey: '',
      bodyType: 'system',
      text: sm.text,
      createdAt: new Date().toISOString(),
    })),
  ];

  // ── Render ─────────────────────────────────────────────────────────

  return (
    <Box flexDirection="column" height={terminalHeight}>
      {/* Header */}
      <Box paddingX={1} flexDirection="row" justifyContent="space-between">
        <Box width={14}>
          <Text>
            <Text color={connected ? theme.success : theme.error}>{connected ? '\u25cf' : '\u25cb'}</Text>
            {' '}
            <Text dimColor>{connected ? 'online' : 'offline'}</Text>
          </Text>
        </Box>
        <Box flexGrow={1} justifyContent="center">
          <Text bold color={theme.brand}>
            {activeConvName || 'qntm messenger'}
          </Text>
        </Box>
        <Box width={32} justifyContent="flex-end">
          <Text dimColor>
            {scrollMode ? 'j/k: scroll | Esc: exit' : 'Tab: sidebar | Esc: scroll | /help'}
          </Text>
        </Box>
      </Box>

      {/* Main content: sidebar + chat */}
      <Box flexDirection="row" flexGrow={1}>
        {sidebarVisible && (
          <Box width={30} flexShrink={0}>
            <Sidebar
              conversations={conversations}
              activeId={activeConvId}
              unread={unread}
              lastMessages={lastMessages}
              onSelect={(id) => {
                setActiveConvId(id);
                setMessages(store.loadHistory(id));
                setScrollOffset(0);
                setUnread((prev) => ({ ...prev, [id]: 0 }));
              }}
              visible={true}
            />
          </Box>
        )}

        <Box flexDirection="column" flexGrow={1}>
          <ChatPane
            messages={allMessages}
            conversationName={activeConvName}
            scrollOffset={scrollOffset}
            terminalHeight={terminalHeight}
            resolveContact={(kid) => store.resolveContact(kid)}
          />
        </Box>
      </Box>

      {/* Status bar */}
      <StatusBar
        kid={kidHex}
        name={displayName}
        connected={connected}
        conversationCount={conversations.length}
        scrollMode={scrollMode}
        scrollOffset={scrollOffset}
      />

      {/* Composer */}
      <Composer
        onSend={handleSend}
        onCommand={handleCommand}
        activeConversation={activeConvId}
      />
    </Box>
  );
}
