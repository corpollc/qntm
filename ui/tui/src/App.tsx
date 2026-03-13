/**
 * App — Main TUI layout.
 *
 * Vertical stack: header, sidebar/chat pane, status bar, composer.
 * Manages identity lifecycle, conversation state, and message polling.
 */

import React, { useCallback, useEffect, useRef, useState } from 'react';
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

  const addSystemMessage = useCallback((text: string, color = 'yellow') => {
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
      addSystemMessage('Generated new identity.', 'green');
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

    addSystemMessage(`Identity loaded: ${bytesToHex(id.keyID)}`, 'cyan');
    addSystemMessage('Type /help for available commands.', 'gray');
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
      addSystemMessage(`Send failed: ${msg}`, 'red');
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
      case 'h':
        addSystemMessage('Commands: /invite [name], /join <token>, /name <name>, /nick <name>', 'cyan');
        addSystemMessage('  /alias <kid> <name>, /identity, /conversations, /approve <reqid>, /quit', 'cyan');
        addSystemMessage('Navigation: Tab=sidebar, 1-9=switch conv, Esc=scroll j/k=up/down', 'cyan');
        break;

      case 'identity':
      case 'id':
        if (identity) {
          addSystemMessage(`Key ID: ${kidHex}`, 'cyan');
          addSystemMessage(`Public key: ${bytesToHex(identity.publicKey)}`, 'cyan');
          addSystemMessage(`Config: ${configDir}`, 'cyan');
        }
        break;

      case 'invite': {
        if (!identity) {
          addSystemMessage('No identity loaded.', 'red');
          break;
        }
        const name = args.trim() || undefined;
        const { token, convId } = store.createInvite(identity, name);
        setConversations(store.loadConversations());
        setActiveConvId(convId);
        setMessages([]);
        setScrollOffset(0);
        addSystemMessage('Invite created! Share this token:', 'green');
        addSystemMessage(token, 'white');
        break;
      }

      case 'join': {
        if (!identity) {
          addSystemMessage('No identity loaded.', 'red');
          break;
        }
        const token = args.trim();
        if (!token) {
          addSystemMessage('Usage: /join <invite-token>', 'red');
          break;
        }
        try {
          const convId = store.acceptInvite(identity, token);
          setConversations(store.loadConversations());
          setActiveConvId(convId);
          setMessages(store.loadHistory(convId));
          setScrollOffset(0);
          addSystemMessage(`Joined conversation ${convId.slice(0, 12)}`, 'green');
        } catch (err: unknown) {
          const msg = err instanceof Error ? err.message : String(err);
          addSystemMessage(`Failed to join: ${msg}`, 'red');
        }
        break;
      }

      case 'name': {
        const name = args.trim();
        if (!name) {
          addSystemMessage('Usage: /name <conversation-name>', 'red');
          break;
        }
        if (!activeConvId) {
          addSystemMessage('No active conversation.', 'red');
          break;
        }
        const convs = store.loadConversations();
        const conv = convs.find((c) => c.id === activeConvId);
        if (conv) {
          conv.name = name;
          store.saveConversations(convs);
          setConversations([...convs]);
          addSystemMessage(`Conversation renamed to: ${name}`, 'green');
        }
        break;
      }

      case 'nick': {
        const name = args.trim();
        if (!name) {
          addSystemMessage('Usage: /nick <display-name>', 'red');
          break;
        }
        store.setName(name);
        setDisplayName(name);
        addSystemMessage(`Display name set to: ${name}`, 'green');
        break;
      }

      case 'alias': {
        const parts = args.trim().split(/\s+/);
        if (parts.length < 2) {
          addSystemMessage('Usage: /alias <kid-prefix> <name>', 'red');
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
        addSystemMessage(`Alias set: ${matchedKid.slice(0, 12)} -> ${aliasName}`, 'green');
        break;
      }

      case 'conversations':
      case 'convs': {
        const convs = store.loadConversations();
        if (convs.length === 0) {
          addSystemMessage('No conversations. Use /invite to create one.', 'yellow');
        } else {
          for (const [i, c] of convs.entries()) {
            const marker = c.id === activeConvId ? '>' : ' ';
            addSystemMessage(`${marker} ${i + 1}. ${c.name || c.id.slice(0, 12)} [${c.type}]`, 'cyan');
          }
        }
        break;
      }

      case 'approve': {
        const reqId = args.trim();
        if (!reqId) {
          addSystemMessage('Usage: /approve <request-id-prefix>', 'red');
          break;
        }
        addSystemMessage(`API Gateway approval for ${reqId} — not yet implemented in TUI`, 'yellow');
        break;
      }

      case '_no_conv':
        addSystemMessage('No active conversation. Use /invite or /join first.', 'yellow');
        break;

      default:
        addSystemMessage(`Unknown command: /${cmd}. Type /help for commands.`, 'red');
        break;
    }
  }, [identity, kidHex, activeConvId, configDir, store, addSystemMessage, exit]);

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
      <Box paddingX={1} justifyContent="space-between">
        <Text bold color="cyan">qntm messenger</Text>
        <Text dimColor>v0.1.0</Text>
      </Box>

      {/* Main content: sidebar + chat */}
      <Box flexDirection="row" flexGrow={1}>
        {sidebarVisible && (
          <Box width={30} flexShrink={0}>
            <Sidebar
              conversations={conversations}
              activeId={activeConvId}
              unread={unread}
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
        activeConversation={activeConvId}
        activeConversationName={activeConvName}
        connected={connected}
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
