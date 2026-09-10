/**
 * App — Main TUI layout.
 *
 * Vertical stack: header, sidebar/chat pane, status bar, composer.
 * Manages identity lifecycle, conversation state, and message polling.
 */

import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Box, Text, useApp, useInput, useStdout } from 'ink';
import { DropboxClient, inviteFromURL, inviteToURL } from '@corpollc/qntm';
import wrapAnsi from 'wrap-ansi';
import { createRequire } from 'node:module';
const { version: packageVersion } = createRequire(import.meta.url)('../package.json') as { version: string };
import { GatewayActions, terminalText, type GatewayReview } from './lib/gateway.js';

import { Store, bytesToHex, type StoredConversation, type StoredMessage } from './lib/store.js';
import { applyIncomingEnvelope, sendMessage } from './lib/poller.js';

import Sidebar from './components/Sidebar.js';
import ChatPane from './components/ChatPane.js';
import StatusBar from './components/StatusBar.js';
import Composer from './components/Composer.js';

import type { DropboxSubscription, Identity } from '@corpollc/qntm';
import { keyIDToString } from '@corpollc/qntm';
import { COMMANDS, findCommand, matchCommands } from './lib/commands.js';
import { theme } from './lib/theme.js';
import { groupNotice, type GroupSubscription } from './lib/groups.js';
import { runGroupCommand } from './lib/group-commands.js';

// ── Types ────────────────────────────────────────────────────────────────

interface SystemMessage {
  text: string;
  color: string;
  createdAt: string;
  afterId?: string;
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
  const [bellEnabled, setBellEnabled] = useState(true);
  const [sidebarFocusIdx, setSidebarFocusIdx] = useState(0);

  const subscriptionsRef = useRef<Map<string, DropboxSubscription | GroupSubscription>>(new Map());
  const connectedConversationsRef = useRef(new Set<string>());
  const activeConvIdRef = useRef<string | null>(null);

  const terminalHeight = stdout?.rows ?? 24;
  const terminalWidth = stdout?.columns ?? 80;
  const actions = useMemo(() => identity ? new GatewayActions(store, dropbox, identity) : null, [identity, store, dropbox]);
  const [review, setReview] = useState<(GatewayReview & { confirmable: boolean }) | null>(null);
  const [reviewPage, setReviewPage] = useState(0);
  const [reviewNotice, setReviewNotice] = useState('');
  const [gatewayBusy, setGatewayBusy] = useState(false);
  const gatewayBusyRef = useRef(false);
  const reviewedPages = useRef(new Set<number>());
  const composerEditing = useRef(false);
  const groupBusy = useRef(false);
  const reviewLines = useMemo(() => review ? wrapAnsi(review.details, Math.max(20, terminalWidth - 6), { hard: true, trim: false }).split('\n') : [], [review, terminalWidth]);
  const pageSize = Math.max(3, terminalHeight - 13);
  const pageCount = Math.max(1, Math.ceil(reviewLines.length / pageSize));
  useEffect(() => { reviewedPages.current = new Set([0]); setReviewPage(0); }, [terminalWidth, terminalHeight]);
  const showReview = (value: GatewayReview, confirmable: boolean) => {
    reviewedPages.current = new Set([0]); setReviewPage(0); setReviewNotice(''); setReview({ ...value, confirmable });
  };

  // ── System message helper ──────────────────────────────────────────

  const addSystemMessage = useCallback((text: string, color: string = theme.system) => {
    const afterId = activeConvIdRef.current ? store.loadHistory(activeConvIdRef.current).at(-1)?.id : undefined;
    setSystemMessages((prev) => {
      const next = [...prev, { text: terminalText(text), color, createdAt: new Date().toISOString(), afterId }];
      return next.length > 50 ? next.slice(-50) : next;
    });
  }, [store]);

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
      activeConvIdRef.current = first.id;
      setMessages(store.loadHistory(first.id));
    }

    addSystemMessage(`Keypair loaded: ${bytesToHex(id.keyID)}`, theme.info);
    addSystemMessage('Type /help for available commands.', theme.textDim);
  }, [store, addSystemMessage]);

  useEffect(() => {
    activeConvIdRef.current = activeConvId;
  }, [activeConvId]);

  // ── Live subscriptions ────────────────────────────────────────────

  useEffect(() => {
    if (!identity) return;
    const nextSubscriptions = new Map<string, DropboxSubscription | GroupSubscription>();
    subscriptionsRef.current.forEach((subscription) => subscription.close());
    subscriptionsRef.current = nextSubscriptions;
    connectedConversationsRef.current = new Set();
    setConnected(false);

    for (const conv of store.loadConversations()) {
      if (conv.managedGroup) {
        let seen = new Set(store.loadHistory(conv.id).map(message => message.id));
        const subscription = store.groups.watch(conv.id, {
          onChange: () => {
            try {
              const history = store.loadHistory(conv.id);
              const count = history.filter(message => !seen.has(message.id) && message.direction === 'incoming').length;
              seen = new Set(history.map(message => message.id));
              setConversations(store.loadConversations());
              if (activeConvIdRef.current === conv.id) setMessages(history);
              else if (count) {
                setUnread(previous => ({ ...previous, [conv.id]: (previous[conv.id] || 0) + count }));
                if (bellEnabled) process.stdout.write('\x07');
              }
            } catch (error) { addSystemMessage(error instanceof Error ? error.message : 'Cannot read group state.', theme.error); }
          },
          onStatus: (online, error) => {
            if (online) connectedConversationsRef.current.add(conv.id);
            else connectedConversationsRef.current.delete(conv.id);
            setConnected(connectedConversationsRef.current.size > 0);
            if (error) addSystemMessage(error, theme.error);
          },
        });
        nextSubscriptions.set(conv.id, subscription);
        continue;
      }
      const convCrypto = store.getConversationCrypto(conv.id);
      if (!convCrypto) continue;

      const subscription = dropbox.subscribeMessages(convCrypto.id, store.loadCursor(conv.id), {
        getCursor: () => store.loadCursor(conv.id),
        onOpen: () => {
          connectedConversationsRef.current.add(conv.id);
          setConnected(connectedConversationsRef.current.size > 0);
        },
        onClose: () => {
          connectedConversationsRef.current.delete(conv.id);
          setConnected(connectedConversationsRef.current.size > 0);
        },
        onError: () => {
          connectedConversationsRef.current.delete(conv.id);
          setConnected(connectedConversationsRef.current.size > 0);
        },
        onReconnect: () => {
          connectedConversationsRef.current.delete(conv.id);
          setConnected(connectedConversationsRef.current.size > 0);
        },
        onMessage: async ({ seq, envelope }) => {
          const message = await applyIncomingEnvelope(store, dropbox, identity, conv.id, envelope, seq);
          setConversations(store.loadConversations());
          if (!message) {
            return;
          }

          if (activeConvIdRef.current === conv.id) {
            setMessages(store.loadHistory(conv.id));
            setScrollOffset(0);
            return;
          }

          setUnread((prev) => ({
            ...prev,
            [conv.id]: (prev[conv.id] || 0) + 1,
          }));
          if (bellEnabled) {
            process.stdout.write('\x07');
          }
        },
      });

      nextSubscriptions.set(conv.id, subscription);
    }

    return () => {
      for (const subscription of nextSubscriptions.values()) {
        subscription.close();
      }
      connectedConversationsRef.current = new Set();
      setConnected(false);
    };
  }, [identity, store, dropbox, bellEnabled, conversations.map((conv) => conv.id).sort().join('|')]);

  // ── Terminal title with unread count ─────────────────────────────

  const totalUnread = Object.values(unread).reduce((a, b) => a + b, 0);

  useEffect(() => {
    process.stdout.write(`\x1b]0;qntm messenger${totalUnread > 0 ? ` (${totalUnread})` : ''}\x07`);
  }, [totalUnread]);

  // Reset terminal title on unmount
  useEffect(() => {
    return () => {
      process.stdout.write('\x1b]0;\x07');
    };
  }, []);

  // ── Conversation selection helper ─────────────────────────────────

  const selectConversationByIndex = useCallback((idx: number) => {
    if (idx >= 0 && idx < conversations.length) {
      const conv = conversations[idx];
      setActiveConvId(conv.id);
      setMessages(store.loadHistory(conv.id));
      setScrollOffset(0);
      setSidebarFocusIdx(idx);
      setUnread((prev) => ({ ...prev, [conv.id]: 0 }));
    }
  }, [conversations, store]);

  // ── Keyboard navigation ────────────────────────────────────────────

  useInput((input, key) => {
    if (composerEditing.current || review) return;
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

    // Up/Down arrows navigate sidebar focus (when sidebar is visible)
    if (sidebarVisible && conversations.length > 0) {
      if (key.upArrow) {
        setSidebarFocusIdx((i) => (i > 0 ? i - 1 : conversations.length - 1));
        return;
      }
      if (key.downArrow) {
        setSidebarFocusIdx((i) => (i < conversations.length - 1 ? i + 1 : 0));
        return;
      }
      if (key.return) {
        selectConversationByIndex(sidebarFocusIdx);
        return;
      }
    }

    // Number keys to switch conversations (only outside scroll mode)
    if (/^[1-9]$/.test(input)) {
      selectConversationByIndex(parseInt(input, 10) - 1);
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
    if (['group', 'contact'].includes(cmd.toLowerCase()) || (cmd.toLowerCase() === 'join' && args.includes('#group='))) {
      void (async () => {
        if (groupBusy.current) { addSystemMessage('Group command is still running. Wait for its receipt, then /group retry if an operation is pending.', theme.warning); return; }
        groupBusy.current = true;
        try {
          const result = await runGroupCommand(store, cmd.toLowerCase(), args, activeConvId);
          if (result.conversationId) { activeConvIdRef.current = result.conversationId; setActiveConvId(result.conversationId); }
          setConversations(store.loadConversations());
          if (activeConvIdRef.current) setMessages(store.loadHistory(activeConvIdRef.current));
          setScrollOffset(0); addSystemMessage(result.text, theme.info);
        } catch (error) {
          setConversations(store.loadConversations());
          addSystemMessage(error instanceof Error ? error.message : 'Group command failed.', theme.error);
        } finally { groupBusy.current = false; }
      })();
      return;
    }
    const gatewayCommands = ['gate', 'request', 'secret', 'propose', 'approve', 'disapprove', 'gov-approve', 'gov-disapprove', 'review', 'confirm', 'cancel'];
    if (gatewayCommands.includes(cmd.toLowerCase())) {
      void (async () => {
        if (gatewayBusyRef.current) {
          const notice = 'Gateway action is still running. Wait for its receipt before retrying.';
          setReviewNotice(notice); addSystemMessage(notice, theme.warning);
          return;
        }
        gatewayBusyRef.current = true; setGatewayBusy(true);
        try {
          if (!actions || !activeConvId) throw new Error('Select a conversation first.');
          const command = cmd.toLowerCase();
          if (command === 'cancel') {
            actions.cancel(); setReview(null); setReviewNotice('');
            addSystemMessage('Review closed. No action sent.', theme.info);
          } else if (command === 'review') {
            if (!review) throw new Error('No review open. Prepare an action or use /gate.');
            const page = args.trim() ? Number(args.trim()) - 1 : reviewPage;
            if (!Number.isInteger(page) || page < 0 || page >= pageCount) throw new Error(`Use /review <page> between 1 and ${pageCount}.`);
            reviewedPages.current.add(page); setReviewPage(page); setReviewNotice('');
          } else if (command === 'confirm') {
            if (!review?.confirmable) throw new Error('No action awaiting confirmation.');
            if (reviewedPages.current.size !== pageCount) throw new Error(`Review all ${pageCount} pages with /review <page> before confirming.`);
            setReview(null);
            const result = await actions.confirm(activeConvId);
            setConversations(store.loadConversations()); setMessages(store.loadHistory(activeConvId));
            addSystemMessage(result, theme.success);
          } else if (command === 'gate' && !args.trim()) {
            actions.cancel(); showReview({ title: 'Verified gateway state', details: terminalText(actions.status(activeConvId)) }, false);
          } else if (command === 'gate' && args.trim() === 'retry') {
            actions.cancel(); setReview(null); addSystemMessage(await actions.retry(activeConvId), theme.info);
          } else {
            const prepared = await actions.prepare(activeConvId, command, args);
            showReview(prepared, true);
          }
        } catch (error) {
          const message = terminalText(error instanceof Error ? error.message : 'Gateway action failed');
          setReviewNotice(message); addSystemMessage(message, theme.error);
        } finally { gatewayBusyRef.current = false; setGatewayBusy(false); }
      })();
      return;
    }
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
          addSystemMessage('Navigation: Tab=sidebar, Up/Down+Enter=select, 1-9=switch, Esc=scroll j/k', theme.info);
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
          addSystemMessage(`Version: v${packageVersion}`, theme.info);
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
        addSystemMessage('Invite created! Share this link:', theme.success);
        addSystemMessage(inviteToURL(inviteFromURL(token), 'https://chat.corpo.llc'), theme.text);
        addSystemMessage('They can also join with the CLI: uvx qntm convo join <token>', theme.textDim);
        break;
      }

      case 'join': {
        if (!identity) {
          addSystemMessage('No identity loaded.', theme.error);
          break;
        }
        const token = args.trim();
        if (!token) {
          addSystemMessage('Usage: /join <invite-link-or-token>', theme.error);
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
        if (store.findConversation(activeConvId)?.managedGroup) {
          void store.groups.run(['convo', 'name', '--', activeConvId, name]).then(() => {
            setConversations(store.loadConversations()); addSystemMessage(`Conversation renamed to: ${name}`, theme.success);
          }).catch(error => addSystemMessage(error instanceof Error ? error.message : 'Rename failed.', theme.error));
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

      case 'notifications': {
        const arg = args.trim().toLowerCase();
        if (arg === 'on') {
          setBellEnabled(true);
          addSystemMessage('Notifications: on', theme.success);
        } else if (arg === 'off') {
          setBellEnabled(false);
          addSystemMessage('Notifications: off', theme.warning);
        } else {
          setBellEnabled((prev) => {
            const next = !prev;
            addSystemMessage(`Notifications: ${next ? 'on' : 'off'}`, next ? theme.success : theme.warning);
            return next;
          });
        }
        break;
      }

      case 'mute':
        setBellEnabled(false);
        addSystemMessage('Notifications: off', theme.warning);
        break;

      case 'unmute':
        setBellEnabled(true);
        addSystemMessage('Notifications: on', theme.success);
        break;

      case 'select':
      case 'sel': {
        const num = parseInt(args.trim(), 10);
        if (isNaN(num) || num < 1) {
          addSystemMessage('Usage: /select <number> (1-9)', theme.error);
          break;
        }
        const selIdx = num - 1;
        if (selIdx >= conversations.length) {
          addSystemMessage(`No conversation at position ${num}. You have ${conversations.length} conversation(s).`, theme.error);
        } else {
          selectConversationByIndex(selIdx);
          const selConv = conversations[selIdx];
          addSystemMessage(`Switched to: ${selConv.name || selConv.id.slice(0, 12)}`, theme.success);
        }
        break;
      }

      case 'settings':
      case 'config':
        addSystemMessage('Current configuration:', theme.info);
        addSystemMessage(`  Config directory: ${configDir}`, theme.info);
        addSystemMessage(`  Relay URL: ${dropboxUrl}`, theme.info);
        addSystemMessage(`  Bell notifications: ${bellEnabled ? 'on' : 'off'}`, theme.info);
        addSystemMessage(`  Display name: ${displayName || '(not set)'}`, theme.info);
        break;

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
  }, [identity, kidHex, activeConvId, configDir, dropboxUrl, bellEnabled, displayName, conversations, store, addSystemMessage, exit, selectConversationByIndex, actions, review, reviewPage, pageCount]);

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

  // Insert local notices after the message visible when they were issued;
  // preserve relay order instead of sorting by sender-controlled timestamps.
  const notices = systemMessages.map((sm, i) => ({
    afterId: sm.afterId,
    message: { id: `sys-${i}`, conversationId: activeConvId || '', direction: 'incoming' as const,
      sender: 'system', senderKey: '', bodyType: 'system', text: sm.text, createdAt: sm.createdAt },
  }));
  const ids = new Set(messages.map(message => message.id));
  const allMessages: StoredMessage[] = notices.filter(notice => !notice.afterId || !ids.has(notice.afterId)).map(notice => notice.message);
  for (const message of messages) {
    allMessages.push(message, ...notices.filter(notice => notice.afterId === message.id).map(notice => notice.message));
  }

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
            {terminalText(activeConvName || 'qntm messenger').replace(/[\r\n\t]/g, ' ')}
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
        {sidebarVisible && !review && (
          <Box width={30} flexShrink={0}>
            <Sidebar
              conversations={conversations}
              activeId={activeConvId}
              unread={unread}
              lastMessages={lastMessages}
              focusIndex={sidebarFocusIdx}
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
          {review ? (
            <Box borderStyle="single" borderColor={theme.warning} flexDirection="column" paddingX={1} flexGrow={1}>
              <Text bold color={theme.warning}>{review.title} — page {reviewPage + 1}/{pageCount}</Text>
              <Text>{reviewLines.slice(reviewPage * pageSize, (reviewPage + 1) * pageSize).join('\n')}</Text>
              <Box flexGrow={1} />
              <Text color={theme.warning}>{reviewNotice || (review.confirmable ? 'Read every page, then /confirm to send. /cancel closes without sending.' : '/cancel closes this view.')}</Text>
              <Text dimColor>/review &lt;page&gt; | {reviewedPages.current.size}/{pageCount} pages viewed{gatewayBusy ? ' | working…' : ''}</Text>
            </Box>
          ) : <ChatPane
            messages={allMessages}
            conversationName={activeConvName}
            scrollOffset={scrollOffset}
            terminalHeight={terminalHeight - (groupNotice(conversations.find(conversation => conversation.id === activeConvId)) ? 2 : 0)}
            sidebarVisible={sidebarVisible}
            resolveContact={(kid) => store.resolveContact(kid)}
          />}
        </Box>
      </Box>

      {/* Status bar */}
      {groupNotice(conversations.find(conversation => conversation.id === activeConvId)) && (
        <Box paddingX={1}><Text color={theme.warning}>{groupNotice(conversations.find(conversation => conversation.id === activeConvId))}</Text></Box>
      )}
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
        onEditingChanged={(editing) => { composerEditing.current = editing; }}
      />
    </Box>
  );
}
