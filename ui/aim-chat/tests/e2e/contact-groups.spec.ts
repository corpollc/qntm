import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { resolve, join } from 'node:path'
import { test, expect, type Page } from '@playwright/test'
import { generateIdentity, DropboxClient, openGroupWelcome, parseGroupLink, createGroupSession, receiveGroupEvent, groupSessionConversation,
  createMessage, serializeEnvelope, deserializeEnvelope, isGroupWelcomeEnvelope, prepareGroupSessionAddition, assertGroupAdditionAccepted,
  createGroupControlMessage, createGroupRemoveBody, prepareGroupSessionRekey, createGroupLink, prepareGroupWelcomeRefresh } from '@corpollc/qntm'
import type { Identity, GroupSessionState } from '@corpollc/qntm'
import { WebSocket } from 'ws'
import { RelayStub } from './fixtures/relay-stub'
import { gatewayResultFixture } from './fixtures/gateway-result'
const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString('hex')
let relay: Pick<RelayStub, 'url' | 'stop' | 'expire'>
let browserIdentity: Identity
let originalWebSocket: typeof globalThis.WebSocket

test.beforeEach(async ({ page, context }) => {
  originalWebSocket = globalThis.WebSocket
  Object.defineProperty(globalThis, 'WebSocket', { value: WebSocket, configurable: true })
  if (process.env.QNTM_BROWSER_RELAY_URL) {
    relay = { url: process.env.QNTM_BROWSER_RELAY_URL, stop: async () => {}, expire: () => { throw new Error('Use real relay retention instead of a fixture expiry') } }
  } else { const local = new RelayStub(); await local.start(); relay = local }
  const data = gatewayResultFixture(relay.url)
  data.conversations = {}; data.history = {}; data.contacts = {}
  const stored = data.identities[data.activeProfileId]
  browserIdentity = { publicKey: new Uint8Array(Buffer.from(stored.publicKey, 'hex')), privateKey: new Uint8Array(Buffer.from(stored.privateKey, 'hex')), keyID: new Uint8Array(Buffer.from(stored.keyId, 'hex')) }
  await page.addInitScript(value => { if (!localStorage.getItem('aim-store')) localStorage.setItem('aim-store', JSON.stringify(value)) }, data)
  await context.grantPermissions(['clipboard-read', 'clipboard-write'])
})
test.afterEach(async () => { await relay.stop(); Object.defineProperty(globalThis, 'WebSocket', { value: originalWebSocket, configurable: true }) })
async function contacts(page: Page) {
  const button = page.getByRole('button', { name: /^Contacts$/i })
  if (await button.getAttribute('aria-expanded') !== 'true') await button.click()
}
async function pin(page: Page, name: string, identity: Identity) {
  await contacts(page)
  await page.getByLabel('Contact name', { exact: true }).fill(name)
  await page.getByLabel('Full public key', { exact: true }).fill(hex(identity.publicKey))
  await page.getByLabel('I checked this key with the contact').check()
  await page.getByRole('button', { name: 'Pin contact', exact: true }).click()
  await expect(page.getByRole('status').filter({ hasText: 'Contact pinned' })).toBeVisible()
}
async function add(page: Page, name: string) {
  await page.getByLabel('Pinned contact', { exact: true }).selectOption({ label: name })
  await page.getByRole('button', { name: 'Add to group', exact: true }).click()
  await expect(page.getByLabel('Public group link', { exact: true })).toBeVisible()
  await expect(page.getByRole('status').filter({ hasText: `${name} added` })).toBeVisible()
  return page.getByLabel('Public group link', { exact: true }).inputValue()
}
async function peerOpen(identity: Identity, link: string) {
  const locator = parseGroupLink(link), relayClient = new DropboxClient(locator.relayUrl)
  const batch = await relayClient.receiveMessages(locator.conversationId, 0)
  let state: GroupSessionState | undefined
  for (const row of batch.entries) {
    if (!state) {
      try { const welcome = openGroupWelcome(identity, row.envelope, locator); state = createGroupSession(identity, welcome.conversation, welcome.state) } catch { /* Before admission */ }
    } else {
      const envelope = deserializeEnvelope(row.envelope)
      if (!isGroupWelcomeEnvelope(envelope)) state = receiveGroupEvent(identity, envelope, state).state
    }
  }
  expect(state).toBeDefined()
  return { state: state!, cursor: batch.sequence, relayClient, locator }
}
async function browserOpen(page: Page, link: string) {
  const url = new URL(link)
  await page.goto(`/${url.hash}`)
  await expect(page.getByRole('heading', { name: 'Open your contact group?' })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Open group', exact: true })).toBeDisabled()
  await page.getByLabel('I verified this contact and relay').check()
  await page.getByRole('button', { name: 'Open group', exact: true }).click()
  await expect(page.locator('.join-modal-card')).toHaveCount(0)
}

test('browser adds two pinned TypeScript contacts; reverse opening order, reply, removal and restart', async ({ page }) => {
  await page.goto('/'); await contacts(page)
  const bob = generateIdentity(), carol = generateIdentity()
  await pin(page, 'Bob', bob); await pin(page, 'Carol', carol)
  await page.getByLabel('Group name', { exact: true }).fill('Browser contact room')
  await page.getByRole('button', { name: 'Create contact group', exact: true }).click()
  await expect(page.getByRole('status').filter({ hasText: 'Group created' })).toBeVisible()
  await page.getByPlaceholder('Type a message').fill('before their admission')
  await page.getByRole('button', { name: 'Send', exact: true }).click()
  const link = await add(page, 'Bob')
  expect(await add(page, 'Carol')).toBe(link)
  const layout = await page.evaluate(() => ({ sidebarBottom: document.querySelector('.sidebar')!.getBoundingClientRect().bottom, footerTop: document.querySelector('.status-bar')!.getBoundingClientRect().top, pageHeight: document.documentElement.scrollHeight, viewport: window.innerHeight }))
  expect(layout.sidebarBottom).toBeLessThanOrEqual(layout.footerTop + 1)
  expect(layout.pageHeight).toBeLessThanOrEqual(layout.viewport)
  const carolPeer = await peerOpen(carol, link), bobPeer = await peerOpen(bob, link)
  expect(carolPeer.state.epoch).toBe(2); expect(bobPeer.state.epoch).toBe(2)
  const reply = createMessage(bob, groupSessionConversation(bobPeer.state), 'text', new TextEncoder().encode('TypeScript contact reply'))
  await bobPeer.relayClient.postMessage(bobPeer.locator.conversationId, serializeEnvelope(reply))
  await expect(page.locator('.message-body', { hasText: 'TypeScript contact reply' })).toBeVisible()
  await page.getByLabel('Pinned contact', { exact: true }).selectOption({ label: 'Bob' })
  await page.getByRole('button', { name: 'Remove from group', exact: true }).click()
  await expect(page.getByRole('status').filter({ hasText: 'Bob removed' })).toBeVisible()
  const removal = await bobPeer.relayClient.receiveMessages(bobPeer.locator.conversationId, bobPeer.cursor)
  for (const row of removal.entries) if (!isGroupWelcomeEnvelope(deserializeEnvelope(row.envelope))) bobPeer.state = receiveGroupEvent(bob, deserializeEnvelope(row.envelope), bobPeer.state).state
  expect(bobPeer.state.removed).toBe(true)
  await page.reload(); await contacts(page)
  await expect(page.getByText('2 members · key epoch 3')).toBeVisible()
  expect(await page.evaluate(() => JSON.parse(localStorage.getItem('aim-store')!).contactPins)).toBeTruthy()
})

test('browser opens its sealed welcome, persists removal, then accepts explicit readmission without exclusion history', async ({ page }) => {
  // Seed a creator group using the browser host, then let a TypeScript member add the browser's second identity.
  await page.goto('/'); await contacts(page)
  const peer = generateIdentity()
  await pin(page, 'Peer', peer)
  await page.getByLabel('Group name', { exact: true }).fill('Shared room')
  await page.getByRole('button', { name: 'Create contact group', exact: true }).click()
  await expect(page.getByRole('status').filter({ hasText: 'Group created' })).toBeVisible()
  const ownerLink = await add(page, 'Peer'), peerState = await peerOpen(peer, ownerLink)
  const recipient = generateIdentity()
  const addition = prepareGroupSessionAddition(peer, peerState.state, [recipient.publicKey])
  for (const control of [addition.addition, addition.rekey]) {
    await peerState.relayClient.postMessage(peerState.locator.conversationId, serializeEnvelope(control))
    peerState.state = receiveGroupEvent(peer, control, peerState.state).state
  }
  assertGroupAdditionAccepted(peer, peerState.state, addition)
  await peerState.relayClient.postMessage(peerState.locator.conversationId, serializeEnvelope(addition.welcomes[0]))
  const link = createGroupLink({ ...peerState.locator, inviterPublicKey: peer.publicKey })
  await page.evaluate(identity => {
    const data = JSON.parse(localStorage.getItem('aim-store')!); data.activeProfileId = 'recipient'; data.profiles.push({ id: 'recipient', name: 'Recipient browser' }); data.identities.recipient = identity; localStorage.setItem('aim-store', JSON.stringify(data))
  }, { privateKey: hex(recipient.privateKey), publicKey: hex(recipient.publicKey), keyId: hex(recipient.keyID) })
  await page.reload()
  await browserOpen(page, link)
  await expect(page.getByPlaceholder('Type a message')).toBeEnabled()
  const remove = createGroupControlMessage(peer, groupSessionConversation(peerState.state), 'group_remove', createGroupRemoveBody([recipient.keyID]))
  await peerState.relayClient.postMessage(peerState.locator.conversationId, serializeEnvelope(remove)); peerState.state = receiveGroupEvent(peer, remove, peerState.state).state
  const rekey = prepareGroupSessionRekey(peer, peerState.state)
  await peerState.relayClient.postMessage(peerState.locator.conversationId, serializeEnvelope(rekey.rekey)); peerState.state = receiveGroupEvent(peer, rekey.rekey, peerState.state).state
  await expect(page.getByText('You were removed from this group.', { exact: true })).toBeVisible()
  await page.reload(); await expect(page.getByPlaceholder('Type a message')).toBeDisabled()
  await peerState.relayClient.postMessage(peerState.locator.conversationId, serializeEnvelope(createMessage(peer, groupSessionConversation(peerState.state), 'text', new TextEncoder().encode('excluded interval'))))
  const readmit = prepareGroupSessionAddition(peer, peerState.state, [recipient.publicKey])
  for (const control of [readmit.addition, readmit.rekey]) { await peerState.relayClient.postMessage(peerState.locator.conversationId, serializeEnvelope(control)); peerState.state = receiveGroupEvent(peer, control, peerState.state).state }
  await peerState.relayClient.postMessage(peerState.locator.conversationId, serializeEnvelope(readmit.welcomes[0]))
  await browserOpen(page, link)
  await expect(page.getByPlaceholder('Type a message')).toBeEnabled()
  await expect(page.locator('.message-body', { hasText: 'excluded interval' })).toHaveCount(0)
})


test('browser welcomes a fresh Python CLI peer, exchanges messages, refreshes and removes it', async ({ page }) => {
  const directory = await mkdtemp(join(tmpdir(), 'qntm-browser-python-'))
  const python = process.env.QNTM_TEST_PYTHON || 'python3'
  const command = async (...args: string[]) => {
    const result = await promisify(execFile)(python, [resolve('tests/e2e/fixtures/python-group-peer.py'), directory, ...args], {
      env: { ...process.env, PYTHONPATH: resolve('../../python-dist/src') }, timeout: 45_000,
    })
    return JSON.parse(result.stdout)
  }
  try {
    const peer = await command('identity')
    await page.goto('/'); await contacts(page)
    await page.getByLabel('Contact name', { exact: true }).fill('Python colleague')
    await page.getByLabel('Full public key', { exact: true }).fill(peer.public_key)
    await page.getByLabel('I checked this key with the contact').check()
    await page.getByRole('button', { name: 'Pin contact', exact: true }).click()
    await page.getByLabel('Group name', { exact: true }).fill('Python and browser')
    await page.getByRole('button', { name: 'Create contact group', exact: true }).click()
    await expect(page.getByRole('status').filter({ hasText: 'Group created' })).toBeVisible()
    const link = await add(page, 'Python colleague'), id = hex(parseGroupLink(link).conversationId)
    await command('command', 'group', 'join', link)
    await command('command', 'send', id, 'Python CLI contact reply')
    await expect(page.locator('.message-body', { hasText: 'Python CLI contact reply' })).toBeVisible()
    await page.getByPlaceholder('Type a message').fill('Browser contact reply')
    await page.getByRole('button', { name: 'Send', exact: true }).click()
    await expect(page.locator('.message-body', { hasText: 'Browser contact reply' })).toBeVisible()
    const received = await command('command', 'recv', id)
    expect(received.messages.some((message: { unsafe_body: string }) => message.unsafe_body === 'Browser contact reply')).toBe(true)
    await page.getByRole('button', { name: 'Refresh welcome', exact: true }).click()
    await expect(page.getByRole('status').filter({ hasText: 'Current welcome sent' })).toBeVisible()
    expect(await page.getByLabel('Public group link', { exact: true }).inputValue()).toBe(link)
    await command('command', 'group', 'join', link)
    await page.getByRole('button', { name: 'Remove from group', exact: true }).click()
    await expect(page.getByRole('status').filter({ hasText: 'Python colleague removed' })).toBeVisible()
    await command('command', 'recv', id)
    await expect(command('command', 'send', id, 'removed peer cannot send')).rejects.toThrow(/removed/i)
  } finally { await rm(directory, { recursive: true, force: true }) }
})


test('browser pauses on retained-history loss and recovers only with its new signed challenge', async ({ page }) => {
  test.skip(!!process.env.QNTM_BROWSER_RELAY_URL, 'Deterministic retained-row omission is exercised by the relay fixture')
  await page.goto('/'); await contacts(page)
  const peer = generateIdentity()
  await pin(page, 'Recovery peer', peer)
  await page.getByLabel('Group name', { exact: true }).fill('Recovery room')
  await page.getByRole('button', { name: 'Create contact group', exact: true }).click()
  await expect(page.getByRole('status').filter({ hasText: 'Group created' })).toBeVisible()
  const ownerLink = await add(page, 'Recovery peer'), opened = await peerOpen(peer, ownerLink)
  const id = hex(opened.locator.conversationId)
  await page.goto('about:blank')
  const missed = createMessage(peer, groupSessionConversation(opened.state), 'text', new TextEncoder().encode('retained row disappears'))
  const sequence = await opened.relayClient.postMessage(opened.locator.conversationId, serializeEnvelope(missed))
  relay.expire(id, sequence)
  await page.goto('/'); await contacts(page)
  await expect(page.getByText('Group recovery required', { exact: true })).toBeVisible()
  await expect(page.getByPlaceholder('Type a message')).toBeDisabled()
  const challenge = await page.evaluate(cid => {
    const data = JSON.parse(localStorage.getItem('aim-store')!)
    return data.conversations[data.activeProfileId].find((conv: { id: string }) => conv.id === cid).group.session.recovery.challenge
  }, id)
  const refresh = prepareGroupWelcomeRefresh(peer, opened.state, [browserIdentity.publicKey], undefined, new Uint8Array(Buffer.from(challenge, 'hex')), sequence)
  await opened.relayClient.postMessage(opened.locator.conversationId, serializeEnvelope(refresh.welcomes[0]))
  const link = createGroupLink({ ...opened.locator, inviterPublicKey: peer.publicKey })
  await browserOpen(page, link)
  await expect(page.getByPlaceholder('Type a message')).toBeEnabled()
  await expect(page.getByText('Group recovery required', { exact: true })).toHaveCount(0)
  await page.reload(); await expect(page.getByPlaceholder('Type a message')).toBeEnabled()
})


test('two browser tabs serialize member additions against one durable checkpoint', async ({ page, context }) => {
  await page.goto('/'); await contacts(page)
  const bob = generateIdentity(), carol = generateIdentity()
  await pin(page, 'Concurrent Bob', bob); await pin(page, 'Concurrent Carol', carol)
  await page.getByLabel('Group name', { exact: true }).fill('Two tabs')
  await page.getByRole('button', { name: 'Create contact group', exact: true }).click()
  await expect(page.getByRole('status').filter({ hasText: 'Group created' })).toBeVisible()
  const second = await context.newPage()
  await second.goto(page.url()); await contacts(second)
  await page.getByLabel('Pinned contact', { exact: true }).selectOption({ label: 'Concurrent Bob' })
  await second.getByLabel('Pinned contact', { exact: true }).selectOption({ label: 'Concurrent Carol' })
  await Promise.all([page.getByRole('button', { name: 'Add to group', exact: true }).click(), second.getByRole('button', { name: 'Add to group', exact: true }).click()])
  await expect(page.getByRole('status').filter({ hasText: 'Concurrent Bob added' })).toBeVisible()
  await expect(second.getByRole('status').filter({ hasText: 'Concurrent Carol added' })).toBeVisible()
  const link = await page.getByLabel('Public group link', { exact: true }).inputValue()
  expect((await peerOpen(bob, link)).state.epoch).toBe(2)
  expect((await peerOpen(carol, link)).state.epoch).toBe(2)
  await second.close()
})
