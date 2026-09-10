import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { resolve, join } from 'node:path'
import { test, expect, type Page } from '@playwright/test'
import { generateIdentity, DropboxClient, openGroupWelcome, parseGroupLink, createGroupSession, receiveGroupEvent, groupSessionConversation,
  createMessage, serializeEnvelope, deserializeEnvelope, isGroupWelcomeEnvelope, prepareGroupSessionAddition, assertGroupAdditionAccepted, base64UrlEncode,
  createGroupControlMessage, createGroupRemoveBody, prepareGroupSessionRekey, createGroupLink, prepareGroupWelcomeRefresh } from '@corpollc/qntm'
import type { Identity, GroupSessionState } from '@corpollc/qntm'
import { WebSocket } from 'ws'
import { RelayStub } from './fixtures/relay-stub'
import { gatewayResultFixture } from './fixtures/gateway-result'
const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString('hex')
let relay: Pick<RelayStub, 'url' | 'stop' | 'expire'>
let browserIdentity: Identity
let restoreWebSocket: (() => void) | undefined
let stopRelay: (() => Promise<void>) | undefined

test.beforeEach(async ({ page, context }) => {
  const originalWebSocket = globalThis.WebSocket
  Object.defineProperty(globalThis, 'WebSocket', { value: WebSocket, configurable: true })
  restoreWebSocket = () => Object.defineProperty(globalThis, 'WebSocket', { value: originalWebSocket, configurable: true })
  if (process.env.QNTM_BROWSER_RELAY_URL) {
    relay = { url: process.env.QNTM_BROWSER_RELAY_URL, stop: async () => {}, expire: () => { throw new Error('Use real relay retention instead of a fixture expiry') } }
  } else {
    const local = new RelayStub()
    stopRelay = () => local.stop()
    await local.start(); relay = local
  }
  const data = gatewayResultFixture(relay.url)
  data.conversations = {}; data.history = {}; data.contacts = {}
  const stored = data.identities[data.activeProfileId]
  browserIdentity = { publicKey: new Uint8Array(Buffer.from(stored.publicKey, 'hex')), privateKey: new Uint8Array(Buffer.from(stored.privateKey, 'hex')), keyID: new Uint8Array(Buffer.from(stored.keyId, 'hex')) }
  await page.addInitScript(value => { if (!localStorage.getItem('aim-store')) localStorage.setItem('aim-store', JSON.stringify(value)) }, data)
  await context.grantPermissions(['clipboard-read', 'clipboard-write'])
})
test.afterEach(async () => {
  // Browser fixture setup can fail before beforeEach starts. Restore only
  // resources actually acquired, including when relay startup/cleanup fails.
  try { await stopRelay?.() }
  finally {
    stopRelay = undefined
    restoreWebSocket?.(); restoreWebSocket = undefined
  }
})
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
      try { const welcome = openGroupWelcome(identity, row.envelope, locator); state = createGroupSession(identity, welcome.conversation, welcome.state, { admissions: welcome.admissions }) } catch { /* Before admission */ }
    } else {
      const envelope = deserializeEnvelope(row.envelope)
      if (!isGroupWelcomeEnvelope(envelope)) state = receiveGroupEvent(identity, envelope, state).state
    }
  }
  expect(state).toBeDefined()
  return { state: state!, cursor: batch.sequence, relayClient, locator }
}
async function catchUpPeer(identity: Identity, peer: Awaited<ReturnType<typeof peerOpen>>, supersededIds: string[] = []) {
  const batch = await peer.relayClient.receiveMessages(peer.locator.conversationId, peer.cursor)
  for (const row of batch.entries) {
    const envelope = deserializeEnvelope(row.envelope)
    if (!isGroupWelcomeEnvelope(envelope)) {
      try { peer.state = receiveGroupEvent(identity, envelope, peer.state).state }
      catch (error) { if (!supersededIds.includes(hex(envelope.msg_id))) throw error }
    }
  }
  peer.cursor = batch.sequence
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
  const addition = prepareGroupSessionAddition(peer, peerState.state, [recipient.publicKey], undefined, undefined, peerState.cursor)
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
  await catchUpPeer(peer, peerState)
  const readmit = prepareGroupSessionAddition(peer, peerState.state, [recipient.publicKey], undefined, undefined, peerState.cursor)
  for (const control of [readmit.addition, readmit.rekey]) { await peerState.relayClient.postMessage(peerState.locator.conversationId, serializeEnvelope(control)); peerState.state = receiveGroupEvent(peer, control, peerState.state).state }
  await peerState.relayClient.postMessage(peerState.locator.conversationId, serializeEnvelope(readmit.welcomes[0]))
  await browserOpen(page, link)
  await expect(page.getByPlaceholder('Type a message')).toBeEnabled()
  await expect(page.locator('.message-body', { hasText: 'excluded interval' })).toHaveCount(0)
})


test('browser welcomes a fresh Python CLI peer and renews its later readmission after removal', async ({ page }) => {
  test.setTimeout(60_000)
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
    const checkpoint = async () => JSON.parse(await readFile(join(directory, 'conversations.json'), 'utf8'))
      .find((record: { id: string }) => record.id === id).group_session
    const removed = await checkpoint()
    expect(removed.removed).toBe(true); expect(removed.removedAtEpoch).toBe(1)
    await page.getByPlaceholder('Type a message').fill('Excluded interval stays private')
    await page.getByRole('button', { name: 'Send', exact: true }).click()
    expect(await add(page, 'Python colleague')).toBe(link)
    // The recipient stays offline through readmission and another rotation.
    const other = generateIdentity()
    await pin(page, 'Later TS colleague', other)
    await add(page, 'Later TS colleague')
    await page.getByLabel('Pinned contact', { exact: true }).selectOption({ label: 'Python colleague' })
    await page.getByRole('button', { name: 'Refresh welcome', exact: true }).click()
    await expect(page.getByRole('status').filter({ hasText: 'Current welcome sent' })).toBeVisible()
    await command('command', 'group', 'join', link)
    const renewed = await checkpoint()
    expect(renewed.epoch).toBe(4); expect(renewed.removed).toBe(false)
    expect(renewed.removedAtEpoch).toBe(1)
    expect(renewed.admissions[peer.key_id].sourceEpoch).toBe(2)
    // Replaying an old addition plus rotations would retain old roots. A
    // current admission renewal starts at this epoch with none of those keys.
    expect(renewed.rekeys).toEqual([])
    const reopened = await command('command', 'recv', id)
    expect(reopened.messages.some((message: { unsafe_body: string }) => message.unsafe_body === 'Excluded interval stays private')).toBe(false)
    await command('command', 'send', id, 'Python renewed admission reply')
    await expect(page.locator('.message-body', { hasText: 'Python renewed admission reply' })).toBeVisible()
    await page.getByRole('button', { name: 'Remove from group', exact: true }).click()
    await expect(page.getByRole('status').filter({ hasText: 'Python colleague removed' })).toBeVisible()
    await command('command', 'recv', id)
    await expect(command('command', 'group', 'join', link)).rejects.toThrow()
    expect((await checkpoint()).removedAtEpoch).toBe(4)
  } finally { await rm(directory, { recursive: true, force: true }) }
})

for (const phase of ['completed', 'partial'] as const) test(`browser retries a ${phase} addition after its original delivery expires and a fresh Python process opens the renewal`, async ({ page }) => {
  test.setTimeout(60_000)
  const directory = await mkdtemp(join(tmpdir(), 'qntm-browser-expired-python-'))
  const command = async (...args: string[]) => JSON.parse((await promisify(execFile)(process.env.QNTM_TEST_PYTHON || 'python3',
    [resolve('tests/e2e/fixtures/python-group-peer.py'), directory, ...args], {
      env: { ...process.env, PYTHONPATH: resolve('../../python-dist/src') }, timeout: 45_000,
    })).stdout)
  try {
    const peer = await command('identity')
    await page.goto('/'); await contacts(page)
    await page.getByLabel('Group name', { exact: true }).fill('Expired delivery window')
    await page.getByRole('button', { name: 'Create contact group', exact: true }).click()
    await expect(page.getByRole('status').filter({ hasText: 'Group created' })).toBeVisible()
    const saved = await page.evaluate(() => {
      const data = JSON.parse(localStorage.getItem('aim-store')!)
      return { profile: data.activeProfileId, record: data.conversations[data.activeProfileId][0] }
    })
    const id = saved.record.id, sender = saved.record.group.session as GroupSessionState, recipient = new Uint8Array(Buffer.from(peer.public_key, 'hex'))
    const operation = prepareGroupSessionAddition(browserIdentity, sender, [recipient], 12, new Uint8Array(32).fill(0x53), saved.record.group.cursor)
    let expected = sender
    for (const envelope of [operation.addition, operation.rekey]) expected = receiveGroupEvent(browserIdentity, envelope, expected).state
    // Private journal staging models a browser crash after the controls were
    // committed. The actual browser receive path must authenticate their replay.
    await page.evaluate(({ profile, id, pending }) => {
      const data = JSON.parse(localStorage.getItem('aim-store')!)
      const record = data.conversations[profile].find((row: { id: string }) => row.id === id)
      record.group.operation = pending; record.group.revision++
      localStorage.setItem('aim-store', JSON.stringify(data))
    }, { profile: saved.profile, id, pending: { kind: 'addition', expected, controls: [operation.addition, operation.rekey].map(e => base64UrlEncode(serializeEnvelope(e))), welcomes: operation.welcomes.map(e => base64UrlEncode(serializeEnvelope(e))), delivered: 0 } })
    await page.reload(); await contacts(page)
    const client = new DropboxClient(relay.url), cid = operation.conversation.id
    for (const envelope of phase === 'completed' ? [operation.addition, operation.rekey] : [operation.addition]) await client.postMessage(cid, serializeEnvelope(envelope))
    await expect(page.getByText(`2 members · key epoch ${phase === 'completed' ? 1 : 0}`)).toBeVisible()
    const accepted = await page.evaluate(() => {
      const data = JSON.parse(localStorage.getItem('aim-store')!)
      return data.conversations[data.activeProfileId][0].group
    })
    expect(accepted.session.admissions[peer.key_id].completion === null).toBe(phase === 'partial')
    expect(accepted.cursor).toBeGreaterThanOrEqual(phase === 'completed' ? 3 : 2)
    const delay = Math.max(0, (operation.welcomes[0].expiry_ts + 1) * 1000 - Date.now())
    await new Promise(resolve => setTimeout(resolve, delay))
    await page.reload(); await contacts(page)
    const posted: Uint8Array[] = []
    page.on('request', request => {
      if (request.method() === 'POST' && new URL(request.url()).pathname === '/v1/send') posted.push(new Uint8Array(Buffer.from(request.postDataJSON().envelope_b64, 'base64')))
    })
    await page.getByRole('button', { name: 'Retry saved operation', exact: true }).click()
    await expect(page.getByRole('status').filter({ hasText: 'Saved operation completed' })).toBeVisible()
    expect(posted).toHaveLength(phase === 'completed' ? 1 : 2)
    expect(isGroupWelcomeEnvelope(deserializeEnvelope(posted.at(-1)!))).toBe(true)
    expect(base64UrlEncode(posted.at(-1)!)).not.toBe(base64UrlEncode(serializeEnvelope(operation.welcomes[0])))
    for (const wire of posted) {
      expect(hex(deserializeEnvelope(wire).msg_id)).not.toBe(hex(operation.addition.msg_id))
      expect(hex(deserializeEnvelope(wire).msg_id)).not.toBe(hex(operation.rekey.msg_id))
    }
    const canonical = await page.evaluate(() => {
      const data = JSON.parse(localStorage.getItem('aim-store')!)
      return data.conversations[data.activeProfileId][0].group.session
    })
    expect(canonical.epoch).toBe(1); expect(canonical.needsRekey).toBe(false)
    const link = await page.getByLabel('Public group link', { exact: true }).inputValue()
    await command('command', 'group', 'join', link)
    const record = JSON.parse(await readFile(join(directory, 'conversations.json'), 'utf8')).find((row: { id: string }) => row.id === id)
    expect(record.group_session.epoch).toBe(1)
    expect(record.group_session.rekeys).toEqual([])
    expect(record.group_session.admissions[peer.key_id]).toEqual(canonical.admissions[peer.key_id])
    expect(record.group_session.admissions[peer.key_id].addId).toBe(expected.admissions[peer.key_id].addId)
    expect(record.group_session.admissions[peer.key_id].addDigest).toBe(expected.admissions[peer.key_id].addDigest)
    await command('command', 'send', id, 'Python received the retried admission renewal')
    await expect(page.locator('.message-body', { hasText: 'Python received the retried admission renewal' })).toBeVisible()
  } finally { await rm(directory, { recursive: true, force: true }) }
})


test('browser recovers retained-history loss with its signed challenge and preserves its name when reopening', async ({ page }) => {
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
  await expect(page.locator('.chat-header-title strong')).toHaveText('Recovery room')
  await page.reload(); await expect(page.getByPlaceholder('Type a message')).toBeEnabled()
  await expect(page.locator('.chat-header-title strong')).toHaveText('Recovery room')
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


for (const timing of ['before welcome', 'after opening'] as const) test(`browser rejects a competing pre-admission rekey ${timing} and recovers to a challenged same-epoch welcome`, async ({ page }) => {
  await page.goto('/'); await contacts(page)
  const peer = generateIdentity(), recipient = generateIdentity()
  await pin(page, 'Canonical peer', peer)
  await page.getByLabel('Group name', { exact: true }).fill('Competing rotation')
  await page.getByRole('button', { name: 'Create contact group', exact: true }).click()
  await expect(page.getByRole('status').filter({ hasText: 'Group created' })).toBeVisible()
  const ownerLink = await add(page, 'Canonical peer'), opened = await peerOpen(peer, ownerLink)
  // Stop the creator browser while the peer posts both branches. Its own
  // conservative rewind recovery is separate from this new recipient's join.
  await page.goto('about:blank')
  await catchUpPeer(peer, opened)
  let addition = prepareGroupSessionAddition(peer, opened.state, [recipient.publicKey], undefined, undefined, opened.cursor)
  for (let n = 0; addition.rekey.msg_id[0] < 128 && n < 128; n++) addition = prepareGroupSessionAddition(peer, opened.state, [recipient.publicKey], undefined, undefined, opened.cursor)
  expect(addition.rekey.msg_id[0]).toBeGreaterThanOrEqual(128)
  const afterAdd = receiveGroupEvent(peer, addition.addition, opened.state).state
  let competing = prepareGroupSessionRekey(peer, afterAdd)
  for (let n = 0; hex(competing.rekey.msg_id) >= hex(addition.rekey.msg_id) && n < 128; n++) competing = prepareGroupSessionRekey(peer, afterAdd)
  expect(hex(competing.rekey.msg_id) < hex(addition.rekey.msg_id)).toBe(true)
  for (const control of [addition.addition, addition.rekey]) {
    await opened.relayClient.postMessage(opened.locator.conversationId, serializeEnvelope(control))
    opened.state = receiveGroupEvent(peer, control, opened.state).state
  }
  assertGroupAdditionAccepted(peer, opened.state, addition)
  const losingRoot = opened.state.root
  const link = createGroupLink({ ...opened.locator, inviterPublicKey: peer.publicKey }), id = hex(opened.locator.conversationId)
  const openRecipient = async () => {
    await page.goto('/')
    await page.evaluate(identity => {
      const data = JSON.parse(localStorage.getItem('aim-store')!); data.activeProfileId = 'recipient'; data.profiles.push({ id: 'recipient', name: 'Recovering browser' }); data.identities.recipient = identity; localStorage.setItem('aim-store', JSON.stringify(data))
    }, { privateKey: hex(recipient.privateKey), publicKey: hex(recipient.publicKey), keyId: hex(recipient.keyID) })
    await page.reload(); await browserOpen(page, link)
  }
  if (timing === 'after opening') {
    await opened.relayClient.postMessage(opened.locator.conversationId, serializeEnvelope(addition.welcomes[0]))
    await openRecipient()
    await expect(page.getByPlaceholder('Type a message')).toBeEnabled()
    // Resume the normal saved subscriber with the whole race in its backlog,
    // proving a later unknown control blocks earlier plaintext in that batch.
    await page.goto('about:blank')
  }
  const losingText = createMessage(peer, groupSessionConversation(opened.state), 'text', new TextEncoder().encode('readable losing-branch text must stay hidden'))
  await opened.relayClient.postMessage(opened.locator.conversationId, serializeEnvelope(losingText))
  await opened.relayClient.postMessage(opened.locator.conversationId, serializeEnvelope(competing.rekey))
  const canonical = receiveGroupEvent(peer, competing.rekey, opened.state)
  expect(canonical.rewound).toBe(true); opened.state = canonical.state
  expect(opened.state.root).not.toBe(losingRoot)
  await opened.relayClient.postMessage(opened.locator.conversationId, serializeEnvelope(createMessage(peer, groupSessionConversation(opened.state), 'text', new TextEncoder().encode('canonical text before recovery'))))
  if (timing === 'before welcome') {
    await opened.relayClient.postMessage(opened.locator.conversationId, serializeEnvelope(addition.welcomes[0]))
    await openRecipient()
  } else await page.goto('/')
  await expect(page.getByPlaceholder('Type a message')).toBeDisabled()
  await expect(page.locator('.message-body', { hasText: 'readable losing-branch text must stay hidden' })).toHaveCount(0)
  await expect(page.locator('.message-body', { hasText: 'canonical text before recovery' })).toHaveCount(0)
  const saved = await page.evaluate(cid => {
    const data = JSON.parse(localStorage.getItem('aim-store')!)
    return data.conversations[data.activeProfileId].find((conv: { id: string }) => conv.id === cid).group.session
  }, id)
  expect(saved.root).toBe(losingRoot)
  expect(saved.recovery.reason).toBe('missing_history')
  await contacts(page)
  await expect(page.getByText('Group recovery required', { exact: true })).toBeVisible()
  await test.info().attach('competing-welcome-blocked', { body: await page.screenshot(), contentType: 'image/png' })
  await page.reload(); await expect(page.getByPlaceholder('Type a message')).toBeDisabled()
  await catchUpPeer(peer, opened, [hex(losingText.msg_id)])
  const refreshed = prepareGroupWelcomeRefresh(peer, opened.state, [recipient.publicKey], undefined, new Uint8Array(Buffer.from(saved.recovery.challenge, 'hex')), opened.cursor)
  await opened.relayClient.postMessage(opened.locator.conversationId, serializeEnvelope(refreshed.welcomes[0]))
  await browserOpen(page, link)
  await expect(page.getByPlaceholder('Type a message')).toBeEnabled()
  await page.reload(); await expect(page.getByPlaceholder('Type a message')).toBeEnabled()
  await page.getByPlaceholder('Type a message').fill('recovered canonical branch reply')
  await page.getByRole('button', { name: 'Send', exact: true }).click()
  await expect(page.locator('.message-body', { hasText: 'recovered canonical branch reply' })).toBeVisible()
  await test.info().attach('challenged-welcome-recovered', { body: await page.screenshot(), contentType: 'image/png' })
  const replyBatch = await opened.relayClient.receiveMessages(opened.locator.conversationId, opened.cursor)
  const reply = replyBatch.entries.map(row => deserializeEnvelope(row.envelope)).filter(envelope => !isGroupWelcomeEnvelope(envelope)).map(envelope => receiveGroupEvent(peer, envelope, opened.state)).find(result => !result.duplicate && new TextDecoder().decode(result.message.inner.body) === 'recovered canonical branch reply')
  expect(reply).toBeDefined()
})

test('browser hides an invalidated branch immediately while preserving earlier accepted history', async ({ page }) => {
  await page.goto('/'); await contacts(page)
  await pin(page, 'History peer', generateIdentity())
  await page.getByLabel('Group name', { exact: true }).fill('History validity')
  await page.getByRole('button', { name: 'Create contact group', exact: true }).click()
  await expect(page.getByRole('status').filter({ hasText: 'Group created' })).toBeVisible()
  await page.getByPlaceholder('Type a message').fill('earlier stable history')
  await page.getByRole('button', { name: 'Send', exact: true }).click()
  await expect(page.locator('.message-body', { hasText: 'earlier stable history' })).toBeVisible()
  const link = await add(page, 'History peer'), locator = parseGroupLink(link), id = hex(locator.conversationId)
  await page.getByPlaceholder('Type a message').fill('losing descendant history')
  await page.getByRole('button', { name: 'Send', exact: true }).click()
  await expect(page.locator('.message-body', { hasText: 'losing descendant history' })).toBeVisible()
  const saved: GroupSessionState = await page.evaluate(cid => {
    const data = JSON.parse(localStorage.getItem('aim-store')!)
    return data.conversations[data.activeProfileId].find((conv: { id: string }) => conv.id === cid).group.session
  }, id)
  const frame = saved.rekeys[0]
  const source = { ...saved, epoch: frame.epoch, root: frame.root, snapshot: frame.snapshot,
    admissions: structuredClone(frame.admissions), needsRekey: Object.values(frame.admissions).some(admission => admission.completion === null),
    rekeys: [], seen: {}, recovery: null }
  // Choose the test control's ID before signing/encryption, avoiding a random
  // retry budget when the original rekey happened to have a very small ID.
  const getRandomValues = crypto.getRandomValues
  let competing
  try {
    Object.defineProperty(crypto, 'getRandomValues', { configurable: true, value: (value: Uint8Array) => {
      const result = getRandomValues.call(crypto, value)
      if (value.byteLength === 16) value.fill(0)
      return result
    } })
    competing = prepareGroupSessionRekey(browserIdentity, source)
  } finally { Object.defineProperty(crypto, 'getRandomValues', { configurable: true, value: getRandomValues }) }
  expect(hex(competing.rekey.msg_id) < frame.messageId).toBe(true)
  await new DropboxClient(locator.relayUrl).postMessage(locator.conversationId, serializeEnvelope(competing.rekey))
  await expect(page.getByText('Group recovery required', { exact: true })).toBeVisible()
  await expect(page.locator('.message-body', { hasText: 'losing descendant history' })).toHaveCount(0)
  await expect(page.locator('.message-body', { hasText: 'earlier stable history' })).toBeVisible()
  await page.reload()
  await expect(page.locator('.message-body', { hasText: 'losing descendant history' })).toHaveCount(0)
  await expect(page.locator('.message-body', { hasText: 'earlier stable history' })).toBeVisible()
  const archive = await page.evaluate(cid => {
    const data = JSON.parse(localStorage.getItem('aim-store')!)
    return data.history[data.activeProfileId][cid]
  }, id)
  expect(archive.find((message: { text: string }) => message.text === 'losing descendant history').groupBinding.valid).toBe(false)
})
