import { test, expect } from '@playwright/test'
import { RelayStub } from './fixtures/relay-stub'
import { Bob } from './fixtures/bob'
import { Alice } from './fixtures/alice'

let relay: RelayStub

test.beforeEach(async () => {
  relay = new RelayStub()
  await relay.start()
})

test.afterEach(async () => {
  await relay.stop()
})

test('cancel delete keeps conversation', async ({ page }) => {
  const alice = new Alice(page)
  await alice.setup(relay.url)
  await alice.createProfile('Alice')

  const bob = new Bob(relay.url)
  bob.install()
  try {
    bob.createProfile('Bob')
    const token = bob.createInvite('To Delete')
    await alice.joinInviteViaSidebar(token, 'To Delete')

    await alice.cancelDeleteConversation('To Delete')

    const names = await alice.getConversationNames()
    expect(names).toContain('To Delete')
  } finally {
    bob.uninstall()
  }
})

test('confirm delete removes conversation permanently', async ({ page }) => {
  const alice = new Alice(page)
  await alice.setup(relay.url)
  await alice.createProfile('Alice')

  const bob = new Bob(relay.url)
  bob.install()
  try {
    bob.createProfile('Bob')
    const token = bob.createInvite('Doomed')
    await alice.joinInviteViaSidebar(token, 'Doomed')

    let names = await alice.getConversationNames()
    expect(names).toContain('Doomed')

    await alice.deleteConversation('Doomed')

    names = await alice.getConversationNames()
    expect(names).not.toContain('Doomed')

    await alice.refresh()
    names = await alice.getConversationNames()
    expect(names).not.toContain('Doomed')
  } finally {
    bob.uninstall()
  }
})

test('deleting selected conversation clears the chat pane', async ({ page }) => {
  const alice = new Alice(page)
  await alice.setup(relay.url)
  await alice.createProfile('Alice')

  const bob = new Bob(relay.url)
  bob.install()
  try {
    bob.createProfile('Bob')
    const token = bob.createInvite('Active Chat')
    await alice.joinInviteViaSidebar(token, 'Active Chat')

    await page.locator('.conversation-select', { hasText: 'Active Chat' }).click()

    await alice.deleteConversation('Active Chat')

    const names = await alice.getConversationNames()
    expect(names).not.toContain('Active Chat')
  } finally {
    bob.uninstall()
  }
})
