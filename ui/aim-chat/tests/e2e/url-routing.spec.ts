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

test('selecting a conversation updates the URL', async ({ page }) => {
  const alice = new Alice(page)
  await alice.setup(relay.url)
  await alice.createProfile('Alice')

  const bob = new Bob(relay.url)
  bob.install()
  try {
    bob.createProfile('Bob')
    const token = bob.createInvite('URL Test')
    await alice.joinInviteViaSidebar(token, 'URL Test')

    // Click the conversation
    await page.locator('.conversation-name', { hasText: 'URL Test' }).click()

    // URL should contain /c/
    await expect(page).toHaveURL(/#\/c\//)
  } finally {
    bob.uninstall()
  }
})

test('refreshing on #/c/<convId> reloads the correct conversation', async ({ page }) => {
  const alice = new Alice(page)
  await alice.setup(relay.url)
  await alice.createProfile('Alice')

  const bob = new Bob(relay.url)
  bob.install()
  try {
    bob.createProfile('Bob')
    const token = bob.createInvite('Persist Test')
    await alice.joinInviteViaSidebar(token, 'Persist Test')

    await page.locator('.conversation-name', { hasText: 'Persist Test' }).click()

    const url = page.url()
    expect(url).toMatch(/#\/c\//)

    await alice.refresh()

    const names = await alice.getConversationNames()
    expect(names).toContain('Persist Test')
    await expect(page).toHaveURL(/#\/c\//)
  } finally {
    bob.uninstall()
  }
})

test('navigating to #/c/nonexistent falls back to first conversation', async ({ page }) => {
  const alice = new Alice(page)
  await alice.setup(relay.url)
  await alice.createProfile('Alice')

  const bob = new Bob(relay.url)
  bob.install()
  try {
    bob.createProfile('Bob')
    const token = bob.createInvite('Fallback Test')
    await alice.joinInviteViaSidebar(token, 'Fallback Test')

    await page.goto('/#/c/nonexistent')
    await page.waitForTimeout(1000)

    const names = await alice.getConversationNames()
    expect(names).toContain('Fallback Test')
  } finally {
    bob.uninstall()
  }
})
