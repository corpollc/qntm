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

test('joining via sidebar preserves the custom name', async ({ page }) => {
  const alice = new Alice(page)
  await alice.setup(relay.url)
  await alice.createProfile('Alice')

  const bob = new Bob(relay.url)
  bob.install()
  try {
    bob.createProfile('Bob')
    const token = bob.createInvite('Bobs Chat')

    await alice.joinInviteViaSidebar(token, 'My Custom Chat')

    let names = await alice.getConversationNames()
    expect(names).toContain('My Custom Chat')

    await alice.refresh()
    names = await alice.getConversationNames()
    expect(names).toContain('My Custom Chat')
  } finally {
    bob.uninstall()
  }
})

test('joining a second invite also preserves its name', async ({ page }) => {
  const alice = new Alice(page)
  await alice.setup(relay.url)
  await alice.createProfile('Alice')

  const bob = new Bob(relay.url)
  bob.install()
  try {
    bob.createProfile('Bob')

    const token1 = bob.createInvite('First')
    await alice.joinInviteViaSidebar(token1, 'Chat One')

    const token2 = bob.createInvite('Second')
    await alice.joinInviteViaSidebar(token2, 'Chat Two')

    const names = await alice.getConversationNames()
    expect(names).toContain('Chat One')
    expect(names).toContain('Chat Two')
  } finally {
    bob.uninstall()
  }
})
