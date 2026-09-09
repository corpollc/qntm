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

test('rename a conversation and verify persistence', async ({ page }) => {
  const alice = new Alice(page)
  await alice.setup(relay.url)
  await alice.createProfile('Alice')

  const bob = new Bob(relay.url)
  bob.install()
  try {
    bob.createProfile('Bob')
    const token = bob.createInvite('Project Alpha')

    await alice.joinInviteViaSidebar(token, 'Project Alpha')

    let names = await alice.getConversationNames()
    expect(names).toContain('Project Alpha')

    await alice.renameConversation('Project Alpha', 'Project Beta')

    names = await alice.getConversationNames()
    expect(names).toContain('Project Beta')
    expect(names).not.toContain('Project Alpha')

    await alice.refresh()
    names = await alice.getConversationNames()
    expect(names).toContain('Project Beta')
  } finally {
    bob.uninstall()
  }
})
