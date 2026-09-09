import { test, expect } from '@playwright/test'
import { RelayStub } from './fixtures/relay-stub'
import { gatewayResultFixture } from './fixtures/gateway-result'

let relay: RelayStub
test.beforeEach(async ({ page }) => {
  relay = new RelayStub(); await relay.start()
  const data = gatewayResultFixture(relay.url)
  data.conversations = {}; data.history = {}
  await page.addInitScript(value => localStorage.setItem('aim-store', JSON.stringify(value)), data)
  await page.goto('/')
})
test.afterEach(async () => { await relay.stop() })

test('collapsed panels exclude controls from agent discovery and keyboard navigation', async ({ page }) => {
  const invites = page.getByRole('button', { name: /^Invites$/i })
  await expect(invites).toHaveAttribute('aria-expanded', 'false')
  await expect(page.getByRole('textbox', { name: 'Name your conversation' })).toHaveCount(0)
  await expect(page.getByRole('button', { name: 'Create', exact: true })).toHaveCount(0)
  const bodyId = await invites.getAttribute('aria-controls')
  expect(bodyId).toBeTruthy()
  expect(await page.evaluate(id => document.getElementById(id!)?.inert, bodyId)).toBe(true)

  await invites.focus()
  await page.keyboard.press('Tab')
  await expect(page.getByRole('button', { name: /^Conversations$/i })).toBeFocused()
  await page.keyboard.press('Shift+Tab')
  await expect(invites).toBeFocused()
  await page.keyboard.press('Enter')
  await expect(invites).toHaveAttribute('aria-expanded', 'true')
  await page.keyboard.press('Tab')
  await expect(page.getByPlaceholder('Name your conversation')).toBeFocused()
  await expect(page.getByRole('button', { name: 'Create', exact: true })).toBeVisible()
})

test('closing and reopening a panel preserves drafts without hidden tab stops', async ({ page }) => {
  const invites = page.getByRole('button', { name: /^Invites$/i })
  await invites.click()
  await page.getByPlaceholder('Name your conversation').fill('Keep this draft')
  await invites.focus()
  await page.keyboard.press('Space')
  await expect(invites).toHaveAttribute('aria-expanded', 'false')
  await expect(page.getByRole('button', { name: 'Create', exact: true })).toHaveCount(0)
  await page.keyboard.press('Tab')
  await expect(page.getByRole('button', { name: /^Conversations$/i })).toBeFocused()
  await invites.click()
  await expect(page.getByPlaceholder('Name your conversation')).toHaveValue('Keep this draft')
  await page.getByRole('button', { name: 'Create', exact: true }).click()
  await expect(page.getByRole('button', { name: 'Copy Invite Link', exact: true })).toBeVisible()
})
