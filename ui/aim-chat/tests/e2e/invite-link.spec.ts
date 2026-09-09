import { test, expect } from '@playwright/test'
import { createInvite, generateIdentity, inviteFromURL, inviteToToken } from '@corpollc/qntm'
import { RelayStub } from './fixtures/relay-stub'
import { gatewayResultFixture } from './fixtures/gateway-result'

let relay: RelayStub
test.beforeEach(async ({ page, context }) => {
  relay = new RelayStub(); await relay.start()
  const data = gatewayResultFixture(relay.url)
  data.conversations = {}; data.history = {}
  await page.addInitScript(value => {
    if (!localStorage.getItem('aim-store')) localStorage.setItem('aim-store', JSON.stringify(value))
  }, data)
  await context.grantPermissions(['clipboard-read', 'clipboard-write'])
})
test.afterEach(async () => { await relay.stop() })

test('both browser copy actions produce a standard fragment invite', async ({ page }) => {
  await page.goto('/')
  await page.getByRole('button', { name: /^Invites$/i }).click()
  await page.getByPlaceholder('Name your conversation').fill('Fragment link review')
  await page.getByRole('button', { name: 'Create', exact: true }).click()
  const copy = page.getByRole('button', { name: 'Copy Invite Link', exact: true })
  await copy.click()
  const link = await page.evaluate(() => navigator.clipboard.readText())
  const url = new URL(link)
  expect(url.search).toBe('')
  const invite = inviteFromURL(link)
  expect(url.hash).toBe(`#${inviteToToken(invite)}`)
  // The selected conversation's header shortcut uses the same format.
  await page.getByTitle('Invite', { exact: true }).click()
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(link)
})

test('opening a fragment invite keeps the token out of HTTP and requires an explicit join', async ({ page }) => {
  const invite = createInvite(generateIdentity(), 'group'), token = inviteToToken(invite)
  const requests: string[] = []
  page.on('request', request => requests.push(request.url()))
  const response = await page.goto(`/#${token}`)
  expect(response).not.toBeNull()
  expect(response!.request().url()).not.toContain(token)
  await expect(page.getByRole('heading', { name: 'Do you want to join this chat?' })).toBeVisible()
  await expect.poll(() => page.url().includes(token)).toBe(false)
  expect(requests.every(url => !url.includes(token))).toBe(true)
  expect(await page.evaluate(() => Object.values(JSON.parse(localStorage.getItem('aim-store')!).conversations).flat().length)).toBe(0)
  await page.getByLabel('Name The Chat').fill('Reviewed fragment invitation')
  await page.locator('.join-modal-card').getByRole('button', { name: 'Join', exact: true }).click()
  await expect(page.locator('.join-modal-card')).toHaveCount(0)
  const convId = Buffer.from(invite.conv_id).toString('hex')
  await expect.poll(() => page.evaluate(id => Object.values(JSON.parse(localStorage.getItem('aim-store')!).conversations)
    .flat().some((conversation: { id: string }) => conversation.id === id), convId)).toBe(true)
})

test('normal hash routes still work and same-document invite navigation is consumed', async ({ page }) => {
  await page.goto('/#/settings')
  await expect(page.getByRole('heading', { name: 'Backup & Restore' })).toBeVisible()
  await expect(page.locator('.join-modal-card')).toHaveCount(0)
  const token = inviteToToken(createInvite(generateIdentity(), 'group'))
  await page.evaluate(value => { window.location.hash = value }, token)
  await expect(page.getByRole('heading', { name: 'Do you want to join this chat?' })).toBeVisible()
  await expect.poll(() => page.url().includes(token)).toBe(false)
})

test('legacy query links remain readable and are scrubbed without discarding the current route', async ({ page }) => {
  const token = inviteToToken(createInvite(generateIdentity(), 'group'))
  await page.goto(`/?invite=${token}&view=legacy#/settings`)
  await expect(page.getByRole('heading', { name: 'Do you want to join this chat?' })).toBeVisible()
  await expect.poll(() => page.url().includes(token)).toBe(false)
  expect(new URL(page.url()).searchParams.get('view')).toBe('legacy')
  expect(new URL(page.url()).hash).toBe('#/settings')
})
