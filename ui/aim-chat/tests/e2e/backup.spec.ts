import { test, expect } from '@playwright/test'
import { readFile } from 'node:fs/promises'
import { generateIdentity } from '@corpollc/qntm'

const hex = (b: Uint8Array) => Buffer.from(b).toString('hex')
const identity = generateIdentity()
function backup(name = 'Original') {
  return {
    activeProfileId: 'alice-1234', profiles: [{ id: 'alice-1234', name }],
    identities: { 'alice-1234': { privateKey: hex(identity.privateKey), publicKey: hex(identity.publicKey), keyId: hex(identity.keyID) } },
    conversations: {}, history: {}, contacts: {}, guidanceContacts: {}, cursors: {}, dropboxUrl: 'https://relay.invalid',
  }
}
test.beforeEach(async ({ page }) => {
  await page.addInitScript(data => { if (!localStorage.getItem('aim-store')) localStorage.setItem('aim-store', JSON.stringify(data)) }, backup())
  await page.route('https://relay.invalid/**', route => route.abort())
  await page.goto('/#/settings')
  await expect(page.getByRole('heading', { name: 'Backup & Restore' })).toBeVisible()
})

test('legacy restore requires destination review and confirmation; cancel and malformed files preserve data', async ({ page }) => {
  const replacement = { ...backup('Restored'), dropboxUrl: 'https://replacement.invalid' }
  replacement.guidanceContacts = { 'alice-1234': [{ id: 'counsel', name: 'Local counsel', category: 'legal', kind: 'human', recipientKeyId: 'ab'.repeat(16), conversationId: 'cd'.repeat(16), relayUrl: 'https://counsel.invalid' }] }
  const input = page.getByLabel('Backup file (up to 10 MiB)')
  await input.setInputFiles({ name: 'legacy.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(replacement)) })
  await page.getByRole('button', { name: 'Review backup', exact: true }).click()
  const review = page.getByRole('region', { name: 'Backup replacement review' })
  await expect(review).toContainText('https://replacement.invalid')
  await expect(review).toContainText('https://counsel.invalid')
  await expect(review).toContainText('ab'.repeat(16))
  await expect(review.getByRole('button', { name: 'Replace browser data' })).toBeDisabled()
  expect(await page.evaluate(() => JSON.parse(localStorage.getItem('aim-store')!).profiles[0].name)).toBe('Original')
  await page.getByRole('button', { name: 'Cancel restore' }).click()
  await expect(review).toHaveCount(0)
  await input.setInputFiles({ name: 'bad.json', mimeType: 'application/json', buffer: Buffer.from('{"privateKey":"do not echo') })
  await page.getByRole('button', { name: 'Review backup', exact: true }).click()
  await expect(page.getByRole('alert')).toHaveText('Invalid backup: JSON syntax.')
  expect(await page.evaluate(() => JSON.parse(localStorage.getItem('aim-store')!).profiles[0].name)).toBe('Original')
  await input.setInputFiles({ name: 'legacy.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(replacement)) })
  await page.getByRole('button', { name: 'Review backup', exact: true }).click()
  await page.getByRole('checkbox', { name: /I trust this backup/ }).check()
  await page.getByRole('button', { name: 'Replace browser data' }).click()
  await expect.poll(() => page.evaluate(() => JSON.parse(localStorage.getItem('aim-store')!).profiles[0].name)).toBe('Restored')
  await expect(page.getByText('https://replacement.invalid', { exact: false }).first()).toBeVisible()
})

test('encrypted download restores through the browser and rejects a wrong password', async ({ page }) => {
  const password = 'unique backup password for this test'
  await page.getByLabel('New backup password (at least 12 characters)').fill(password)
  await page.getByLabel('Confirm backup password').fill(password)
  const download = page.waitForEvent('download')
  await page.getByRole('button', { name: 'Export encrypted backup' }).click()
  const file = await download
  const contents = await readFile((await file.path())!)
  expect(contents.toString()).not.toContain(hex(identity.privateKey))
  expect(JSON.parse(contents.toString()).format).toBe('qntm-aim-backup')
  await expect(page.getByLabel('New backup password (at least 12 characters)')).toHaveValue('')
  await page.getByLabel('Backup file (up to 10 MiB)').setInputFiles({ name: 'encrypted.json', mimeType: 'application/json', buffer: contents })
  await page.getByLabel('Password for encrypted backup', { exact: true }).fill('wrong password')
  await page.getByRole('button', { name: 'Review backup', exact: true }).click()
  await expect(page.getByRole('alert')).toContainText('incorrect password or damaged file')
  await page.getByLabel('Password for encrypted backup', { exact: true }).fill(password)
  await page.getByRole('button', { name: 'Review backup', exact: true }).click()
  await expect(page.getByRole('region', { name: 'Backup replacement review' })).toContainText('Password-encrypted backup')
  await page.getByRole('checkbox', { name: /I trust this backup/ }).check()
  await page.getByRole('button', { name: 'Replace browser data' }).click()
  await expect(page.getByRole('heading', { name: 'Backup & Restore' })).toBeVisible()
  expect(await page.evaluate(() => JSON.parse(localStorage.getItem('aim-store')!).identities['alice-1234'].keyId)).toBe(hex(identity.keyID))
})

test('an empty store initializes one profile and keeps settings open', async ({ page }) => {
  await page.evaluate(() => localStorage.setItem('aim-store', JSON.stringify({ activeProfileId: '', profiles: [], identities: {}, conversations: {}, history: {}, contacts: {}, guidanceContacts: {}, cursors: {}, dropboxUrl: 'https://relay.invalid' })))
  await page.reload()
  await expect(page.getByRole('contentinfo')).toContainText('Profile: You')
  await expect(page.getByRole('heading', { name: 'Backup & Restore' })).toBeVisible()
  expect(await page.evaluate(() => JSON.parse(localStorage.getItem('aim-store')!).profiles.length)).toBe(1)
})
