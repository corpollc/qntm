import { test, expect } from '@playwright/test'
import { RelayStub } from './fixtures/relay-stub'
import { gatewayResultFixture } from './fixtures/gateway-result'

let relay: RelayStub
test.beforeEach(async ({ page }) => {
  relay = new RelayStub(); await relay.start()
  const data = gatewayResultFixture(relay.url)
  await page.addInitScript(value => localStorage.setItem('aim-store', JSON.stringify(value)), data)
  await page.goto('/')
})
test.afterEach(async () => { await relay.stop() })

test('long response expands completely, remains literal text and collapses without changing stored history', async ({ page }) => {
  const card = page.locator('.gate-result[data-request-id="long-response"]')
  const body = card.locator('.gate-result-body')
  const saved = await page.evaluate(() => JSON.parse(localStorage.getItem('aim-store')!).history)
  await expect(body).not.toContainText('Complete response visible')
  const expand = card.getByRole('button', { name: 'Show full response' })
  await expect(expand).toHaveAttribute('aria-expanded', 'false')
  await expand.click()
  await expect(body).toContainText('Complete response visible')
  await expect(body).toContainText('<img src=x onerror=')
  await expect(body.locator('img')).toHaveCount(0)
  expect(await page.evaluate(() => 'responseExecuted' in window)).toBe(false)
  await expect(card.getByRole('button', { name: 'Show preview' })).toHaveAttribute('aria-expanded', 'true')
  await body.focus(); await page.keyboard.press('ControlOrMeta+End')
  await card.getByRole('button', { name: 'Show preview' }).click()
  await expect(body).not.toContainText('Complete response visible')
  expect(await page.evaluate(() => JSON.parse(localStorage.getItem('aim-store')!).history)).toEqual(saved)
})
