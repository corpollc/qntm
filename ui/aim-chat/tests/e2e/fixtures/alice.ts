/**
 * Alice — Playwright page object for interacting with AIM UI in a real browser.
 */
import type { Page } from '@playwright/test'

export class Alice {
  constructor(private page: Page) {}

  /** Seed localStorage with the relay URL before navigating */
  async setup(relayUrl: string): Promise<void> {
    await this.page.goto('/')
    await this.page.evaluate((url) => {
      const existing = localStorage.getItem('aim-store')
      const data = existing ? JSON.parse(existing) : {}
      data.dropboxUrl = url
      localStorage.setItem('aim-store', JSON.stringify(data))
    }, relayUrl)
    await this.page.reload()
  }

  /** Create a new profile */
  async createProfile(name: string): Promise<void> {
    await this.page.getByRole('button', { name: 'Profile' }).click()
    const nameInput = this.page.getByPlaceholder('New profile name')
    await nameInput.waitFor({ state: 'visible' })
    await nameInput.fill(name)
    await this.page.getByRole('button', { name: 'Add' }).click()
    await this.page.waitForSelector('.pubkey-value')
  }

  /** Join a conversation using the sidebar InvitePanel */
  async joinInviteViaSidebar(token: string, name: string): Promise<void> {
    // Ensure the Invites panel is open (click header only if currently collapsed)
    const invitesHeader = this.page.getByRole('button', { name: 'Invites', exact: true })
    const isExpanded = await invitesHeader.getAttribute('aria-expanded')
    if (isExpanded !== 'true') {
      await invitesHeader.click()
    }
    const tokenInput = this.page.getByPlaceholder('Paste an invite link or token')
    await tokenInput.waitFor({ state: 'visible' })
    await tokenInput.fill(token)
    if (name) {
      await this.page.getByPlaceholder('Label for this conversation (optional)').fill(name)
    }
    await this.page.getByRole('button', { name: 'Join' }).click()
    await this.page.waitForTimeout(500)
  }

  /** Join a conversation via the JoinModal (URL-based invite) */
  async joinInviteViaModal(name: string): Promise<void> {
    if (name) {
      await this.page.getByPlaceholder('e.g. Team Chat, Project Alpha').fill(name)
    }
    await this.page.getByRole('button', { name: 'Join' }).click()
    await this.page.waitForTimeout(500)
  }

  /** Rename a conversation by clicking edit, typing new name, pressing Enter */
  async renameConversation(currentName: string, newName: string): Promise<void> {
    const row = this.page.locator('.conversation', { hasText: currentName })
    await row.getByLabel('Rename conversation').click()
    const input = this.page.locator('.conversation-rename-input')
    await input.fill(newName)
    await input.press('Enter')
  }

  /** Delete a conversation — clicks delete then confirms dialog */
  async deleteConversation(name: string): Promise<void> {
    const row = this.page.locator('.conversation', { hasText: name })
    await row.getByLabel('Delete conversation').click()
    const dialog = this.page.getByRole('dialog', { name: 'Delete Conversation' })
    await dialog.waitFor({ state: 'visible' })
    await dialog.getByRole('button', { name: 'Delete' }).click()
  }

  /** Cancel a delete confirmation */
  async cancelDeleteConversation(name: string): Promise<void> {
    const row = this.page.locator('.conversation', { hasText: name })
    await row.getByLabel('Delete conversation').click()
    const dialog = this.page.getByRole('dialog', { name: 'Delete Conversation' })
    await dialog.waitFor({ state: 'visible' })
    await dialog.getByRole('button', { name: 'Cancel' }).click()
  }

  /** Get all visible conversation names */
  async getConversationNames(): Promise<string[]> {
    const names = await this.page.locator('.conversation-name').allTextContents()
    return names
  }

  /** Refresh the page */
  async refresh(): Promise<void> {
    await this.page.reload()
    await this.page.waitForTimeout(500)
  }
}
