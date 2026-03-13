import { FormEvent, useState, useCallback } from 'react'
import type { Conversation, IdentityInfo, Profile } from '../types'
import { IdentityPanel } from './IdentityPanel'
import { InvitePanel } from './InvitePanel'
import { ConversationList } from './ConversationList'
import { ContactList } from './ContactList'
import { CollapsiblePanel } from './CollapsiblePanel'

export interface SidebarProps {
  profiles: Profile[]
  activeProfileId: string
  identity: IdentityInfo
  newProfileName: string
  setNewProfileName: (value: string) => void
  inviteName: string
  setInviteName: (value: string) => void
  inviteToken: string
  setInviteToken: (value: string) => void
  createdInviteToken: string
  visibleConversations: Conversation[]
  selectedConversationId: string
  setSelectedConversationId: (id: string) => void
  hiddenConversations: Set<string>
  unreadCounts: Record<string, number>
  hiddenCount: number
  showHidden: boolean
  setShowHidden: (fn: (prev: boolean) => boolean) => void
  toggleHideConversation: (convId: string) => void
  visibleContactKeys: string[]
  contactDrafts: Record<string, string>
  contactNameByKey: Record<string, string>
  isWorking: boolean
  onSelectProfile: (profileId: string) => void
  onCreateProfile: (event: FormEvent<HTMLFormElement>) => void
  onGenerateIdentity: () => void
  onCreateInvite: () => void
  onAcceptInvite: () => void
  onContactDraftChange: (key: string, value: string) => void
  onSaveContact: (key: string) => void
  setStatus: (value: string) => void
}

type PanelId = 'identity' | 'invites' | 'conversations' | 'contacts'

export function Sidebar({
  profiles,
  activeProfileId,
  identity,
  newProfileName,
  setNewProfileName,
  inviteName,
  setInviteName,
  inviteToken,
  setInviteToken,
  createdInviteToken,
  visibleConversations,
  selectedConversationId,
  setSelectedConversationId,
  hiddenConversations,
  unreadCounts,
  hiddenCount,
  showHidden,
  setShowHidden,
  toggleHideConversation,
  visibleContactKeys,
  contactDrafts,
  contactNameByKey,
  isWorking,
  onSelectProfile,
  onCreateProfile,
  onGenerateIdentity,
  onCreateInvite,
  onAcceptInvite,
  onContactDraftChange,
  onSaveContact,
  setStatus,
}: SidebarProps) {
  const [expandedPanels, setExpandedPanels] = useState<Set<PanelId>>(
    () => new Set(['conversations']),
  )
  const [conversationFilter, setConversationFilter] = useState('')

  const toggle = useCallback((id: PanelId) => {
    setExpandedPanels((prev) => {
      const next = new Set(prev)
      if (next.has(id)) {
        next.delete(id)
      } else {
        next.add(id)
      }
      return next
    })
  }, [])

  const filteredConversations = conversationFilter
    ? visibleConversations.filter((c) =>
        c.name.toLowerCase().includes(conversationFilter.toLowerCase()),
      )
    : visibleConversations

  return (
    <aside className="sidebar">
      <CollapsiblePanel
        title="Identities"
        expanded={expandedPanels.has('identity')}
        onToggle={() => toggle('identity')}
      >
        <IdentityPanel
          profiles={profiles}
          activeProfileId={activeProfileId}
          identity={identity}
          newProfileName={newProfileName}
          setNewProfileName={setNewProfileName}
          isWorking={isWorking}
          onSelectProfile={onSelectProfile}
          onCreateProfile={onCreateProfile}
          onGenerateIdentity={onGenerateIdentity}
          setStatus={setStatus}
        />
      </CollapsiblePanel>

      <CollapsiblePanel
        title="Invites"
        expanded={expandedPanels.has('invites')}
        onToggle={() => toggle('invites')}
      >
        <InvitePanel
          inviteName={inviteName}
          setInviteName={setInviteName}
          inviteToken={inviteToken}
          setInviteToken={setInviteToken}
          createdInviteToken={createdInviteToken}
          identity={identity}
          isWorking={isWorking}
          onCreateInvite={onCreateInvite}
          onAcceptInvite={onAcceptInvite}
        />
      </CollapsiblePanel>

      <CollapsiblePanel
        title="Conversations"
        expanded={expandedPanels.has('conversations')}
        onToggle={() => toggle('conversations')}
        grow
        trailing={
          hiddenCount > 0 ? (
            <button
              className="button-small"
              type="button"
              onClick={(e) => {
                e.stopPropagation()
                setShowHidden((v) => !v)
              }}
              title={showHidden ? 'Hide hidden conversations' : 'Show hidden conversations'}
            >
              {showHidden ? `Hide (${hiddenCount})` : `${hiddenCount} hidden`}
            </button>
          ) : undefined
        }
      >
        <ConversationList
          visibleConversations={filteredConversations}
          selectedConversationId={selectedConversationId}
          setSelectedConversationId={setSelectedConversationId}
          hiddenConversations={hiddenConversations}
          unreadCounts={unreadCounts}
          hiddenCount={hiddenCount}
          showHidden={showHidden}
          setShowHidden={setShowHidden}
          toggleHideConversation={toggleHideConversation}
          conversationFilter={conversationFilter}
          setConversationFilter={setConversationFilter}
        />
      </CollapsiblePanel>

      <CollapsiblePanel
        title="Contacts"
        expanded={expandedPanels.has('contacts')}
        onToggle={() => toggle('contacts')}
      >
        <ContactList
          visibleContactKeys={visibleContactKeys}
          contactDrafts={contactDrafts}
          contactNameByKey={contactNameByKey}
          isWorking={isWorking}
          onContactDraftChange={onContactDraftChange}
          onSaveContact={onSaveContact}
        />
      </CollapsiblePanel>
    </aside>
  )
}
