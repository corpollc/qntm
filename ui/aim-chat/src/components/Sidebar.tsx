import { FormEvent } from 'react'
import type { Conversation, IdentityInfo, Profile } from '../types'
import { IdentityPanel } from './IdentityPanel'
import { InvitePanel } from './InvitePanel'
import { ConversationList } from './ConversationList'
import { ContactList } from './ContactList'

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
  return (
    <aside className="sidebar">
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

      <ConversationList
        visibleConversations={visibleConversations}
        selectedConversationId={selectedConversationId}
        setSelectedConversationId={setSelectedConversationId}
        hiddenConversations={hiddenConversations}
        hiddenCount={hiddenCount}
        showHidden={showHidden}
        setShowHidden={setShowHidden}
        toggleHideConversation={toggleHideConversation}
      />

      <ContactList
        visibleContactKeys={visibleContactKeys}
        contactDrafts={contactDrafts}
        contactNameByKey={contactNameByKey}
        isWorking={isWorking}
        onContactDraftChange={onContactDraftChange}
        onSaveContact={onSaveContact}
      />
    </aside>
  )
}
