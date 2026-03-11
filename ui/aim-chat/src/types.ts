export interface Profile {
  id: string
  name: string
  configDir: string
  storage: string
  dropboxUrl: string
  qntmBin: string
}

export interface IdentityInfo {
  exists: boolean
  keyId: string
  publicKey: string
}

export interface Conversation {
  id: string
  name: string
  type: string
  participants: string[]
  createdAt: string | null
}

export interface ContactAlias {
  key: string
  name: string
}

export type MessageDirection = 'incoming' | 'outgoing'

export interface ChatMessage {
  id: string
  conversationId: string
  direction: MessageDirection
  sender: string
  senderKey?: string
  bodyType: string
  text: string
  createdAt: string
}

export interface RecipeParam {
  name: string
  description: string
  required: boolean
  default?: string
  type: string // "string", "integer", "boolean"
}

export interface GateRecipe {
  name: string
  description: string
  service: string
  verb: string
  endpoint: string
  target_url: string
  risk_tier: string
  threshold: number
  path_params?: RecipeParam[]
  query_params?: RecipeParam[]
  body_schema?: Record<string, unknown>
  body_example?: Record<string, unknown>
}
