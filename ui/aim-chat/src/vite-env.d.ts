/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_DEFAULT_GATEWAY_URL?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
