import { openSecret, base64UrlDecode } from '@corpollc/qntm';
import type { VaultEntry, GateSecretMessage } from './types.js';

/**
 * Process a gate.secret message: decrypt the NaCl box using the gateway's
 * per-conversation private key and sender's public key, then encrypt at rest
 * using AES-256-GCM with GATE_VAULT_KEY.
 */
export async function processSecret(
  msg: GateSecretMessage,
  gatewayPrivateKey: Uint8Array,
  senderPublicKey: Uint8Array,
  vaultKey: CryptoKey,
): Promise<VaultEntry> {
  // Decrypt the NaCl box (X25519-XSalsa20-Poly1305)
  const encryptedBlob = base64UrlDecode(msg.encrypted_blob);
  const decryptedBytes = openSecret(gatewayPrivateKey, senderPublicKey, encryptedBlob);

  // Encrypt at rest with AES-256-GCM
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encryptedAtRest = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    vaultKey,
    decryptedBytes,
  );

  // Combine IV + ciphertext for storage
  const combined = new Uint8Array(iv.length + encryptedAtRest.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(encryptedAtRest), iv.length);

  // Zero the plaintext in memory
  decryptedBytes.fill(0);

  // Compute expiry
  let expiresAt = '';
  if (msg.ttl && msg.ttl > 0) {
    expiresAt = new Date(Date.now() + msg.ttl * 1000).toISOString();
  }

  return {
    secret_id: msg.secret_id,
    service: msg.service,
    header_name: msg.header_name,
    header_template: msg.header_template,
    encrypted_value: uint8ToBase64(combined),
    expires_at: expiresAt,
    stored_at: new Date().toISOString(),
  };
}

/**
 * Decrypt a vault entry's credential value for use in API execution.
 * Returns the plaintext credential value. Caller must zero it after use.
 */
export async function decryptVaultEntry(
  entry: VaultEntry,
  vaultKey: CryptoKey,
): Promise<string> {
  const combined = base64ToUint8(entry.encrypted_value);
  const iv = combined.slice(0, 12);
  const ciphertext = combined.slice(12);

  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    vaultKey,
    ciphertext,
  );

  return new TextDecoder().decode(decrypted);
}

/**
 * Check if a vault entry has expired.
 */
export function isExpired(entry: VaultEntry, now: number = Date.now()): boolean {
  if (!entry.expires_at) return false;
  return now > new Date(entry.expires_at).getTime();
}

/**
 * Import the GATE_VAULT_KEY secret as a CryptoKey for AES-256-GCM.
 */
export async function importVaultKey(keyHex: string): Promise<CryptoKey> {
  const keyBytes = hexToBytes(keyHex);
  return crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'AES-GCM' },
    false,
    ['encrypt', 'decrypt'],
  );
}


function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

function uint8ToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToUint8(s: string): Uint8Array {
  const binary = atob(s);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
