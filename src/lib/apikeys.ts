import { createHash, randomBytes } from 'crypto'
import { db } from './supabase.js'

export function generateApiKey(): { raw: string; hash: string; prefix: string } {
  const raw    = `sk_live_${randomBytes(24).toString('hex')}`
  const hash   = createHash('sha256').update(raw).digest('hex')
  const prefix = raw.slice(0, 14)
  return { raw, hash, prefix }
}

export function hashApiKey(raw: string): string {
  return createHash('sha256').update(raw).digest('hex')
}

export async function validateApiKey(raw: string): Promise<{
  userId:    string
  scopes:    string[]
  keyId:     string
} | null> {
  if (!raw.startsWith('sk_live_') && !raw.startsWith('sk_test_')) return null

  const hash = hashApiKey(raw)

  const { data } = await db
    .from('api_keys')
    .select('id, user_id, scopes, is_active, expires_at')
    .eq('key_hash', hash)
    .maybeSingle()

  if (!data || !data.is_active) return null
  if (data.expires_at && new Date(data.expires_at) < new Date()) return null

  // Update last_used_at — fire and forget
  void db.from('api_keys')
    .update({ last_used_at: new Date().toISOString() })
    .eq('id', data.id)
    .then(() => {}, () => {})

  return {
    userId: data.user_id,
    scopes: data.scopes as string[],
    keyId:  data.id,
  }
}