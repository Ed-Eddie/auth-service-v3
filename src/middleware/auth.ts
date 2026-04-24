import type { FastifyRequest, FastifyReply } from 'fastify'
import { createClient }  from '@supabase/supabase-js'
import { validateApiKey } from '../lib/apikeys.js'
import { db }             from '../lib/supabase.js'
import { getScopesForRole } from '../lib/types.js'
import type { RequestUser, Role } from '../lib/types.js'

declare module 'fastify' {
  interface FastifyRequest {
    user?: RequestUser
  }
}

const SUPABASE_URL = process.env.SUPABASE_URL ?? ''
const ANON_KEY     = process.env.SUPABASE_ANON_KEY ?? ''

// ── Main auth middleware ───────────────────────────────────────
export async function authenticate(req: FastifyRequest, reply: FastifyReply) {
  const header = req.headers['authorization']
  if (!header) return reply.status(401).send({ error: 'Missing authorization header' })

  // ── API Key ────────────────────────────────────────────────
  if (header.startsWith('ApiKey ')) {
    const raw    = header.slice(7).trim()
    const result = await validateApiKey(raw)

    if (!result) return reply.status(401).send({ error: 'Invalid or revoked API key' })

    // Load user profile to get role
    const { data: profile } = await db
      .from('profiles')
      .select('id, email, role, is_active')
      .eq('id', result.userId)
      .single()

    if (!profile || !profile.is_active) {
      return reply.status(401).send({ error: 'Account is inactive' })
    }

    req.user = {
      sub:       profile.id,
      email:     profile.email,
      role:      profile.role as Role,
      is_active: profile.is_active,
      scopes:    result.scopes,
      aud:       'authenticated',
      exp:       0,
    }
    return
  }

  // ── Bearer JWT (Supabase token) ────────────────────────────
  if (header.startsWith('Bearer ')) {
    const token = header.slice(7)

    // Verify with Supabase
    const client = createClient(SUPABASE_URL, ANON_KEY, {
      auth:    { persistSession: false },
      global:  { headers: { Authorization: `Bearer ${token}` } },
    })

    const { data: { user }, error } = await client.auth.getUser()

    if (error || !user) {
      return reply.status(401).send({ error: 'Invalid or expired token' })
    }

    // Get profile for role and active status
    const { data: profile } = await db
      .from('profiles')
      .select('role, is_active, full_name')
      .eq('id', user.id)
      .maybeSingle()

    if (!profile || !profile.is_active) {
      return reply.status(403).send({ error: 'Account is inactive. Contact support.' })
    }

    const role   = (profile.role ?? 'user') as Role
    const scopes = getScopesForRole(role)

    req.user = {
      sub:       user.id,
      email:     user.email ?? '',
      role,
      is_active: profile.is_active,
      scopes,
      aud:       'authenticated',
      exp:       0,
    }
    return
  }

  return reply.status(401).send({ error: 'Use Bearer <token> or ApiKey <key>' })
}

// ── Role guards ────────────────────────────────────────────────
export function requireRole(...roles: Role[]) {
  return async function (req: FastifyRequest, reply: FastifyReply) {
    if (!req.user) return reply.status(401).send({ error: 'Not authenticated' })
    if (!roles.includes(req.user.role)) {
      return reply.status(403).send({ error: `Requires role: ${roles.join(' or ')}` })
    }
  }
}

export function requireScope(scope: string) {
  return async function (req: FastifyRequest, reply: FastifyReply) {
    const scopes = req.user?.scopes ?? []
    if (!scopes.includes(scope) && !scopes.includes('*')) {
      return reply.status(403).send({ error: `Missing required scope: ${scope}` })
    }
  }
}

// Shorthand middleware combos
export const requireAdmin      = [authenticate, requireRole('admin', 'super_admin')]
export const requireSuperAdmin = [authenticate, requireRole('super_admin')]
export const requireAuth       = [authenticate]