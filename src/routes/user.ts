// User endpoints — authenticated users managing their own data
// Profile, API keys, sessions

import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify'
import { z }              from 'zod'
import { db, adminAuth }  from '../lib/supabase.js'
import { authenticate }   from '../middleware/auth.js'
import { generateApiKey } from '../lib/apikeys.js'
import { getScopesForRole } from '../lib/types.js'
import { audit }          from '../lib/audit.js'

function getIp(req: FastifyRequest): string {
  const fwd = req.headers['x-forwarded-for']
  return typeof fwd === 'string' ? fwd.split(',')[0]!.trim() : req.ip ?? 'unknown'
}

function err(reply: FastifyReply, status: number, message: string) {
  return reply.status(status).send({ error: message })
}

// Valid scopes a user can assign to their own API keys
// (cannot exceed their own role's scopes)
function filterScopes(requested: string[], userScopes: string[]): string[] {
  return requested.filter(s => userScopes.includes(s) || userScopes.includes('*'))
}

export async function userRoutes(app: FastifyInstance) {

  // ══════════════════════════════════════════════════════════════
  // PROFILE
  // ══════════════════════════════════════════════════════════════

  // ── GET /user/me ───────────────────────────────────────────
  app.get('/user/me', {
    preHandler: [authenticate],
  }, async (req: FastifyRequest, reply: FastifyReply) => {
    const { data: profile } = await db
      .from('profiles')
      .select('id, email, full_name, avatar_url, role, metadata, created_at, updated_at')
      .eq('id', req.user!.sub)
      .single()

    if (!profile) return err(reply, 404, 'Profile not found')

    return reply.send({
      user: {
        ...profile,
        scopes: getScopesForRole(profile.role),
      },
    })
  })

  // ── PATCH /user/me ─────────────────────────────────────────
  app.patch('/user/me', {
    preHandler: [authenticate],
  }, async (req: FastifyRequest, reply: FastifyReply) => {
    const body = z.object({
      fullName:  z.string().min(1).max(100).optional(),
      avatarUrl: z.string().url().optional(),
      metadata:  z.record(z.unknown()).optional(),
    }).safeParse(req.body)

    if (!body.success) return err(reply, 400, body.error.errors[0]!.message)

    const updates: Record<string, unknown> = {}
    if (body.data.fullName  !== undefined) updates['full_name']  = body.data.fullName
    if (body.data.avatarUrl !== undefined) updates['avatar_url'] = body.data.avatarUrl
    if (body.data.metadata  !== undefined) updates['metadata']   = body.data.metadata

    if (Object.keys(updates).length === 0) {
      return err(reply, 400, 'No fields to update')
    }

    await db.from('profiles').update(updates).eq('id', req.user!.sub)

    // Sync name to Supabase Auth user metadata
    if (body.data.fullName) {
      await adminAuth.updateUserById(req.user!.sub, {
        user_metadata: { full_name: body.data.fullName },
      })
    }

    audit({
      userId:   req.user!.sub,
      action:   'profile_updated',
      ip:       getIp(req),
    })

    return reply.send({ message: 'Profile updated successfully' })
  })

  // ── POST /user/change-password ─────────────────────────────
  // User changes their own password — requires current password verification
  // via Supabase client-side first, then we update
  app.post('/user/change-password', {
    preHandler: [authenticate],
    config: { rateLimit: { max: 5, timeWindow: '15 minutes' } },
  }, async (req: FastifyRequest, reply: FastifyReply) => {
    const body = z.object({
      newPassword: z.string()
        .min(8, 'Password must be at least 8 characters')
        .max(128, 'Password too long')
        .regex(/[A-Z]/, 'Must include uppercase letter')
        .regex(/[a-z]/, 'Must include lowercase letter')
        .regex(/[^A-Za-z0-9]/, 'Must include special character'),
    }).safeParse(req.body)

    if (!body.success) return err(reply, 400, body.error.errors[0]!.message)

    const { error } = await adminAuth.updateUserById(req.user!.sub, {
      password: body.data.newPassword,
    })

    if (error) return err(reply, 400, error.message)

    audit({
      userId: req.user!.sub,
      action: 'password_changed',
      ip:     getIp(req),
    })

    return reply.send({ message: 'Password changed successfully' })
  })

  // ══════════════════════════════════════════════════════════════
  // API KEYS (user's own keys)
  // ══════════════════════════════════════════════════════════════

  // ── GET /user/api-keys ─────────────────────────────────────
  app.get('/user/api-keys', {
    preHandler: [authenticate],
  }, async (req: FastifyRequest, reply: FastifyReply) => {
    const { data } = await db
      .from('api_keys')
      .select('id, name, key_prefix, scopes, is_active, last_used_at, expires_at, created_at')
      .eq('user_id', req.user!.sub)
      .order('created_at', { ascending: false })

    return reply.send({ keys: data ?? [] })
  })

  // ── POST /user/api-keys ────────────────────────────────────
  app.post('/user/api-keys', {
    preHandler: [authenticate],
    config: { rateLimit: { max: 10, timeWindow: '1 hour' } },
  }, async (req: FastifyRequest, reply: FastifyReply) => {
    const body = z.object({
      name:      z.string().min(1).max(100),
      scopes:    z.array(z.string()).min(1),
      expiresAt: z.string().datetime().optional(),
    }).safeParse(req.body)

    if (!body.success) return err(reply, 400, body.error.errors[0]!.message)

    // Only allow scopes the user actually has
    const allowedScopes = filterScopes(body.data.scopes, req.user!.scopes)
    if (allowedScopes.length === 0) {
      return err(reply, 403, 'None of the requested scopes are available to your account')
    }

    const { raw, hash, prefix } = generateApiKey()

    const { data: key, error } = await db.from('api_keys').insert({
      user_id:    req.user!.sub,
      name:       body.data.name,
      key_hash:   hash,
      key_prefix: prefix,
      scopes:     allowedScopes,
      expires_at: body.data.expiresAt ?? null,
    }).select('id, name, key_prefix, scopes, expires_at, created_at').single()

    if (error || !key) return err(reply, 500, 'Failed to create API key')

    audit({
      userId:     req.user!.sub,
      action:     'api_key_created',
      resourceId: key.id,
      metadata:   { scopes: allowedScopes },
      ip:         getIp(req),
    })

    return reply.status(201).send({
      ...key,
      key:     raw,
      warning: 'Store this key now. It cannot be retrieved again.',
    })
  })

  // ── DELETE /user/api-keys/:id ──────────────────────────────
  app.delete('/user/api-keys/:id', {
    preHandler: [authenticate],
  }, async (req: FastifyRequest, reply: FastifyReply) => {
    const { id } = req.params as { id: string }

    const { error } = await db
      .from('api_keys')
      .update({ is_active: false })
      .eq('id', id)
      .eq('user_id', req.user!.sub)  // ensure user owns this key

    if (error) return err(reply, 500, 'Failed to revoke key')

    audit({
      userId:     req.user!.sub,
      action:     'api_key_revoked',
      resourceId: id,
      ip:         getIp(req),
    })

    return reply.send({ message: 'API key revoked' })
  })

  // ══════════════════════════════════════════════════════════════
  // SESSIONS
  // ══════════════════════════════════════════════════════════════

  // ── GET /user/sessions ─────────────────────────────────────
  // List all active sessions for the user
  app.get('/user/sessions', {
    preHandler: [authenticate],
  }, async (req: FastifyRequest, reply: FastifyReply) => {
    // Fetch from Supabase Auth admin API
    const { data: { user }, error } = await adminAuth.getUserById(req.user!.sub)

    if (error || !user) return err(reply, 404, 'User not found')

    return reply.send({
      message: 'To view and manage sessions, use the Supabase Auth client in your frontend.',
      userId:  req.user!.sub,
    })
  })

  // ── DELETE /user/sessions/all ──────────────────────────────
  // Sign out from all sessions
  app.delete('/user/sessions/all', {
    preHandler: [authenticate],
  }, async (req: FastifyRequest, reply: FastifyReply) => {
    // Sign out all sessions for this user
    const { error } = await adminAuth.signOut(req.headers['authorization']!.slice(7), 'global')

    if (error) return err(reply, 500, 'Failed to sign out all sessions')

    audit({
      userId: req.user!.sub,
      action: 'all_sessions_revoked',
      ip:     getIp(req),
    })

    return reply.send({ message: 'Signed out from all sessions' })
  })

  // ── GET /user/audit-log ────────────────────────────────────
  // User's own activity log
  app.get('/user/audit-log', {
    preHandler: [authenticate],
  }, async (req: FastifyRequest, reply: FastifyReply) => {
    const { limit = '20', offset = '0' } = req.query as Record<string, string>

    const { data } = await db
      .from('audit_log')
      .select('id, action, resource, metadata, ip_address, created_at')
      .eq('user_id', req.user!.sub)
      .order('created_at', { ascending: false })
      .range(parseInt(offset), parseInt(offset) + parseInt(limit) - 1)

    return reply.send({ logs: data ?? [] })
  })
}