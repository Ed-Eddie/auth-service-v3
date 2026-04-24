// Admin endpoints — requires admin or super_admin role
// User management, API key management, audit log

import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify'
import { z }             from 'zod'
import { db, adminAuth } from '../lib/supabase.js'
import { requireAdmin, requireSuperAdmin, authenticate } from '../middleware/auth.js'
import { generateApiKey } from '../lib/apikeys.js'
import { audit }          from '../lib/audit.js'
import type { Role }      from '../lib/types.js'

function getIp(req: FastifyRequest): string {
  const fwd = req.headers['x-forwarded-for']
  return typeof fwd === 'string' ? fwd.split(',')[0]!.trim() : req.ip ?? 'unknown'
}

function err(reply: FastifyReply, status: number, message: string) {
  return reply.status(status).send({ error: message })
}

export async function adminRoutes(app: FastifyInstance) {

  // ══════════════════════════════════════════════════════════════
  // USER MANAGEMENT
  // ══════════════════════════════════════════════════════════════

  // ── GET /admin/users ───────────────────────────────────────
  app.get('/admin/users', {
    preHandler: requireAdmin,
  }, async (req: FastifyRequest, reply: FastifyReply) => {
    const { limit = '50', offset = '0', role, search, is_active } =
      req.query as Record<string, string>

    let query = db
      .from('profiles')
      .select('id, email, full_name, role, is_active, created_at, updated_at')
      .order('created_at', { ascending: false })
      .range(parseInt(offset), parseInt(offset) + parseInt(limit) - 1)

    if (role)      query = query.eq('role', role)
    if (is_active) query = query.eq('is_active', is_active === 'true')
    if (search)    query = query.or(
      `email.ilike.%${search}%,full_name.ilike.%${search}%`
    )

    // Non-super_admins cannot see super_admin users
    if (req.user!.role !== 'super_admin') {
      query = query.neq('role', 'super_admin')
    }

    const { data, count } = await query
    return reply.send({ users: data ?? [], total: count ?? 0 })
  })

  // ── GET /admin/users/:id ───────────────────────────────────
  app.get('/admin/users/:id', {
    preHandler: requireAdmin,
  }, async (req: FastifyRequest, reply: FastifyReply) => {
    const { id } = req.params as { id: string }

    const { data: profile } = await db
      .from('profiles')
      .select('id, email, full_name, avatar_url, role, is_active, metadata, created_at')
      .eq('id', id)
      .single()

    if (!profile) return err(reply, 404, 'User not found')

    // Prevent non-super_admins from viewing super_admin users
    if (profile.role === 'super_admin' && req.user!.role !== 'super_admin') {
      return err(reply, 403, 'Access denied')
    }

    // Get user's API keys (without hash)
    const { data: keys } = await db
      .from('api_keys')
      .select('id, name, key_prefix, scopes, is_active, last_used_at, expires_at, created_at')
      .eq('user_id', id)
      .order('created_at', { ascending: false })

    return reply.send({ user: profile, apiKeys: keys ?? [] })
  })

  // ── POST /admin/users/invite ───────────────────────────────
  // Create a user and send them an invite email via Supabase
  app.post('/admin/users/invite', {
    preHandler: requireAdmin,
    config: { rateLimit: { max: 20, timeWindow: '1 hour' } },
  }, async (req: FastifyRequest, reply: FastifyReply) => {
    const body = z.object({
      email:    z.string().email(),
      fullName: z.string().min(1).max(100).optional(),
      role:     z.enum(['admin', 'user']).default('user'),
    }).safeParse(req.body)

    if (!body.success) return err(reply, 400, body.error.errors[0]!.message)

    // Prevent non-super_admins from creating admin users
    if (body.data.role === 'admin' && req.user!.role !== 'super_admin') {
      return err(reply, 403, 'Only super admins can create admin users')
    }

    const { email, fullName, role } = body.data

    // Invite via Supabase — sends invite email automatically
    const { data, error } = await adminAuth.inviteUserByEmail(email, {
      data: { full_name: fullName, role },
    })

    if (error) {
      if (error.message.includes('already')) {
        return err(reply, 409, 'A user with this email already exists')
      }
      return err(reply, 400, error.message)
    }

    // Ensure profile has correct role
    await db.from('profiles').upsert({
      id:        data.user.id,
      email,
      full_name: fullName ?? null,
      role,
    }, { onConflict: 'id' })

    audit({
      userId:     req.user!.sub,
      action:     'user_invited',
      resource:   'profiles',
      resourceId: data.user.id,
      metadata:   { email, role },
      ip:         getIp(req),
    })

    return reply.status(201).send({
      message: `Invite sent to ${email}`,
      userId:  data.user.id,
    })
  })

  // ── PATCH /admin/users/:id/role ────────────────────────────
  app.patch('/admin/users/:id/role', {
    preHandler: requireAdmin,
  }, async (req: FastifyRequest, reply: FastifyReply) => {
    const { id }   = req.params as { id: string }
    const body     = z.object({
      role: z.enum(['admin', 'user']),
    }).safeParse(req.body)

    if (!body.success) return err(reply, 400, body.error.errors[0]!.message)

    // Only super_admin can assign admin role
    if (body.data.role === 'admin' && req.user!.role !== 'super_admin') {
      return err(reply, 403, 'Only super admins can assign the admin role')
    }

    // Cannot change own role
    if (id === req.user!.sub) return err(reply, 400, 'Cannot change your own role')

    await db.from('profiles').update({ role: body.data.role }).eq('id', id)

    // Update user metadata in Supabase Auth
    await adminAuth.updateUserById(id, {
      user_metadata: { role: body.data.role },
    })

    audit({
      userId:     req.user!.sub,
      action:     'user_role_changed',
      resource:   'profiles',
      resourceId: id,
      metadata:   { newRole: body.data.role },
      ip:         getIp(req),
    })

    return reply.send({ message: `User role updated to ${body.data.role}` })
  })

  // ── PATCH /admin/users/:id/status ─────────────────────────
  app.patch('/admin/users/:id/status', {
    preHandler: requireAdmin,
  }, async (req: FastifyRequest, reply: FastifyReply) => {
    const { id }      = req.params as { id: string }
    const { is_active } = req.body as { is_active: boolean }

    if (id === req.user!.sub) return err(reply, 400, 'Cannot change your own status')

    await db.from('profiles').update({ is_active }).eq('id', id)

    // Ban/unban in Supabase Auth
    if (!is_active) {
      await adminAuth.updateUserById(id, { ban_duration: '87600h' })  // 10 years = banned
    } else {
      await adminAuth.updateUserById(id, { ban_duration: 'none' })
    }

    audit({
      userId:     req.user!.sub,
      action:     is_active ? 'user_activated' : 'user_deactivated',
      resource:   'profiles',
      resourceId: id,
      ip:         getIp(req),
    })

    return reply.send({ message: `User ${is_active ? 'activated' : 'deactivated'}` })
  })

  // ── DELETE /admin/users/:id ────────────────────────────────
  app.delete('/admin/users/:id', {
    preHandler: requireSuperAdmin,
  }, async (req: FastifyRequest, reply: FastifyReply) => {
    const { id } = req.params as { id: string }

    if (id === req.user!.sub) return err(reply, 400, 'Cannot delete your own account')

    // Delete from Supabase Auth — cascades to profiles via FK
    const { error } = await adminAuth.deleteUser(id)
    if (error) return err(reply, 500, error.message)

    audit({
      userId:     req.user!.sub,
      action:     'user_deleted',
      resource:   'profiles',
      resourceId: id,
      ip:         getIp(req),
    })

    return reply.send({ message: 'User deleted permanently' })
  })

  // ── POST /admin/users/:id/reset-password ──────────────────
  // Send password reset email to a user
  app.post('/admin/users/:id/reset-password', {
    preHandler: requireAdmin,
  }, async (req: FastifyRequest, reply: FastifyReply) => {
    const { id } = req.params as { id: string }

    const { data: profile } = await db
      .from('profiles')
      .select('email')
      .eq('id', id)
      .single()

    if (!profile) return err(reply, 404, 'User not found')

    // Supabase sends password reset email using configured SMTP
    await adminAuth.generateLink({
      type:  'recovery',
      email: profile.email,
      options: {
        redirectTo: `${process.env.FRONTEND_URL}/reset-password`,
      },
    })

    audit({
      userId:     req.user!.sub,
      action:     'password_reset_sent',
      resourceId: id,
      ip:         getIp(req),
    })

    return reply.send({ message: `Password reset email sent to ${profile.email}` })
  })

  // ══════════════════════════════════════════════════════════════
  // API KEY MANAGEMENT (admin view — all keys)
  // ══════════════════════════════════════════════════════════════

  // ── GET /admin/api-keys ────────────────────────────────────
  app.get('/admin/api-keys', {
    preHandler: requireAdmin,
  }, async (req: FastifyRequest, reply: FastifyReply) => {
    const { limit = '50', offset = '0', userId } =
      req.query as Record<string, string>

    let query = db
      .from('api_keys')
      .select(`
        id, name, key_prefix, scopes, is_active,
        last_used_at, expires_at, created_at,
        profiles(id, email, full_name)
      `)
      .order('created_at', { ascending: false })
      .range(parseInt(offset), parseInt(offset) + parseInt(limit) - 1)

    if (userId) query = query.eq('user_id', userId)

    const { data } = await query
    return reply.send({ keys: data ?? [] })
  })

  // ── DELETE /admin/api-keys/:id ─────────────────────────────
  app.delete('/admin/api-keys/:id', {
    preHandler: requireAdmin,
  }, async (req: FastifyRequest, reply: FastifyReply) => {
    const { id } = req.params as { id: string }

    await db.from('api_keys').update({ is_active: false }).eq('id', id)

    audit({
      userId:     req.user!.sub,
      action:     'api_key_revoked_by_admin',
      resourceId: id,
      ip:         getIp(req),
    })

    return reply.send({ message: 'API key revoked' })
  })

  // ══════════════════════════════════════════════════════════════
  // AUDIT LOG
  // ══════════════════════════════════════════════════════════════

  // ── GET /admin/audit-log ───────────────────────────────────
  app.get('/admin/audit-log', {
    preHandler: requireAdmin,
  }, async (req: FastifyRequest, reply: FastifyReply) => {
    const { limit = '50', offset = '0', userId, action } =
      req.query as Record<string, string>

    let query = db
      .from('audit_log')
      .select(`
        id, action, resource, resource_id, metadata,
        ip_address, created_at,
        profiles(id, email, full_name)
      `)
      .order('created_at', { ascending: false })
      .range(parseInt(offset), parseInt(offset) + parseInt(limit) - 1)

    if (userId) query = query.eq('user_id', userId)
    if (action) query = query.eq('action', action)

    const { data } = await query
    return reply.send({ logs: data ?? [] })
  })
}