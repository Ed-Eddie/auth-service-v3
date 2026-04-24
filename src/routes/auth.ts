// Public auth endpoints — thin wrappers over Supabase Auth
// Supabase handles: OTP email, password reset, MFA, brute force protection
// We handle: profile creation, role assignment, scopes

import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify'
import { z }              from 'zod'
import { createClient }   from '@supabase/supabase-js'
import { db, adminAuth }  from '../lib/supabase.js'
import { authenticate }   from '../middleware/auth.js'
import { getScopesForRole } from '../lib/types.js'
import { audit }          from '../lib/audit.js'
import type { Role }      from '../lib/types.js'

function getIp(req: FastifyRequest): string {
  const fwd = req.headers['x-forwarded-for']
  return typeof fwd === 'string' ? fwd.split(',')[0]!.trim() : req.ip ?? 'unknown'
}

function err(reply: FastifyReply, status: number, message: string) {
  return reply.status(status).send({ error: message })
}

export async function authRoutes(app: FastifyInstance) {

  // ── POST /auth/register ────────────────────────────────────
  // Supabase creates the user and sends OTP email automatically
  // We just ensure a profile record exists with the right role
  app.post('/auth/register', {
    config: { rateLimit: { max: 5, timeWindow: '1 hour' } },
  }, async (req: FastifyRequest, reply: FastifyReply) => {
    const body = z.object({
      email:    z.string().email(),
      password: z.string().min(8, 'Password must be at least 8 characters'),
      fullName: z.string().min(1).max(100).optional(),
      role:     z.enum(['admin', 'user']).default('user'),
    }).safeParse(req.body)

    if (!body.success) return err(reply, 400, body.error.errors[0]!.message)

    const { email, password, fullName, role } = body.data

    // Create user in Supabase Auth — triggers OTP email automatically
    const { data, error } = await adminAuth.createUser({
      email,
      password,
      email_confirm: false,  // require email verification
      user_metadata: { full_name: fullName, role },
    })

    if (error) {
      if (error.message.includes('already registered')) {
        return err(reply, 409, 'An account with this email already exists')
      }
      return err(reply, 400, error.message)
    }

    // Profile is created automatically by the DB trigger
    // Update role explicitly in case trigger doesn't get metadata
    await db.from('profiles').upsert({
      id:        data.user.id,
      email,
      full_name: fullName ?? null,
      role,
    }, { onConflict: 'id' })

    audit({
      userId:   data.user.id,
      action:   'user_registered',
      resource: 'profiles',
      ip:       getIp(req),
    })

    return reply.status(201).send({
      message: 'Account created. Please check your email for a verification code.',
      userId:  data.user.id,
    })
  })

  // ── POST /auth/login ───────────────────────────────────────
  // Validates token from Supabase and returns enriched user info
  // Actual login happens client-side via Supabase SDK
  // This endpoint is called after Supabase login to get scopes/role
  app.post('/auth/login', {
    config: { rateLimit: { max: 20, timeWindow: '15 minutes' } },
  }, async (req: FastifyRequest, reply: FastifyReply) => {
    const body = z.object({
      accessToken: z.string().min(1),
    }).safeParse(req.body)

    if (!body.success) return err(reply, 400, 'accessToken is required')

    // Verify the Supabase token by creating a user-scoped client
    const userClient = createClient(
      process.env.SUPABASE_URL ?? '',
      process.env.SUPABASE_ANON_KEY ?? '',
      { auth: { persistSession: false }, global: { headers: { Authorization: `Bearer ${body.data.accessToken}` } } }
    )
    const { data: { user }, error } = await userClient.auth.getUser()

    if (error || !user) return err(reply, 401, 'Invalid or expired token')

    // Get profile
    const { data: profile } = await db
      .from('profiles')
      .select('role, is_active, full_name, avatar_url')
      .eq('id', user.id)
      .single()

    if (!profile) return err(reply, 404, 'Profile not found. Please contact support.')
    if (!profile.is_active) return err(reply, 403, 'Account suspended. Contact support.')

    const role   = (profile.role ?? 'user') as Role
    const scopes = getScopesForRole(role)

    audit({
      userId:   user.id,
      action:   'login_success',
      ip:       getIp(req),
      userAgent: req.headers['user-agent'],
    })

    return reply.send({
      user: {
        id:        user.id,
        email:     user.email,
        fullName:  profile.full_name,
        avatarUrl: profile.avatar_url,
        role,
        scopes,
        emailVerified: !!user.email_confirmed_at,
      },
    })
  })

  // ── POST /auth/logout ──────────────────────────────────────
  app.post('/auth/logout', {
    preHandler: [authenticate],
  }, async (req: FastifyRequest, reply: FastifyReply) => {
    // Supabase handles session invalidation client-side
    // We just log the action
    audit({
      userId: req.user!.sub,
      action: 'logout',
      ip:     getIp(req),
    })
    return reply.send({ message: 'Logged out successfully' })
  })

  // ── GET /auth/me ───────────────────────────────────────────
  app.get('/auth/me', {
    preHandler: [authenticate],
  }, async (req: FastifyRequest, reply: FastifyReply) => {
    const { data: profile } = await db
      .from('profiles')
      .select('id, email, full_name, avatar_url, role, is_active, metadata, created_at')
      .eq('id', req.user!.sub)
      .single()

    if (!profile) return err(reply, 404, 'Profile not found')

    return reply.send({
      user: {
        ...profile,
        scopes: getScopesForRole(profile.role as Role),
      },
    })
  })

  // ── GET /.well-known/jwks.json ─────────────────────────────
  // Proxy Supabase's JWKS so other services can verify tokens
  // using this service's URL instead of Supabase directly
  app.get('/.well-known/jwks.json', async (_req, reply) => {
    const supabaseUrl = process.env.SUPABASE_URL
    const res = await fetch(`${supabaseUrl}/auth/v1/.well-known/jwks.json`)
    const data = await res.json()
    return reply
      .header('Cache-Control', 'public, max-age=3600')
      .send(data)
  })

  // ── GET /health ────────────────────────────────────────────
  app.get('/health', async () => ({
    status:  'ok',
    service: 'auth',
    version: '2.0.0',
    time:    new Date().toISOString(),
  }))
}