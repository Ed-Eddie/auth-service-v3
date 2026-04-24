import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify'
import { z }             from 'zod'
import { createClient }  from '@supabase/supabase-js'
import { db, adminAuth } from '../lib/supabase.js'
import { authenticate }  from '../middleware/auth.js'
import { getScopesForRole } from '../lib/types.js'
import { audit }         from '../lib/audit.js'
import type { Role }     from '../lib/types.js'

const SUPABASE_URL  = process.env.SUPABASE_URL  ?? ''
const ANON_KEY      = process.env.SUPABASE_ANON_KEY ?? ''
const FRONTEND_URL  = process.env.FRONTEND_URL ?? 'http://localhost:3000'

function getIp(req: FastifyRequest): string {
  const fwd = req.headers['x-forwarded-for']
  return typeof fwd === 'string' ? fwd.split(',')[0]!.trim() : req.ip ?? 'unknown'
}

function err(reply: FastifyReply, status: number, message: string) {
  return reply.status(status).send({ error: message })
}

// Create a Supabase client scoped to the user's token
function userClient(token: string) {
  return createClient(SUPABASE_URL, ANON_KEY, {
    auth:   { persistSession: false },
    global: { headers: { Authorization: `Bearer ${token}` } },
  })
}

export async function authRoutes(app: FastifyInstance) {

  // ── POST /auth/register ────────────────────────────────────
  // Creates user in Supabase — Supabase sends 6-digit OTP automatically
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

    // Create user — Supabase sends OTP email automatically
    const { data, error } = await adminAuth.createUser({
      email,
      password,
      email_confirm:  false,
      user_metadata:  { full_name: fullName, role },
    })

    if (error) {
      if (error.message.toLowerCase().includes('already')) {
        return err(reply, 409, 'An account with this email already exists')
      }
      return err(reply, 400, error.message)
    }

    // Profile created by DB trigger — update role explicitly
    await db.from('profiles').upsert({
      id:        data.user.id,
      email,
      full_name: fullName ?? null,
      role,
    }, { onConflict: 'id' })

    audit({ userId: data.user.id, action: 'user_registered', ip: getIp(req) })

    return reply.status(201).send({
      message: 'Account created. Check your email for a 6-digit verification code.',
      email,
    })
  })

  // ── POST /auth/verify-otp ──────────────────────────────────
  // User submits the 6-digit code from email
  // Returns tokens on success — user is fully logged in
  app.post('/auth/verify-otp', {
    config: { rateLimit: { max: 10, timeWindow: '15 minutes' } },
  }, async (req: FastifyRequest, reply: FastifyReply) => {
    const body = z.object({
      email: z.string().email(),
      otp:   z.string().length(6).regex(/^\d{6}$/, 'OTP must be 6 digits'),
    }).safeParse(req.body)

    if (!body.success) return err(reply, 400, body.error.errors[0]!.message)

    const { email, otp } = body.data

    // Verify OTP with Supabase — this is their built-in email OTP verification
    const client = createClient(SUPABASE_URL, ANON_KEY, { auth: { persistSession: false } })
    const { data, error } = await client.auth.verifyOtp({
      email,
      token: otp,
      type:  'email',
    })

    if (error || !data.session) {
      return err(reply, 400, 'Invalid or expired code. Request a new one.')
    }

    // Get profile — create it if trigger didn't fire
    let { data: profile } = await db
      .from('profiles')
      .select('role, is_active, full_name')
      .eq('id', data.user!.id)
      .maybeSingle()

    if (!profile) {
      // Profile missing — create it now
      const { data: newProfile } = await db.from('profiles').insert({
        id:        data.user!.id,
        email:     data.user!.email ?? '',
        full_name: data.user!.user_metadata?.['full_name'] ?? null,
        role:      data.user!.user_metadata?.['role'] ?? 'user',
        is_active: true,
      }).select('role, is_active, full_name').single()

      profile = newProfile
    }

    if (!profile) return err(reply, 500, 'Failed to load profile. Please try again.')
    if (!profile.is_active) return err(reply, 403, 'Account suspended. Contact support.')

    const role   = (profile.role ?? 'user') as Role
    const scopes = getScopesForRole(role)

    audit({ userId: data.user!.id, action: 'email_verified', ip: getIp(req) })

    return reply.send({
      message:      'Email verified successfully.',
      accessToken:  data.session.access_token,
      refreshToken: data.session.refresh_token,
      expiresIn:    data.session.expires_in,
      user: {
        id:       data.user!.id,
        email:    data.user!.email,
        fullName: profile.full_name,
        role,
        scopes,
      },
    })
  })

  // ── POST /auth/resend-otp ──────────────────────────────────
  // Resend the 6-digit verification code
  app.post('/auth/resend-otp', {
    config: { rateLimit: { max: 3, timeWindow: '15 minutes' } },
  }, async (req: FastifyRequest, reply: FastifyReply) => {
    const body = z.object({
      email: z.string().email(),
    }).safeParse(req.body)

    if (!body.success) return err(reply, 400, body.error.errors[0]!.message)

    const client = createClient(SUPABASE_URL, ANON_KEY, { auth: { persistSession: false } })
    const { error } = await client.auth.resend({
      type:  'signup',
      email: body.data.email,
    })

    // Always return success to prevent email enumeration
    if (error) {
      app.log.error({ err: error }, 'Resend OTP failed')
    }

    return reply.send({
      message: 'If that email exists and is unverified, a new code has been sent.',
    })
  })

  // ── POST /auth/login ───────────────────────────────────────
  // Email + password → returns tokens + user info + scopes
  app.post('/auth/login', {
    config: { rateLimit: { max: 10, timeWindow: '15 minutes' } },
  }, async (req: FastifyRequest, reply: FastifyReply) => {
    const body = z.object({
      email:    z.string().email(),
      password: z.string().min(1),
    }).safeParse(req.body)

    if (!body.success) return err(reply, 400, body.error.errors[0]!.message)

    const { email, password } = body.data

    // Sign in via Supabase
    const client = createClient(SUPABASE_URL, ANON_KEY, { auth: { persistSession: false } })
    const { data, error } = await client.auth.signInWithPassword({ email, password })

    if (error) {
      if (error.message.toLowerCase().includes('email not confirmed')) {
        return err(reply, 403, 'Please verify your email first. Check your inbox for the 6-digit code.')
      }
      if (error.message.toLowerCase().includes('invalid')) {
        return err(reply, 401, 'Invalid email or password.')
      }
      return err(reply, 401, error.message)
    }

    if (!data.session || !data.user) {
      return err(reply, 401, 'Login failed. Please try again.')
    }

    // Get profile — create if trigger didn't fire
    let { data: profile } = await db
      .from('profiles')
      .select('role, is_active, full_name, avatar_url')
      .eq('id', data.user.id)
      .maybeSingle()

    if (!profile) {
      const { data: newProfile } = await db.from('profiles').insert({
        id:        data.user.id,
        email:     data.user.email ?? '',
        full_name: data.user.user_metadata?.['full_name'] ?? null,
        role:      data.user.user_metadata?.['role'] ?? 'user',
        is_active: true,
      }).select('role, is_active, full_name, avatar_url').single()
      profile = newProfile
    }

    if (!profile) return err(reply, 500, 'Failed to load profile. Please try again.')
    if (!profile.is_active) return err(reply, 403, 'Account suspended. Contact support.')

    const role   = (profile.role ?? 'user') as Role
    const scopes = getScopesForRole(role)

    audit({
      userId:    data.user.id,
      action:    'login_success',
      ip:        getIp(req),
      userAgent: req.headers['user-agent'],
    })

    return reply.send({
      accessToken:  data.session.access_token,
      refreshToken: data.session.refresh_token,
      expiresIn:    data.session.expires_in,
      tokenType:    'Bearer',
      user: {
        id:        data.user.id,
        email:     data.user.email,
        fullName:  profile.full_name,
        avatarUrl: profile.avatar_url,
        role,
        scopes,
      },
    })
  })

  // ── POST /auth/refresh ─────────────────────────────────────
  // Exchange refresh token for new access token
  app.post('/auth/refresh', {
    config: { rateLimit: { max: 30, timeWindow: '15 minutes' } },
  }, async (req: FastifyRequest, reply: FastifyReply) => {
    const body = z.object({
      refreshToken: z.string().min(1),
    }).safeParse(req.body)

    if (!body.success) return err(reply, 400, 'refreshToken is required')

    const client = createClient(SUPABASE_URL, ANON_KEY, { auth: { persistSession: false } })
    const { data, error } = await client.auth.refreshSession({
      refresh_token: body.data.refreshToken,
    })

    if (error || !data.session) {
      return err(reply, 401, 'Invalid or expired refresh token. Please log in again.')
    }

    return reply.send({
      accessToken:  data.session.access_token,
      refreshToken: data.session.refresh_token,
      expiresIn:    data.session.expires_in,
      tokenType:    'Bearer',
    })
  })

  // ── POST /auth/logout ──────────────────────────────────────
  app.post('/auth/logout', {
    preHandler: [authenticate],
  }, async (req: FastifyRequest, reply: FastifyReply) => {
    const token  = req.headers['authorization']!.slice(7)
    const client = userClient(token)
    await client.auth.signOut()

    audit({ userId: req.user!.sub, action: 'logout', ip: getIp(req) })
    return reply.send({ message: 'Logged out successfully' })
  })

  // ── POST /auth/forgot-password ─────────────────────────────
  // Sends password reset email via Supabase SMTP
  app.post('/auth/forgot-password', {
    config: { rateLimit: { max: 3, timeWindow: '15 minutes' } },
  }, async (req: FastifyRequest, reply: FastifyReply) => {
    const body = z.object({
      email: z.string().email(),
    }).safeParse(req.body)

    if (!body.success) return err(reply, 400, body.error.errors[0]!.message)

    const client = createClient(SUPABASE_URL, ANON_KEY, { auth: { persistSession: false } })
    await client.auth.resetPasswordForEmail(body.data.email, {
      redirectTo: `${FRONTEND_URL}/reset-password`,
    })

    // Always return same message — prevents email enumeration
    return reply.send({
      message: 'If that email is registered, a reset link has been sent.',
    })
  })

  // ── POST /auth/reset-password ──────────────────────────────
  // User lands on frontend with token from email link
  // Frontend calls this with the new password and the token
  app.post('/auth/reset-password', {
    config: { rateLimit: { max: 5, timeWindow: '15 minutes' } },
  }, async (req: FastifyRequest, reply: FastifyReply) => {
    const body = z.object({
      accessToken: z.string().min(1),  // token from reset email URL
      newPassword: z.string()
        .min(8, 'Password must be at least 8 characters')
        .regex(/[A-Z]/, 'Must include uppercase letter')
        .regex(/[a-z]/, 'Must include lowercase letter')
        .regex(/[^A-Za-z0-9]/, 'Must include special character'),
    }).safeParse(req.body)

    if (!body.success) return err(reply, 400, body.error.errors[0]!.message)

    const client = userClient(body.data.accessToken)
    const { error } = await client.auth.updateUser({
      password: body.data.newPassword,
    })

    if (error) return err(reply, 400, error.message)

    audit({ action: 'password_reset_completed', ip: getIp(req) })

    return reply.send({ message: 'Password reset successfully. Please log in.' })
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
  app.get('/.well-known/jwks.json', async (_req, reply) => {
    const res  = await fetch(`${SUPABASE_URL}/auth/v1/.well-known/jwks.json`)
    const data = await res.json()
    return reply.header('Cache-Control', 'public, max-age=3600').send(data)
  })

  // ── GET /health ────────────────────────────────────────────
  app.get('/health', async () => ({
    status:  'ok',
    service: 'auth',
    version: '2.0.0',
    time:    new Date().toISOString(),
  }))
}