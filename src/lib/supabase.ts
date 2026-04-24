import { createClient } from '@supabase/supabase-js'

const url = process.env.SUPABASE_URL
const key = process.env.SUPABASE_SERVICE_ROLE_KEY

if (!url || !key) throw new Error('Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY')

// Service role client — full DB access, bypasses RLS
// Only used server-side, never exposed to clients
export const db = createClient(url, key, {
  auth: { persistSession: false, autoRefreshToken: false },
})

// Admin auth client — manages users via Supabase Auth Admin API
export const adminAuth = db.auth.admin