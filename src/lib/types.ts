export type Role = 'super_admin' | 'admin' | 'user'

export const ROLE_SCOPES: Record<Role, string[]> = {
  super_admin: [
    'mpesa:stk', 'mpesa:b2c', 'mpesa:b2b', 'mpesa:c2b',
    'mpesa:reversal', 'mpesa:balance', 'mpesa:transaction_status',
    'sms:send', 'sms:bulk',
    'whatsapp:send', 'whatsapp:template',
    'push:send', 'push:broadcast',
    'ws:connect',
    'api_keys:manage', 'admin:manage', 'users:manage',
  ],
  admin: [
    'mpesa:stk', 'mpesa:b2c', 'mpesa:b2b', 'mpesa:c2b',
    'mpesa:reversal', 'mpesa:balance',
    'sms:send', 'sms:bulk',
    'whatsapp:send', 'whatsapp:template',
    'push:send',
    'ws:connect',
    'api_keys:manage', 'users:manage',
  ],
  user: [
    'mpesa:stk',
    'sms:send',
    'ws:connect',
  ],
}

export function getScopesForRole(role: Role | string): string[] {
  return ROLE_SCOPES[role as Role] ?? ROLE_SCOPES.user
}

export interface AuthUser {
  id:         string
  email:      string
  role:       Role
  is_active:  boolean
  full_name?: string
}

export interface RequestUser {
  sub:       string
  email:     string
  role:      Role
  is_active: boolean
  scopes:    string[]
  aud:       string
  exp:       number
}