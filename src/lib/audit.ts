import { db } from './supabase.js'

interface AuditParams {
  userId?:     string
  action:      string
  resource?:   string
  resourceId?: string
  metadata?:   Record<string, unknown>
  ip?:         string
  userAgent?:  string
}

export function audit(params: AuditParams): void {
  void db.from('audit_log').insert({
    user_id:     params.userId ?? null,
    action:      params.action,
    resource:    params.resource ?? null,
    resource_id: params.resourceId ?? null,
    metadata:    params.metadata ?? {},
    ip_address:  params.ip ?? null,
    user_agent:  params.userAgent ?? null,
  }).then(
    () => {},
    (err: unknown) => {
      console.error('[audit] failed to log:', err)
    },
  )
}