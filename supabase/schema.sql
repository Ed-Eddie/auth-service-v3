-- ============================================================
-- Auth Service v2 — Supabase Auth based
-- Run in Supabase SQL Editor
-- ============================================================

-- ── Profiles — extends Supabase auth.users ────────────────────
-- One row per user — created automatically on signup via trigger
create table if not exists profiles (
  id          uuid primary key references auth.users(id) on delete cascade,
  email       text not null,
  full_name   text,
  avatar_url  text,
  role        text not null default 'user' check (role in ('super_admin', 'admin', 'user')),
  is_active   boolean not null default true,
  metadata    jsonb not null default '{}',
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

alter table profiles enable row level security;

-- Users can read/update their own profile
create policy "users can view own profile"
  on profiles for select using (auth.uid() = id);

create policy "users can update own profile"
  on profiles for update using (auth.uid() = id)
  with check (auth.uid() = id);

-- Service role can do everything (used by auth-service backend)
create policy "service role full access"
  on profiles for all using (true);

-- ── API Keys ──────────────────────────────────────────────────
create table if not exists api_keys (
  id          uuid primary key default gen_random_uuid(),
  user_id     uuid not null references auth.users(id) on delete cascade,
  name        text not null,
  key_hash    text not null unique,
  key_prefix  text not null,
  scopes      text[] not null default '{}',
  is_active   boolean not null default true,
  last_used_at timestamptz,
  expires_at  timestamptz,
  created_at  timestamptz not null default now()
);

alter table api_keys enable row level security;

create policy "users can manage own api keys"
  on api_keys for all using (auth.uid() = user_id);

create policy "service role full access"
  on api_keys for all using (true);

create index ak_user_idx   on api_keys(user_id);
create index ak_hash_idx   on api_keys(key_hash);
create index ak_prefix_idx on api_keys(key_prefix);

-- ── Audit log ─────────────────────────────────────────────────
create table if not exists audit_log (
  id          uuid primary key default gen_random_uuid(),
  user_id     uuid references auth.users(id),
  action      text not null,
  resource    text,
  resource_id text,
  metadata    jsonb default '{}',
  ip_address  text,
  user_agent  text,
  created_at  timestamptz not null default now()
);

alter table audit_log enable row level security;

create policy "service role full access"
  on audit_log for all using (true);

create policy "admins can view audit log"
  on audit_log for select using (
    exists (
      select 1 from profiles
      where id = auth.uid()
      and role in ('super_admin', 'admin')
    )
  );

create index al_user_idx   on audit_log(user_id);
create index al_action_idx on audit_log(action);
create index al_created_idx on audit_log(created_at desc);

-- ── Auto-create profile on signup ────────────────────────────
create or replace function handle_new_user()
returns trigger language plpgsql security definer as $$
begin
  insert into profiles (id, email, full_name, avatar_url, role)
  values (
    new.id,
    new.email,
    coalesce(new.raw_user_meta_data->>'full_name', split_part(new.email, '@', 1)),
    new.raw_user_meta_data->>'avatar_url',
    coalesce(new.raw_user_meta_data->>'role', 'user')
  )
  on conflict (id) do nothing;
  return new;
end;
$$;

create or replace trigger on_auth_user_created
  after insert on auth.users
  for each row execute function handle_new_user();

-- ── updated_at trigger ────────────────────────────────────────
create or replace function set_updated_at()
returns trigger language plpgsql as $$
begin new.updated_at = now(); return new; end;
$$;

create trigger profiles_updated_at
  before update on profiles
  for each row execute function set_updated_at();

-- ── Custom claims hook ────────────────────────────────────────
-- Called by Supabase to add custom data to JWT
-- Enable in: Supabase Dashboard → Auth → Hooks → Custom Access Token
create or replace function custom_access_token_hook(event jsonb)
returns jsonb language plpgsql security definer as $$
declare
  claims      jsonb;
  user_role   text;
  user_active boolean;
begin
  -- Get user role and status from profiles
  select role, is_active
  into user_role, user_active
  from profiles
  where id = (event->>'user_id')::uuid;

  claims := event->'claims';

  -- Add custom claims to JWT
  claims := jsonb_set(claims, '{role}',      to_jsonb(coalesce(user_role, 'user')));
  claims := jsonb_set(claims, '{is_active}', to_jsonb(coalesce(user_active, true)));

  return jsonb_set(event, '{claims}', claims);
end;
$$;

grant execute on function custom_access_token_hook to supabase_auth_admin;
grant select on profiles to supabase_auth_admin;