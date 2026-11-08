-- CL Finance: PostgreSQL/Supabase foundation, v1
-- Run in a new, private Supabase project via SQL Editor.
-- No production credentials, users or financial data belong in GitHub.
create extension if not exists pgcrypto;
create table if not exists public.properties (
 id uuid primary key default gen_random_uuid(),
 title text not null check (length(trim(title)) between 1 and 120),
 created_at timestamptz not null default now()
);
create table if not exists public.property_memberships (
 property_id uuid not null references public.properties(id) on delete cascade,
 user_id uuid not null references auth.users(id) on delete cascade,
 role text not null check (role in ('admin','owner','cleaner')),
 created_at timestamptz not null default now(),
 primary key (property_id,user_id)
);
create table if not exists public.bookings (
 id uuid primary key default gen_random_uuid(),
 property_id uuid not null references public.properties(id) on delete cascade,
 check_in date not null,
 check_out date not null,
 nightly_rate numeric(14,2) not null default 0 check (nightly_rate>=0),
 channel_commission_pct numeric(5,2) not null default 0 check (channel_commission_pct between 0 and 100),
 created_at timestamptz not null default now(),
 check (check_out>check_in)
);
create table if not exists public.expenses (
 id uuid primary key default gen_random_uuid(),
 property_id uuid not null references public.properties(id) on delete cascade,
 incurred_on date not null,
 category text not null check (length(trim(category)) between 1 and 100),
 amount numeric(14,2) not null check (amount>=0),
 created_at timestamptz not null default now()
);
create table if not exists public.cleaning_tasks (
 id uuid primary key default gen_random_uuid(),
 property_id uuid not null references public.properties(id) on delete cascade,
 scheduled_for timestamptz not null,
 status text not null default 'pending' check (status in ('pending','in_progress','done')),
 notes text not null default '',
 assigned_to uuid references auth.users(id) on delete set null,
 completed_at timestamptz,
 created_at timestamptz not null default now()
);
create index if not exists idx_memberships_user on public.property_memberships(user_id);
create index if not exists idx_bookings_property_dates on public.bookings(property_id,check_in);
create index if not exists idx_expenses_property_date on public.expenses(property_id,incurred_on);
create index if not exists idx_cleaning_property_date on public.cleaning_tasks(property_id,scheduled_for);

-- SECURITY DEFINER helpers avoid recursion when checking memberships.
create schema if not exists private;
revoke all on schema private from public;
grant usage on schema private to authenticated;
create or replace function private.has_property_role(p_id uuid, allowed_roles text[])
returns boolean language sql stable security definer set search_path = ''
as $$ select exists (
 select 1 from public.property_memberships m
 where m.property_id=p_id and m.user_id=(select auth.uid()) and m.role=any(allowed_roles)
) $$;
revoke all on function private.has_property_role(uuid,text[]) from public;
grant execute on function private.has_property_role(uuid,text[]) to authenticated;

alter table public.properties enable row level security;
alter table public.property_memberships enable row level security;
alter table public.bookings enable row level security;
alter table public.expenses enable row level security;
alter table public.cleaning_tasks enable row level security;

-- No client-side INSERT/UPDATE/DELETE policies for properties or memberships.
-- Provision and revoke memberships using a trusted server with service-role credentials only.
create policy "property visible to assigned user" on public.properties for select to authenticated
using (private.has_property_role(id,array['admin','owner','cleaner']));
create policy "membership visible to self or property admin" on public.property_memberships for select to authenticated
using (user_id=(select auth.uid()) or private.has_property_role(property_id,array['admin']));
create policy "booking visible to admin and owner" on public.bookings for select to authenticated
using (private.has_property_role(property_id,array['admin','owner']));
create policy "booking insert by admin" on public.bookings for insert to authenticated
with check (private.has_property_role(property_id,array['admin']));
create policy "booking update by admin" on public.bookings for update to authenticated
using (private.has_property_role(property_id,array['admin']))
with check (private.has_property_role(property_id,array['admin']));
create policy "booking delete by admin" on public.bookings for delete to authenticated
using (private.has_property_role(property_id,array['admin']));
create policy "expense visible to admin and owner" on public.expenses for select to authenticated
using (private.has_property_role(property_id,array['admin','owner']));
create policy "expense insert by admin" on public.expenses for insert to authenticated
with check (private.has_property_role(property_id,array['admin']));
create policy "expense update by admin" on public.expenses for update to authenticated
using (private.has_property_role(property_id,array['admin']))
with check (private.has_property_role(property_id,array['admin']));
create policy "expense delete by admin" on public.expenses for delete to authenticated
using (private.has_property_role(property_id,array['admin']));
create policy "cleaning visible to assigned roles" on public.cleaning_tasks for select to authenticated
using (private.has_property_role(property_id,array['admin','owner'])
 or (assigned_to=(select auth.uid()) and private.has_property_role(property_id,array['cleaner'])));
create policy "cleaning insert by admin" on public.cleaning_tasks for insert to authenticated
with check (private.has_property_role(property_id,array['admin']));
create policy "cleaning update by admin" on public.cleaning_tasks for update to authenticated
using (private.has_property_role(property_id,array['admin']))
with check (private.has_property_role(property_id,array['admin']));
create policy "cleaning delete by admin" on public.cleaning_tasks for delete to authenticated
using (private.has_property_role(property_id,array['admin']));

-- Cleaner task completion MUST be handled by a trusted backend endpoint that checks:
-- 1) authenticated caller is assigned cleaner, 2) task belongs to property,
-- 3) only status/notes/completed_at change. Do not grant general UPDATE to cleaner:
-- RLS cannot constrain individual columns on its own.
