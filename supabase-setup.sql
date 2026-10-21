-- ASTEKToolStock Supabase schema and access rules
-- Run this once in Supabase Dashboard > SQL Editor.

create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  first_name text not null default '',
  last_name text not null default '',
  role text not null default 'Teknik personel',
  approved boolean not null default false,
  created_at timestamptz not null default now(),
  constraint profiles_role_check check (role in ('Patron','Müdür','Teknik personel','Depo sorumlusu','Çalışan','Diğer'))
);

create table if not exists public.inventory_items (
  id uuid primary key default gen_random_uuid(),
  kind text not null check (kind in ('products','tools')),
  name text not null,
  category text not null default '',
  qty numeric not null default 0 check (qty >= 0),
  unit text not null default 'adet',
  price numeric check (price is null or price >= 0),
  note text not null default '',
  min numeric not null default 5,
  updated_at timestamptz not null default now()
);

create table if not exists public.activity (
  id uuid primary key default gen_random_uuid(),
  text text not null,
  type text not null default 'add',
  detail text not null default '',
  by_name text not null default '',
  created_at timestamptz not null default now()
);

create or replace function public.current_user_is_approved()
returns boolean language sql stable security definer set search_path = '' as $$
  select coalesce((select p.approved from public.profiles p where p.id = (select auth.uid())), false)
$$;

create or replace function public.current_user_is_patron()
returns boolean language sql stable security definer set search_path = '' as $$
  select coalesce((select p.approved and p.role = 'Patron' from public.profiles p where p.id = (select auth.uid())), false)
$$;

create or replace function public.bootstrap_profile()
returns trigger language plpgsql security definer set search_path = '' as $$
declare
  is_first boolean;
begin
  perform pg_advisory_xact_lock(781234905);
  select not exists(select 1 from public.profiles) into is_first;
  insert into public.profiles(id, first_name, last_name, role, approved)
  values (
    new.id,
    coalesce(new.raw_user_meta_data->>'first_name',''),
    coalesce(new.raw_user_meta_data->>'last_name',''),
    case when is_first then 'Patron' else 'Teknik personel' end,
    is_first
  );
  return new;
end
$$;

drop trigger if exists on_auth_user_created_astek on auth.users;
create trigger on_auth_user_created_astek
  after insert on auth.users
  for each row execute procedure public.bootstrap_profile();

alter table public.profiles enable row level security;
alter table public.inventory_items enable row level security;
alter table public.activity enable row level security;

drop policy if exists "approved users read profiles" on public.profiles;
create policy "approved users read profiles" on public.profiles
  for select to authenticated using (id = (select auth.uid()) or public.current_user_is_approved());
drop policy if exists "patron manages profiles" on public.profiles;
create policy "patron manages profiles" on public.profiles
  for all to authenticated using (public.current_user_is_patron())
  with check (public.current_user_is_patron());

drop policy if exists "approved users read inventory" on public.inventory_items;
create policy "approved users read inventory" on public.inventory_items
  for select to authenticated using (public.current_user_is_approved());
drop policy if exists "approved users add inventory" on public.inventory_items;
create policy "approved users add inventory" on public.inventory_items
  for insert to authenticated with check (public.current_user_is_approved());
drop policy if exists "approved users update inventory" on public.inventory_items;
create policy "approved users update inventory" on public.inventory_items
  for update to authenticated using (public.current_user_is_approved())
  with check (public.current_user_is_approved());
drop policy if exists "approved users delete inventory" on public.inventory_items;
create policy "approved users delete inventory" on public.inventory_items
  for delete to authenticated using (public.current_user_is_approved());

create or replace function public.prevent_non_patron_price_change()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  if not public.current_user_is_patron() and (
    (tg_op = 'INSERT' and new.price is not null)
    or (tg_op = 'UPDATE' and new.price is distinct from old.price)
  ) then
    raise exception 'Fiyatı yalnızca Patron ekleyebilir veya değiştirebilir.' using errcode = '42501';
  end if;
  return new;
end
$$;
drop trigger if exists protect_inventory_price on public.inventory_items;
create trigger protect_inventory_price before insert or update on public.inventory_items
  for each row execute procedure public.prevent_non_patron_price_change();

drop policy if exists "approved users read activity" on public.activity;
create policy "approved users read activity" on public.activity
  for select to authenticated using (public.current_user_is_approved());
drop policy if exists "approved users add activity" on public.activity;
create policy "approved users add activity" on public.activity
  for insert to authenticated with check (public.current_user_is_approved());
drop policy if exists "patron deletes activity" on public.activity;
create policy "patron deletes activity" on public.activity
  for delete to authenticated using (public.current_user_is_patron());

grant usage on schema public to authenticated;
grant select, insert, update, delete on public.profiles to authenticated;
grant select, insert, update, delete on public.inventory_items to authenticated;
grant select, insert, delete on public.activity to authenticated;
