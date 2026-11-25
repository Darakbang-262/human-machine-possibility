-- Run once in a NEW Supabase project. Replace UUID with Authentication > Users > UID.
begin;
create table public.lab_owner (uid uuid primary key references auth.users(id));
insert into public.lab_owner values ('REPLACE_WITH_OWNER_USER_UUID');
alter table public.lab_owner enable row level security;
revoke all on public.lab_owner from anon, authenticated;
create function public.lab_is_owner() returns boolean language sql stable security definer set search_path = '' as $$
  select exists(select 1 from public.lab_owner where uid = auth.uid());
$$;
revoke all on function public.lab_is_owner() from public;
grant execute on function public.lab_is_owner() to anon, authenticated;
create table public.lab_records (
 id text primary key,
 visibility text not null default 'private' check (visibility in ('public','private')),
 payload jsonb not null check(jsonb_typeof(payload) = 'object'),
 attachments jsonb not null default '[]'::jsonb check(jsonb_typeof(attachments) = 'array' and jsonb_array_length(attachments)<=20),
 updated_at timestamptz not null default now()
);
alter table public.lab_records enable row level security;
revoke all on public.lab_records from anon, authenticated;
grant select on public.lab_records to anon, authenticated;
grant insert, update, delete on public.lab_records to authenticated;
create policy lab_read on public.lab_records for select to anon, authenticated using (visibility = 'public' or public.lab_is_owner());
create policy lab_insert on public.lab_records for insert to authenticated with check (public.lab_is_owner());
create policy lab_update on public.lab_records for update to authenticated using (public.lab_is_owner()) with check (public.lab_is_owner());
create policy lab_delete on public.lab_records for delete to authenticated using (public.lab_is_owner());
insert into storage.buckets(id,name,public,file_size_limit,allowed_mime_types) values ('lab-images','lab-images',false,12582912,array['image/png','image/jpeg','image/gif','image/webp','image/bmp','image/avif']);
create policy lab_image_read on storage.objects for select to anon, authenticated using (
 bucket_id = 'lab-images' and (public.lab_is_owner() or exists (
 select 1 from public.lab_records r cross join lateral jsonb_array_elements(r.attachments) a
 where r.visibility='public' and a->>'path'=storage.objects.name))
);
create policy lab_image_insert on storage.objects for insert to authenticated with check (bucket_id='lab-images' and public.lab_is_owner() and (storage.foldername(name))[1]=auth.uid()::text);
create policy lab_image_delete on storage.objects for delete to authenticated using (bucket_id='lab-images' and public.lab_is_owner() and (storage.foldername(name))[1]=auth.uid()::text);
commit;
