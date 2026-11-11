# Translation review

A web page where bilingual staff check every piece of text in the family app,
one language at a time. For each piece you see the English, the translation the
app shows now, and a box for your version.

- **Looks good**: the current translation is right.
- **Type in the box**: a better version. It saves when you click away from the box.
- **Add a note**: anything Mark should know, for example that the English itself is unclear.
- Where there's no translation yet, the box asks you to write one.

Mark reads what comes in and decides what goes into the app.

## Opening it

1. Open the link Mark sends you.
2. Type the review password and click **Unlock**.
   Tick **Remember me on this computer** only on your own computer.
3. The first time, type your first name and last initial.

**Lock** (top right) closes the review on this computer.

## Saving

Everything saves automatically, as you go. If the internet drops, your changes
wait on this computer and are sent when it's back; the top of the page says
"✓ All changes saved" once they're all in. Other reviewers see your work within
about a minute.

Adding `?env=test` to the address opens a practice copy, kept apart from the real review.

## Updating the text

Mark refreshes the text in `data/` from time to time; reviewers don't need to do anything.
After changing `app.js` or `style.css`, raise the `?v=` number where `index.html` loads them.

## Setting up the table (Supabase)

Create one reviewer user in Supabase Auth whose password is the review password,
put its email in `REVIEWER_EMAIL` in `config.js`, then run:

```sql
create table public.translation_suggestions (
  submission_id uuid primary key,
  created_at    timestamptz not null default now(),
  client_at     timestamptz not null,
  environment   text not null check (environment in ('review', 'test')),
  lang          text not null check (lang in ('es', 'zh-Hant', 'ht', 'ar', 'pt')),
  entry_key     text not null check (char_length(entry_key) <= 300),
  verdict       text not null check (verdict in ('ok', 'suggest')),
  suggested     text check (char_length(suggested) <= 20000),
  note          text check (char_length(note) <= 2000),
  reviewer      text not null check (char_length(reviewer) between 1 and 80),
  reviewer_id   uuid not null,
  seen_en       text not null check (char_length(seen_en) <= 20000),
  seen_current  text not null check (char_length(seen_current) <= 20000),
  snapshot      text not null check (char_length(snapshot) <= 60),
  check ((verdict = 'ok' and suggested is null)
      or (verdict = 'suggest' and char_length(btrim(coalesce(suggested, ''))) > 0))
);

create index translation_suggestions_lang on public.translation_suggestions (lang, environment, created_at);

alter table public.translation_suggestions enable row level security;

-- Nobody without the reviewer sign-in can touch the table, and nobody can
-- change or delete a row from the page.
revoke all on public.translation_suggestions from anon;
revoke update, delete, truncate on public.translation_suggestions from authenticated;
grant select, insert on public.translation_suggestions to authenticated;

create policy "reviewers read" on public.translation_suggestions
  for select to authenticated
  using (auth.jwt() ->> 'email' = '<REVIEWER_EMAIL>');

create policy "reviewers add" on public.translation_suggestions
  for insert to authenticated
  with check (auth.jwt() ->> 'email' = '<REVIEWER_EMAIL>');
```

Replace `<REVIEWER_EMAIL>` with the reviewer account's email.

Changing the review password means changing it in two places at once: the
reviewer account in Supabase, and the encrypted text files (Mark does both).
Anyone remembered on a computer is then asked for the new password.
