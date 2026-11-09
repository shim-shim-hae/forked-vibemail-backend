-- VibeMail — Full database rebuild (public.users + public.messages)
-- Matches what the backend code and src/types/database.ts expect.
-- Run in the Supabase SQL editor. Replaces migrations 001 + 002 (+ 003).
--
-- !! DESTRUCTIVE: section 0 drops both tables and ALL their data. !!
-- !! Users will need to sign in again to re-issue OAuth tokens.   !!
-- Delete section 0 if you want to run this against an empty database only.

-- ─────────────────────────────────────────────────────────────────────────────
-- 0. Drop existing objects
-- ─────────────────────────────────────────────────────────────────────────────

DROP TABLE IF EXISTS public.messages CASCADE;
DROP TABLE IF EXISTS public.users    CASCADE;
DROP FUNCTION IF EXISTS public.set_updated_at() CASCADE;
DROP FUNCTION IF EXISTS public.set_message_id()  CASCADE;

-- ─────────────────────────────────────────────────────────────────────────────
-- 1. users
-- ─────────────────────────────────────────────────────────────────────────────
-- Tokens are AES-256-GCM ciphertext produced by the app (ENCRYPTION_KEY);
-- never plaintext. Expiry columns are Unix epoch milliseconds (numbers),
-- as returned by the Google APIs and compared numerically in src/cron.

CREATE TABLE public.users (
  id                      UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  google_id               TEXT        NOT NULL UNIQUE,  -- upsert conflict target
  email                   TEXT        NOT NULL,
  name                    TEXT,
  encrypted_access_token  TEXT,
  encrypted_refresh_token TEXT,
  token_expires_at        BIGINT,                       -- Unix ms
  history_id              TEXT,                         -- last synced Gmail historyId
  watch_expiry            BIGINT,                       -- Unix ms; Gmail watch() expiration
  watch_resource_id       TEXT,
  created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ─────────────────────────────────────────────────────────────────────────────
-- 2. messages
-- ─────────────────────────────────────────────────────────────────────────────
-- Column mapping: from→from_address, to→to_address (reserved words).
-- Code upserts with onConflict: 'gmail_id', so gmail_id MUST be UNIQUE on its
-- own. id is never supplied by the app; the trigger below sets it to gmail_id.

CREATE TABLE public.messages (
  id           TEXT        PRIMARY KEY,
  user_id      UUID        NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),   -- set from Gmail internalDate
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  gmail_id     TEXT        NOT NULL UNIQUE,
  thread_id    TEXT        NOT NULL,
  label_ids    TEXT[]      NOT NULL DEFAULT '{}',
  from_address TEXT        NOT NULL,
  to_address   TEXT        NOT NULL,
  subject      TEXT        NOT NULL DEFAULT '',
  date         TEXT        NOT NULL,                 -- RFC 2822 Date header
  snippet      TEXT        NOT NULL DEFAULT '',
  body_plain   TEXT,
  body_html    TEXT,
  is_read      BOOLEAN     NOT NULL DEFAULT false,
  is_starred   BOOLEAN     NOT NULL DEFAULT false,
  status       TEXT        NOT NULL DEFAULT 'inbox'
               CHECK (status IN ('inbox', 'sent', 'draft', 'archived', 'trash')),
  draft_id     TEXT                                  -- Gmail drafts.id; NULL unless a draft
);

-- ─────────────────────────────────────────────────────────────────────────────
-- 3. Triggers
-- ─────────────────────────────────────────────────────────────────────────────

CREATE FUNCTION public.set_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$;

CREATE FUNCTION public.set_message_id()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.id IS NULL THEN
    NEW.id = NEW.gmail_id;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_users_updated_at
  BEFORE UPDATE ON public.users
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

CREATE TRIGGER trg_messages_updated_at
  BEFORE UPDATE ON public.messages
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

CREATE TRIGGER trg_messages_set_id
  BEFORE INSERT ON public.messages
  FOR EACH ROW EXECUTE FUNCTION public.set_message_id();

-- ─────────────────────────────────────────────────────────────────────────────
-- 4. Indexes
-- ─────────────────────────────────────────────────────────────────────────────

CREATE INDEX idx_messages_user_id      ON public.messages (user_id);
CREATE INDEX idx_messages_user_created ON public.messages (user_id, created_at DESC, gmail_id DESC);
CREATE INDEX idx_messages_thread_id    ON public.messages (thread_id);
CREATE INDEX idx_messages_label_ids    ON public.messages USING GIN (label_ids);
CREATE INDEX idx_messages_user_status  ON public.messages (user_id, status);
CREATE INDEX idx_messages_draft_id     ON public.messages (draft_id) WHERE draft_id IS NOT NULL;
CREATE INDEX idx_users_watch_expiry    ON public.users (watch_expiry) WHERE watch_expiry IS NOT NULL;

-- ─────────────────────────────────────────────────────────────────────────────
-- 5. Row-Level Security (defence in depth; the server uses the service-role key,
--    which bypasses RLS)
-- ─────────────────────────────────────────────────────────────────────────────

ALTER TABLE public.users    ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.messages ENABLE ROW LEVEL SECURITY;

CREATE POLICY users_self ON public.users
  USING (id = auth.uid()) WITH CHECK (id = auth.uid());

CREATE POLICY messages_own ON public.messages
  USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());

-- ─────────────────────────────────────────────────────────────────────────────
-- 6. Refresh PostgREST schema cache
-- ─────────────────────────────────────────────────────────────────────────────

NOTIFY pgrst, 'reload schema';
