-- Optional single sign-on: the identity provider's subject a user is linked to,
-- and, on a session started through it, the provider session and refresh token
-- used to re-check access.
ALTER TABLE users ADD COLUMN auth_sub text;
CREATE UNIQUE INDEX users_auth_sub_key ON users (auth_sub);

ALTER TABLE sessions
  ADD COLUMN auth_sid text,
  ADD COLUMN auth_refresh_token text,
  ADD COLUMN auth_recheck_at timestamptz;
CREATE INDEX sessions_auth_sid_idx ON sessions (auth_sid) WHERE auth_sid IS NOT NULL;
