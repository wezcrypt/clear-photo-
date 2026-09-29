-- VoidMail initial schema. See PRIVACY.md for the data inventory of every column.

CREATE TABLE users (
  id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  username             text NOT NULL UNIQUE,
  display_name         text NOT NULL DEFAULT '',
  kdf_salt             bytea NOT NULL,
  kdf_params           jsonb NOT NULL,
  auth_hash            text NOT NULL,
  mk_wrapped_password  bytea NOT NULL,
  mk_wrapped_recovery  bytea,
  recovery_auth_hash   text,
  recovery_email       text,
  totp_secret_enc      bytea,
  totp_enabled         boolean NOT NULL DEFAULT false,
  totp_last_step       bigint,
  locale               text NOT NULL DEFAULT 'en' CHECK (locale IN ('en','ar')),
  theme                text NOT NULL DEFAULT 'system' CHECK (theme IN ('system','dark','light')),
  remote_images        text NOT NULL DEFAULT 'ask' CHECK (remote_images IN ('ask','never')),
  quota_bytes          bigint NOT NULL DEFAULT 1073741824,
  status               text NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended')),
  failed_logins        integer NOT NULL DEFAULT 0,
  login_locked_until   timestamptz,
  vault_enc            bytea,
  vault_version        integer NOT NULL DEFAULT 0,
  created_at           timestamptz NOT NULL DEFAULT now()
);

-- Prevents re-registration of a deleted address (mail to it could otherwise reach a new owner).
CREATE TABLE username_tombstones (
  username_hash bytea PRIMARY KEY,
  deleted_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE user_keys (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id             uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  fingerprint         text NOT NULL,
  public_key          text NOT NULL,
  private_key_enc     text NOT NULL,
  revocation_cert_enc bytea,
  status              text NOT NULL CHECK (status IN ('active','retired','locked')),
  created_at          timestamptz NOT NULL DEFAULT now(),
  retired_at          timestamptz
);
CREATE UNIQUE INDEX user_keys_one_active ON user_keys(user_id) WHERE status = 'active';
CREATE INDEX user_keys_user ON user_keys(user_id);

CREATE TABLE sessions (
  id_hash       bytea PRIMARY KEY,
  user_id       uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at    timestamptz NOT NULL DEFAULT now(),
  last_seen_at  timestamptz NOT NULL DEFAULT now(),
  expires_at    timestamptz NOT NULL,
  user_agent    text NOT NULL DEFAULT ''
);
CREATE INDEX sessions_user ON sessions(user_id);

CREATE TABLE login_challenges (
  id_hash    bytea PRIMARY KEY,
  user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  purpose    text NOT NULL CHECK (purpose IN ('totp','recovery')),
  attempts   integer NOT NULL DEFAULT 0,
  expires_at timestamptz NOT NULL
);

CREATE TABLE recovery_codes (
  user_id   uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash bytea NOT NULL,
  used_at   timestamptz,
  PRIMARY KEY (user_id, code_hash)
);

CREATE TABLE password_resets (
  token_hash bytea PRIMARY KEY,
  user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at timestamptz NOT NULL,
  used_at    timestamptz
);

CREATE TABLE messages (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id          uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  folder           text NOT NULL CHECK (folder IN ('inbox','sent','drafts','archive','spam','trash')),
  prev_folder      text,
  kind             text NOT NULL CHECK (kind IN ('internal_in','internal_out','external_in','external_out','draft','system')),
  security         text NOT NULL CHECK (security IN ('e2ee','external_encrypted_on_arrival','standard_tls_optional','standard_tls_required','draft','system')),
  key_fingerprint  text NOT NULL,
  header_enc       bytea NOT NULL,
  body_enc         bytea NOT NULL,
  size_bytes       bigint NOT NULL,
  unread           boolean NOT NULL DEFAULT true,
  starred          boolean NOT NULL DEFAULT false,
  sender_address   text,
  message_id       text,
  in_reply_to      text,
  raw_hash         bytea,
  received_at      timestamptz NOT NULL DEFAULT now(),
  folder_changed_at timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX messages_list ON messages(user_id, folder, received_at DESC, id DESC);
CREATE INDEX messages_starred ON messages(user_id, received_at DESC) WHERE starred;
CREATE UNIQUE INDEX messages_inbound_dedupe ON messages(user_id, raw_hash) WHERE raw_hash IS NOT NULL;
CREATE INDEX messages_retention ON messages(folder, folder_changed_at) WHERE folder IN ('trash','spam');

CREATE TABLE labels (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name       text NOT NULL,
  color      text NOT NULL DEFAULT 'violet',
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, name)
);

CREATE TABLE message_labels (
  message_id uuid NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  label_id   uuid NOT NULL REFERENCES labels(id) ON DELETE CASCADE,
  PRIMARY KEY (message_id, label_id)
);
CREATE INDEX message_labels_label ON message_labels(label_id);

-- Encrypted attachment objects. Content lives in the blob store under storage_key.
CREATE TABLE blobs (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  size_bytes    bigint NOT NULL,
  storage_key   text NOT NULL UNIQUE,
  created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE message_blobs (
  message_id uuid NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  blob_id    uuid NOT NULL REFERENCES blobs(id) ON DELETE RESTRICT,
  PRIMARY KEY (message_id, blob_id)
);
CREATE INDEX message_blobs_blob ON message_blobs(blob_id);

CREATE TABLE outbound_queue (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id         uuid REFERENCES users(id) ON DELETE SET NULL,
  message_id      uuid REFERENCES messages(id) ON DELETE SET NULL,
  kind            text NOT NULL DEFAULT 'user' CHECK (kind IN ('user','system')),
  require_tls     boolean NOT NULL DEFAULT false,
  envelope_from   text NOT NULL,
  rfc_message_id  text NOT NULL,
  payload_enc     bytea,
  status          text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','sending','relayed','failed','cancelled')),
  attempts        integer NOT NULL DEFAULT 0,
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  lease_until     timestamptz,
  last_error      text,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX outbound_due ON outbound_queue(next_attempt_at) WHERE status IN ('queued','sending');

CREATE TABLE outbound_recipients (
  queue_id   uuid NOT NULL REFERENCES outbound_queue(id) ON DELETE CASCADE,
  address    text NOT NULL,
  status     text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','relayed','delivered','deferred','bounced','failed','cancelled')),
  diagnostic text,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (queue_id, address)
);

-- Counts only, for sending limits. No addresses or content.
CREATE TABLE send_log (
  id         bigserial PRIMARY KEY,
  user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  external   integer NOT NULL,
  internal   integer NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX send_log_user ON send_log(user_id, created_at);

CREATE TABLE security_events (
  id         bigserial PRIMARY KEY,
  user_id    uuid REFERENCES users(id) ON DELETE CASCADE,
  type       text NOT NULL,
  ip_prefix  text,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX security_events_user ON security_events(user_id, created_at DESC);

CREATE TABLE admin_audit (
  id         bigserial PRIMARY KEY,
  actor      text NOT NULL,
  action     text NOT NULL,
  target     text,
  created_at timestamptz NOT NULL DEFAULT now()
);
