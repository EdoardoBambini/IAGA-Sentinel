-- 1.5.2 API key scopes: minimal single-tenant separation between keys that
-- may administer the gateway (manage keys, webhooks, rate-limit config,
-- threat intel, plugin reloads) and keys that may only drive the governance
-- surface (/v1/inspect & co.).
--
-- DEFAULT 'admin' keeps every pre-existing key fully privileged, so upgrading
-- changes nothing until an operator opts a key into the narrower 'agent'
-- scope. Multi-tenant/SSO/SIEM remain out of scope here (ADR 0010).

ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS scope TEXT NOT NULL DEFAULT 'admin';
