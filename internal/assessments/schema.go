package assessments

// Schema is applied under the storage migration lock. No destructive DDL.
func Schema(s string) []string {
	return append(baseSchema(s), mirrorSchema(s)...)
}

func baseSchema(s string) []string {
	return []string{
		`CREATE INDEX IF NOT EXISTS assets_github_locator_idx ON ` + s + `.assets(lower(locator)) WHERE type='github_repo'`,
		`CREATE INDEX IF NOT EXISTS assets_gitlab_locator_idx ON ` + s + `.assets(lower(locator)) WHERE type='gitlab_repo'`,
		`CREATE TABLE IF NOT EXISTS ` + s + `.assessments (
 id uuid PRIMARY KEY, asset_id uuid NOT NULL REFERENCES ` + s + `.assets(id), connection_id uuid NOT NULL REFERENCES ` + s + `.connections(id), connection_revision bigint NOT NULL,
 request jsonb NOT NULL, requested_by text NOT NULL, actor_id uuid NOT NULL,
 status text NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','running','succeeded','failed','cancelled','superseded')),
 verdict text NOT NULL DEFAULT 'incomplete' CHECK(verdict IN ('pass','warn','fail','incomplete')),
 resolved_commit text NOT NULL DEFAULT '',ref_moved boolean NOT NULL DEFAULT false,
 stages jsonb NOT NULL DEFAULT '[]',counts jsonb NOT NULL DEFAULT '{}',
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), completed_at timestamptz,
 attempts integer NOT NULL DEFAULT 0,run_after timestamptz NOT NULL DEFAULT clock_timestamp(),lease uuid,lease_until timestamptz,
 error text NOT NULL DEFAULT '',sbom_key text NOT NULL DEFAULT '',sbom_sha256 text NOT NULL DEFAULT ''
 )`,
		`CREATE INDEX IF NOT EXISTS assessments_queue_idx ON ` + s + `.assessments(run_after,created_at) WHERE status='queued'`,
		`CREATE UNIQUE INDEX IF NOT EXISTS assessments_running_asset_uq ON ` + s + `.assessments(asset_id) WHERE status='running'`,
		`CREATE INDEX IF NOT EXISTS assessments_asset_created_idx ON ` + s + `.assessments(asset_id,created_at DESC)`,
		`CREATE INDEX IF NOT EXISTS assessments_actor_page_idx ON ` + s + `.assessments(actor_id,id)`,
		`CREATE TABLE IF NOT EXISTS ` + s + `.assessment_idempotency(actor_id uuid NOT NULL,key text NOT NULL,body_hash text NOT NULL,assessment_id uuid NOT NULL REFERENCES ` + s + `.assessments(id),expires_at timestamptz NOT NULL,PRIMARY KEY(actor_id,key))`,
		`CREATE TABLE IF NOT EXISTS ` + s + `.inbound_events(id uuid PRIMARY KEY,assessment_id uuid REFERENCES ` + s + `.assessments(id),actor_id uuid NOT NULL,body jsonb NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp())`,
		`CREATE TABLE IF NOT EXISTS ` + s + `.components(assessment_id uuid NOT NULL REFERENCES ` + s + `.assessments(id),ordinal integer NOT NULL,body jsonb NOT NULL,PRIMARY KEY(assessment_id,ordinal))`,
		`CREATE TABLE IF NOT EXISTS ` + s + `.findings(id uuid PRIMARY KEY,asset_id uuid NOT NULL REFERENCES ` + s + `.assets(id),fingerprint text NOT NULL UNIQUE,ref text NOT NULL,type text NOT NULL,advisory_id text NOT NULL,title text NOT NULL,severity text NOT NULL,score integer NOT NULL CHECK(score BETWEEN 0 AND 100),status text NOT NULL DEFAULT 'open',component jsonb NOT NULL,evidence jsonb NOT NULL,guidance jsonb NOT NULL,first_seen timestamptz NOT NULL DEFAULT clock_timestamp(),last_seen timestamptz NOT NULL DEFAULT clock_timestamp(),last_assessment_id uuid NOT NULL REFERENCES ` + s + `.assessments(id),waiver_until timestamptz,revision bigint NOT NULL DEFAULT 1)`,
		`CREATE INDEX IF NOT EXISTS findings_asset_ref_idx ON ` + s + `.findings(asset_id,ref)`,
		`CREATE TABLE IF NOT EXISTS ` + s + `.assessment_findings(assessment_id uuid NOT NULL REFERENCES ` + s + `.assessments(id),finding_id uuid NOT NULL REFERENCES ` + s + `.findings(id),snapshot jsonb NOT NULL,PRIMARY KEY(assessment_id,finding_id))`,
		`CREATE TABLE IF NOT EXISTS ` + s + `.finding_events(id bigserial PRIMARY KEY,finding_id uuid NOT NULL REFERENCES ` + s + `.findings(id),actor_id uuid,action text NOT NULL,details jsonb NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp())`,
		`CREATE INDEX IF NOT EXISTS finding_events_history_idx ON ` + s + `.finding_events(finding_id,id DESC)`,
		`CREATE TABLE IF NOT EXISTS ` + s + `.retention_policy(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),revision bigint NOT NULL DEFAULT 1,inbound_event_days integer NOT NULL DEFAULT 0 CHECK(inbound_event_days BETWEEN 0 AND 36500))`,
		`INSERT INTO ` + s + `.retention_policy(singleton) VALUES(true) ON CONFLICT DO NOTHING`,
		`CREATE INDEX IF NOT EXISTS inbound_events_age_idx ON ` + s + `.inbound_events(created_at)`,
		`CREATE TABLE IF NOT EXISTS ` + s + `.indicator_bundles(id uuid PRIMARY KEY,version text NOT NULL UNIQUE,body jsonb NOT NULL,active boolean NOT NULL DEFAULT true,created_at timestamptz NOT NULL DEFAULT clock_timestamp())`,
		`CREATE UNIQUE INDEX IF NOT EXISTS indicator_bundles_active_uq ON ` + s + `.indicator_bundles(active) WHERE active`,
		`CREATE TABLE IF NOT EXISTS ` + s + `.automatic_remediations(parent_id uuid NOT NULL REFERENCES ` + s + `.assessments(id),manifest text NOT NULL,status text NOT NULL DEFAULT 'pending',assessment_id uuid REFERENCES ` + s + `.assessments(id),error text NOT NULL DEFAULT '',PRIMARY KEY(parent_id,manifest))`,
		`CREATE TABLE IF NOT EXISTS ` + s + `.assessment_files(assessment_id uuid PRIMARY KEY REFERENCES ` + s + `.assessments(id),body jsonb NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS ` + s + `.remediation_results(assessment_id uuid PRIMARY KEY REFERENCES ` + s + `.assessments(id),artifact_key text NOT NULL,sha256 text NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp())`,
		`CREATE TABLE IF NOT EXISTS ` + s + `.advisories(id text PRIMARY KEY,body jsonb NOT NULL,imported_at timestamptz NOT NULL DEFAULT clock_timestamp())`,
		// 2026-11-13: diffs, request ids, source snapshots, event-based integrity entries.
		`ALTER TABLE ` + s + `.assessments ADD COLUMN IF NOT EXISTS diff jsonb NOT NULL DEFAULT '{}'`,
		`ALTER TABLE ` + s + `.assessments ADD COLUMN IF NOT EXISTS request_id text NOT NULL DEFAULT ''`,
		`ALTER TABLE ` + s + `.assessments ADD COLUMN IF NOT EXISTS snapshot_key text NOT NULL DEFAULT ''`,
		`CREATE INDEX IF NOT EXISTS assessments_baseline_idx ON ` + s + `.assessments(asset_id,(request->'target'->>'ref'),created_at DESC) WHERE status='succeeded'`,
		`CREATE INDEX IF NOT EXISTS assessments_commit_idx ON ` + s + `.assessments(asset_id,resolved_commit,created_at DESC)`,
		`ALTER TABLE ` + s + `.findings ALTER COLUMN last_assessment_id DROP NOT NULL`,
		`CREATE TABLE IF NOT EXISTS ` + s + `.integrity_events(id uuid PRIMARY KEY,delivery_id text NOT NULL,kind text NOT NULL,severity text NOT NULL,repository text NOT NULL DEFAULT '',ref text NOT NULL DEFAULT '',asset_id uuid REFERENCES ` + s + `.assets(id),finding_id uuid REFERENCES ` + s + `.findings(id),actor text NOT NULL DEFAULT '',details jsonb NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),UNIQUE(delivery_id,kind))`,
		`CREATE INDEX IF NOT EXISTS integrity_events_asset_idx ON ` + s + `.integrity_events(asset_id,created_at DESC)`,
		`ALTER TABLE ` + s + `.inbound_events ADD COLUMN IF NOT EXISTS mode text NOT NULL DEFAULT 'trigger'`,
		`ALTER TABLE ` + s + `.inbound_events ADD COLUMN IF NOT EXISTS event_type text NOT NULL DEFAULT ''`,
		`ALTER TABLE ` + s + `.retention_policy ADD COLUMN IF NOT EXISTS webhook_delivery_days integer NOT NULL DEFAULT 0 CHECK(webhook_delivery_days BETWEEN 0 AND 36500)`,
		// AST-002: owners and asset attributes used for routing and context.
		`CREATE TABLE IF NOT EXISTS ` + s + `.owners(id uuid PRIMARY KEY,name text NOT NULL UNIQUE,email text NOT NULL DEFAULT '',team text NOT NULL DEFAULT '',chat text NOT NULL DEFAULT '',secondary_contact text NOT NULL DEFAULT '',revision bigint NOT NULL DEFAULT 1,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),updated_at timestamptz NOT NULL DEFAULT clock_timestamp())`,
		`ALTER TABLE ` + s + `.assets ADD COLUMN IF NOT EXISTS owner_id uuid REFERENCES ` + s + `.owners(id)`,
		`ALTER TABLE ` + s + `.assets ADD COLUMN IF NOT EXISTS environment text NOT NULL DEFAULT '' CHECK(environment IN ('','dev','stg','prod'))`,
		`ALTER TABLE ` + s + `.assets ADD COLUMN IF NOT EXISTS criticality integer NOT NULL DEFAULT 0 CHECK(criticality BETWEEN 0 AND 5)`,
		`ALTER TABLE ` + s + `.assets ADD COLUMN IF NOT EXISTS exposure text NOT NULL DEFAULT '' CHECK(exposure IN ('','internet','internal','offline'))`,
		`ALTER TABLE ` + s + `.assets ADD COLUMN IF NOT EXISTS labels jsonb NOT NULL DEFAULT '{}'`,
		`ALTER TABLE ` + s + `.assets ADD COLUMN IF NOT EXISTS revision bigint NOT NULL DEFAULT 1`,
		`CREATE INDEX IF NOT EXISTS assets_owner_idx ON ` + s + `.assets(owner_id)`,
	}
}
