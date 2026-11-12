package assessments

// Schema is applied under the storage migration lock. No destructive DDL.
func Schema(s string) []string {
	return []string{
		`CREATE INDEX IF NOT EXISTS assets_github_locator_idx ON ` + s + `.assets(lower(locator)) WHERE type='github_repo'`,
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
		`CREATE TABLE IF NOT EXISTS ` + s + `.remediation_results(assessment_id uuid PRIMARY KEY REFERENCES ` + s + `.assessments(id),artifact_key text NOT NULL,sha256 text NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp())`,
		`CREATE TABLE IF NOT EXISTS ` + s + `.advisories(id text PRIMARY KEY,body jsonb NOT NULL,imported_at timestamptz NOT NULL DEFAULT clock_timestamp())`,
	}
}
