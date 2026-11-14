package assessments

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// TAXII 2.1 feeds (TIF): a taxii source polls one collection. The API seals
// the credentials with SCRS_MASTER_KEY before they reach the store; the
// worker claims due feeds with a lease, imports each page with a STIX merge
// and keeps the added_after cursor.

func taxiiSchema(s string) []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS ` + s + `.taxii_feeds(source_id uuid PRIMARY KEY REFERENCES ` + s + `.indicator_sources(id) ON DELETE CASCADE,api_root text NOT NULL,collection text NOT NULL,auth_type text NOT NULL CHECK(auth_type IN ('none','api_key','basic')),auth_header text NOT NULL DEFAULT '',client_cert boolean NOT NULL DEFAULT false,ca_pem text NOT NULL DEFAULT '',credential bytea,interval_minutes integer NOT NULL DEFAULT 60 CHECK(interval_minutes BETWEEN 5 AND 10080),page_size integer NOT NULL DEFAULT 1000 CHECK(page_size BETWEEN 1 AND 10000),valid_days integer NOT NULL DEFAULT 180 CHECK(valid_days BETWEEN 1 AND 3650),cursor text NOT NULL DEFAULT '',next_poll_at timestamptz NOT NULL DEFAULT clock_timestamp(),lease_until timestamptz,last_poll_at timestamptz,last_success_at timestamptz,last_error text NOT NULL DEFAULT '',failures integer NOT NULL DEFAULT 0,objects_polled bigint NOT NULL DEFAULT 0)`,
	}
}

// TAXIIFeed is a feed's settings and poll state; credentials are never read back.
type TAXIIFeed struct {
	SourceID        uuid.UUID  `json:"source_id"`
	APIRoot         string     `json:"api_root"`
	Collection      string     `json:"collection"`
	AuthType        string     `json:"auth_type"`
	AuthHeader      string     `json:"auth_header"`
	ClientCert      bool       `json:"client_cert"`
	CAPEM           string     `json:"ca_pem"`
	IntervalMinutes int        `json:"interval_minutes"`
	PageSize        int        `json:"page_size"`
	ValidDays       int        `json:"valid_days"`
	Cursor          string     `json:"cursor"`
	NextPollAt      time.Time  `json:"next_poll_at"`
	LastPollAt      *time.Time `json:"last_poll_at"`
	LastSuccessAt   *time.Time `json:"last_success_at"`
	LastError       string     `json:"last_error"`
	Failures        int        `json:"failures"`
	ObjectsPolled   int64      `json:"objects_polled"`
}

// TAXIIAAD binds a sealed credential to its source.
func TAXIIAAD(source uuid.UUID) []byte { return []byte("taxii:" + source.String()) }

const taxiiColumns = `source_id,api_root,collection,auth_type,auth_header,client_cert,ca_pem,interval_minutes,page_size,valid_days,cursor,next_poll_at,last_poll_at,last_success_at,last_error,failures,objects_polled`

func scanFeed(row pgx.Row, extra ...any) (TAXIIFeed, error) {
	var f TAXIIFeed
	targets := append([]any{&f.SourceID, &f.APIRoot, &f.Collection, &f.AuthType, &f.AuthHeader, &f.ClientCert, &f.CAPEM, &f.IntervalMinutes, &f.PageSize, &f.ValidDays, &f.Cursor, &f.NextPollAt, &f.LastPollAt, &f.LastSuccessAt, &f.LastError, &f.Failures, &f.ObjectsPolled}, extra...)
	if err := row.Scan(targets...); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return f, ErrNotFound
		}
		return f, err
	}
	return f, nil
}

func validFeed(f TAXIIFeed) bool {
	return f.IntervalMinutes >= 5 && f.IntervalMinutes <= 10080 && f.PageSize >= 1 && f.PageSize <= 10000 && f.ValidDays >= 1 && f.ValidDays <= 3650
}

func feedAudit(ctx context.Context, tx pgx.Tx, schema, action string, f TAXIIFeed, actor uuid.UUID, credential bool) error {
	details, _ := json.Marshal(map[string]any{"actor_id": actor, "api_root": f.APIRoot, "collection": f.Collection, "auth_type": f.AuthType, "client_cert": f.ClientCert, "interval_minutes": f.IntervalMinutes, "credential_changed": credential})
	_, err := tx.Exec(ctx, `INSERT INTO `+schema+`.audit_log(action,target_id,details) VALUES($1,$2,$3)`, action, f.SourceID, details)
	return err
}

// CreateTAXIISource stores a taxii source and its feed. seal encrypts the
// credential once the source ID is known (it is bound into the ciphertext).
// The settings must already be validated by the taxii package.
func (s *Store) CreateTAXIISource(ctx context.Context, r IndicatorSource, f TAXIIFeed, actor uuid.UUID, seal func(source uuid.UUID) ([]byte, error)) (IndicatorSource, TAXIIFeed, error) {
	r.Kind = "taxii"
	if !validFeed(f) {
		return r, f, ErrInput
	}
	var feed TAXIIFeed
	created, err := s.createSource(ctx, r, actor, func(tx pgx.Tx, created IndicatorSource) error {
		credential, err := seal(created.ID)
		if err != nil {
			return err
		}
		if feed, err = scanFeed(tx.QueryRow(ctx, `INSERT INTO `+s.schema+`.taxii_feeds(source_id,api_root,collection,auth_type,auth_header,client_cert,ca_pem,credential,interval_minutes,page_size,valid_days) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING `+taxiiColumns, created.ID, f.APIRoot, f.Collection, f.AuthType, f.AuthHeader, f.ClientCert, f.CAPEM, credential, f.IntervalMinutes, f.PageSize, f.ValidDays)); err != nil {
			return err
		}
		return feedAudit(ctx, tx, s.schema, "taxii_feed.created", feed, actor, true)
	})
	return created, feed, err
}

// TAXIIFeedFor returns a source's feed.
func (s *Store) TAXIIFeedFor(ctx context.Context, source uuid.UUID) (TAXIIFeed, error) {
	return scanFeed(s.pool.QueryRow(ctx, `SELECT `+taxiiColumns+` FROM `+s.schema+`.taxii_feeds WHERE source_id=$1`, source))
}

// TAXIIFeedCredential returns a feed's settings with its sealed credential.
func (s *Store) TAXIIFeedCredential(ctx context.Context, source uuid.UUID) (TAXIIFeed, []byte, error) {
	var sealed []byte
	f, err := scanFeed(s.pool.QueryRow(ctx, `SELECT `+taxiiColumns+`,credential FROM `+s.schema+`.taxii_feeds WHERE source_id=$1`, source), &sealed)
	return f, sealed, err
}

// UpdateTAXIIFeed replaces a feed's settings; a nil credential keeps the
// sealed one. Moving to another server or collection, or resetCursor,
// restarts from the beginning of the collection. The next poll is due now.
func (s *Store) UpdateTAXIIFeed(ctx context.Context, f TAXIIFeed, credential []byte, resetCursor bool, actor uuid.UUID) (TAXIIFeed, error) {
	if !validFeed(f) {
		return f, ErrInput
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return f, err
	}
	defer tx.Rollback(ctx)
	before, err := scanFeed(tx.QueryRow(ctx, `SELECT `+taxiiColumns+` FROM `+s.schema+`.taxii_feeds WHERE source_id=$1 FOR UPDATE`, f.SourceID))
	if err != nil {
		return f, err
	}
	resetCursor = resetCursor || before.APIRoot != f.APIRoot || before.Collection != f.Collection
	updated, err := scanFeed(tx.QueryRow(ctx, `UPDATE `+s.schema+`.taxii_feeds SET api_root=$2,collection=$3,auth_type=$4,auth_header=$5,client_cert=$6,ca_pem=$7,credential=COALESCE($8,credential),interval_minutes=$9,page_size=$10,valid_days=$11,cursor=CASE WHEN $12 THEN '' ELSE cursor END,next_poll_at=clock_timestamp(),failures=0,last_error='' WHERE source_id=$1 RETURNING `+taxiiColumns, f.SourceID, f.APIRoot, f.Collection, f.AuthType, f.AuthHeader, f.ClientCert, f.CAPEM, credential, f.IntervalMinutes, f.PageSize, f.ValidDays, resetCursor))
	if err != nil {
		return f, err
	}
	if err := feedAudit(ctx, tx, s.schema, "taxii_feed.changed", updated, actor, credential != nil); err != nil {
		return f, err
	}
	return updated, tx.Commit(ctx)
}

// PollTAXIINow makes a feed due immediately.
func (s *Store) PollTAXIINow(ctx context.Context, source uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `UPDATE `+s.schema+`.taxii_feeds SET next_poll_at=clock_timestamp() WHERE source_id=$1`, source)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// TAXIIClaim is a due feed leased to one worker.
type TAXIIClaim struct {
	Feed       TAXIIFeed
	Source     IndicatorSource
	Credential []byte
}

// TAXIILease bounds one poll; a worker that dies frees the feed after it.
const TAXIILease = 15 * time.Minute

// ClaimTAXII leases the most overdue feed of an enabled source, or returns
// ErrNotFound when none is due.
func (s *Store) ClaimTAXII(ctx context.Context) (TAXIIClaim, error) {
	var c TAXIIClaim
	var err error
	c.Feed, err = scanFeed(s.pool.QueryRow(ctx, `UPDATE `+s.schema+`.taxii_feeds f SET lease_until=clock_timestamp()+($1*interval '1 second'),last_poll_at=clock_timestamp() WHERE f.source_id=(SELECT t.source_id FROM `+s.schema+`.taxii_feeds t JOIN `+s.schema+`.indicator_sources src ON src.id=t.source_id WHERE src.enabled AND t.next_poll_at<=clock_timestamp() AND (t.lease_until IS NULL OR t.lease_until<clock_timestamp()) ORDER BY t.next_poll_at LIMIT 1 FOR UPDATE OF t SKIP LOCKED) RETURNING `+taxiiColumns+`,credential`, int64(TAXIILease.Seconds())), &c.Credential)
	if err != nil {
		return c, err
	}
	c.Source, err = s.IndicatorSourceByID(ctx, c.Feed.SourceID)
	return c, err
}

// AdvanceTAXII records an imported page: the cursor moves only when the
// server sent one, and the lease is extended.
func (s *Store) AdvanceTAXII(ctx context.Context, source uuid.UUID, cursor string, objects int) error {
	_, err := s.pool.Exec(ctx, `UPDATE `+s.schema+`.taxii_feeds SET cursor=CASE WHEN $2='' THEN cursor ELSE $2 END,objects_polled=objects_polled+$3,lease_until=clock_timestamp()+($4*interval '1 second') WHERE source_id=$1`, source, cursor, objects, int64(TAXIILease.Seconds()))
	return err
}

// FinishTAXII ends a poll and schedules the next. A success is due again
// after the interval, or now when the collection has more pages. A failure
// backs off from the interval, doubling per consecutive failure up to a day.
// It returns the consecutive failure count.
func (s *Store) FinishTAXII(ctx context.Context, source uuid.UUID, pollErr error, more bool) (int, error) {
	var failures int
	var err error
	if pollErr == nil {
		err = s.pool.QueryRow(ctx, `UPDATE `+s.schema+`.taxii_feeds SET lease_until=NULL,failures=0,last_error='',last_success_at=clock_timestamp(),next_poll_at=CASE WHEN $2 THEN clock_timestamp() ELSE clock_timestamp()+interval_minutes*interval '1 minute' END WHERE source_id=$1 RETURNING failures`, source, more).Scan(&failures)
	} else {
		message := pollErr.Error()
		if len(message) > 1000 {
			message = message[:1000]
		}
		err = s.pool.QueryRow(ctx, `UPDATE `+s.schema+`.taxii_feeds SET lease_until=NULL,failures=failures+1,last_error=$2,next_poll_at=clock_timestamp()+LEAST(interval_minutes*power(2,LEAST(failures,10)),1440)*interval '1 minute' WHERE source_id=$1 RETURNING failures`, source, message).Scan(&failures)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrNotFound
	}
	return failures, err
}

// TAXIIVersion names a TAXII import in the source's version.
func TAXIIVersion(cursor string) string {
	if cursor == "" {
		return "taxii"
	}
	return "taxii:" + cursor
}

// TAXIIFeeds returns every feed by source, for source listings.
func (s *Store) TAXIIFeeds(ctx context.Context) (map[uuid.UUID]TAXIIFeed, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+taxiiColumns+` FROM `+s.schema+`.taxii_feeds`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[uuid.UUID]TAXIIFeed{}
	for rows.Next() {
		f, err := scanFeed(rows)
		if err != nil {
			return nil, err
		}
		out[f.SourceID] = f
	}
	return out, rows.Err()
}
