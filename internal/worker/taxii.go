package worker

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/intelligence"
	"github.com/ORIBData/scrstack/internal/taxii"
	"github.com/google/uuid"
)

// maxTAXIIPages bounds one poll; a collection with more is polled again at once.
const maxTAXIIPages = 20

// taxiiFailureAlert is the consecutive failure count that raises feed.stale.
const taxiiFailureAlert = 3

// PollTAXII polls due TAXII feeds every interval until ctx ends.
func (w Worker) PollTAXII(ctx context.Context, every time.Duration) {
	for {
		for ctx.Err() == nil {
			polled, err := w.PollTAXIIOnce(ctx)
			if err != nil {
				w.Logger.Warn("TAXII poll bookkeeping failed", "error", err)
			}
			if !polled || err != nil {
				break
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

// PollTAXIIOnce polls the most overdue feed, if any is due. Feed errors are
// recorded on the feed, not returned.
func (w Worker) PollTAXIIOnce(ctx context.Context) (bool, error) {
	claim, err := w.Store.ClaimTAXII(ctx)
	if errors.Is(err, assessments.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	pollCtx, cancel := context.WithTimeout(ctx, assessments.TAXIILease-time.Minute)
	more, pollErr := w.pollFeed(pollCtx, claim)
	cancel()
	finishCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	failures, err := w.Store.FinishTAXII(finishCtx, claim.Source.ID, pollErr, more)
	if pollErr != nil {
		w.Logger.Warn("TAXII poll failed", "source", claim.Source.Name, "failures", failures, "error", pollErr)
		if failures == taxiiFailureAlert && w.Notify != nil {
			if err := w.Notify.EmitNow(finishCtx, "feed.stale", map[string]any{"feed": "taxii", "source": claim.Source.Name, "source_id": claim.Source.ID, "failures": failures, "detail": "TAXII polling failed " + pollErr.Error() + "; indicators from this source are no longer updated"}); err != nil {
				w.Logger.Warn("feed.stale event not recorded", "error", err)
			}
		}
	}
	return true, err
}

// pollFeed imports pages until the collection has no more or the page bound
// is reached; more reports the latter. Each page is a STIX merge, and the
// cursor is saved after it, so a crash re-fetches at most one page.
func (w Worker) pollFeed(ctx context.Context, c assessments.TAXIIClaim) (more bool, err error) {
	plain, err := w.Connections.Unseal(c.Credential, assessments.TAXIIAAD(c.Source.ID))
	if err != nil {
		return false, err
	}
	var secret taxii.Secret
	if err := json.Unmarshal(plain, &secret); err != nil {
		return false, errors.New("TAXII credential invalid")
	}
	client, err := taxii.NewClient(taxii.Feed{APIRoot: c.Feed.APIRoot, Collection: c.Feed.Collection, AuthType: c.Feed.AuthType, Header: c.Feed.AuthHeader, CAPEM: c.Feed.CAPEM, PageSize: c.Feed.PageSize}, secret, w.TAXIIPrivateHosts)
	if err != nil {
		return false, err
	}
	compile := w.ValidateRules
	if compile == nil {
		compile = func(context.Context, string) error { return errors.New("YARA compiler not configured") }
	}
	allow := func(assessments.IndicatorSource) error { return nil }
	// added_after stays fixed while the server pages with next; servers that
	// page only by date continue from the last page's X-TAXII-Date-Added-Last.
	after, cursor, next := c.Feed.Cursor, c.Feed.Cursor, ""
	for range maxTAXIIPages {
		page, err := client.Objects(ctx, after, next)
		if err != nil {
			return false, err
		}
		if page.AddedLast != "" {
			cursor = page.AddedLast
		}
		if len(page.Objects) > 0 {
			imp := intelligence.ParseSTIXObjects(page.Objects, assessments.TAXIIVersion(cursor), time.Now(), time.Duration(c.Feed.ValidDays)*24*time.Hour)
			if len(imp.Yara) > 0 {
				if err := imp.CheckYara(ctx, compile); err != nil {
					return false, err
				}
			}
			if _, _, err := w.Store.ImportSTIX(ctx, c.Source.ID, imp, true, uuid.Nil, allow, compile); err != nil {
				return false, err
			}
		}
		if err := w.Store.AdvanceTAXII(ctx, c.Source.ID, page.AddedLast, len(page.Objects)); err != nil {
			return false, err
		}
		switch {
		case !page.More:
			return false, nil
		case page.Next != "":
			next = page.Next
		case page.AddedLast != "":
			after, next = page.AddedLast, ""
		default:
			return false, errors.New("TAXII server reported more objects but sent neither next nor X-TAXII-Date-Added-Last")
		}
	}
	return true, nil
}
