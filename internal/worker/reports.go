package worker

import (
	"context"
	"time"

	"github.com/ORIBData/scrstack/internal/buildinfo"
	"github.com/ORIBData/scrstack/internal/compliance"
)

// ReportStore keeps compliance evidence report files.
type ReportStore interface {
	PutReport(ctx context.Context, data []byte, extension string) (string, string, error)
}

// RunReports builds queued compliance evidence reports (CMP-006).
func (w Worker) RunReports(ctx context.Context, every time.Duration) {
	for {
		started := time.Now()
		built, err := w.BuildReportOnce(ctx)
		if err != nil && ctx.Err() == nil {
			w.Logger.Warn("report generation failed", "error", err)
		}
		if built {
			continue
		}
		_ = w.Store.RecordJob(context.WithoutCancel(ctx), "compliance_reports", every, started, err, nil)
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

// BuildReportOnce builds the oldest queued report, if any.
func (w Worker) BuildReportOnce(ctx context.Context) (bool, error) {
	if w.Reports == nil {
		return false, nil
	}
	job, err := w.Store.ClaimReport(ctx)
	if err != nil || job == nil {
		return false, err
	}
	buildCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	// Data time is when the register was read, not when the file was written.
	dataAsOf := time.Now().UTC()
	pack, input, err := w.Store.ReportInput(buildCtx, *job)
	if err != nil {
		return true, w.Store.FailReport(context.WithoutCancel(ctx), *job, "report data could not be read")
	}
	input.DataAsOf = dataAsOf
	input.Version = buildinfo.Version()
	report := compliance.Build(pack, input)
	data, err := compliance.Render(report, job.Format)
	if err != nil {
		return true, w.Store.FailReport(context.WithoutCancel(ctx), *job, "report rendering failed")
	}
	key, digest, err := w.Reports.PutReport(buildCtx, data, job.Format)
	if err != nil {
		return true, w.Store.FailReport(context.WithoutCancel(ctx), *job, "report storage failed")
	}
	summary := map[string]any{"assets": len(report.Assets), "gaps": len(report.Gaps), "findings_considered": report.Totals.Considered, "open": report.Totals.Open}
	if report.Unmapped != nil {
		summary["unmapped_no_cwe"], summary["unmapped_outside_pack"] = report.Unmapped.NoCWE, report.Unmapped.OutsidePack
	}
	return true, w.Store.FinishReport(context.WithoutCancel(ctx), *job, key, digest, int64(len(data)), input.DataAsOf, input.Version, report.Feeds, summary)
}
