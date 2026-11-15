package scanner

import (
	"archive/zip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/versions"
)

// osvRecord is the part of an OSV record safe-version computation needs.
type osvRecord struct {
	ID        string `json:"id"`
	Withdrawn string `json:"withdrawn"`
	Affected  []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges   []versions.Range `json:"ranges"`
		Versions []string         `json:"versions"`
	} `json:"affected"`
}

// Advisory reduces an OSV record to one package's affected entries.
func (r osvRecord) Advisory(ecosystem, name string) versions.Advisory {
	a := versions.Advisory{ID: r.ID, Withdrawn: r.Withdrawn != "", Affected: []versions.Affected{}}
	for _, entry := range r.Affected {
		if entry.Package.Ecosystem != ecosystem || !strings.EqualFold(entry.Package.Name, name) {
			continue
		}
		a.Affected = append(a.Affected, versions.Affected{Ecosystem: entry.Package.Ecosystem, Name: entry.Package.Name, Ranges: entry.Ranges, Versions: entry.Versions})
	}
	return a
}

// ParseAdvisory reads an OSV record (a finding's evidence) for one package.
func ParseAdvisory(raw []byte, ecosystem, name string) (versions.Advisory, bool) {
	var r osvRecord
	if json.Unmarshal(raw, &r) != nil || r.ID == "" {
		return versions.Advisory{}, false
	}
	return r.Advisory(ecosystem, name), true
}

// Bounds on the advisory set returned per scan.
const (
	maxPackageAdvisories = 500
	maxAdvisoryRecords   = 20000
)

// packageAdvisories reads, from the feed snapshot's package index, every
// advisory for each package with a vulnerability finding. Snapshots
// synced before the index existed return nothing; the worker then uses
// the matched advisories alone.
func packageAdvisories(database string, components []assessments.Component, findings []assessments.Finding) []versions.Package {
	type key struct{ ecosystem, name string }
	wanted := map[string]map[key]bool{}
	for _, f := range findings {
		if f.Type != "vulnerability" || f.Component.Name == "" {
			continue
		}
		base, _, _ := strings.Cut(f.Component.Ecosystem, ":")
		if wanted[base] == nil {
			wanted[base] = map[key]bool{}
		}
		wanted[base][key{f.Component.Ecosystem, f.Component.Name}] = true
	}
	out := []versions.Package{}
	total := 0
	for base, packages := range wanted {
		directory := filepath.Join(database, "osv-scalibr", filepath.Base(base))
		index, err := readIndex(filepath.Join(directory, "index.json"))
		if err != nil {
			continue
		}
		archive, err := zip.OpenReader(filepath.Join(directory, "all.zip"))
		if err != nil {
			continue
		}
		entries := make(map[string]*zip.File, len(archive.File))
		for _, f := range archive.File {
			entries[f.Name] = f
		}
		for k := range packages {
			pkg := versions.Package{Ecosystem: k.ecosystem, Name: k.name, Advisories: []versions.Advisory{}, Complete: true}
			names := index[strings.ToLower(k.name)]
			if len(names) > maxPackageAdvisories {
				names, pkg.Complete = names[:maxPackageAdvisories], false
			}
			for _, name := range names {
				if total >= maxAdvisoryRecords {
					pkg.Complete = false
					break
				}
				entry := entries[name]
				if entry == nil {
					pkg.Complete = false
					continue
				}
				reader, err := entry.Open()
				if err != nil {
					pkg.Complete = false
					continue
				}
				raw, err := io.ReadAll(io.LimitReader(reader, 2<<20))
				reader.Close()
				a, ok := ParseAdvisory(raw, k.ecosystem, k.name)
				if err != nil || !ok {
					pkg.Complete = false
					continue
				}
				if len(a.Affected) > 0 {
					pkg.Advisories = append(pkg.Advisories, a)
					total++
				}
			}
			out = append(out, pkg)
		}
		archive.Close()
	}
	return out
}

func readIndex(path string) (map[string][]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var index map[string][]string
	if err := json.NewDecoder(io.LimitReader(f, 256<<20)).Decode(&index); err != nil {
		return nil, err
	}
	return index, nil
}
