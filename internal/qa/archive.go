package qa

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// File is one archive member.
type File struct {
	Path string
	Data []byte
}

// Pack writes files into a gzip tar in path order, so equal inputs give
// equal archives.
func Pack(files []File) ([]byte, error) {
	sorted := append([]File(nil), files...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	tw := tar.NewWriter(gz)
	epoch := time.Unix(0, 0)
	for _, f := range sorted {
		if !safePath(f.Path) {
			return nil, errors.New("unsafe archive path " + f.Path)
		}
		if err := tw.WriteHeader(&tar.Header{Name: f.Path, Mode: 0o644, Size: int64(len(f.Data)), Typeflag: tar.TypeReg, ModTime: epoch}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(f.Data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func safePath(p string) bool {
	return p != "" && len(p) <= 1024 && !strings.ContainsAny(p, "\\\x00") && !strings.HasPrefix(p, "/") && path.Clean(p) == p && filepath.IsLocal(filepath.FromSlash(p))
}

// Walk visits the regular files of a gzip tar with an expansion limit.
// Directories are skipped; links and special files are an error.
func Walk(archive io.Reader, maxFiles int, maxBytes int64, visit func(name string, size int64, r io.Reader) error) error {
	gz, err := gzip.NewReader(archive)
	if err != nil {
		return errors.New("invalid gzip archive")
	}
	defer gz.Close()
	limited := &io.LimitedReader{R: gz, N: maxBytes + 64<<10 + 1}
	reader := tar.NewReader(limited)
	files := 0
	var total int64
	for {
		h, err := reader.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return errors.New("invalid tar archive")
		}
		switch h.Typeflag {
		case tar.TypeDir:
			continue
		case tar.TypeReg:
		case tar.TypeXGlobalHeader:
			continue
		default:
			return errors.New("archive contains links or special files")
		}
		name := strings.TrimPrefix(h.Name, "./")
		files++
		total += h.Size
		if h.Size < 0 || files > maxFiles || total > maxBytes {
			return errors.New("archive expansion limit exceeded")
		}
		if err := visit(name, h.Size, io.LimitReader(reader, h.Size)); err != nil {
			return err
		}
	}
}

// Unpack extracts an archive into dir. Paths must be local; .karate
// directories (karate-cli project settings that could change the Karate
// version or JVM) are dropped.
func Unpack(archive io.Reader, dir string, maxFiles int, maxBytes int64) error {
	return Walk(archive, maxFiles, maxBytes, func(name string, size int64, r io.Reader) error {
		if !safePath(name) {
			return errors.New("unsafe archive path")
		}
		for _, part := range strings.Split(name, "/") {
			if part == ".karate" {
				return nil
			}
		}
		destination := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
			return err
		}
		f, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err != nil {
			return errors.New("duplicate or invalid archive path")
		}
		_, copyErr := io.CopyN(f, r, size)
		closeErr := f.Close()
		if copyErr != nil || closeErr != nil {
			return errors.New("archive extraction failed")
		}
		return nil
	})
}

// Snapshot is a repository source archive read into memory: every path, and
// the contents of the files a selector kept.
type Snapshot struct {
	Paths []string
	Files map[string][]byte
}

// ReadSnapshot reads a provider source archive (one root directory, as
// GitHub and GitLab produce). keep chooses the files whose contents are
// kept, within maxKept files and maxKeptBytes in total; the rest are listed.
func ReadSnapshot(archive []byte, keep func(rel string, size int64) bool, maxKept int, maxKeptBytes int64) (Snapshot, error) {
	out := Snapshot{Files: map[string][]byte{}}
	var kept int64
	root := ""
	err := Walk(bytes.NewReader(archive), 50000, 1<<30, func(name string, size int64, r io.Reader) error {
		name = strings.TrimSuffix(name, "/")
		first, rel, ok := strings.Cut(name, "/")
		if !ok || first == "" || first == ".." || !safePath(rel) {
			return errors.New("unsafe archive path")
		}
		if root == "" {
			root = first
		}
		if first != root {
			return errors.New("archive contains multiple roots")
		}
		out.Paths = append(out.Paths, rel)
		if keep == nil || !keep(rel, size) || len(out.Files) >= maxKept || kept+size > maxKeptBytes {
			return nil
		}
		data, err := io.ReadAll(r)
		if err != nil {
			return errors.New("archive read failed")
		}
		kept += size
		out.Files[rel] = data
		return nil
	})
	sort.Strings(out.Paths)
	return out, err
}

// Under reports whether rel is dir or inside it ("" and "." mean the root).
func Under(rel, dir string) bool {
	dir = strings.Trim(dir, "/")
	if dir == "" || dir == "." {
		return true
	}
	return rel == dir || strings.HasPrefix(rel, dir+"/")
}
