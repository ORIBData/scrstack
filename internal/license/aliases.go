package license

import (
	"regexp"
	"strings"
)

// aliasKey reduces licence text to a comparable form: lower case, Python
// classifier prefixes and filler words removed, punctuation collapsed.
func aliasKey(text string) string {
	t := strings.ToLower(strings.TrimSpace(text))
	if i := strings.LastIndex(t, "::"); i >= 0 && strings.HasPrefix(t, "license ::") {
		t = t[i+2:]
	}
	t = strings.NewReplacer("licence", "license", "‐", "-", "–", "-", "_", " ", ",", " ", "\"", " ", "'", " ").Replace(t)
	fields := strings.Fields(t)
	kept := fields[:0]
	for _, f := range fields {
		switch f {
		case "the", "license", "version", "ver", "ver.", "v.", "terms", "of":
			continue
		}
		kept = append(kept, f)
	}
	return strings.Join(kept, " ")
}

// aliases maps aliasKey forms to SPDX expressions. Families with versions
// are handled by the patterns below.
var aliases = map[string]string{
	"mit": "MIT", "mit/x11": "MIT", "expat": "MIT", "mit expat": "MIT", "x11": "X11", "mit x11": "MIT",
	"mit-style": "LicenseRef-scrs-mit-style", "mit style": "LicenseRef-scrs-mit-style", "mit like": "LicenseRef-scrs-mit-style",
	"isc": "ISC", "iscl": "ISC", "isc iscl": "ISC",
	"apache": "LicenseRef-scrs-apache-unversioned", "apache software": "Apache-2.0", "asl": "LicenseRef-scrs-apache-unversioned",
	"bsd": "LicenseRef-scrs-bsd-unversioned", "bsd-style": "LicenseRef-scrs-bsd-unversioned", "bsd style": "LicenseRef-scrs-bsd-unversioned", "bsd like": "LicenseRef-scrs-bsd-unversioned",
	"simplified bsd": "BSD-2-Clause", "freebsd": "BSD-2-Clause", "bsd 2-clause": "BSD-2-Clause", "bsd-2": "BSD-2-Clause", "2-clause bsd": "BSD-2-Clause", "bsd 2 clause": "BSD-2-Clause", "bsd-2-clause": "BSD-2-Clause",
	"new bsd": "BSD-3-Clause", "modified bsd": "BSD-3-Clause", "revised bsd": "BSD-3-Clause", "bsd 3-clause": "BSD-3-Clause", "bsd-3": "BSD-3-Clause", "3-clause bsd": "BSD-3-Clause", "bsd 3 clause": "BSD-3-Clause", "bsd-3-clause": "BSD-3-Clause", "bsd 3-clause new or revised": "BSD-3-Clause",
	"original bsd": "BSD-4-Clause", "bsd 4-clause": "BSD-4-Clause", "bsd-4": "BSD-4-Clause", "4-clause bsd": "BSD-4-Clause", "bsd-4-clause": "BSD-4-Clause",
	"0bsd": "0BSD", "zero-clause bsd": "0BSD", "bsd zero clause": "0BSD",
	"zlib": "Zlib", "zlib/libpng": "Zlib", "libpng": "Libpng",
	"python software foundation": "PSF-2.0", "psf": "PSF-2.0", "psfl": "PSF-2.0", "psf-2": "PSF-2.0", "python": "Python-2.0", "python-2.0": "Python-2.0",
	"boost": "BSL-1.0", "boost software 1.0": "BSL-1.0", "boost software": "BSL-1.0", "bsl": "BSL-1.0",
	"unlicense": "Unlicense", "unlicensed public domain": "Unlicense",
	"cc0": "CC0-1.0", "cc0 1.0 universal": "CC0-1.0", "cc0 1.0": "CC0-1.0", "cc0-1.0 universal": "CC0-1.0", "creative commons zero": "CC0-1.0",
	"public domain": "LicenseRef-scrs-public-domain", "public-domain": "LicenseRef-scrs-public-domain", "pd": "LicenseRef-scrs-public-domain", "publicdomain": "LicenseRef-scrs-public-domain",
	"wtfpl": "WTFPL", "do what fuck you want to public": "WTFPL",
	"artistic": "LicenseRef-scrs-artistic", "artistic 2.0": "Artistic-2.0", "artistic-2": "Artistic-2.0", "artistic 1.0": "Artistic-1.0",
	"perl": "Artistic-1.0-Perl OR GPL-1.0-or-later", "perl 5": "Artistic-1.0-Perl OR GPL-1.0-or-later", "perl_5": "Artistic-1.0-Perl OR GPL-1.0-or-later", "same as perl": "Artistic-1.0-Perl OR GPL-1.0-or-later",
	"ruby": "Ruby", "php": "PHP-3.01", "php-3": "PHP-3.0", "postgresql": "PostgreSQL", "openssl": "OpenSSL", "ssleay": "OpenSSL",
	"mpl": "LicenseRef-scrs-mpl-unversioned", "mozilla public": "LicenseRef-scrs-mpl-unversioned",
	"gpl": "LicenseRef-scrs-gpl-unversioned", "gnu gpl": "LicenseRef-scrs-gpl-unversioned", "gnu general public": "LicenseRef-scrs-gpl-unversioned", "gnu general public gpl": "LicenseRef-scrs-gpl-unversioned",
	"lgpl": "LicenseRef-scrs-lgpl-unversioned", "gnu lgpl": "LicenseRef-scrs-lgpl-unversioned", "gnu lesser general public": "LicenseRef-scrs-lgpl-unversioned", "gnu library or lesser general public lgpl": "LicenseRef-scrs-lgpl-unversioned", "gnu library or lesser general public": "LicenseRef-scrs-lgpl-unversioned",
	"agpl": "LicenseRef-scrs-agpl-unversioned", "gnu affero general public": "LicenseRef-scrs-agpl-unversioned",
	"academic free": "LicenseRef-scrs-afl-unversioned", "academic free afl": "LicenseRef-scrs-afl-unversioned", "afl": "LicenseRef-scrs-afl-unversioned",
	"cddl": "CDDL-1.0", "common development and distribution": "CDDL-1.0", "common development and distribution 1.0": "CDDL-1.0", "cddl-1.0": "CDDL-1.0",
	"epl": "EPL-1.0", "eclipse public": "EPL-1.0", "eclipse public 1.0": "EPL-1.0", "eclipse public 2.0": "EPL-2.0", "epl-2": "EPL-2.0", "eclipse distribution": "BSD-3-Clause", "edl 1.0": "BSD-3-Clause",
	"universal permissive": "UPL-1.0", "upl": "UPL-1.0",
	"sspl": "SSPL-1.0", "server side public": "SSPL-1.0", "business source": "BUSL-1.1", "bsl-1.1": "BUSL-1.1", "busl": "BUSL-1.1",
	"elastic": "Elastic-2.0", "elastic 2.0": "Elastic-2.0", "elv2": "Elastic-2.0", "elastic-2": "Elastic-2.0",
	"proprietary": "LicenseRef-scrs-proprietary", "commercial": "LicenseRef-scrs-proprietary", "unlicensed": "LicenseRef-scrs-proprietary", "all rights reserved": "LicenseRef-scrs-proprietary",
	"other/proprietary": "LicenseRef-scrs-proprietary", "private": "LicenseRef-scrs-proprietary", "closed": "LicenseRef-scrs-proprietary", "closed source": "LicenseRef-scrs-proprietary",
	"permissive": "LicenseRef-scrs-permissive", "osi approved": "LicenseRef-scrs-permissive",
	"json": "JSON", "curl": "curl", "ncsa": "NCSA", "university of illinois/ncsa open source": "NCSA", "w3c": "W3C", "unicode": "Unicode-DFS-2016", "icu": "ICU",
	"eupl": "EUPL-1.2", "european union public 1.2": "EUPL-1.2", "european union public 1.1": "EUPL-1.1", "eupl 1.2": "EUPL-1.2", "eupl 1.1": "EUPL-1.1",
	"ms-pl": "MS-PL", "microsoft public": "MS-PL", "ms-rl": "MS-RL", "microsoft reciprocal": "MS-RL",
	"cc-by": "CC-BY-4.0", "cc by 4.0": "CC-BY-4.0", "cc-by-4": "CC-BY-4.0", "cc by-sa 4.0": "CC-BY-SA-4.0", "cc-by-sa": "CC-BY-SA-4.0",
	"cc by-nc 4.0": "CC-BY-NC-4.0", "cc-by-nc": "CC-BY-NC-4.0", "cc by-nc-sa 4.0": "CC-BY-NC-SA-4.0",
	"ofl": "OFL-1.1", "sil open font": "OFL-1.1", "sil open font 1.1": "OFL-1.1", "ofl-1.1": "OFL-1.1",
	"wxwindows": "LGPL-2.0-or-later WITH WxWindows-exception-3.1", "hpnd": "HPND", "historical permission notice and disclaimer": "HPND",
	"gpl-2+ with autoconf exception": "GPL-2.0-or-later WITH Autoconf-exception-2.0", "gpl-3+ with autoconf exception": "GPL-3.0-or-later WITH Autoconf-exception-3.0",
}

var (
	// GNU families: "GPLv2", "GPL-2+", "GNU General Public License v3 or later (GPLv3+)", "LGPL 2.1".
	gnuFamily     = regexp.MustCompile(`^(?:gnu\s+)?(affero general public|lesser general public|library general public|library or lesser general public|general public|free documentation|agpl|lgpl|gpl|gfdl|fdl)\s*-?\s*v?\s*([0-9](?:\.[0-9])?)(?:\.0)?\s*(\+|or later|or-later|-or-later|or any later|and later|only|-only)?(?:\s*\(.*\))?$`)
	apacheFamily  = regexp.MustCompile(`^(?:apache|asl|apache software|apache public)\s*-?\s*v?\s*([12](?:\.[01])?)$`)
	mplFamily     = regexp.MustCompile(`^(?:mozilla public|mpl)\s*-?\s*v?\s*([12](?:\.[01])?)$`)
	ccFamily      = regexp.MustCompile(`^(?:creative commons|cc)[ -](by(?:-nc)?(?:-sa|-nd)?)[ -]?([1-4]\.[05])(?: international| generic| unported)?$`)
	ccLongFamily  = regexp.MustCompile(`^creative commons attribution(?:[ -](noncommercial))?(?:[ -](sharealike|noderivatives|no derivatives))?\s+([1-4]\.[05])(?: international| generic| unported)?$`)
	debianShort   = regexp.MustCompile(`^(a?gpl|lgpl|gfdl)-([0-9](?:\.[0-9])?)(\+)?$`)
	versionedSPDX = regexp.MustCompile(`^([a-z]+)\s+([0-9]+(?:\.[0-9]+)?)$`)
)

// alias resolves licence text that is not a strict expression.
func alias(text string) (string, bool) {
	key := aliasKey(text)
	if key == "" {
		return "", false
	}
	if id, ok := aliases[key]; ok {
		return id, true
	}
	if id, ok := canonicalID(strings.ReplaceAll(key, " ", "-")); ok {
		return id, true
	}
	if m := debianShort.FindStringSubmatch(key); m != nil {
		return gnu(m[1], m[2], m[3] == "+")
	}
	if m := gnuFamily.FindStringSubmatch(key); m != nil {
		family := map[string]string{"affero general public": "agpl", "lesser general public": "lgpl", "library general public": "lgpl", "library or lesser general public": "lgpl", "general public": "gpl", "free documentation": "gfdl", "fdl": "gfdl"}[m[1]]
		if family == "" {
			family = m[1]
		}
		later := m[3] != "" && !strings.Contains(m[3], "only")
		return gnu(family, m[2], later)
	}
	if m := apacheFamily.FindStringSubmatch(key); m != nil {
		v := map[string]string{"1": "1.0", "1.0": "1.0", "1.1": "1.1", "2": "2.0", "2.0": "2.0"}[m[1]]
		if v != "" {
			return "Apache-" + v, true
		}
	}
	if m := mplFamily.FindStringSubmatch(key); m != nil {
		v := map[string]string{"1": "1.0", "1.0": "1.0", "1.1": "1.1", "2": "2.0", "2.0": "2.0"}[m[1]]
		if v != "" {
			return "MPL-" + v, true
		}
	}
	if m := ccFamily.FindStringSubmatch(key); m != nil {
		return canonicalID("CC-" + strings.ToUpper(m[1]) + "-" + m[2])
	}
	if m := ccLongFamily.FindStringSubmatch(key); m != nil {
		id := "CC-BY"
		if m[1] != "" {
			id += "-NC"
		}
		switch m[2] {
		case "sharealike":
			id += "-SA"
		case "noderivatives", "no derivatives":
			id += "-ND"
		}
		return canonicalID(id + "-" + m[3])
	}
	// "EPL 2.0", "AGPL 3.0" and similar: id and version separated by a space.
	if m := versionedSPDX.FindStringSubmatch(key); m != nil {
		for _, candidate := range []string{m[1] + "-" + m[2], m[1] + "-" + m[2] + ".0"} {
			if id, ok := canonicalID(candidate); ok {
				return id, true
			}
		}
	}
	return "", false
}

// gnu builds a GNU licence id from family, version and "or later".
func gnu(family, version string, later bool) (string, bool) {
	family = strings.ToUpper(family)
	if family == "FDL" {
		family = "GFDL"
	}
	if !strings.Contains(version, ".") {
		version += ".0"
	}
	suffix := "-only"
	if later {
		suffix = "-or-later"
	}
	return canonicalID(family + "-" + version + suffix)
}

// exceptionAlias maps "Classpath", "GCC runtime library" and similar to an
// SPDX exception id, choosing the variant that fits the base licence.
func exceptionAlias(text, base string) (string, bool) {
	key := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(text), "exception")))
	if e, ok := exceptions[strings.ToLower(strings.TrimSpace(text))]; ok {
		return e, true
	}
	v3 := strings.HasPrefix(base, "GPL-3") || strings.HasPrefix(base, "LGPL-3")
	switch {
	case strings.Contains(key, "classpath"):
		return "Classpath-exception-2.0", true
	case strings.Contains(key, "gcc") || strings.Contains(key, "runtime library"):
		if v3 {
			return "GCC-exception-3.1", true
		}
		return "GCC-exception-2.0", true
	case strings.Contains(key, "autoconf"):
		if v3 {
			return "Autoconf-exception-3.0", true
		}
		return "Autoconf-exception-2.0", true
	case strings.Contains(key, "bison"):
		return "Bison-exception-2.2", true
	case strings.Contains(key, "font"):
		return "Font-exception-2.0", true
	case strings.Contains(key, "llvm"):
		return "LLVM-exception", true
	case strings.Contains(key, "openssl") && strings.Contains(key, "openvpn"):
		return "openvpn-openssl-exception", true
	case strings.Contains(key, "syscall"):
		return "Linux-syscall-note", true
	}
	return "", false
}
