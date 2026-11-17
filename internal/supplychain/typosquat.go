// Package supplychain holds package-name heuristics that need no network
// (MAL-006): typosquat detection against a list of popular packages.
//
// The list is a curated seed, not a ranking, and the heuristic is one edit or
// one separator away from a listed name. It informs a reviewer; it cannot
// tell a typosquat from a legitimate neighbour such as a real `color` next
// to `colors`, so its findings are never gating.
package supplychain

import "strings"

// popularNPM and popularPyPI are well-known package names, lowercase and
// normalised the way the registries compare them.
var popularNPM = strings.Fields(`
react react-dom lodash lodash-es express axios moment chalk commander debug request async underscore bluebird uuid webpack
typescript vue jquery next eslint prettier jest mocha core-js rxjs tslib classnames prop-types redux react-redux react-router
react-router-dom body-parser cors dotenv mongoose mysql sequelize socket.io yargs minimist glob rimraf mkdirp fs-extra semver
inquirer ora colors cheerio puppeteer jsonwebtoken bcrypt bcryptjs passport nodemon gulp grunt handlebars ejs pug marked
markdown-it highlight.js chart.js leaflet node-fetch superagent cross-env concurrently husky lint-staged rollup vite esbuild
postcss autoprefixer sass tailwindcss styled-components ramda immutable date-fns dayjs validator joi yup zod ajv formik graphql
express-session cookie-parser helmet morgan multer compression request-promise form-data mime mime-types iconv-lite safe-buffer
inherits readable-stream through2 event-stream left-pad core-util-is chokidar archiver adm-zip xml2js js-yaml yaml uglify-js
terser coffee-script angular backbone svelte preact mongodb redis ioredis kafkajs winston pino bunyan nodemailer sharp jimp
shelljs execa cross-spawn which open opn tmp temp rxjs-compat webpack-cli webpack-dev-server babel-loader css-loader
style-loader file-loader ts-node ts-jest supertest chai sinon karma jasmine enzyme cypress playwright
`)

var popularPyPI = strings.Fields(`
requests numpy pandas django flask scipy matplotlib tensorflow torch boto3 botocore urllib3 setuptools pip wheel six pyyaml
pytest sqlalchemy jinja2 markupsafe werkzeug click certifi idna chardet charset-normalizer cryptography pillow lxml
beautifulsoup4 scikit-learn keras pydantic fastapi uvicorn gunicorn celery redis psycopg2 pymysql pymongo httpx aiohttp attrs
typing-extensions python-dateutil pytz tqdm rich colorama docutils pygments packaging pyparsing cffi pycparser protobuf grpcio
awscli paramiko pyjwt oauthlib requests-oauthlib openpyxl xlrd seaborn plotly nltk spacy opencv-python selenium scrapy tornado
twisted gevent pycodestyle flake8 black isort mypy pylint coverage tox virtualenv poetry jsonschema simplejson ujson toml
decorator mock nose wrapt regex sympy networkx h5py numba dask xgboost lightgbm transformers openai langchain
`)

var (
	npmSet  = toSet(popularNPM)
	pypiSet = toSet(popularPyPI)
)

func toSet(names []string) map[string]bool {
	out := make(map[string]bool, len(names))
	for _, n := range names {
		out[n] = true
	}
	return out
}

// Normalize returns the registry-comparable form of a package name for an
// ecosystem (PyPI folds case and treats `_` and `.` as `-`), and the list and
// set of popular names to compare against; ok is false for ecosystems the
// heuristic does not cover.
func normalize(ecosystem, name string) (n string, list []string, set map[string]bool, ok bool) {
	base, _, _ := strings.Cut(ecosystem, ":")
	n = strings.ToLower(name)
	switch base {
	case "npm":
		if strings.HasPrefix(n, "@") {
			return "", nil, nil, false // scoped names are owned by their scope
		}
		return n, popularNPM, npmSet, true
	case "PyPI":
		return strings.NewReplacer("_", "-", ".", "-").Replace(n), popularPyPI, pypiSet, true
	}
	return "", nil, nil, false
}

// Lookalike reports a popular package that name resembles without being it:
// the same name once `-`, `_` and `.` are dropped, or one edit away (an
// insertion, deletion, substitution or swap of neighbouring letters). Names
// of fewer than five characters are never compared; they are too close to
// everything.
func Lookalike(ecosystem, name string) (popular string, ok bool) {
	n, list, set, covered := normalize(ecosystem, name)
	if !covered || len(n) < 5 || set[n] {
		return "", false
	}
	bare := stripSeparators(n)
	for _, p := range list {
		if len(p) < 5 {
			continue
		}
		if stripSeparators(p) == bare {
			return p, true
		}
		if d := len(n) - len(p); d >= -1 && d <= 1 && distanceIsOne(n, p) {
			return p, true
		}
	}
	return "", false
}

func stripSeparators(s string) string {
	return strings.NewReplacer("-", "", "_", "", ".", "").Replace(s)
}

// distanceIsOne reports whether a and b differ by exactly one edit: one
// insertion, deletion or substitution, or one swap of adjacent letters.
func distanceIsOne(a, b string) bool {
	if a == b {
		return false
	}
	if len(a) > len(b) {
		a, b = b, a
	}
	i := 0
	for i < len(a) && a[i] == b[i] {
		i++
	}
	switch len(b) - len(a) {
	case 0:
		if a[i+1:] == b[i+1:] {
			return true // substitution
		}
		return i+1 < len(a) && a[i] == b[i+1] && a[i+1] == b[i] && a[i+2:] == b[i+2:] // adjacent swap
	case 1:
		return a[i:] == b[i+1:] // insertion in b
	}
	return false
}
