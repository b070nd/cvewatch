package confdoc

import (
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/b070nd/cvewatch/app/src/catalog"
	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/feeds"
	"github.com/b070nd/cvewatch/app/src/model"
)

// Type is how a setting is edited and checked.
type Type string

const (
	TypeDuration Type = "duration" // 30s, 4h; 0 where the setting allows it
	TypeInt      Type = "int"
	TypeFloat    Type = "float"
	TypeBool     Type = "bool"
	TypeEnum     Type = "enum"
	TypeString   Type = "string"
	TypeList     Type = "list"   // Elem says what an item is
	TypeMap      Type = "map"    // Elem says what a value is
	TypeRecord   Type = "record" // a mapping with known keys; only appears as an Elem
	TypeEnvRef   Type = "envref" // the name of an environment variable, never its value
)

// Document kinds, as used by Field.Doc and Document.Kind.
const (
	KindSettings = "config"  // config/config.yaml
	KindTechs    = "techs"   // config/techs.yaml
	KindSources  = "sources" // sources/*.yaml
)

// Field is one setting. Path is the dotted yaml path inside its document, with
// "*" standing for any list position or map key. A struct is not a field:
// only the values inside it are. A list or map of records is one field (the
// collection, with Key and Elem) plus one field per key of the record.
type Field struct {
	Path    string   `json:"path"`
	Doc     string   `json:"doc"`
	Section string   `json:"section"`
	Label   string   `json:"label"`
	Type    Type     `json:"type"`
	Elem    Type     `json:"elem,omitempty"`
	Enum    []string `json:"enum,omitempty"`
	Help    string   `json:"help,omitempty"`
	Secret  bool     `json:"secret,omitempty"` // its value is never shown; previews say "(set)"
	// Min and Max bound numbers; for durations they are seconds.
	Min     *float64 `json:"min,omitempty"`
	Max     *float64 `json:"max,omitempty"`
	Default string   `json:"default,omitempty"`
	Key     string   `json:"key,omitempty"` // for collections of records: the key that names an item
}

// Sections, in the order a front end lists them.
const (
	SecCore    = "Core"
	SecHTTP    = "HTTP"
	SecNotify  = "Notify"
	SecPolicy  = "Policy"
	SecSources = "Sources"
	SecTechs   = "Tech catalog"
	SecAccess  = "Access"
)

// Sections lists the section names in display order.
func Sections() []string {
	return []string{SecCore, SecHTTP, SecNotify, SecPolicy, SecSources, SecTechs, SecAccess}
}

func num(v float64) *float64 { return &v }

var (
	severities = []string{string(model.SevUnknown), string(model.SevLow), string(model.SevMedium), string(model.SevHigh), string(model.SevCritical)}
	channels   = []string{"slack", "webhook", "email"}
)

func fields() []Field {
	var fs []Field
	add := func(f Field) { fs = append(fs, f) }
	core := func(path, label string, t Type, help string) Field {
		return Field{Path: path, Doc: KindSettings, Section: SecCore, Label: label, Type: t, Help: help}
	}
	httpF := func(path, label string, t Type, help string) Field {
		return Field{Path: "http." + path, Doc: KindSettings, Section: SecHTTP, Label: label, Type: t, Help: help}
	}
	notify := func(path, label string, t Type, help string) Field {
		return Field{Path: path, Doc: KindSettings, Section: SecNotify, Label: label, Type: t, Help: help}
	}

	f := core("interval", "Interval", TypeDuration, "How often a project is refreshed unless its file says otherwise (update.every), and the longest the daemon sleeps before it looks at the configuration again.")
	f.Min = num(1)
	add(f)
	add(core("update.auto", "Scheduled updates", TypeBool, "Refresh projects by themselves, the daemon and the full-screen interface alike. Off, only update and the u key refresh. A project can opt out or pick its own period in its file (update.auto, update.every)."))
	add(core("lookback", "Lookback", TypeDuration, "How far back a source's first run reaches. A project's since date reaches further, once: after you set or move it, the next fetch goes back to that date."))
	add(core("retention", "Retention", TypeDuration, "Forget items that matched nothing after this long; 0 keeps them. At least twice the lookback. Until then a new tech or project can pick them up again (cvewatch revalidate)."))
	add(core("data_dir", "Data directory", TypeString, "Where state, the audit log and backups live; relative to the root folder."))
	add(core("alerts_dir", "Alerts directory", TypeString, "Where markdown reports and calendar pages are written; relative to the root folder."))
	add(core("enrich.epss", "EPSS lookups", TypeBool, "Ask FIRST's EPSS service about the CVEs you track. Reveals your stack to that service."))
	add(core("enrich.cvss", "CVSS lookups", TypeBool, "Rate tracked CVEs that no source gave a score, from NVD's public data (a few per cycle, no key needed). Only the CVE id is sent. Default on."))
	f = core("storage.backend", "Storage backend", TypeEnum, "Where state is kept.")
	f.Enum = []string{"file", "sqlite"}
	add(f)
	add(core("dashboard.enabled", "Dashboard", TypeBool, "Rewrite a static status page after every cycle."))
	add(core("dashboard.file", "Dashboard file", TypeString, "Default: dashboard.html inside the alerts directory."))
	f = core("tui.refresh", "TUI refresh", TypeDuration, "How often the full-screen interface re-reads the state. At least 1s.")
	f.Min = num(1)
	add(f)
	f = core("tui.fetch", "TUI fetch", TypeDuration, "A fixed period at which the full-screen interface fetches the feeds for every project, whatever the project schedule says. 0 leaves it to tui.auto.")
	f.Min = num(0)
	add(f)
	add(core("tui.auto", "TUI auto update", TypeBool, "When no daemon is running, the full-screen interface refreshes on the project schedule (each project's update.every, else the interval). With a daemon it never fetches by itself. Needs update.auto."))
	add(core("tui.editor", "TUI editor", TypeString, "The editor the E key opens files in, with its options, such as code --wait. Empty uses $VISUAL, then $EDITOR, then the first of the usual editors found on this machine."))
	f = core("horizon.window", "Alert horizon", TypeEnum, "Only vulnerabilities published inside this window are judged, alerted and digested; findings that exist stay. unlimited is any time; custom uses from and to. Sources are fetched back to the lookback on a first run, so keep the lookback at least as long.")
	f.Enum = config.Windows
	add(f)
	add(core("horizon.from", "Horizon from", TypeString, "Custom window only: YYYY-MM-DD or RFC3339. Empty means no start."))
	add(core("horizon.to", "Horizon to", TypeString, "Custom window only: YYYY-MM-DD (that whole day) or RFC3339. Empty means no end."))

	add(httpF("user_agent", "User agent", TypeString, "Sent with every request."))
	add(httpF("timeout", "Timeout", TypeDuration, "Per request."))
	f = httpF("retries", "Retries", TypeInt, "Extra attempts after a failed request.")
	f.Min = num(0)
	add(f)
	f = httpF("retry_delay", "Retry delay", TypeDuration, "Wait before a retry.")
	f.Min = num(0)
	add(f)
	f = httpF("rate", "Rate", TypeFloat, "Requests per second, per host.")
	f.Min = num(0)
	add(f)
	f = httpF("host_rates", "Host rates", TypeMap, "Stricter or looser requests per second for single hosts.")
	f.Elem, f.Min = TypeFloat, num(0)
	add(f)
	f = httpF("max_body", "Max body", TypeInt, "Largest response accepted, in bytes.")
	f.Min = num(1)
	add(f)
	f = httpF("threshold_429", "429 threshold", TypeInt, "Consecutive 429 answers before a host cools down.")
	f.Min = num(1)
	add(f)
	add(httpF("cooldown_429", "429 cooldown", TypeDuration, "How long a host is left alone after repeated 429 answers."))
	add(httpF("allow_private", "Allow private", TypeBool, "Permit http:// and internal addresses, such as an internal feed or proxy."))

	add(notify("slack.webhook_env", "Slack webhook variable", TypeEnvRef, "Name of the environment variable holding the Slack webhook URL."))
	f = notify("slack.min_severity", "Slack minimum severity", TypeEnum, "")
	f.Enum = severities
	add(f)
	add(notify("notify.webhook.url_env", "Webhook URL variable", TypeEnvRef, "Name of the environment variable holding the https URL."))
	add(notify("notify.webhook.secret_env", "Webhook secret variable", TypeEnvRef, "Name of the environment variable holding the HMAC secret; optional."))
	f = notify("notify.webhook.min_severity", "Webhook minimum severity", TypeEnum, "")
	f.Enum = severities
	add(f)
	add(notify("notify.webhook.allow_private", "Webhook allow private", TypeBool, "Internal receivers over http."))
	add(notify("notify.email.host", "Email host", TypeString, "SMTP host; empty disables email."))
	f = notify("notify.email.port", "Email port", TypeInt, "Default 587.")
	f.Min, f.Max = num(1), num(65535)
	add(f)
	add(notify("notify.email.from", "Email from", TypeString, ""))
	f = notify("notify.email.to", "Email to", TypeList, "Recipients.")
	f.Elem = TypeString
	add(f)
	add(notify("notify.email.username_env", "Email user variable", TypeEnvRef, "Name of the environment variable holding the SMTP user."))
	add(notify("notify.email.password_env", "Email password variable", TypeEnvRef, "Name of the environment variable holding the SMTP password."))
	f = notify("notify.email.min_severity", "Email minimum severity", TypeEnum, "")
	f.Enum = severities
	add(f)
	add(notify("notify.digest.daily_at", "Digest time", TypeString, "Local time like 08:00; empty disables the digest."))
	add(notify("notify.digest.env", "Digest environment", TypeString, "Only findings in this environment (any name, such as prod); empty means all."))
	f = notify("notify.digest.channels", "Digest channels", TypeList, "Empty means every active channel.")
	f.Elem, f.Enum = TypeEnum, channels
	add(f)
	f = notify("notify.digest.max", "Digest size", TypeInt, "Items listed; default 20.")
	f.Min = num(0)
	add(f)

	pol := func(path, label string, t Type, help string) Field {
		return Field{Path: path, Doc: KindSettings, Section: SecPolicy, Label: label, Type: t, Help: help}
	}
	f = pol("policy.rules", "Rules", TypeList, "Deadlines that `cvewatch policy` checks.")
	f.Elem, f.Key = TypeRecord, "name"
	add(f)
	add(pol("policy.rules.*.name", "Name", TypeString, ""))
	add(pol("policy.rules.*.env", "Environment", TypeString, "Any environment name, such as prod. Empty means every environment."))
	add(pol("policy.rules.*.kev", "KEV only", TypeBool, "Only issues on the CISA KEV list."))
	f = pol("policy.rules.*.min_severity", "Minimum severity", TypeEnum, "")
	f.Enum = severities
	add(f)
	add(pol("policy.rules.*.owner_within", "Owner within", TypeDuration, "An owner must be set this long after detection."))
	add(pol("policy.rules.*.fix_within", "Fix within", TypeDuration, "The finding must be closed this long after detection."))

	f = Field{Path: "access", Doc: KindSettings, Section: SecAccess, Label: "Access rules", Type: TypeMap, Elem: TypeRecord, Key: "",
		Help: "Who may see and change which projects, by actor name. Empty means everyone may do everything. Authorization on a local identity, not authentication."}
	add(f)
	f = Field{Path: "access.*.projects", Doc: KindSettings, Section: SecAccess, Label: "Projects", Type: TypeList, Elem: TypeString, Help: `Project names; vendor:NAME means every project of that vendor, also one added later; "*" means every project.`}
	add(f)
	add(Field{Path: "access.*.write", Doc: KindSettings, Section: SecAccess, Label: "Write", Type: TypeBool, Help: "May change what the projects hold."})

	sourceFields(&fs, "sources", KindSources, SecSources)

	tech := func(path, label string, t Type, help string) Field {
		return Field{Path: "techs.*." + path, Doc: KindTechs, Section: SecTechs, Label: label, Type: t, Help: help}
	}
	list := func(f Field) Field { f.Elem = TypeString; return f }
	add(Field{Path: "techs", Doc: KindTechs, Section: SecTechs, Label: "Technologies", Type: TypeList, Elem: TypeRecord, Key: "name",
		Help: "Your additions to the built-in catalog. An entry with a shipped name replaces it; disabled removes it."})
	add(tech("name", "Name", TypeString, "Short key used in project files."))
	add(list(tech("aliases", "Aliases", TypeList, "Words advisories use for it; the name is used when none are given.")))
	add(list(tech("excludes", "Excludes", TypeList, "An item containing any of these is not about this technology.")))
	add(list(tech("cpe", "CPE names", TypeList, "vendor:product, lowercase, as in NVD's CPE data.")))
	add(tech("title", "Title", TypeString, "Display name."))
	f = tech("category", "Category", TypeEnum, "")
	f.Enum = catalog.Categories
	add(f)
	add(tech("vendor", "Vendor", TypeString, ""))
	f = tech("source", "Source", TypeEnum, "")
	f.Enum = catalog.Sources
	add(f)
	f = tech("scheme", "Version scheme", TypeEnum, "Version ordering; empty means dotted numbers.")
	f.Enum = []string{"pypi", "maven", "go"}
	add(f)
	add(list(tech("detect.files", "Marker files", TypeList, "File names that show it in a repository.")))
	add(list(tech("detect.images", "Images", TypeList, "Container image names without registry or tag.")))
	f = tech("detect.packages", "Packages", TypeList, "Lockfile packages that imply it.")
	f.Elem = TypeRecord
	add(f)
	add(tech("detect.packages.*.ecosystem", "Ecosystem", TypeString, ""))
	add(tech("detect.packages.*.name", "Package", TypeString, ""))
	f = tech("detect.versions", "Version hints", TypeList, "Where its version can be read.")
	f.Elem = TypeRecord
	add(f)
	add(tech("detect.versions.*.file", "File", TypeString, "Base name, such as .nvmrc."))
	add(tech("detect.versions.*.pattern", "Pattern", TypeString, "Regular expression with one capture group holding the version."))
	f = tech("feeds", "Feeds", TypeList, "Vendor advisory feeds that switch on with the technology.")
	f.Elem, f.Key = TypeRecord, "id"
	add(f)
	sourceFields(&fs, "techs.*.feeds", KindTechs, SecTechs)
	add(tech("disabled", "Disabled", TypeBool, "Drops the shipped entry of this name."))
	return fs
}

// sourceFields adds the fields of a feed list at prefix. The collection row
// itself is added by the caller for techs and here for the sources document.
func sourceFields(fs *[]Field, prefix, doc, section string) {
	row := func(path, label string, t Type, help string) Field {
		return Field{Path: prefix + ".*." + path, Doc: doc, Section: section, Label: label, Type: t, Help: help}
	}
	if prefix == "sources" {
		*fs = append(*fs, Field{Path: "sources", Doc: doc, Section: section, Label: "Feeds", Type: TypeList, Elem: TypeRecord, Key: "id",
			Help: "Your own feeds, added to the shipped ones. A feed with a shipped id replaces it."})
	}
	*fs = append(*fs, row("id", "Id", TypeString, "Unique; the same id as an existing feed changes only the fields given here."))
	t := row("type", "Type", TypeEnum, "")
	t.Enum = feeds.Types()
	u := row("url", "URL", TypeString, "May contain {since}, {since_unix}, {since_date}, {now}. Never put credentials in it.")
	u.Secret = true
	h := row("headers", "Headers", TypeMap, "Request headers, such as an API key. Values are never shown.")
	h.Elem, h.Secret = TypeString, true
	a := row("auth_env", "Token variable", TypeEnvRef, "Name of the environment variable holding a token, sent as a Bearer Authorization header. Unset or empty sends nothing. The value is never shown.")
	*fs = append(*fs, t, u, h, a,
		row("disabled", "Disabled", TypeBool, "Keep the entry but do not poll it."),
		row("match_title_only", "Match title only", TypeBool, "Match technologies on the title only; for firehoses like NVD."),
		row("match_structured", "Match structured", TypeBool, "A technology with CPE names matches only on the feed's product data."))
}

var (
	schemaOnce sync.Once
	schema     []Field
)

// Schema lists every setting of config.yaml, techs.yaml and sources/*.yaml, in
// display order. It is the one place a new setting is declared; a test fails
// when a key of config.Settings, model.Tech or model.Source is missing here.
func Schema() []Field {
	return slices.Clone(fieldList())
}

func fieldList() []Field {
	schemaOnce.Do(func() {
		schema = fields()
		d := reflect.ValueOf(config.Defaults())
		for i := range schema {
			if schema[i].Doc == KindSettings {
				schema[i].Default = defaultAt(d, strings.Split(schema[i].Path, "."))
			}
		}
	})
	return schema
}

// Lookup finds the field a concrete path belongs to. List items are written by
// position (rules.0) or by key (rules.[name=slow]); both match "*".
func Lookup(doc, path string) (Field, bool) {
	segs, err := ParsePath(path)
	if err != nil {
		return Field{}, false
	}
	return lookup(doc, segs)
}

func lookup(doc string, segs []string) (Field, bool) {
	for _, f := range fieldList() {
		if f.Doc == doc && matches(strings.Split(f.Path, "."), segs) {
			return f, true
		}
	}
	return Field{}, false
}

func matches(pattern, segs []string) bool {
	if len(pattern) != len(segs) {
		return false
	}
	for i, p := range pattern {
		if p != "*" && p != segs[i] {
			return false
		}
	}
	return true
}

// childOrder is the position of a record's keys, for writing them in the
// order the schema lists them.
func childOrder(doc, record string) map[string]int {
	out := map[string]int{}
	prefix := record + "."
	for i, f := range fieldList() {
		if f.Doc == doc && strings.HasPrefix(f.Path, prefix) && !strings.Contains(f.Path[len(prefix):], ".") {
			out[f.Path[len(prefix):]] = i
		}
	}
	return out
}

// defaultAt formats the default value found by walking yaml tags; empty when
// the path does not end at a plain value or the default is the zero value.
func defaultAt(v reflect.Value, segs []string) string {
	for _, seg := range segs {
		if v.Kind() != reflect.Struct {
			return ""
		}
		found := false
		for i := 0; i < v.NumField(); i++ {
			if tag := yamlName(v.Type().Field(i)); tag == seg {
				v, found = v.Field(i), true
				break
			}
		}
		if !found {
			return ""
		}
	}
	if v.IsZero() {
		return ""
	}
	switch x := v.Interface().(type) {
	case time.Duration:
		return formatDuration(x)
	case map[string]float64:
		var parts []string
		for _, k := range sortedKeys(x) {
			parts = append(parts, fmt.Sprintf("%s=%g", k, x[k]))
		}
		return strings.Join(parts, ", ")
	}
	switch v.Kind() {
	case reflect.String, reflect.Bool, reflect.Int, reflect.Int64, reflect.Float64:
		return fmt.Sprint(v.Interface())
	}
	return ""
}

func yamlName(f reflect.StructField) string {
	name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
	return name
}

// formatDuration writes 4h0m0s as 4h and 2m0s as 2m.
func formatDuration(d time.Duration) string {
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = s[:len(s)-2]
	}
	if strings.HasSuffix(s, "h0m") {
		s = s[:len(s)-2]
	}
	return s
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
