package discovery

import (
	"path"
	"strings"

	"gopkg.in/yaml.v3"
)

// ddevConfig reads what a DDEV project runs: the PHP and Node.js versions, the
// database with its version and the web server.
func (s *scanner) ddevConfig(f *file) {
	if path.Base(path.Dir(f.rel)) != ".ddev" || !strings.HasPrefix(f.low, "config.") || !strings.HasSuffix(f.low, ".yaml") {
		return
	}
	var c struct {
		PHP      string `yaml:"php_version"`
		Node     string `yaml:"nodejs_version"`
		Webserve string `yaml:"webserver_type"`
		Database struct {
			Type    string `yaml:"type"`
			Version string `yaml:"version"`
		} `yaml:"database"`
	}
	if err := yaml.Unmarshal(f.bytes(), &c); err != nil {
		s.note("cannot read %s", f.rel)
		return
	}
	use := func(term, version, what string) {
		if t, ok := s.cat.ForTerm(term); ok {
			s.add(f, t, strings.TrimSpace(version), Medium, "DDEV "+what)
		}
	}
	if c.PHP != "" {
		use("php", c.PHP, "runs PHP "+c.PHP)
	}
	if c.Node != "" {
		use("nodejs", c.Node, "runs Node.js "+c.Node)
	}
	switch db := strings.ToLower(c.Database.Type); db {
	case "mysql", "mariadb":
		use(db, c.Database.Version, "runs "+db+" "+c.Database.Version)
	case "postgres", "postgresql":
		use("postgresql", c.Database.Version, "runs postgres "+c.Database.Version)
	}
	switch ws := strings.ToLower(c.Webserve); {
	case strings.HasPrefix(ws, "nginx"):
		use("nginx", "", "serves with "+ws)
	case strings.HasPrefix(ws, "apache"):
		use("apache-httpd", "", "serves with "+ws)
	}
}
