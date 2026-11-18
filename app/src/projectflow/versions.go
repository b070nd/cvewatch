package projectflow

import (
	"strings"

	"github.com/b070nd/cvewatch/app/src/discovery"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/ops"
)

// VersionDiff is a technology a scan found at another version than the
// project declares, with the environments the project runs in.
type VersionDiff struct {
	Tech, Found, Have string
	Envs              []model.Env
}

// VersionDiffs scans the folder or file at path and lists the declared
// technologies it finds at another version: not the same release series,
// and not on low confidence. A path that does not scan gives none.
func VersionDiffs(s *ops.Session, project, path string) []VersionDiff {
	src, err := ResolveSource(path)
	if err != nil {
		return nil
	}
	res, err := ScanSourceWith(src, s.Catalog(), discovery.Options{IncludeIgnored: src.IsFile()})
	if err != nil {
		return nil
	}
	var out []VersionDiff
	for _, p := range s.Cfg.Projects {
		if p.Name != project {
			continue
		}
		for _, t := range p.Techs {
			for _, f := range res.Techs {
				if strings.EqualFold(f.Tech, t.Name) && f.Version != "" && t.Version != "" && f.Confidence != discovery.Low && !sameSeries(f.Version, t.Version) {
					out = append(out, VersionDiff{Tech: t.Name, Found: f.Version, Have: t.Version, Envs: p.EffectiveEnvs()})
				}
			}
		}
	}
	return out
}

// sameSeries reports whether one version is the other or a release of it (8.2 and 8.2.35).
func sameSeries(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+".") || strings.HasPrefix(b, a+".")
}
