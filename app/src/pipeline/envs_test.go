package pipeline

import (
	"testing"

	"github.com/b070nd/cvewatch/app/src/model"
)

func TestHasProdAcceptsProductionNames(t *testing.T) {
	for env, want := range map[model.Env]bool{"prod": true, "production": true, "local": false, "qa": false} {
		if got := hasProd([]model.Finding{{Env: model.EnvDev}, {Env: env}}); got != want {
			t.Errorf("hasProd(%s) = %v, want %v", env, got, want)
		}
	}
}
