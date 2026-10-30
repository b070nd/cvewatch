package ops

import (
	"log/slog"

	"github.com/b070nd/cvewatch/app/src/config"
)

func OpenRepair(root string, log *slog.Logger) (*Session, error) {
	return openLoaded(root, log, config.LoadLenient)
}

func OpenReadOnlyRepair(root string, log *slog.Logger) (*Session, error) {
	return openReadOnlyLoaded(root, log, config.LoadLenient)
}
