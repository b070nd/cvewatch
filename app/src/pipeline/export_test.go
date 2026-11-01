package pipeline

import "time"

func SetHeartbeat(d time.Duration) (restore func()) {
	old := heartbeat
	heartbeat = d
	return func() { heartbeat = old }
}
