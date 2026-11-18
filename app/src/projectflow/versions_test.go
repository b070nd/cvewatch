package projectflow

import "testing"

func TestSameSeriesIsAReleaseOfTheOther(t *testing.T) {
	for _, c := range []struct {
		a, b string
		same bool
	}{
		{"8.2", "8.2.35", true}, {"8.2.35", "8.2", true}, {"8.2", "8.2", true},
		{"8.2", "8.3", false}, {"8.2", "8.20", false}, {"8.1", "8.2.35", false},
	} {
		if got := sameSeries(c.a, c.b); got != c.same {
			t.Errorf("sameSeries(%s, %s) = %v", c.a, c.b, got)
		}
	}
}
