package model

import "testing"

func TestRatingPrecedence(t *testing.T) {
	r := func(score float64, version, source string) Rating {
		return Rating{Score: score, Version: version, Source: source}
	}
	cases := []struct {
		name       string
		cand, have Rating
		replaces   bool
		bestOfBoth Rating
	}{
		{"anything beats nothing", r(3, "", ScoreText), Rating{}, true, r(3, "", ScoreText)},
		{"newer version in the same group", r(9.3, CVSS40, ScoreNVD), r(9.8, CVSS31, ScoreNVD), true, r(9.3, CVSS40, ScoreNVD)},
		{"3.1 over 3.0", r(9.8, CVSS31, ScoreCNA), r(9.1, CVSS30, ScoreCNA), true, r(9.8, CVSS31, ScoreCNA)},
		{"3.0 over 2.0", r(7.5, CVSS30, ScoreGHSA), r(7.5, CVSS20, ScoreGHSA), true, r(7.5, CVSS30, ScoreGHSA)},
		{"a known version over an unknown one", r(7, CVSS20, ScoreCSAF), r(7, "", ScoreCSAF), true, r(7, CVSS20, ScoreCSAF)},
		{"a secondary 4.0 never replaces a primary 3.1", r(9.3, CVSS40, ScoreNVDSecondary), r(9.8, CVSS31, ScoreNVD), false, r(9.8, CVSS31, ScoreNVD)},
		{"an ADP 4.0 never replaces the CNA's 2.0", r(9.3, CVSS40, ScoreADP), r(7.5, CVSS20, ScoreCNA), false, r(7.5, CVSS20, ScoreCNA)},
		{"a primary 2.0 replaces a secondary 4.0", r(7.5, CVSS20, ScoreNVD), r(9.3, CVSS40, ScoreADP), true, r(7.5, CVSS20, ScoreNVD)},
		{"text never replaces a feed score", r(10, CVSS40, ScoreText), r(4, CVSS20, ScoreNVDSecondary), false, r(4, CVSS20, ScoreNVDSecondary)},
		{"a feed score replaces text", r(4, CVSS20, ScoreNVDSecondary), r(10, CVSS40, ScoreText), true, r(4, CVSS20, ScoreNVDSecondary)},
		{"equal rank keeps the first", r(9.1, CVSS31, ScoreNVD), r(9.8, CVSS31, ScoreCNA), false, r(9.8, CVSS31, ScoreCNA)},
		{"data from before sources counts as secondary", r(7, CVSS31, ScoreNVD), r(9.8, "", ""), true, r(7, CVSS31, ScoreNVD)},
		{"an unusable score replaces nothing", r(0, CVSS40, ScoreNVD), r(2, CVSS20, ScoreText), false, r(2, CVSS20, ScoreText)},
		{"out of range is unusable", r(11, CVSS40, ScoreNVD), Rating{}, false, Rating{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.cand.Better(c.have); got != c.replaces {
				t.Errorf("Better = %v, want %v (ranks %d vs %d)", got, c.replaces, c.cand.Rank(), c.have.Rank())
			}
			if got := BestRating(c.have, c.cand); got != c.bestOfBoth {
				t.Errorf("BestRating = %+v, want %+v", got, c.bestOfBoth)
			}
		})
	}
}

func TestBestRatingTiesTakeTheHigherScore(t *testing.T) {
	a := Rating{Score: 6.5, Version: CVSS30, Source: ScoreCSAF}
	b := Rating{Score: 9.8, Version: CVSS30, Source: ScoreCSAF}
	if got := BestRating(a, b); got != b {
		t.Fatalf("got %+v", got)
	}
}

func TestSeverityOfScoreUsesTheScaleOfTheVersion(t *testing.T) {
	cases := []struct {
		version string
		score   float64
		want    Severity
	}{
		{CVSS20, 10, SevHigh}, {CVSS20, 9.0, SevHigh}, {CVSS20, 7.0, SevHigh}, {CVSS20, 6.9, SevMedium}, {CVSS20, 4.0, SevMedium}, {CVSS20, 3.9, SevLow}, {CVSS20, 0, SevUnknown},
		{CVSS30, 9.0, SevCritical}, {CVSS31, 9.8, SevCritical}, {CVSS31, 8.9, SevHigh}, {CVSS31, 6.9, SevMedium}, {CVSS31, 3.9, SevLow},
		{CVSS40, 9.3, SevCritical}, {CVSS40, 0.1, SevLow},
		{"", 9.8, SevCritical},
	}
	for _, c := range cases {
		if got := SeverityOfScore(c.version, c.score); got != c.want {
			t.Errorf("SeverityOfScore(%q, %v) = %v, want %v", c.version, c.score, got, c.want)
		}
	}
}

func TestNormVersionAndVectors(t *testing.T) {
	for in, want := range map[string]string{"3.1": CVSS31, "3": CVSS30, "v4.0": CVSS40, "4": CVSS40, "CVSS:3.0/AV:N": CVSS30, "2": CVSS20, "2.0": CVSS20, "5.0": "", "": "", "x": ""} {
		if got := NormVersion(in); got != want {
			t.Errorf("NormVersion(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": CVSS31, "CVSS:4.0/AV:N": CVSS40, "AV:N/AC:L/Au:N/C:P/I:P/A:P": CVSS20, "foo": ""} {
		if got := VectorVersion(in); got != want {
			t.Errorf("VectorVersion(%q) = %q, want %q", in, got, want)
		}
	}
	for _, ok := range []string{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "AV:N/AC:L/Au:N/C:P/I:P/A:P", "(AV:N/AC:L/Au:N/C:P/I:P/A:P)"} {
		if CleanVector(ok) == "" {
			t.Errorf("CleanVector(%q) rejected", ok)
		}
	}
	for _, bad := range []string{"", "CVSS:3.1/AV:N [x](http://e)", "AV:N\nAC:L", "javascript:alert(1)//", "CVSS:3.1/" + string(make([]byte, 400))} {
		if v := CleanVector(bad); v != "" {
			t.Errorf("CleanVector(%q) = %q, want empty", bad, v)
		}
	}
}

func TestUnratedCountsTextScoresAsUnrated(t *testing.T) {
	for _, c := range []struct {
		v    Vulnerability
		want bool
	}{
		{Vulnerability{}, true},
		{Vulnerability{CVSS: 9.8, CVSSSource: ScoreText}, true},
		{Vulnerability{CVSS: 9.8, CVSSSource: ScoreNVD}, false},
		{Vulnerability{CVSS: 5}, false}, // from before sources were recorded
	} {
		if got := c.v.Unrated(); got != c.want {
			t.Errorf("%+v: Unrated = %v", c.v, got)
		}
	}
}
