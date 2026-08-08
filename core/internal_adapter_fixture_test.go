package core

import "testing"

type internalAdapterFixture struct {
	Version  string
	Fixtures internalAdapterValues
}

type internalAdapterValues struct {
	ActiveSessionsPrefix     string
	VerificationPrefix       string
	NonAtomicWarningIncludes string
	TTLSeconds               []internalAdapterTTLCase
	HashedIdentifier         internalAdapterHashCase
	ReservationID            internalAdapterReservationCase
}

type internalAdapterTTLCase struct {
	Milliseconds int64
	Seconds      int64
}

type internalAdapterHashCase struct {
	Input  string
	Stored string
}

type internalAdapterReservationCase struct {
	Identifier string
	ID         string
}

func loadInternalAdapterFixture(*testing.T) internalAdapterFixture {
	return internalAdapterFixture{
		Version: "1.6.26",
		Fixtures: internalAdapterValues{
			ActiveSessionsPrefix:     "active-sessions-",
			VerificationPrefix:       "verification:",
			NonAtomicWarningIncludes: "getAndDelete",
			TTLSeconds: []internalAdapterTTLCase{
				{Milliseconds: 3_599_500, Seconds: 3_599},
				{Milliseconds: 500, Seconds: 0},
				{Milliseconds: 7_199_999, Seconds: 7_199},
			},
			HashedIdentifier: internalAdapterHashCase{
				Input:  "reset-password:my-token-123",
				Stored: "9h1R6RWKumpn0VWtY6hCVYxSgnuvt2X1th9uYrQIw18",
			},
			ReservationID: internalAdapterReservationCase{
				Identifier: "reserve:fresh",
				ID:         "Cil7sa_jy31laKIsf7Vdsa5ny8SwODEqfTNbVner3wA",
			},
		},
	}
}

func TestInternalAdapterFixtureMatchesRuntime(t *testing.T) {
	fixture := loadInternalAdapterFixture(t)
	if fixture.Version != "1.6.26" {
		t.Fatalf("fixture version = %q", fixture.Version)
	}
	if fixture.Fixtures.ActiveSessionsPrefix != activeSessionsPrefix ||
		fixture.Fixtures.VerificationPrefix != verificationPrefix {
		t.Fatalf("secondary prefixes=%q/%q", activeSessionsPrefix, verificationPrefix)
	}
	for _, ttl := range fixture.Fixtures.TTLSeconds {
		if got := secondaryTTL(
			internalAdapterEpoch.Add(durationMilliseconds(ttl.Milliseconds)),
			internalAdapterEpoch,
		); got != ttl.Seconds {
			t.Fatalf("secondaryTTL(%dms)=%d, want %d", ttl.Milliseconds, got, ttl.Seconds)
		}
	}
}
