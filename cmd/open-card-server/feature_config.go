package main

import "errors"

func validateFeatureHierarchy(database, m1, m2, m3, m4, m4Rollout, m5, m6 bool) error {
	if m1 && !database {
		return errors.New("M1 requires PostgreSQL")
	}
	if m2 && (!database || !m1) {
		return errors.New("M2 requires PostgreSQL and M1")
	}
	if m3 && (!database || !m1 || !m2) {
		return errors.New("M3 requires PostgreSQL, M1, and M2")
	}
	if m4 && (!database || !m1 || !m2) {
		return errors.New("M4 requires PostgreSQL, M1, and M2")
	}
	if m4Rollout && (!m4 || !m3) {
		return errors.New("M4 rollout requires M4 and M3 RouteProvider")
	}
	if m5 && (!database || !m4) {
		return errors.New("M5 requires PostgreSQL and M4 observations")
	}
	if m6 && (!database || !m4 || !m5) {
		return errors.New("M6 requires PostgreSQL, M4 observations, and M5 usage aggregates")
	}
	return nil
}
