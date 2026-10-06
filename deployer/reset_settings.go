package main

import (
	"errors"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Additional reset settings are explicit values. In particular an empty lookup
// selects the packaged source and must not be mistaken for a missing key.
func explicitResetSettings(req resetServerRequest) (map[string]string, error) {
	values := make(map[string]string)
	if req.ServerName != nil {
		name := *req.ServerName
		if name == "" || strings.TrimSpace(name) != name || utf8.RuneCountInString(name) > 100 || strings.IndexFunc(name, unicode.IsControl) >= 0 {
			return nil, errors.New("reset server name is invalid")
		}
		values["SERVER_NAME"] = name
	}
	if req.MaxGeneral != nil {
		if *req.MaxGeneral < 1 || *req.MaxGeneral > 9999 {
			return nil, errors.New("reset maxGeneral must be an integer from 1 to 9999")
		}
		values["RESET_MAXGENERAL"] = strconv.Itoa(*req.MaxGeneral)
	}
	if req.FirstTurn != nil {
		if *req.FirstTurn != "immediate" && *req.FirstTurn != "scheduled" {
			return nil, errors.New("reset firstTurn must be immediate or scheduled")
		}
		values["RESET_FIRST_TURN"] = *req.FirstTurn
	}
	if req.ScenarioLookupDir != nil {
		if *req.ScenarioLookupDir != "" && *req.ScenarioLookupDir != "/data/scenarios" {
			return nil, errors.New("reset scenario lookup must be empty or /data/scenarios")
		}
		values["SCENARIO_LOOKUP_DIR"] = *req.ScenarioLookupDir
	}
	return values, nil
}

func validateExplicitResetTargetSettings(values map[string]string) error {
	var req resetServerRequest
	if name, exists := values["SERVER_NAME"]; exists {
		req.ServerName = &name
	}
	if text, exists := values["RESET_MAXGENERAL"]; exists {
		if text == "" || strings.IndexFunc(text, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
			return errors.New("reset maxGeneral is invalid")
		}
		value, err := strconv.Atoi(text)
		if err != nil {
			return errors.New("reset maxGeneral is invalid")
		}
		req.MaxGeneral = &value
	}
	if policy, exists := values["RESET_FIRST_TURN"]; exists {
		req.FirstTurn = &policy
	}
	if lookup, exists := values["SCENARIO_LOOKUP_DIR"]; exists {
		req.ScenarioLookupDir = &lookup
	}
	_, err := explicitResetSettings(req)
	return err
}
