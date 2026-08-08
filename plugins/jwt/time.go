package jwt

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var timeStringPattern = regexp.MustCompile(`(?i)^(\+|\-)? ?(\d+|\d+\.\d+) ?(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|months?|mo|years?|yrs?|y)(?: (ago|from now))?$`)

// ToExpJWT implements single-auth's number | Date | TimeString conversion.
func ToExpJWT(expiration any, issuedAt float64) (float64, error) {
	switch value := expiration.(type) {
	case int:
		return float64(value), nil
	case int8:
		return float64(value), nil
	case int16:
		return float64(value), nil
	case int32:
		return float64(value), nil
	case int64:
		return float64(value), nil
	case uint:
		return float64(value), nil
	case uint8:
		return float64(value), nil
	case uint16:
		return float64(value), nil
	case uint32:
		return float64(value), nil
	case uint64:
		return float64(value), nil
	case float32:
		return float64(value), nil
	case float64:
		return value, nil
	case time.Time:
		return math.Floor(float64(value.UnixMilli()) / 1000), nil
	case *time.Time:
		if value == nil {
			return 0, invalidTimeString("")
		}
		return math.Floor(float64(value.UnixMilli()) / 1000), nil
	case string:
		seconds, err := parseTimeSeconds(value)
		if err != nil {
			return 0, err
		}
		return issuedAt + seconds, nil
	case nil:
		return 0, invalidTimeString("")
	default:
		return 0, fmt.Errorf("jwt: unsupported expiration type %T", expiration)
	}
}

func parseTimeSeconds(value string) (float64, error) {
	match := timeStringPattern.FindStringSubmatch(value)
	if match == nil || (match[4] != "" && match[1] != "") {
		return 0, invalidTimeString(value)
	}
	number, err := strconv.ParseFloat(match[2], 64)
	if err != nil {
		return 0, invalidTimeString(value)
	}
	var milliseconds float64
	switch strings.ToLower(match[3]) {
	case "years", "year", "yrs", "yr", "y":
		milliseconds = number * 365.25 * 24 * 60 * 60 * 1000
	case "months", "month", "mo":
		milliseconds = number * 30 * 24 * 60 * 60 * 1000
	case "weeks", "week", "w":
		milliseconds = number * 7 * 24 * 60 * 60 * 1000
	case "days", "day", "d":
		milliseconds = number * 24 * 60 * 60 * 1000
	case "hours", "hour", "hrs", "hr", "h":
		milliseconds = number * 60 * 60 * 1000
	case "minutes", "minute", "mins", "min", "m":
		milliseconds = number * 60 * 1000
	case "seconds", "second", "secs", "sec", "s":
		milliseconds = number * 1000
	default:
		return 0, invalidTimeString(value)
	}
	if match[1] == "-" || strings.EqualFold(match[4], "ago") {
		milliseconds = -milliseconds
	}
	// JavaScript Math.round(x) is floor(x+0.5), unlike Go's math.Round which
	// rounds negative half values away from zero.
	return math.Floor(milliseconds/1000 + 0.5), nil
}

func invalidTimeString(value string) error {
	return fmt.Errorf(`Invalid time string format: "%s". Use formats like "7d", "30m", "1 hour", etc.`, value)
}
