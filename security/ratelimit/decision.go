package ratelimit

import "time"

type consumeDecision struct {
	next       Record
	update     bool
	allowed    bool
	retryAfter *int64
}

func decideConsume(data *Record, rule Rule, now int64) consumeDecision {
	windowMillis := secondsToMillis(rule.Window)
	if data == nil {
		return consumeDecision{
			next:    Record{Count: 1, LastRequest: now},
			allowed: true,
		}
	}
	if now-data.LastRequest > windowMillis {
		return consumeDecision{
			next:    Record{Key: data.Key, Count: 1, LastRequest: now},
			update:  true,
			allowed: true,
		}
	}
	if data.Count >= rule.Max {
		retry := retryAfterAt(data.LastRequest, rule.Window, now)
		return consumeDecision{next: *data, update: true, retryAfter: &retry}
	}
	return consumeDecision{
		next: Record{
			Key:         data.Key,
			Count:       data.Count + 1,
			LastRequest: now,
		},
		update:  true,
		allowed: true,
	}
}

func retryAfterAt(lastRequest, windowSeconds, now int64) int64 {
	remaining := lastRequest + secondsToMillis(windowSeconds) - now
	// Math.ceil(milliseconds / 1000), including zero and negative values.
	if remaining >= 0 {
		return (remaining + 999) / 1000
	}
	return remaining / 1000
}

func secondsToMillis(seconds int64) int64 {
	// reference implementation uses JavaScript numbers. Saturating here prevents integer
	// overflow from turning a misconfigured long window into an expired one.
	const max = int64(^uint64(0) >> 1)
	const min = -max - 1
	if seconds > max/1000 {
		return max
	}
	if seconds < min/1000 {
		return min
	}
	return seconds * 1000
}

func unixMillis(now func() time.Time) int64 {
	if now == nil {
		return time.Now().UnixMilli()
	}
	return now().UnixMilli()
}
