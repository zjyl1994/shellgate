package audit

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const maxScannedRecords = 100000

type Search struct {
	Mode          string `json:"mode"`
	Query         string `json:"query"`
	CaseSensitive bool   `json:"case_sensitive,omitempty"`
}

type Query struct {
	Hosts     []string `json:"hosts"`
	From      string   `json:"from,omitempty"`
	To        string   `json:"to,omitempty"`
	TimeRange string   `json:"time_range,omitempty"`
	Events    []string `json:"events,omitempty"`
	Search    *Search  `json:"search,omitempty"`
	Limit     int      `json:"limit,omitempty"`
	Cursor    string   `json:"cursor,omitempty"`
}

type QueryResult struct {
	Records        []map[string]any `json:"records"`
	NextCursor     string           `json:"next_cursor,omitempty"`
	Truncated      bool             `json:"truncated"`
	ScannedRecords int              `json:"scanned_records"`
	SkippedRecords int              `json:"skipped_records"`
	From           string           `json:"from"`
	To             string           `json:"to"`
}

type cursor struct {
	Filter string `json:"filter"`
	Date   string `json:"date"`
	Host   string `json:"host"`
	Offset int64  `json:"offset"`
	From   string `json:"from"`
	To     string `json:"to"`
}

// QueryLogs streams audit JSONL files in chronological date/host order. Hosts
// must already have been authorized by the caller; they are never paths.
func QueryLogs(dir string, q Query, cursorKey []byte) (QueryResult, error) {
	from, to, err := resolveTimeRange(q)
	if err != nil {
		return QueryResult{}, err
	}
	if to.Before(from) || to.Sub(from) > 31*24*time.Hour {
		return QueryResult{}, errors.New("time range must be between 0 and 31 days")
	}
	if q.Limit == 0 {
		q.Limit = 100
	}
	if q.Limit < 1 || q.Limit > 1000 {
		return QueryResult{}, errors.New("limit must be between 1 and 1000")
	}
	if q.Search != nil && q.Search.Query != "" && q.Search.Mode != "substring" && q.Search.Mode != "glob" {
		return QueryResult{}, errors.New("search.mode must be substring or glob")
	}
	if q.Search != nil && len([]rune(q.Search.Query)) > 512 {
		return QueryResult{}, errors.New("search query exceeds 512 characters")
	}
	hosts := append([]string(nil), q.Hosts...)
	sort.Strings(hosts)
	filter := filterID(q)
	var start cursor
	if q.Cursor != "" {
		start, err = decodeCursor(q.Cursor, cursorKey)
		if err != nil || start.Filter != filter {
			return QueryResult{}, errors.New("invalid cursor")
		}
		from, err = time.ParseInLocation("20060102150405", start.From, time.Local)
		if err != nil {
			return QueryResult{}, errors.New("invalid cursor")
		}
		to, err = time.ParseInLocation("20060102150405", start.To, time.Local)
		if err != nil {
			return QueryResult{}, errors.New("invalid cursor")
		}
	}
	events := make(map[string]bool, len(q.Events))
	for _, event := range q.Events {
		events[event] = true
	}
	result := QueryResult{Records: make([]map[string]any, 0, q.Limit), From: from.Format(time.RFC3339), To: to.Format(time.RFC3339)}
	for day := dayStart(from); !day.After(dayStart(to)); day = day.AddDate(0, 0, 1) {
		date := day.Format("2006-01-02")
		for _, host := range hosts {
			if start.Date != "" && (date < start.Date || date == start.Date && host < start.Host) {
				continue
			}
			offset := int64(0)
			if date == start.Date && host == start.Host {
				offset = start.Offset
			}
			file, err := os.Open(filepath.Join(dir, date, host+".jsonl"))
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return result, err
			}
			reader := bufio.NewReader(file)
			if offset > 0 {
				if _, err = file.Seek(offset, 0); err != nil {
					file.Close()
					return result, err
				}
				reader.Reset(file)
			}
			for {
				line, readErr := reader.ReadBytes('\n')
				nextOffset := offset + int64(len(line))
				if len(line) > 0 && line[len(line)-1] == '\n' {
					result.ScannedRecords++
					var record map[string]any
					if json.Unmarshal(line, &record) != nil {
						result.SkippedRecords++
					} else if matches(record, from, to, events, q.Search) {
						result.Records = append(result.Records, record)
						if len(result.Records) == q.Limit {
							file.Close()
							result.NextCursor = encodeCursor(cursor{Filter: filter, Date: date, Host: host, Offset: nextOffset, From: from.Format("20060102150405"), To: to.Format("20060102150405")}, cursorKey)
							return result, nil
						}
					}
				}
				offset = nextOffset
				if result.ScannedRecords >= maxScannedRecords {
					file.Close()
					result.Truncated = true
					result.NextCursor = encodeCursor(cursor{Filter: filter, Date: date, Host: host, Offset: offset, From: from.Format("20060102150405"), To: to.Format("20060102150405")}, cursorKey)
					return result, nil
				}
				if readErr != nil {
					break
				}
			}
			file.Close()
		}
	}
	return result, nil
}

func resolveTimeRange(q Query) (time.Time, time.Time, error) {
	if q.TimeRange != "" {
		if q.From != "" || q.To != "" {
			return time.Time{}, time.Time{}, errors.New("time_range cannot be combined with from or to")
		}
		now := time.Now().In(time.Local)
		today := dayStart(now)
		switch q.TimeRange {
		case "today":
			return today, now, nil
		case "yesterday":
			return today.AddDate(0, 0, -1), today.Add(-time.Nanosecond), nil
		case "last_1h":
			return now.Add(-time.Hour), now, nil
		case "last_24h":
			return now.Add(-24 * time.Hour), now, nil
		case "last_7d":
			return now.AddDate(0, 0, -7), now, nil
		default:
			return time.Time{}, time.Time{}, errors.New("time_range must be today, yesterday, last_1h, last_24h, or last_7d")
		}
	}
	if q.From == "" || q.To == "" {
		return time.Time{}, time.Time{}, errors.New("from and to are required when time_range is omitted")
	}
	from, err := time.ParseInLocation("20060102150405", q.From, time.Local)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("from must use YYYYMMDDHHMMSS: %w", err)
	}
	to, err := time.ParseInLocation("20060102150405", q.To, time.Local)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("to must use YYYYMMDDHHMMSS: %w", err)
	}
	return from, to, nil
}

func dayStart(t time.Time) time.Time {
	y, m, d := t.In(time.Local).Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.Local)
}
func matches(r map[string]any, from, to time.Time, events map[string]bool, s *Search) bool {
	ts, ok := r["ts"].(string)
	if !ok {
		return false
	}
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil || t.Before(from) || t.After(to) {
		return false
	}
	if len(events) > 0 && !events[fmt.Sprint(r["event"])] {
		return false
	}
	if s == nil || s.Query == "" {
		return true
	}
	for _, value := range stringsIn(r) {
		if textMatches(value, *s) {
			return true
		}
	}
	return false
}
func stringsIn(v any) []string {
	var out []string
	var walk func(any)
	walk = func(x any) {
		switch y := x.(type) {
		case map[string]any:
			for _, z := range y {
				walk(z)
			}
		case []any:
			for _, z := range y {
				walk(z)
			}
		case string:
			out = append(out, y)
		case float64, bool:
			out = append(out, fmt.Sprint(y))
		}
	}
	walk(v)
	return out
}
func textMatches(value string, s Search) bool {
	if !s.CaseSensitive {
		value, s.Query = strings.ToLower(value), strings.ToLower(s.Query)
	}
	if s.Mode == "glob" {
		return globContains([]rune(value), parseGlob([]rune(s.Query)))
	}
	return strings.Contains(value, s.Query)
}

type globToken struct {
	star, one bool
	char      rune
}

func parseGlob(p []rune) []globToken {
	out := []globToken{{star: true}}
	escape := false
	for _, r := range p {
		if escape {
			out = append(out, globToken{char: r})
			escape = false
			continue
		}
		if r == '\\' {
			escape = true
			continue
		}
		if r == '*' {
			out = append(out, globToken{star: true})
		} else if r == '?' {
			out = append(out, globToken{one: true})
		} else {
			out = append(out, globToken{char: r})
		}
	}
	if escape {
		out = append(out, globToken{char: '\\'})
	}
	return append(out, globToken{star: true})
}
func globContains(s []rune, p []globToken) bool {
	i, j, star, mark := 0, 0, -1, 0
	for i < len(s) {
		if j < len(p) && (p[j].one || !p[j].star && p[j].char == s[i]) {
			i++
			j++
			continue
		}
		if j < len(p) && p[j].star {
			star = j
			j++
			mark = i
			continue
		}
		if star >= 0 {
			j = star + 1
			mark++
			i = mark
			continue
		}
		return false
	}
	for j < len(p) && p[j].star {
		j++
	}
	return j == len(p)
}
func filterID(q Query) string {
	q.Cursor = ""
	b, _ := json.Marshal(q)
	sum := sha256.Sum256(b)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
func encodeCursor(c cursor, key []byte) string {
	b, _ := json.Marshal(c)
	mac := hmac.New(sha256.New, key)
	mac.Write(b)
	return base64.RawURLEncoding.EncodeToString(b) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
func decodeCursor(v string, key []byte) (cursor, error) {
	parts := strings.Split(v, ".")
	if len(parts) != 2 {
		return cursor{}, errors.New("format")
	}
	b, e := base64.RawURLEncoding.DecodeString(parts[0])
	if e != nil {
		return cursor{}, e
	}
	sig, e := base64.RawURLEncoding.DecodeString(parts[1])
	if e != nil {
		return cursor{}, e
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(b)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return cursor{}, errors.New("signature")
	}
	var c cursor
	e = json.Unmarshal(b, &c)
	return c, e
}
