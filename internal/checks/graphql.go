package checks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const HasuraEndpoint = "https://hasura.venturatravel.org/v1/graphql"
const DefaultQuery = "query ConnectivityProbe { trip(limit: 10, order_by: {created_at: desc}) { id created_at } }"
const maxResponse = 1024 * 1024

type Trip struct {
	ID        int    `json:"id"`
	CreatedAt string `json:"created_at"`
}

// Reject operation keywords outside comments and strings, including block strings.
// This deliberately rejects fields named mutation/subscription too; the server
// still owns GraphQL syntax validation and anonymous read permissions.
func ValidateQuery(query string) error {
	if len(query) == 0 || len(query) > 8192 {
		return errors.New("query must contain 1 to 8192 characters")
	}
	var first string
	for i := 0; i < len(query); {
		c := query[i]
		if c == '#' {
			for i < len(query) && query[i] != '\n' && query[i] != '\r' {
				i++
			}
			continue
		}
		if c == '"' {
			block := strings.HasPrefix(query[i:], "\"\"\"")
			width := 1
			if block {
				width = 3
			}
			i += width
			closed := false
			for i < len(query) {
				if query[i] == '\\' {
					i += 2
					continue
				}
				if (!block && query[i] == '"') || (block && strings.HasPrefix(query[i:], "\"\"\"")) {
					i += width
					closed = true
					break
				}
				i++
			}
			if !closed {
				return errors.New("unterminated GraphQL string")
			}
			if first == "" {
				first = "string"
			}
			continue
		}
		if c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
			start := i
			for i < len(query) && (query[i] == '_' || query[i] >= 'a' && query[i] <= 'z' || query[i] >= 'A' && query[i] <= 'Z' || query[i] >= '0' && query[i] <= '9') {
				i++
			}
			word := query[start:i]
			if word == "mutation" || word == "subscription" {
				return errors.New("only read-only GraphQL queries are permitted")
			}
			if first == "" {
				first = word
			}
			continue
		}
		if c != ' ' && c != '\t' && c != '\r' && c != '\n' && c != ',' && first == "" {
			first = string(c)
		}
		i++
	}
	if first != "query" && first != "{" {
		return errors.New("start with query or a selection set; mutations and subscriptions are disabled")
	}
	return nil
}

func GraphQL(ctx context.Context, endpoint, query string) []Result {
	start := time.Now()
	u, err := publicURL(endpoint)
	if err == nil {
		err = ValidateQuery(query)
	}
	if err != nil {
		r := result("Hasura", "Configuration", "", "fail", err.Error(), start)
		r.Code = "invalid_configuration"
		return []Result{r}
	}
	target := u.String()
	body, _ := json.Marshal(map[string]string{"query": query})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	response, err := publicClient().Do(req)
	if err != nil {
		return []Result{failure("Hasura", "GraphQL", target, start, err)}
	}
	defer response.Body.Close()
	r := result("Hasura", "GraphQL", target, "pass", "Anonymous read-only GraphQL query succeeded.", start)
	r.HTTPStatus, r.TLSVersion = response.StatusCode, tlsVersion(response)
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		r.Status, r.Code, r.Message = "fail", "http_status", fmt.Sprintf("HTTP %d. Connectivity exists, but the GraphQL request was not accepted. No credentials were sent.", response.StatusCode)
		return []Result{r}
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, maxResponse+1))
	if err != nil {
		return []Result{failure("Hasura", "Response", target, start, err)}
	}
	var envelope struct {
		Data   map[string]json.RawMessage `json:"data"`
		Errors []json.RawMessage          `json:"errors"`
	}
	if len(payload) > maxResponse || json.Unmarshal(payload, &envelope) != nil {
		r.Status, r.Code, r.Message = "fail", "invalid_response", "Response is too large or is not valid GraphQL JSON."
	} else if len(envelope.Errors) > 0 {
		r.Status, r.Code, r.Message = "fail", "graphql_errors", "GraphQL returned errors. Check the query and anonymous permissions. HTTP 200 alone is not success."
	} else if len(envelope.Data) == 0 {
		r.Status, r.Code, r.Message = "fail", "empty_data", "GraphQL returned no data object."
	} else {
		for _, value := range envelope.Data {
			var rows []json.RawMessage
			if json.Unmarshal(value, &rows) == nil {
				r.RecordCount += len(rows)
			}
		}
		// Only display the known public projection. Custom response bodies stay private.
		if target == HasuraEndpoint && query == DefaultQuery {
			_ = json.Unmarshal(envelope.Data["trip"], &r.Trips)
			if len(r.Trips) > 10 {
				r.Trips = r.Trips[:10]
			}
		}
	}
	r.LatencyMS = time.Since(start).Milliseconds()
	return []Result{r}
}
