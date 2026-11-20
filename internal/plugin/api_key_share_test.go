package plugin

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestAPIKeyShareCountersRespectFiltersAndRedaction(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	hashA, hashB := strings.Repeat("a", 32), strings.Repeat("b", 32)
	data := make(map[aggregateKey]Counters)
	add := func(age time.Duration, hash, model, source string, generation, requests, tokens uint64) {
		data[aggregateKey{Hour: now.Add(-age).Unix(), Dimensions: Dimensions{APIKeyHash: hash, APIKeyGeneration: generation, Model: model, Source: source}}] = Counters{Requests: requests, TotalTokens: tokens}
	}
	add(time.Hour, hashA, "model-a", "client", 1, 2, 10)
	add(time.Hour, hashA, "model-b", "client", 1, 3, 20)
	add(time.Hour, hashB, "model-a", "client", 1, 7, 70)
	add(time.Hour, hashA, "model-a", "other", 1, 11, 110)
	add(time.Hour, hashA, "model-a", "client", 2, 13, 130)
	add(48*time.Hour, hashA, "model-a", "client", 1, 17, 170)
	rangeValue := usageRange{Name: "24h", Start: now.Add(-24 * time.Hour), End: now}
	refA := apiKeyRef(1, hashA)
	for _, filter := range []usageFilter{{}, {Source: "client"}, newUsageFilter("client", refA)} {
		full := buildStatsForRangeWithFilter(data, now.Add(-72*time.Hour), now, rangeValue, filter, now, nil)
		initial := buildInitialStatsForRange(data, now.Add(-72*time.Hour), now, rangeValue, filter, now, nil)
		if !reflect.DeepEqual(initial.APIKeys, full.APIKeys) {
			t.Fatal("compact and exact API-key totals differ")
		}
		var requests, tokens uint64
		for _, option := range initial.APIKeys {
			requests += option.Requests
			tokens += option.TotalTokens
			if option.Ref == refA && (filter.Source == "client") && (option.Requests != 5 || option.TotalTokens != 30) {
				t.Fatalf("cross-model totals = %+v", option)
			}
			if filter.APIKeyRefSet != "" && option.Ref != refA && option.Requests != 0 {
				t.Fatal("filtered-out key contributed to the ranking")
			}
		}
		if requests != initial.Summary.Requests || tokens != initial.Summary.TotalTokens {
			t.Fatal("API-key totals do not match the selected summary")
		}
		initial.Redact()
		full.Redact()
		for _, value := range []any{initial, full} {
			raw, err := json.Marshal(value)
			if err != nil || strings.Contains(string(raw), "api_keys") || strings.Contains(string(raw), hashA) {
				t.Fatal("public statistics exposed API-key identities")
			}
		}
	}
}

func TestAPIKeyShareDashboardIsFullModeOnly(t *testing.T) {
	for _, value := range []string{"apiKeySharePanel", "function renderAPIKeyShare()", "data-api-key-share-metric"} {
		if strings.Contains(dashboardHTML, value) || !strings.Contains(fullDashboardHTML, value) {
			t.Fatalf("full-mode-only contract failed: %s", value)
		}
	}
}
