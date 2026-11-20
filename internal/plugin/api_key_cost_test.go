package plugin

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func TestAPIKeyCostsRespectIdentityPricingAndRedaction(t *testing.T) {
	config := testConfig(t)
	config.APIKeySecret = defaultAPIKeySecret
	crypto, err := deriveCryptoContext(config.APIKeySecret)
	if err != nil {
		t.Fatal(err)
	}
	store, err := openStoreWithCrypto(config, crypto)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.SaveModelPrices(map[string]ModelPrice{"model": {Input: 2}}); err != nil {
		t.Fatal(err)
	}
	for _, value := range []struct {
		key, model string
		tokens     uint64
	}{{"a", "model", 1_000_000}, {"a", "unpriced", 3}, {"b", "model", 2_000_000}} {
		usage := encryptedUsageForTest(t, crypto, value.key, value.model, value.tokens)
		usage.Counters.InputTokens = value.tokens
		if err := store.Record(usage); err != nil {
			t.Fatal(err)
		}
	}
	response, err := store.QueryCosts("24h")
	if err != nil {
		t.Fatal(err)
	}
	if len(response.APIKeys) != 2 || math.Abs(response.Summary.TotalUSD-6) > 1e-8 {
		t.Fatalf("cost totals: %+v", response)
	}
	var total float64
	for _, row := range response.APIKeys {
		total += row.TotalUSD
		if row.Ref == apiKeyRef(1, apiKeyFingerprint("a", crypto.indexKey)) && (row.TotalUSD != 2 || row.UnpricedRequests != 1) {
			t.Fatalf("partial pricing: %+v", row)
		}
	}
	if total != response.Summary.TotalUSD {
		t.Fatal("key totals differ from summary")
	}
	copy := cloneCostResponse(response)
	copy.APIKeys[0].TotalUSD = 999
	if response.APIKeys[0].TotalUSD == 999 {
		t.Fatal("cost cache shares mutable API-key rows")
	}
	response.Redact()
	raw, err := json.Marshal(response)
	if err != nil || strings.Contains(string(raw), "api_keys") {
		t.Fatal("public cost response exposes key identities")
	}
}
