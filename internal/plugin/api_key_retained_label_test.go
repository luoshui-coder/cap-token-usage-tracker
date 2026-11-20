package plugin

import (
	"testing"
	"time"
)

func TestAPIKeyLabelsOutsideHotWindowAfterRestart(t *testing.T) {
	config := testConfig(t)
	config.APIKeySecret = defaultAPIKeySecret
	config.SyncOnRecord = true
	ctx, err := deriveCryptoContext(config.APIKeySecret)
	if err != nil {
		t.Fatal(err)
	}
	store, err := openStoreWithCrypto(config, ctx)
	if err != nil {
		t.Fatal(err)
	}
	key := "historical-client"
	usage := encryptedUsageForTest(t, ctx, key, "historical-model", 10)
	usage.RequestedAt = time.Now().UTC().Add(-3 * aggregateHotWindow)
	if err := store.Record(usage); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = openStoreWithCrypto(config, ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ref := apiKeyRef(1, apiKeyFingerprint(key, ctx.indexKey))
	if err := store.SetAPIKeyLabel(ref, "历史用户"); err != nil {
		t.Fatalf("label retained historical key: %v", err)
	}
	resolved, err := store.ResolveAPIKeyHash(apiKeyFingerprint(key, ctx.indexKey))
	if err != nil || resolved != ref {
		t.Fatalf("resolve retained historical key: %q, %v", resolved, err)
	}
	labels, err := store.APIKeyLabels()
	if err != nil || labels[ref] != "历史用户" {
		t.Fatalf("labels = %+v, %v", labels, err)
	}
}
