package main

import (
	"reflect"
	"sort"
	"testing"

	"github.com/pers0na2dev/single-auth/protocol/providers"
)

func TestProviderDocumentationCoversFrozenRegistryExactlyOnce(t *testing.T) {
	want := providers.SocialProviderList()
	got := make([]string, 0, len(providerDocs))
	seen := make(map[string]struct{}, len(providerDocs))
	for _, item := range providerDocs {
		if _, exists := seen[item.ID]; exists {
			t.Fatalf("provider %q is documented more than once", item.ID)
		}
		seen[item.ID] = struct{}{}
		got = append(got, item.ID)
	}

	sort.Strings(want)
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("documented providers = %v, frozen registry = %v", got, want)
	}
}
