package assetclass_test

import (
	"testing"

	"github.com/vistasecurity/vistaplatform-agents/shared/assetclass"
)

// The resource_type half of the collector-vocabulary guard scans the cloud
// collectors, which run only in the hosted platform; the agents write no
// resource_type, so that scan lives with them. The tables themselves are
// still checked here.

// TestFromCloudResourceTypeFallsBackToCloudResource pins the "no opinion"
// answer in BOTH directions: an unrecognised type is a cloud resource (coarse
// and true), and an EMPTY one is no answer at all (there is no cloud resource
// here to classify).
func TestFromCloudResourceTypeFallsBackToCloudResource(t *testing.T) {
	for _, in := range []string{"some_future_service", "aws_quantum_thing"} {
		key, ok := assetclass.FromCloudResourceType(in)
		if !ok || key != assetclass.KeyCloudResource {
			t.Errorf("FromCloudResourceType(%q) = %q, %v; want cloud_resource, true", in, key, ok)
		}
	}
	for _, in := range []string{"", "   "} {
		if key, ok := assetclass.FromCloudResourceType(in); ok {
			t.Errorf("FromCloudResourceType(%q) = %q, true; an absent resource type is not a cloud resource", in, key)
		}
	}
}

// TestCloudAndDeviceVocabulariesDisagreeOnPurpose: "load_balancer" means a box
// in a rack as a device_type and a provider's managed load balancer as a cloud
// resource_type. One merged table would silently pick one answer for both.
func TestCloudAndDeviceVocabulariesDisagreeOnPurpose(t *testing.T) {
	if got := assetclass.FromDeviceType("load_balancer"); got != assetclass.KeyLoadBalancer {
		t.Errorf("device_type load_balancer = %q, want load_balancer (hardware)", got)
	}
	got, _ := assetclass.FromCloudResourceType("load_balancer")
	if got != assetclass.KeyCloudLoadBalancer {
		t.Errorf("resource_type load_balancer = %q, want cloud_load_balancer", got)
	}
}

// TestVocabularyClassKeysAreRegistered holds BOTH tables to the generated
// taxonomy. A class key that is not a real class is still written into
// `assets.class_key` (class_path falls back to the key itself), producing an
// asset in a class no facet can select and no CMDB sync can map.
func TestVocabularyClassKeysAreRegistered(t *testing.T) {
	for name, table := range map[string]map[string]assetclass.Key{
		"device_type":   assetclass.DeviceTypeVocabulary(),
		"resource_type": assetclass.CloudResourceTypeVocabulary(),
	} {
		if len(table) == 0 {
			t.Errorf("%s vocabulary is empty; the guard would pass over nothing", name)
		}
		for value, key := range table {
			if _, ok := assetclass.Get(string(key)); !ok {
				t.Errorf("%s %q maps to class %q, which is not in the generated registry", name, value, key)
			}
		}
	}
}
