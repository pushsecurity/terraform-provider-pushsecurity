package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccCustomDetectionsDataSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: testAccDetectionOneRule + `
data "pushsecurity_custom_detections" "all" {
  depends_on = [pushsecurity_custom_detection.test]
}`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckTypeSetElemAttr("data.pushsecurity_custom_detections.all",
					"detection_event_types.*", "CUSTOM_TF_ACCEPTANCE_DETECTION"),
			),
		}},
	})
}
