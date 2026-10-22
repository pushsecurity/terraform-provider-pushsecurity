// terraform-provider-pushsecurity is the Terraform provider for Push Security control
// configuration.
package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/provider"
)

// version is overwritten at release time with the git tag:
//
//	go build -ldflags "-X main.version=$VERSION"
var version = "dev"

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "run the provider with support for debuggers like delve")
	flag.Parse()

	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		Address: "registry.terraform.io/pushsecurity/pushsecurity",
		Debug:   debug,
	})
	if err != nil {
		log.Fatal(err)
	}
}
