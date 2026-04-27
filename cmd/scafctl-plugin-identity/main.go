// Package main is the entry point for the scafctl-plugin-identity plugin.
package main

import (
	identityprovider "github.com/oakwood-commons/scafctl-plugin-identity/internal/identity"

	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
)

func main() {
	sdkplugin.Serve(identityprovider.NewPlugin())
}
