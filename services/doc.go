// Package ztc is the root of the Zero-Trust Continuum reference implementation.
//
// The code follows the standard Go layout:
//
//	cmd/<service>/main.go   one binary per microservice (ztc-ca, ztc-pdp, ztc-pep, ztc-fog,
//	                        ztc-edge, ztc-ingest, ztc-ids, ztc-migrate) and the CLI ztcctl
//	internal/<package>/     shared libraries; "internal" means they cannot be imported
//	                        from outside this module
//
// Only the Go standard library is used. See ../README.md for the architecture overview.
package ztc
