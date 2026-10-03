// Package ztc is the root of the Zero-Trust continuum reference implementation.
//
// The code follows the standard Go layout:
//
//	cmd/<service>/main.go		One binary per microservice (ztc-ca, ztc-pdp, ztc-pep, ztc-fog, ztc-edge, stc-ingest, ztc-ids, stc-migrate) and the CLI ztcctl
//
//	internal/<package>/			Shared libraries; "internal" means they cannot be imported from outside this module
//
// Only the Go standard library is used. see ../README.md for the full architecture overview.
package ztc
