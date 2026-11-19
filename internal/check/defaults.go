package check

import "github.com/z1kkky/scaner/internal/targetscope"

// DefaultChecksOptions controls the network policy used by the built-in set.
type DefaultChecksOptions struct {
	// PublicTargetsOnly prevents HTTP checks from connecting to non-public IPs.
	// Enable it when scan targets come from an untrusted API request.
	PublicTargetsOnly bool
	// EnableNuclei adds the optional, locally installed Nuclei executable.
	// It is deliberately excluded unless explicitly enabled by the operator.
	EnableNuclei bool
	// TargetPolicy pins network connections to a previously verified job scope.
	TargetPolicy *targetscope.Policy
}

// NewDefaultChecks creates the categories enabled by default for the CLI and
// daemon. Callers receive fresh check instances so per-request options remain
// isolated and the two entrypoints cannot silently drift apart.
func NewDefaultChecks(opts DefaultChecksOptions) []Check {
	headers := &HeadersCheck{}
	tlsCheck := &TLSCheck{publicTargetsOnly: opts.PublicTargetsOnly}
	cms := &CMSCheck{publicTargetsOnly: opts.PublicTargetsOnly}
	if opts.PublicTargetsOnly {
		headers.Client = NewPublicHTTPClient()
	}
	exposures := &ExposuresCheck{publicTargetsOnly: opts.PublicTargetsOnly}
	ports := &PortsCheck{publicTargetsOnly: opts.PublicTargetsOnly}
	if opts.TargetPolicy != nil {
		headers.Client = NewScopedHTTPClient(opts.TargetPolicy)
		tlsCheck.targetPolicy = opts.TargetPolicy
		cms.targetPolicy = opts.TargetPolicy
		exposures.targetPolicy = opts.TargetPolicy
		ports.targetPolicy = opts.TargetPolicy
	}
	checks := []Check{tlsCheck, headers, exposures, ports, cms, &EmailCheck{}}
	if opts.EnableNuclei {
		checks = append(checks, NewNucleiCheck())
	}
	return checks
}
