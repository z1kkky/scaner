package check

// DefaultChecksOptions controls the network policy used by the built-in set.
type DefaultChecksOptions struct {
	// PublicTargetsOnly prevents HTTP checks from connecting to non-public IPs.
	// Enable it when scan targets come from an untrusted API request.
	PublicTargetsOnly bool
}

// NewDefaultChecks creates the categories enabled by default for the CLI and
// daemon. Callers receive fresh check instances so per-request options remain
// isolated and the two entrypoints cannot silently drift apart.
func NewDefaultChecks(opts DefaultChecksOptions) []Check {
	headers := &HeadersCheck{}
	tlsCheck := &TLSCheck{publicTargetsOnly: opts.PublicTargetsOnly}
	if opts.PublicTargetsOnly {
		headers.Client = NewPublicHTTPClient()
	}
	exposures := &ExposuresCheck{publicTargetsOnly: opts.PublicTargetsOnly}
	return []Check{tlsCheck, headers, exposures, &EmailCheck{}}
}
