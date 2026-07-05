package dns

import (
	"errors"
	"fmt"

	"github.com/libdns/cloudflare"
	"github.com/libdns/libdns"
	"github.com/juanfont/headscale/hscontrol/types"
)

// ErrUnknownProvider is returned when the configured provider name
// does not match any registered libdns implementation.
var ErrUnknownProvider = errors.New("dns: unknown provider")

// ErrMissingConfig is returned when a required config key is absent
// for the chosen provider.
var ErrMissingConfig = errors.New("dns: missing required config key")

// NewProvider creates a Provider from the given CertConfig. It uses
// the registry of known libdns providers to instantiate the correct
// backend.
//
// To add a new provider:
//  1. Import its package.
//  2. Add a case to the switch below.
//  3. Map config keys to the provider struct fields.
func NewProvider(cfg types.CertConfig) (Provider, error) {
	if !cfg.Enabled {
		return nil, nil //nolint:nilnil // intentional: nil provider when cert is disabled
	}

	setter, deleter, err := newLibdnsBackend(cfg.DNSProvider)
	if err != nil {
		return nil, err
	}

	return &libdnsProvider{
		setter:  setter,
		deleter: deleter,
	}, nil
}

// newLibdnsBackend returns the libdns RecordSetter and RecordDeleter
// for the configured provider. Most libdns providers implement both
// interfaces on the same struct.
func newLibdnsBackend(cfg types.DNSProviderConfig) (libdns.RecordSetter, libdns.RecordDeleter, error) {
	switch cfg.Name {
	case "cloudflare":
		token, ok := cfg.Config["api_token"]
		if !ok || token == "" {
			return nil, nil, fmt.Errorf("%w: cloudflare requires 'api_token'", ErrMissingConfig)
		}

		provider := &cloudflare.Provider{
			APIToken: token,
		}

		return provider, provider, nil

	// Future providers can be added here:
	// case "route53":
	//     ...
	// case "rfc2136":
	//     ...

	case "":
		return nil, nil, fmt.Errorf("%w: dns_provider.name must be set when cert is enabled", ErrMissingConfig)

	default:
		return nil, nil, fmt.Errorf("%w: %q", ErrUnknownProvider, cfg.Name)
	}
}
