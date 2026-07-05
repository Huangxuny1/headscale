// Package dns provides a pluggable DNS record management layer for
// Headscale. It is used by the /machine/set-dns handler to provision
// ACME DNS-01 challenge TXT records on behalf of nodes running
// `tailscale cert`.
//
// The Provider interface is intentionally broader than just TXT
// records: when Funnel support is added, the same interface will
// create A/AAAA records pointing node FQDNs to the ingress proxy.
package dns

import (
	"context"
	"fmt"
	"time"

	"github.com/libdns/libdns"
)

// Provider is the interface for managing DNS records.
// Implementations wrap a libdns-compatible provider to create,
// update, and delete records in the configured zone.
type Provider interface {
	// SetRecord creates or updates a DNS record in the given zone.
	// For ACME DNS-01 challenges, zone is the base_domain and
	// record contains a TXT entry for _acme-challenge.<node>.
	SetRecord(ctx context.Context, zone string, record libdns.Record) error

	// DeleteRecord removes a DNS record from the given zone.
	// Used to clean up ACME challenge records after verification.
	DeleteRecord(ctx context.Context, zone string, record libdns.Record) error
}

// libdnsProvider wraps any libdns-compatible record setter/deleter
// (most libdns provider packages expose a single struct implementing
// both RecordSetter and RecordDeleter).
type libdnsProvider struct {
	setter  libdns.RecordSetter
	deleter libdns.RecordDeleter
}

func (p *libdnsProvider) SetRecord(ctx context.Context, zone string, record libdns.Record) error {
	_, err := p.setter.SetRecords(ctx, zone, []libdns.Record{record})
	if err != nil {
		return fmt.Errorf("dns: setting record in zone %q: %w", zone, err)
	}

	return nil
}

func (p *libdnsProvider) DeleteRecord(ctx context.Context, zone string, record libdns.Record) error {
	_, err := p.deleter.DeleteRecords(ctx, zone, []libdns.Record{record})
	if err != nil {
		return fmt.Errorf("dns: deleting record in zone %q: %w", zone, err)
	}

	return nil
}

// NewTXTRecord is a convenience constructor for building a libdns.TXT
// record for an ACME DNS-01 challenge.
func NewTXTRecord(name, value string, ttl time.Duration) libdns.TXT {
	return libdns.TXT{
		Name: name,
		Text: value,
		TTL:  ttl,
	}
}
