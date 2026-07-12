package hscontrol

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	hsdns "github.com/juanfont/headscale/hscontrol/dns"
	"github.com/rs/zerolog/log"
	"tailscale.com/tailcfg"
)

const (
	// acmeTXTTTL is the TTL for ACME DNS-01 challenge TXT records.
	// 120s is common for ACME challenges — short enough to not pollute
	// DNS caches after the challenge completes.
	acmeTXTTTL = 120 * time.Second

	// acmePropagationTimeout bounds how long SetDNSHandler waits for a
	// freshly-written TXT record to become visible on the zone's
	// authoritative nameservers before returning to the client.
	acmePropagationTimeout = 60 * time.Second

	// acmePropagationPoll is the interval between authoritative-NS
	// lookups while waiting for propagation.
	acmePropagationPoll = 2 * time.Second
)

// SetDNSHandler handles POST /machine/set-dns. It accepts a
// [tailcfg.SetDNSRequest] from a node performing an ACME DNS-01
// challenge (e.g., `tailscale cert`) and provisions the corresponding
// TXT record via the configured DNS provider.
func (ns *noiseServer) SetDNSHandler(writer http.ResponseWriter, req *http.Request) {
	var dnsReq tailcfg.SetDNSRequest

	if err := json.NewDecoder(req.Body).Decode(&dnsReq); err != nil {
		httpError(writer, NewHTTPError(
			http.StatusBadRequest,
			"invalid SetDNSRequest",
			err,
		))

		return
	}

	// Reject unsupported client versions.
	if rejectUnsupported(writer, dnsReq.Version, ns.machineKey, dnsReq.NodeKey) {
		return
	}

	// Look up the node by its NodeKey and verify the Noise session
	// machine key matches. This ensures only the legitimate node can
	// create DNS records for its own domain.
	nv, ok := ns.headscale.state.GetNodeByNodeKey(dnsReq.NodeKey)
	if !ok {
		httpError(writer, NewHTTPError(
			http.StatusNotFound,
			"node not found",
			nil,
		))

		return
	}

	if nv.MachineKey() != ns.machineKey {
		httpError(writer, NewHTTPError(
			http.StatusUnauthorized,
			"machine key does not match node",
			nil,
		))

		return
	}

	// Verify the DNS provider is configured.
	if ns.headscale.dnsProvider == nil {
		log.Warn().Msg("set-dns called but cert support is not enabled")
		http.Error(writer, "cert support not enabled", http.StatusNotImplemented)

		return
	}

	// Validate domain ownership: the requested record name must be
	// _acme-challenge.<node-hostname>.<base_domain> (or a sub-label
	// thereof). This prevents one node from setting DNS records for
	// another.
	if !ns.headscale.validateCertDNSName(nv, dnsReq.Name) {
		httpError(writer, NewHTTPError(
			http.StatusForbidden,
			"domain not allowed for this node",
			fmt.Errorf("node %q cannot set DNS name %q", nv.Hostname(), dnsReq.Name),
		))

		return
	}

	// Only TXT records are supported (ACME DNS-01 challenges).
	if dnsReq.Type != "TXT" {
		httpError(writer, NewHTTPError(
			http.StatusBadRequest,
			"only TXT records are supported",
			fmt.Errorf("unsupported record type: %s", dnsReq.Type),
		))

		return
	}

	// The DNS zone registered with the provider. This may differ from
	// base_domain: base_domain can be a subdomain (e.g.
	// "pre-magic.workspace.beer") while the provider's authoritative
	// zone is the registered domain ("workspace.beer"). This matters on
	// providers like Cloudflare where a subdomain is not its own zone.
	// Fall back to base_domain when zone is not explicitly configured.
	zoneName := ns.headscale.cfg.Cert.DNSProvider.Zone
	if zoneName == "" {
		zoneName = ns.headscale.cfg.BaseDomain
	}
	zoneName = strings.TrimSuffix(zoneName, ".")
	zone := zoneName + "."

	// The record name is relative to the zone. Strip the zone suffix
	// from the FQDN to get the relative name.
	// e.g., "_acme-challenge.ubuntu.pre-magic.workspace.beer" in zone
	// "workspace.beer." becomes "_acme-challenge.ubuntu.pre-magic"
	relativeName := strings.TrimSuffix(dnsReq.Name, "."+zoneName)

	record := hsdns.NewTXTRecord(relativeName, dnsReq.Value, acmeTXTTTL)

	log.Info().
		Str("node", nv.Hostname()).
		Str("name", dnsReq.Name).
		Str("relative_name", relativeName).
		Str("zone", zone).
		Str("type", dnsReq.Type).
		Str("value", dnsReq.Value).
		Str("base_domain", ns.headscale.cfg.BaseDomain).
		Dur("propagation_timeout", acmePropagationTimeout).
		Msg("setting DNS TXT record for ACME challenge")

	setStart := time.Now()
	if err := ns.headscale.dnsProvider.SetRecord(req.Context(), zone, record); err != nil {
		log.Error().Err(err).
			Str("node", nv.Hostname()).
			Str("name", dnsReq.Name).
			Str("zone", zone).
			Dur("elapsed", time.Since(setStart)).
			Msg("DNS provider rejected TXT record write")

		httpError(writer, NewHTTPError(
			http.StatusInternalServerError,
			"failed to set DNS record",
			err,
		))

		return
	}

	log.Debug().
		Str("node", nv.Hostname()).
		Str("name", dnsReq.Name).
		Str("zone", zone).
		Dur("elapsed", time.Since(setStart)).
		Msg("TXT record written to DNS provider; waiting for propagation")

	// Wait until the TXT record is visible on the zone's authoritative
	// nameservers before responding. The Tailscale client asks Let's
	// Encrypt to validate the DNS-01 challenge immediately after this
	// call returns; if we return before the record has propagated, LE
	// queries the authoritative NS, finds no (or a stale) record, and
	// marks the ACME order "invalid". Blocking here removes that race.
	// Best-effort: on timeout we log and proceed, since the record was
	// written successfully.
	if err := waitForTXTPropagation(
		req.Context(),
		zoneName,
		dnsReq.Name,
		dnsReq.Value,
	); err != nil {
		log.Warn().Err(err).
			Str("node", nv.Hostname()).
			Str("name", dnsReq.Name).
			Msg("could not confirm TXT propagation; responding anyway")
	} else {
		log.Info().
			Str("node", nv.Hostname()).
			Str("name", dnsReq.Name).
			Msg("TXT record confirmed on authoritative nameservers")
	}

	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(writer).Encode(tailcfg.SetDNSResponse{}); err != nil {
		log.Error().Err(err).Msg("failed to encode SetDNSResponse")
	}

	if flusher, ok := writer.(http.Flusher); ok {
		flusher.Flush()
	}
}

// validateCertDNSName checks whether the given DNS name is allowed for
// the node. A node may only set TXT records for its own ACME challenge
// subdomain: _acme-challenge.<hostname>.<base_domain>.
func (h *Headscale) validateCertDNSName(node interface{ Hostname() string }, name string) bool {
	if h.cfg.BaseDomain == "" {
		return false
	}

	// The expected ACME challenge record name for this node.
	expected := "_acme-challenge." + node.Hostname() + "." + h.cfg.BaseDomain

	return strings.EqualFold(name, expected)
}

// waitForTXTPropagation blocks until the TXT record named fqdn contains
// expectedValue on the authoritative nameservers for zone, or until the
// timeout elapses. It queries the zone's authoritative NS directly to
// avoid resolver-side negative caching.
func waitForTXTPropagation(ctx context.Context, zone, fqdn, expectedValue string) error {
	zone = strings.TrimSuffix(zone, ".")

	nsRecords, err := net.LookupNS(zone)
	if err != nil {
		return fmt.Errorf("looking up NS for zone %q: %w", zone, err)
	}
	if len(nsRecords) == 0 {
		return fmt.Errorf("no NS records found for zone %q", zone)
	}

	authNS := strings.TrimSuffix(nsRecords[0].Host, ".")

	nsHosts := make([]string, len(nsRecords))
	for i, rec := range nsRecords {
		nsHosts[i] = strings.TrimSuffix(rec.Host, ".")
	}

	log.Debug().
		Str("zone", zone).
		Str("fqdn", fqdn).
		Strs("nameservers", nsHosts).
		Str("query_ns", authNS).
		Str("expected_value", expectedValue).
		Msg("waiting for TXT record propagation on authoritative nameserver")

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}

			return d.DialContext(ctx, network, net.JoinHostPort(authNS, "53"))
		},
	}

	ctx, cancel := context.WithTimeout(ctx, acmePropagationTimeout)
	defer cancel()

	ticker := time.NewTicker(acmePropagationPoll)
	defer ticker.Stop()

	start := time.Now()
	for attempt := 1; ; attempt++ {
		txts, lookupErr := resolver.LookupTXT(ctx, fqdn)

		e := log.Debug().
			Int("attempt", attempt).
			Dur("elapsed", time.Since(start)).
			Str("fqdn", fqdn).
			Str("query_ns", authNS).
			Strs("found", txts)
		if lookupErr != nil {
			e = e.AnErr("lookup_error", lookupErr)
		}
		e.Msg("polling authoritative NS for TXT record")

		if lookupErr == nil {
			for _, txt := range txts {
				if txt == expectedValue {
					log.Debug().
						Int("attempt", attempt).
						Dur("elapsed", time.Since(start)).
						Str("fqdn", fqdn).
						Msg("TXT record value matched on authoritative NS")

					return nil
				}
			}
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf(
				"timed out after %s (%d attempts) waiting for TXT %q on %s",
				acmePropagationTimeout, attempt, fqdn, authNS,
			)
		case <-ticker.C:
		}
	}
}
