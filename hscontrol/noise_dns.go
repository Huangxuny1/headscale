package hscontrol

import (
	"encoding/json"
	"fmt"
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

	// The zone for libdns is the base_domain with a trailing dot.
	zone := ns.headscale.cfg.BaseDomain + "."

	// The record name is relative to the zone. Strip the zone suffix
	// from the FQDN to get the relative name.
	// e.g., "_acme-challenge.mynode.example.com" in zone "example.com."
	// becomes "_acme-challenge.mynode"
	relativeName := strings.TrimSuffix(dnsReq.Name, "."+ns.headscale.cfg.BaseDomain)

	record := hsdns.NewTXTRecord(relativeName, dnsReq.Value, acmeTXTTTL)

	log.Info().
		Str("node", nv.Hostname()).
		Str("name", dnsReq.Name).
		Str("relative_name", relativeName).
		Str("zone", zone).
		Msg("setting DNS TXT record for ACME challenge")

	if err := ns.headscale.dnsProvider.SetRecord(req.Context(), zone, record); err != nil {
		httpError(writer, NewHTTPError(
			http.StatusInternalServerError,
			"failed to set DNS record",
			err,
		))

		return
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
