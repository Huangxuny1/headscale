package hscontrol

import (
	"encoding/json"
	"net/http"

	"github.com/rs/zerolog/log"
	"tailscale.com/tailcfg"
)

// QueryFeatureHandler handles POST /machine/feature/query. The
// Tailscale client calls this endpoint to determine whether a given
// feature (e.g., "serve", "funnel") is available and what the user
// needs to do to enable it.
func (ns *noiseServer) QueryFeatureHandler(writer http.ResponseWriter, req *http.Request) {
	var featureReq tailcfg.QueryFeatureRequest

	if err := json.NewDecoder(req.Body).Decode(&featureReq); err != nil {
		httpError(writer, NewHTTPError(
			http.StatusBadRequest,
			"invalid QueryFeatureRequest",
			err,
		))

		return
	}

	log.Trace().
		Str("feature", featureReq.Feature).
		Msg("feature query")

	resp := ns.resolveFeatureQuery(featureReq.Feature)

	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(writer).Encode(resp); err != nil {
		log.Error().Err(err).Msg("failed to encode QueryFeatureResponse")
	}

	if flusher, ok := writer.(http.Flusher); ok {
		flusher.Flush()
	}
}

// resolveFeatureQuery returns the appropriate [tailcfg.QueryFeatureResponse]
// for the given feature name.
func (ns *noiseServer) resolveFeatureQuery(feature string) tailcfg.QueryFeatureResponse {
	switch feature {
	case "serve":
		if ns.headscale.cfg.Cert.Enabled {
			return tailcfg.QueryFeatureResponse{
				Complete: true,
			}
		}

		return tailcfg.QueryFeatureResponse{
			Text: "tailscale serve requires certificate support to be enabled.\n" +
				"Ask your Headscale administrator to set cert.enabled = true in the server configuration.",
		}

	case "funnel":
		// Funnel is not yet implemented. When it is, this will check
		// a separate cfg.Cert.Funnel.Enabled (or similar) flag and
		// respond with Complete: true.
		return tailcfg.QueryFeatureResponse{
			Text: "Funnel is not yet supported by this Headscale server.\n" +
				"See: https://github.com/juanfont/headscale/issues/2527",
		}

	default:
		return tailcfg.QueryFeatureResponse{
			Text: "Unknown feature: " + feature,
		}
	}
}
