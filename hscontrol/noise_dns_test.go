package hscontrol

import (
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
)

type mockHostnameNode struct {
	hostname string
}

func (m mockHostnameNode) Hostname() string {
	return m.hostname
}

func TestValidateCertDNSName(t *testing.T) {
	tests := []struct {
		name       string
		baseDomain string
		hostname   string
		dnsName    string
		want       bool
	}{
		{
			name:       "valid acme challenge for node",
			baseDomain: "example.com",
			hostname:   "mynode",
			dnsName:    "_acme-challenge.mynode.example.com",
			want:       true,
		},
		{
			name:       "case insensitive match",
			baseDomain: "example.com",
			hostname:   "MyNode",
			dnsName:    "_acme-challenge.mynode.example.com",
			want:       true,
		},
		{
			name:       "wrong node hostname",
			baseDomain: "example.com",
			hostname:   "mynode",
			dnsName:    "_acme-challenge.othernode.example.com",
			want:       false,
		},
		{
			name:       "wrong domain",
			baseDomain: "example.com",
			hostname:   "mynode",
			dnsName:    "_acme-challenge.mynode.evil.com",
			want:       false,
		},
		{
			name:       "not an acme challenge",
			baseDomain: "example.com",
			hostname:   "mynode",
			dnsName:    "mynode.example.com",
			want:       false,
		},
		{
			name:       "empty base domain",
			baseDomain: "",
			hostname:   "mynode",
			dnsName:    "_acme-challenge.mynode.example.com",
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &Headscale{
				cfg: &types.Config{
					BaseDomain: tt.baseDomain,
				},
			}
			node := mockHostnameNode{hostname: tt.hostname}

			got := h.validateCertDNSName(node, tt.dnsName)
			assert.Equal(t, tt.want, got)
		})
	}
}
