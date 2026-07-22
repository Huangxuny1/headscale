package hscontrol

import (
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
)

type mockGivenNameNode struct {
	givenName string
}

func (m mockGivenNameNode) GivenName() string {
	return m.givenName
}

func TestValidateCertDNSName(t *testing.T) {
	tests := []struct {
		name       string
		baseDomain string
		givenName  string
		dnsName    string
		want       bool
	}{
		{
			name:       "valid acme challenge for node",
			baseDomain: "example.com",
			givenName:  "mynode",
			dnsName:    "_acme-challenge.mynode.example.com",
			want:       true,
		},
		{
			name:       "case insensitive match",
			baseDomain: "example.com",
			givenName:  "MyNode",
			dnsName:    "_acme-challenge.mynode.example.com",
			want:       true,
		},
		{
			name:       "wrong node hostname",
			baseDomain: "example.com",
			givenName:  "mynode",
			dnsName:    "_acme-challenge.othernode.example.com",
			want:       false,
		},
		{
			name:       "wrong domain",
			baseDomain: "example.com",
			givenName:  "mynode",
			dnsName:    "_acme-challenge.mynode.evil.com",
			want:       false,
		},
		{
			name:       "not an acme challenge",
			baseDomain: "example.com",
			givenName:  "mynode",
			dnsName:    "mynode.example.com",
			want:       false,
		},
		{
			name:       "empty base domain",
			baseDomain: "",
			givenName:  "mynode",
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
			node := mockGivenNameNode{givenName: tt.givenName}

			got := h.validateCertDNSName(node, tt.dnsName)
			assert.Equal(t, tt.want, got)
		})
	}
}
