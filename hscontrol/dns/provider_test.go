package dns

import (
	"context"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/libdns/libdns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockLibdnsProvider is a test double that records SetRecords/DeleteRecords
// calls without making real DNS requests.
type mockLibdnsProvider struct {
	setRecords    []libdns.Record
	deleteRecords []libdns.Record
	setZone       string
	deleteZone    string
	setErr        error
	deleteErr     error
}

func (m *mockLibdnsProvider) SetRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	m.setZone = zone
	m.setRecords = append(m.setRecords, recs...)

	return recs, m.setErr
}

func (m *mockLibdnsProvider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	m.deleteZone = zone
	m.deleteRecords = append(m.deleteRecords, recs...)

	return recs, m.deleteErr
}

func TestLibdnsProvider_SetRecord(t *testing.T) {
	mock := &mockLibdnsProvider{}
	p := &libdnsProvider{setter: mock, deleter: mock}

	record := NewTXTRecord("_acme-challenge.mynode", "test-token-value", 120)

	err := p.SetRecord(context.Background(), "example.com.", record)
	require.NoError(t, err)

	assert.Equal(t, "example.com.", mock.setZone)
	require.Len(t, mock.setRecords, 1)
}

func TestLibdnsProvider_DeleteRecord(t *testing.T) {
	mock := &mockLibdnsProvider{}
	p := &libdnsProvider{setter: mock, deleter: mock}

	record := NewTXTRecord("_acme-challenge.mynode", "test-token-value", 120)

	err := p.DeleteRecord(context.Background(), "example.com.", record)
	require.NoError(t, err)

	assert.Equal(t, "example.com.", mock.deleteZone)
	require.Len(t, mock.deleteRecords, 1)
}

func TestNewProvider_Disabled(t *testing.T) {
	cfg := types.CertConfig{
		Enabled: false,
	}

	provider, err := NewProvider(cfg)
	require.NoError(t, err)
	assert.Nil(t, provider)
}

func TestNewProvider_MissingProviderName(t *testing.T) {
	cfg := types.CertConfig{
		Enabled: true,
		DNSProvider: types.DNSProviderConfig{
			Name: "",
		},
	}

	_, err := NewProvider(cfg)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrMissingConfig)
}

func TestNewProvider_UnknownProvider(t *testing.T) {
	cfg := types.CertConfig{
		Enabled: true,
		DNSProvider: types.DNSProviderConfig{
			Name:   "nonexistent",
			Config: map[string]string{},
		},
	}

	_, err := NewProvider(cfg)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnknownProvider)
}

func TestNewProvider_CloudflareMissingToken(t *testing.T) {
	cfg := types.CertConfig{
		Enabled: true,
		DNSProvider: types.DNSProviderConfig{
			Name:   "cloudflare",
			Config: map[string]string{},
		},
	}

	_, err := NewProvider(cfg)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrMissingConfig)
}

func TestNewProvider_CloudflareSuccess(t *testing.T) {
	cfg := types.CertConfig{
		Enabled: true,
		DNSProvider: types.DNSProviderConfig{
			Name: "cloudflare",
			Config: map[string]string{
				"api_token": "test-token",
			},
		},
	}

	provider, err := NewProvider(cfg)
	require.NoError(t, err)
	assert.NotNil(t, provider)
}

func TestNewTXTRecord(t *testing.T) {
	rec := NewTXTRecord("_acme-challenge.node1", "challenge-value", 120)

	assert.Equal(t, "_acme-challenge.node1", rec.Name)
	assert.Equal(t, "challenge-value", rec.Text)
}
