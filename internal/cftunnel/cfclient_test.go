package cftunnel_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"vanora-relay/internal/cftunnel"
)

func TestCFClientEndpoints(t *testing.T) {
	const tunnel = "/client/v4/accounts/account/cfd_tunnel"
	const zone = "/client/v4/zones/zone"
	type exchange struct {
		method, path, query, payload, result string
	}
	requests := []exchange{
		{"POST", tunnel, "", `{"name":"named","config_src":"cloudflare","tunnel_secret":"AQID"}`, `{"id":"id","name":"named","config_src":"cloudflare"}`},
		{"GET", tunnel, "include_prefix=vr-site&is_deleted=false&name=named&page=2&per_page=3&status=down", "", `[]`},
		{"GET", tunnel + "/id", "", "", `{"id":"id","name":"named","status":"down","created_at":"2026-01-01T00:00:00Z","conns_inactive_at":"2026-01-01T01:00:00Z","deleted_at":null,"config_src":"cloudflare"}`},
		{"GET", tunnel + "/id/configurations", "", "", `{"version":4,"config":{"ingress":[{"hostname":"a.example.com","path":"^/a","service":"http://127.0.0.1:8321"},{"service":"http_status:404"}],"warp-routing":{"enabled":true}}}`},
		{"PUT", tunnel + "/id/configurations", "", `{"config":{"ingress":[{"hostname":"a.example.com","service":"http://127.0.0.1:8321"},{"service":"http_status:404"}],"warp-routing":{"enabled":false}}}`, `{}`},
		{"GET", tunnel + "/id/token", "", "", `"connector-token"`},
		{"PATCH", tunnel + "/id", "", `{"tunnel_secret":"AQID"}`, `{}`},
		{"GET", tunnel + "/id/connections", "page=1&per_page=50", "", `[{"id":"connector","conns":[{"id":"edge","is_pending_reconnect":true}]}]`},
		{"DELETE", tunnel + "/id/connections", "", "", `{}`},
		{"DELETE", tunnel + "/id", "", "", `{}`},
		{"GET", zone, "", "", `{"id":"zone","name":"example.com","status":"active","account":{"id":"account"}}`},
		{"GET", zone + "/dns_records", "name.exact=a.example.com&page=1&per_page=100", "", `[{"id":"first"}]`},
		{"GET", zone + "/dns_records", "name.exact=a.example.com&page=2&per_page=100", "", `[{"id":"second"}]`},
		{"GET", zone + "/dns_records", "comment.startswith=vr1%3A&page=3&per_page=20&type=CNAME", "", `[]`},
		{"POST", zone + "/dns_records", "", `{"type":"CNAME","name":"a.example.com","content":"id.cfargotunnel.com","ttl":1,"proxied":true,"comment":"marker"}`, `{"id":"record"}`},
		{"PATCH", zone + "/dns_records/record", "", `{"type":"CNAME","name":"a.example.com","content":"id.cfargotunnel.com","ttl":1,"proxied":true,"comment":"marker"}`, `{"id":"record"}`},
		{"DELETE", zone + "/dns_records/record", "", "", `{}`},
	}
	var count atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		index := int(count.Add(1) - 1)
		if index >= len(requests) {
			t.Errorf("unexpected additional request %s %s", r.Method, r.URL)
			http.Error(w, "extra", 500)
			return
		}
		req := requests[index]
		auth := "Bearer tunnel-secret"
		if strings.HasPrefix(req.path, zone) {
			auth = "Bearer dns-secret"
		}
		if r.Method != req.method || r.URL.Path != req.path || r.URL.RawQuery != req.query || r.Header.Get("Authorization") != auth {
			t.Errorf("request %d = %s %s", index, r.Method, r.URL)
		}
		if req.payload != "" {
			var got, want any
			if json.NewDecoder(r.Body).Decode(&got) != nil || json.Unmarshal([]byte(req.payload), &want) != nil || !reflect.DeepEqual(got, want) {
				t.Errorf("request %d payload = %v, want %s", index, got, req.payload)
			}
		}
		info := `{}`
		if index == 1 || index == 11 || index == 12 {
			info = `{"total_pages":2,"total_count":2}`
		}
		fmt.Fprintf(w, `{"success":true,"result":%s,"result_info":%s}`, req.result, info)
	}))
	defer server.Close()
	cf := testCFClient(t, server, cftunnel.CFClientOptions{})
	ctx := t.Context()
	secret := []byte{1, 2, 3}
	created, err := cf.CreateTunnel(ctx, "named", secret)
	if err != nil || created.ID != "id" {
		t.Fatalf("create: %+v %v", created, err)
	}
	page, err := cf.ListTunnels(ctx, cftunnel.TunnelListQuery{Name: "named", IncludePrefix: "vr-site", Status: cftunnel.TunnelDown, Page: 2, PerPage: 3})
	if err != nil || page.TotalCount != 2 || page.TotalPages != 2 {
		t.Fatalf("list: %+v %v", page, err)
	}
	got, err := cf.GetTunnel(ctx, "id")
	if err != nil || got.Status != cftunnel.TunnelDown || !got.DeletedAt.IsZero() || got.ConnsInactiveAt.Sub(got.CreatedAt) != time.Hour {
		t.Fatalf("get: %+v %v", got, err)
	}
	config, err := cf.GetConfiguration(ctx, "id")
	if err != nil || config.Version != 4 || !config.WarpRoutingEnabled || config.Ingress[0].Path != "^/a" {
		t.Fatalf("configuration: %+v %v", config, err)
	}
	config.WarpRoutingEnabled, config.Ingress[0].Path = false, ""
	check(t, cf.PutConfiguration(ctx, "id", config))
	token, err := cf.GetToken(ctx, "id")
	if err != nil || token != "connector-token" {
		t.Fatal("unexpected connector token result", err)
	}
	check(t, cf.RotateSecret(ctx, "id", secret))
	connections, err := cf.ListConnections(ctx, "id")
	if err != nil || len(connections) != 1 || !connections[0].IsPendingReconnect {
		t.Fatalf("connections: %+v %v", connections, err)
	}
	check(t, cf.DisconnectAll(ctx, "id"))
	check(t, cf.DeleteTunnel(ctx, "id"))
	gotZone, err := cf.GetZone(ctx)
	if err != nil || gotZone.AccountID != "account" || gotZone.Status != "active" {
		t.Fatalf("zone: %+v %v", gotZone, err)
	}
	records, err := cf.ListDNSRecords(ctx, "a.example.com")
	if err != nil || len(records) != 2 || records[1].ID != "second" {
		t.Fatalf("dns list: %+v %v", records, err)
	}
	_, err = cf.ListMarkedDNSRecords(ctx, 3, 20)
	check(t, err)
	record := cftunnel.DNSRecord{Hostname: "a.example.com", Target: "id.cfargotunnel.com", Comment: "marker"}
	first, err := cf.CreateDNSRecord(ctx, record)
	if err != nil || first.ID != "record" {
		t.Fatalf("dns create: %+v %v", first, err)
	}
	record.ID = first.ID
	_, err = cf.PatchDNSRecord(ctx, record)
	check(t, err)
	check(t, cf.DeleteDNSRecord(ctx, first.ID))
	if int(count.Load()) != len(requests) {
		t.Fatalf("requests = %d, want %d", count.Load(), len(requests))
	}
}

func TestCFClientErrorClassification(t *testing.T) {
	now := time.Date(2026, 11, 26, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, body, retry, limits string
		status                    int
		want                      error
		delay                     time.Duration
	}{
		{"resource missing", `{"success":false}`, "", "", 404, cftunnel.ErrCFNotFound, 0},
		{"auth disguised as missing", `{"errors":[{"code":10000}]}`, "", "", 404, cftunnel.ErrCFAuthorization, 0},
		{"name conflict", `{"errors":[{"message":"That name already exists"}]}`, "", "", 400, cftunnel.ErrCFConflict, 0},
		{"missing config", `{"errors":[{"code":1055}]}`, "", "", 400, cftunnel.ErrCFConfigNotFound, 0},
		{"active connections", `{"errors":[{"message":"This tunnel has active connections"}]}`, "", "", 400, cftunnel.ErrCFTunnelInUse, 0},
		{"non-JSON 429", "dns-secret", "12", "", 429, cftunnel.ErrCFRateLimited, 12 * time.Second},
		{"date and policy", "", now.Add(17 * time.Second).Format(http.TimeFormat), `"default";r=0;t=22, "other";r=2;t=50`, 429, cftunnel.ErrCFRateLimited, 22 * time.Second},
		{"default delay", "", "", "", 429, cftunnel.ErrCFRateLimited, time.Minute},
		{"non-JSON success", "tunnel-secret", "", "", 200, cftunnel.ErrCFTransient, 0},
		{"upstream unavailable", `{"errors":[{"message":"dns-secret"}]}`, "", "", 503, cftunnel.ErrCFTransient, 0},
		{"body limit", strings.Repeat(" ", (2<<20)+1), "", "", 200, cftunnel.ErrCFTransient, 0},
		{"redirect", "", "", "", 307, cftunnel.ErrCFTransient, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var count atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				count.Add(1)
				w.Header().Set("Cf-Ray", "request-123")
				w.Header().Set("Retry-After", tc.retry)
				w.Header().Set("Ratelimit", tc.limits)
				w.Header().Set("Location", "/redirect-should-not-follow")
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			}))
			defer server.Close()
			cf := testCFClient(t, server, cftunnel.CFClientOptions{Clock: func() time.Time { return now }, HTTPClient: &http.Client{
				CheckRedirect: func(*http.Request, []*http.Request) error { return nil },
			}})
			_, err := cf.GetConfiguration(t.Context(), "id")
			if !errors.Is(err, tc.want) || count.Load() != 1 || strings.Contains(err.Error(), "secret") {
				t.Fatalf("error = %v, requests = %d", err, count.Load())
			}
			var rate cftunnel.CFRateLimitError
			if tc.delay != 0 && (!errors.As(err, &rate) || rate.RetryAfter != tc.delay) {
				t.Fatalf("incorrect delay: %+v", rate)
			}
			var transient cftunnel.CFTransientError
			if tc.want == cftunnel.ErrCFTransient && (!errors.As(err, &transient) || transient.RequestID != "request-123") {
				t.Fatalf("request ID missing: %+v", transient)
			}
		})
	}
}

func testCFClient(t *testing.T, server *httptest.Server, opts cftunnel.CFClientOptions) *cftunnel.CFClient {
	t.Helper()
	opts.BaseURL = server.URL + "/client/v4"
	cf, err := cftunnel.NewCFClient(cftunnel.Config{AccountID: "account", ZoneID: "zone", TunnelToken: "tunnel-secret", DNSToken: "dns-secret"}, opts)
	check(t, err)
	return cf
}

func check(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
