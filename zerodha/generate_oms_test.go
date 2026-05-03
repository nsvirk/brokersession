package zerodha

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/nsvirk/brokersession"
)

func omsServer(t *testing.T, login, twofa, profile http.HandlerFunc) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	if login == nil {
		login = func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("unexpected call to /api/login")
		}
	}
	if twofa == nil {
		twofa = func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("unexpected call to /api/twofa")
		}
	}
	if profile == nil {
		profile = func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("unexpected call to /oms/user/profile")
		}
	}
	mux.Handle("/api/login", login)
	mux.Handle("/api/twofa", twofa)
	mux.Handle("/oms/user/profile", profile)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	withEndpoints(t, map[*string]string{
		&urlLogin:   srv.URL + "/api/login",
		&urlTwoFA:   srv.URL + "/api/twofa",
		&urlProfile: srv.URL + "/oms/user/profile",
	})
	return srv
}

func TestDoLogin_HappyPath(t *testing.T) {
	var gotForm url.Values
	omsServer(t, func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		gotForm, _ = url.ParseQuery(string(raw))
		http.SetCookie(w, &http.Cookie{Name: "kf_session", Value: "kf-val", Path: "/"})
		_, _ = w.Write([]byte(`{"status":"success","data":{"user_id":"AB1234","request_id":"req-987"}}`))
	}, nil, nil)
	c := New()
	resp, cookies, err := c.doLogin(context.Background(), defaultTestClient(), c.defaultHeaders(), validCreds())
	if err != nil {
		t.Fatalf("doLogin error: %v", err)
	}
	if resp.Data.RequestID != "req-987" {
		t.Errorf("RequestID = %q, want req-987", resp.Data.RequestID)
	}
	if cookieValue(cookies, "kf_session") != "kf-val" {
		t.Errorf("kf_session cookie missing")
	}
	if gotForm.Get("user_id") != validCreds().UserID {
		t.Errorf("form.user_id = %q, want %q", gotForm.Get("user_id"), validCreds().UserID)
	}
	if gotForm.Get("password") != validCreds().Password {
		t.Errorf("form.password = %q, want %q", gotForm.Get("password"), validCreds().Password)
	}
	if gotForm.Get("type") != "user_id" {
		t.Errorf("form.type = %q, want user_id", gotForm.Get("type"))
	}
}

func TestDoLogin_KiteErrorEnvelope(t *testing.T) {
	omsServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"status":"error","message":"Invalid password","error_type":"UserException"}`))
	}, nil, nil)
	c := New()
	_, _, err := c.doLogin(context.Background(), defaultTestClient(), c.defaultHeaders(), validCreds())
	assertBSError(t, err, brokersession.BrokerZerodha, StepLogin, http.StatusForbidden, "Invalid password")

	var bsErr *brokersession.Error
	_ = bsErrAs(err, &bsErr)
	if bsErr.Raw["error_type"] != "UserException" {
		t.Errorf("Raw.error_type = %v, want UserException", bsErr.Raw["error_type"])
	}
}

func TestDoTwoFA_HappyPath(t *testing.T) {
	var gotForm url.Values
	omsServer(t, nil, func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		gotForm, _ = url.ParseQuery(string(raw))
		http.SetCookie(w, &http.Cookie{Name: "enctoken", Value: "enc-tok", Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: "public_token", Value: "pub-tok", Path: "/"})
		_, _ = w.Write([]byte(`{"status":"success"}`))
	}, nil)
	c := New()
	cookies, err := c.doTwoFA(context.Background(), defaultTestClient(), c.defaultHeaders(), validCreds(), "req-987")
	if err != nil {
		t.Fatalf("doTwoFA error: %v", err)
	}
	if cookieValue(cookies, "enctoken") != "enc-tok" {
		t.Errorf("enctoken cookie = %q, want enc-tok", cookieValue(cookies, "enctoken"))
	}
	if cookieValue(cookies, "public_token") != "pub-tok" {
		t.Errorf("public_token cookie = %q, want pub-tok", cookieValue(cookies, "public_token"))
	}
	if gotForm.Get("request_id") != "req-987" {
		t.Errorf("form.request_id = %q, want req-987", gotForm.Get("request_id"))
	}
	if got := gotForm.Get("twofa_value"); len(got) != 6 {
		t.Errorf("twofa_value = %q, want 6 digits", got)
	}
	if gotForm.Get("twofa_type") != "totp" {
		t.Errorf("twofa_type = %q, want totp", gotForm.Get("twofa_type"))
	}
}

// TestDoTwoFA_TOTPValuePassthrough proves that when Credentials.TOTPValue
// is set the library forwards it verbatim as twofa_value and skips TOTP
// generation entirely (so TOTPSecret is allowed to be empty).
func TestDoTwoFA_TOTPValuePassthrough(t *testing.T) {
	var gotForm url.Values
	omsServer(t, nil, func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		gotForm, _ = url.ParseQuery(string(raw))
		http.SetCookie(w, &http.Cookie{Name: "enctoken", Value: "enc-tok", Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: "public_token", Value: "pub-tok", Path: "/"})
		_, _ = w.Write([]byte(`{"status":"success"}`))
	}, nil)
	c := New()
	creds := validCreds()
	creds.TOTPSecret = ""
	creds.TOTPValue = "654321"
	if _, err := c.doTwoFA(context.Background(), defaultTestClient(), c.defaultHeaders(), creds, "req-987"); err != nil {
		t.Fatalf("doTwoFA error: %v", err)
	}
	if got := gotForm.Get("twofa_value"); got != "654321" {
		t.Errorf("twofa_value = %q, want 654321", got)
	}
}

func TestDoProfile_HappyPath(t *testing.T) {
	var gotAuth string
	omsServer(t, nil, nil, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"status":"success","data":{
			"user_id":"AB1234","user_name":"Some User","user_type":"individual",
			"email":"u@x.com","broker":"ZERODHA",
			"exchanges":["NSE"],"products":["CNC"],"order_types":["MARKET"]
		}}`))
	})
	c := New()
	prof, err := c.doProfile(context.Background(), defaultTestClient(), c.defaultHeaders(), "enc-tok")
	if err != nil {
		t.Fatalf("doProfile error: %v", err)
	}
	if gotAuth != "enctoken enc-tok" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "enctoken enc-tok")
	}
	if prof.Data.UserName != "Some User" {
		t.Errorf("UserName = %q, want Some User", prof.Data.UserName)
	}
	if len(prof.Data.Exchanges) != 1 || prof.Data.Exchanges[0] != "NSE" {
		t.Errorf("Exchanges = %v", prof.Data.Exchanges)
	}
}

// TestGenerateSession_OMSOnly_FullFlow drives only the OMS leg
// (APIKey/APISecret unset) and asserts the synthesized Raw shape.
func TestGenerateSession_OMSOnly_FullFlow(t *testing.T) {
	omsServer(t,
		func(w http.ResponseWriter, r *http.Request) {
			http.SetCookie(w, &http.Cookie{Name: "kf_session", Value: "kf-val", Path: "/"})
			_, _ = w.Write([]byte(`{"status":"success","data":{"user_id":"AB1234","request_id":"req-987"}}`))
		},
		func(w http.ResponseWriter, r *http.Request) {
			http.SetCookie(w, &http.Cookie{Name: "enctoken", Value: "enc-tok", Path: "/"})
			http.SetCookie(w, &http.Cookie{Name: "public_token", Value: "pub-tok", Path: "/"})
			_, _ = w.Write([]byte(`{"status":"success"}`))
		},
		func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"status":"success","data":{
				"user_id":"AB1234","user_name":"Some User","user_type":"individual",
				"email":"u@x.com","broker":"ZERODHA",
				"exchanges":["NSE"],"products":["CNC"],"order_types":["MARKET"]
			}}`))
		},
	)
	sess, err := New().GenerateSession(context.Background(), validCreds())
	if err != nil {
		t.Fatalf("GenerateSession error: %v", err)
	}
	if sess.Broker != brokersession.BrokerZerodha {
		t.Errorf("Broker = %s, want zerodha", sess.Broker)
	}
	if sess.Enctoken != "enc-tok" {
		t.Errorf("Enctoken = %q, want enc-tok", sess.Enctoken)
	}
	if sess.APIKey != "" || sess.AccessToken != "" {
		t.Errorf("OMS-only flow leaked API fields: APIKey=%q AccessToken=%q", sess.APIKey, sess.AccessToken)
	}
	if sess.IssuedAt == nil {
		t.Errorf("IssuedAt = nil")
	}
	// Synthesized Raw shape.
	data, ok := sess.Raw["data"].(map[string]any)
	if !ok {
		t.Fatalf("Raw.data not a map")
	}
	if data["enctoken"] != "enc-tok" {
		t.Errorf("Raw.data.enctoken = %v", data["enctoken"])
	}
	if data["public_token"] != "pub-tok" {
		t.Errorf("Raw.data.public_token = %v", data["public_token"])
	}
	if data["kf_session"] != "kf-val" {
		t.Errorf("Raw.data.kf_session = %v", data["kf_session"])
	}
	if _, ok := data["login_time"].(string); !ok {
		t.Errorf("Raw.data.login_time = %v, want string", data["login_time"])
	}
}

// bsErrAs walks err and binds the first *brokersession.Error to target.
func bsErrAs(err error, target **brokersession.Error) bool {
	if err == nil {
		return false
	}
	type unwrapper interface{ Unwrap() error }
	for cur := err; cur != nil; {
		if v, ok := cur.(*brokersession.Error); ok {
			*target = v
			return true
		}
		u, ok := cur.(unwrapper)
		if !ok {
			return false
		}
		cur = u.Unwrap()
	}
	return false
}
