package middleware

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

// fakeAuthServer is the authorization service the scope tests talk to. It
// records every POST /v1/authorize it receives, raw and decoded, in order, and
// answers each with what answer returns for it: a string is written as the
// body as is, any other value is encoded as JSON. Any other method or path
// fails the test and is answered 404, so a client that stops building the
// authorize request correctly cannot pass by being answered anyway.
type fakeAuthServer struct {
	*httptest.Server

	hits atomic.Int64

	mu     sync.Mutex
	calls  []authorizeCall
	answer func(authorizeCall) any
}

// authorizeCall is one /v1/authorize request the fake received.
type authorizeCall struct {
	// raw is the body exactly as sent. The RAW bytes are what the
	// payload-compatibility assertions compare, so an added member, a
	// reordered key or a changed encoding all show up.
	raw string
	// body is the decoded attributes.
	body authorizeRequestBody
}

// authorizeRequestBody is the part of an authorize body a scripted answer
// reads.
type authorizeRequestBody struct {
	Attributes map[string]string `json:"attributes"`
}

func newFakeAuthServer(t *testing.T, answer func(authorizeCall) any) *fakeAuthServer {
	t.Helper()

	srv := &fakeAuthServer{answer: answer}

	srv.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/authorize" {
			t.Errorf("mock authz server: unexpected request %s %s, want POST /v1/authorize", r.Method, r.URL.Path)
			http.Error(w, `{"code":"unexpected_request"}`, http.StatusNotFound)

			return
		}

		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("mock authz server: failed to read body: %v", err)
		}

		var body authorizeRequestBody
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Errorf("mock authz server: failed to decode body: %v", err)
		}

		call := authorizeCall{raw: string(raw), body: body}

		srv.mu.Lock()
		srv.calls = append(srv.calls, call)
		answer := srv.answer
		srv.mu.Unlock()
		srv.hits.Add(1)

		w.Header().Set("Content-Type", "application/json")

		reply := answer(call)
		if text, ok := reply.(string); ok {
			_, _ = w.Write([]byte(text))

			return
		}

		if err := json.NewEncoder(w).Encode(reply); err != nil {
			t.Errorf("mock authz server: failed to encode response: %v", err)
		}
	}))

	t.Cleanup(srv.Close)

	return srv
}

// newRecordingAuthServer answers every question with resp.
func newRecordingAuthServer(t *testing.T, resp AuthResponse) *fakeAuthServer {
	t.Helper()

	return newFakeAuthServer(t, func(authorizeCall) any { return resp })
}

// newDecidingAuthServer answers ALLOW unless the question's attributes carry
// one of the denied values. It is what lets a batch test prove that ONE value
// outside the scope refuses the whole request.
func newDecidingAuthServer(t *testing.T, denied ...string) *fakeAuthServer {
	t.Helper()

	refused := make(map[string]bool, len(denied))
	for _, v := range denied {
		refused[v] = true
	}

	return newDecidingAuthServerFunc(t, func(attributes map[string]string) bool {
		for _, v := range attributes {
			if refused[v] {
				return false
			}
		}

		return true
	})
}

// newDecidingAuthServerFunc is a deciding server whose answer to each question
// is allow's.
func newDecidingAuthServerFunc(t *testing.T, allow func(attributes map[string]string) bool) *fakeAuthServer {
	t.Helper()

	return newFakeAuthServer(t, func(call authorizeCall) any {
		return AuthResponse{Authorized: allow(call.body.Attributes)}
	})
}

// newScriptedAuthServer answers each question with what answer returns for its
// decoded body.
func newScriptedAuthServer(t *testing.T, answer func(authorizeRequestBody) string) *fakeAuthServer {
	t.Helper()

	return newFakeAuthServer(t, func(call authorizeCall) any { return answer(call.body) })
}

func (srv *fakeAuthServer) received() []authorizeCall {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	return append([]authorizeCall(nil), srv.calls...)
}

// requests returns every raw body received, in order.
func (srv *fakeAuthServer) requests() []string {
	calls := srv.received()

	var bodies []string
	for _, call := range calls {
		bodies = append(bodies, call.raw)
	}

	return bodies
}

// lastBody returns the raw body of the last request, failing the test when
// there was none.
func (srv *fakeAuthServer) lastBody(t *testing.T) string {
	t.Helper()

	bodies := srv.requests()
	require.NotEmpty(t, bodies, "authz server was never called")

	return bodies[len(bodies)-1]
}

// attributeCalls returns the attributes of every request, in order.
func (srv *fakeAuthServer) attributeCalls() []map[string]string {
	calls := srv.received()

	var attributes []map[string]string
	for _, call := range calls {
		attributes = append(attributes, call.body.Attributes)
	}

	return attributes
}
