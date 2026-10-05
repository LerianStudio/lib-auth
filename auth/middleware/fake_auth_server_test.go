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
// body as is, any other value is encoded as JSON.
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
	// body is the decoded attributes and filter.
	body authorizeRequestBody
	// pending is the decoded pending member, and pendingSent whether the body
	// carried one at all.
	pending     []string
	pendingSent bool
}

// authorizeRequestBody is the part of an authorize body a scripted answer
// reads.
type authorizeRequestBody struct {
	Attributes map[string]string `json:"attributes"`
	Filter     []string          `json:"filter"`
}

// pendingCall is one /v1/authorize body as the pending tests read it: the
// attributes asked, and the pending member — with whether it was sent at all.
type pendingCall struct {
	attributes map[string]string
	pending    []string
	sent       bool
}

func newFakeAuthServer(t *testing.T, answer func(authorizeCall) any) *fakeAuthServer {
	t.Helper()

	srv := &fakeAuthServer{answer: answer}

	srv.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("mock authz server: failed to read body: %v", err)
		}

		var body struct {
			authorizeRequestBody
			Pending json.RawMessage `json:"pending"`
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Errorf("mock authz server: failed to decode body: %v", err)
		}

		call := authorizeCall{raw: string(raw), body: body.authorizeRequestBody, pendingSent: body.Pending != nil}
		if call.pendingSent {
			if err := json.Unmarshal(body.Pending, &call.pending); err != nil {
				t.Errorf("mock authz server: pending is not a list of names: %s", body.Pending)
			}
		}

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

// newPendingAuthServer allows every question. With coversRule set it answers
// like a service applying the covers rule to accountId: a question that names
// no accountId and does not declare it pending is denied.
func newPendingAuthServer(t *testing.T, coversRule bool) *fakeAuthServer {
	t.Helper()

	return newFakeAuthServer(t, func(call authorizeCall) any {
		authorized := true

		if coversRule && len(call.body.Attributes) > 0 {
			if _, named := call.body.Attributes["accountId"]; !named && !contains(call.pending, "accountId") {
				authorized = false
			}
		}

		return AuthResponse{Authorized: authorized}
	})
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

// recorded returns every request as the pending tests read it, in order.
func (srv *fakeAuthServer) recorded() []pendingCall {
	calls := srv.received()

	var recorded []pendingCall
	for _, call := range calls {
		recorded = append(recorded, pendingCall{attributes: call.body.Attributes, pending: call.pending, sent: call.pendingSent})
	}

	return recorded
}
