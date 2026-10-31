package request

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/windoze95/cantinarr-server/internal/chaptarr"
)

func TestLookupParkedAuthorIDResolvesProviderAlias(t *testing.T) {
	const book = `{"title":"The Witch","authorName":null,"foreignBookId":"hc:2549388","foreignAuthorId":null,"goodreadsWorkId":"gr:284084888","hardcoverBookId":"hc:2549388","author":{"authorName":"Freida McFadden","foreignAuthorId":"hc:297579"}}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/book/lookup":
			// Chaptarr can return repeated rows for one aliased work.
			_, _ = w.Write([]byte("[" + book + "," + book + "," + book + "]"))
		case "/api/v1/author/lookup":
			t.Error("author lookup should not be needed when the book includes an author ID")
			_, _ = w.Write([]byte(`[]`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	got, known := (&Service{}).lookupParkedAuthorID(chaptarr.NewClient(server.URL, "key"), "gr:284084888")
	if !known || got != "hc:297579" {
		t.Fatalf("lookupParkedAuthorID = (%q, %v), want (%q, true)", got, known, "hc:297579")
	}
}

func TestLookupParkedAuthorIDUsesUniqueExactAuthorFallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/book/lookup":
			_, _ = w.Write([]byte(`[{"title":"The Witch","foreignBookId":"hc:2549388","goodreadsWorkId":"gr:284084888","author":{"authorName":"Freida McFadden"}}]`))
		case "/api/v1/author/lookup":
			_, _ = w.Write([]byte(`[
				{"authorName":"Freida McFadden","foreignAuthorId":"gr:7244758"},
				{"authorName":"Freida McFadden","foreignAuthorId":"gr:7244758"},
				{"authorName":"Freida McFadden-Smith","foreignAuthorId":"gr:999"}
			]`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	got, known := (&Service{}).lookupParkedAuthorID(chaptarr.NewClient(server.URL, "key"), "gr:284084888")
	if !known || got != "gr:7244758" {
		t.Fatalf("lookupParkedAuthorID = (%q, %v), want (%q, true)", got, known, "gr:7244758")
	}
}

func TestLookupParkedAuthorIDFailsClosedOnAmbiguousAliases(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/api/v1/book/lookup" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`[
			{"title":"The Witch","foreignBookId":"hc:2549388","goodreadsWorkId":"gr:284084888","author":{"authorName":"Freida McFadden","foreignAuthorId":"hc:297579"}},
			{"title":"The Witch","foreignBookId":"hc:9999999","goodreadsWorkId":"gr:284084888","author":{"authorName":"Different Author","foreignAuthorId":"hc:999"}}
		]`))
	}))
	defer server.Close()

	got, known := (&Service{}).lookupParkedAuthorID(chaptarr.NewClient(server.URL, "key"), "gr:284084888")
	if !known || got != "" {
		t.Fatalf("lookupParkedAuthorID = (%q, %v), want unresolved identity (empty, true)", got, known)
	}
}

func TestLookupParkedAuthorIDDoesNotUseTitleOnlyAlias(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"title":"The Witch","foreignBookId":"hc:2549388","author":{"authorName":"Freida McFadden","foreignAuthorId":"hc:297579"}}]`))
	}))
	defer server.Close()

	got, known := (&Service{}).lookupParkedAuthorID(chaptarr.NewClient(server.URL, "key"), "gr:284084888")
	if !known || got != "" {
		t.Fatalf("lookupParkedAuthorID = (%q, %v), want unresolved identity (empty, true)", got, known)
	}
}

func TestLookupParkedAuthorIDPrefersExactNativeIdentity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[
			{"title":"The Witch","foreignBookId":"gr:284084888","foreignAuthorId":"gr:author-exact"},
			{"title":"The Witch","foreignBookId":"hc:2549388","goodreadsWorkId":"gr:284084888","foreignAuthorId":"hc:author-alias"}
		]`))
	}))
	defer server.Close()

	got, known := (&Service{}).lookupParkedAuthorID(chaptarr.NewClient(server.URL, "key"), "gr:284084888")
	if !known || got != "gr:author-exact" {
		t.Fatalf("lookupParkedAuthorID = (%q, %v), want exact author ID, got (%q, true)", got, known, "gr:author-exact")
	}
}
