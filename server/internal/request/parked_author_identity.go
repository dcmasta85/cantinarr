package request

import (
	"log"
	"strings"

	"github.com/windoze95/cantinarr-server/internal/chaptarr"
)

// lookupParkedAuthorID resolves the Chaptarr author behind a parked book.
// Chaptarr can answer a Goodreads work lookup with its canonical Hardcover
// book ID, so compare the explicit provider identity keys as well as the
// native ID. Never fall back to title-only matching: a wrong author import is
// worse than leaving the request for review.
func (s *Service) lookupParkedAuthorID(client *chaptarr.Client, foreignID string) (string, bool) {
	foreignID = strings.TrimSpace(foreignID)
	results, err := client.LookupBook(foreignID)
	if err != nil {
		log.Printf("request: lookup parked book %q author: %v", foreignID, err)
		return "", false
	}

	// The requested native ID is the strongest match. If Chaptarr doesn't
	// return it, accept only an explicit, typed cross-provider alias carried
	// by the lookup result (e.g. Goodreads work ID -> Hardcover book ID).
	exact := make([]chaptarr.LookupResult, 0, len(results))
	for _, result := range results {
		if strings.TrimSpace(result.ForeignBookID) == foreignID {
			exact = append(exact, result)
		}
	}
	if len(exact) > 0 {
		return authorIDFromBookLookupResults(client, exact)
	}

	requestedKeys := make(map[string]struct{})
	for _, key := range chaptarr.NativeBookIdentityKeys(foreignID) {
		requestedKeys[key] = struct{}{}
	}
	aliases := make([]chaptarr.LookupResult, 0, len(results))
	for _, result := range results {
		for _, key := range result.IdentityKeys() {
			if _, matches := requestedKeys[key]; matches {
				aliases = append(aliases, result)
				break
			}
		}
	}
	return authorIDFromBookLookupResults(client, aliases)
}

// authorIDFromBookLookupResults tolerates Chaptarr returning duplicate rows,
// but refuses conflicting native books or authors. If the book has an
// explicit author name but no author ID, resolve that name separately and
// accept only one exact-name provider identity.
func authorIDFromBookLookupResults(client *chaptarr.Client, results []chaptarr.LookupResult) (string, bool) {
	if len(results) == 0 {
		return "", true
	}

	bookIDs := make(map[string]struct{})
	authorIDs := make(map[string]struct{})
	authorNames := make(map[string]string)
	for _, result := range results {
		bookID := strings.TrimSpace(result.ForeignBookID)
		if bookID == "" {
			return "", true
		}
		bookIDs[bookID] = struct{}{}

		authorID := strings.TrimSpace(result.ForeignAuthorID)
		authorName := strings.TrimSpace(result.AuthorName)
		if result.Author != nil {
			if authorID == "" {
				authorID = strings.TrimSpace(result.Author.ForeignAuthorID)
			}
			if authorName == "" {
				authorName = strings.TrimSpace(result.Author.AuthorName)
			}
		}
		if authorID != "" {
			authorIDs[authorID] = struct{}{}
		}
		if key := normalizeBookAuthorName(authorName); key != "" {
			authorNames[key] = authorName
		}
	}
	if len(bookIDs) != 1 || len(authorIDs) > 1 {
		return "", true
	}
	if len(authorIDs) == 1 {
		for id := range authorIDs {
			return id, true
		}
	}
	if len(authorNames) != 1 {
		return "", true
	}

	var expectedName string
	for expectedName = range authorNames {
	}
	authorResults, err := client.LookupAuthor(authorNames[expectedName])
	if err != nil {
		log.Printf("request: lookup parked book author %q: %v", authorNames[expectedName], err)
		return "", false
	}
	authorIDs = make(map[string]struct{})
	for _, result := range authorResults {
		name := result.AuthorName
		if name == "" && result.Author != nil {
			name = result.Author.AuthorName
		}
		if normalizeBookAuthorName(name) != expectedName {
			continue
		}
		authorID := strings.TrimSpace(result.ForeignAuthorID)
		if authorID == "" && result.Author != nil {
			authorID = strings.TrimSpace(result.Author.ForeignAuthorID)
		}
		if authorID != "" {
			authorIDs[authorID] = struct{}{}
		}
	}
	if len(authorIDs) != 1 {
		return "", true
	}
	for id := range authorIDs {
		return id, true
	}
	return "", true
}

func normalizeBookAuthorName(name string) string {
	return strings.ToLower(strings.Join(strings.Fields(strings.TrimSpace(name)), " "))
}
