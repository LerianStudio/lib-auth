package middleware

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// questionSet accumulates the distinct questions of a request in order. Each
// question carries the dimensions the body names for it and the values the
// other carriers name: a dimension those carriers name several values of asks
// one question per value. Every question must be allowed.
type questionSet struct {
	plan      *bodyPlan
	readings  requestValues
	seen      map[string]struct{}
	questions []map[string]string
	// carried records, per dimension the other carriers name, the values the
	// questions carry, so a value they name and the body never does is caught.
	carried map[string]map[string]struct{}
}

func newQuestionSet(plan *bodyPlan, readings requestValues) *questionSet {
	return &questionSet{plan: plan, readings: readings, seen: make(map[string]struct{}), carried: make(map[string]map[string]struct{})}
}

// add adds the questions one set of body values makes, each combined with
// every value the other carriers name for a dimension the body leaves out.
// locations name where in the body each of those values was read. A body value
// another carrier does not name for the same dimension is a disagreement
// between the two.
func (q *questionSet) add(values, locations map[string]string) *errBodyScope {
	for _, name := range sortedKeys(values) {
		if named, ok := q.readings.values[name]; ok && !containsValue(named, values[name]) {
			return divergence(name, q.readings.where[name], locations[name])
		}
	}

	questions := []map[string]string{values}

	for _, name := range q.readings.names {
		if _, inBody := values[name]; inBody {
			continue
		}

		// The values of one carrier are distinct, so every combination is: the
		// count is exact, and refusing past the cap here never builds them.
		named := q.readings.values[name]
		if len(questions)*len(named) > maxBodyScopeQuestions {
			return q.tooMany()
		}

		next := make([]map[string]string, 0, len(questions)*len(named))
		for _, question := range questions {
			next = append(next, withEach(question, name, named)...)
		}

		questions = next
	}

	for _, question := range questions {
		if err := q.addOne(question); err != nil {
			return err
		}
	}

	return nil
}

// addOne adds a question, once.
func (q *questionSet) addOne(question map[string]string) *errBodyScope {
	key := attributesCacheKey(question)
	if _, dup := q.seen[key]; dup {
		return nil
	}

	if len(q.questions) == maxBodyScopeQuestions {
		return q.tooMany()
	}

	q.seen[key] = struct{}{}
	q.questions = append(q.questions, question)

	for name, value := range question {
		if _, ok := q.readings.values[name]; !ok {
			continue
		}

		if q.carried[name] == nil {
			q.carried[name] = make(map[string]struct{})
		}

		q.carried[name][value] = struct{}{}
	}

	return nil
}

// complete checks that every value another carrier names for a dimension the
// body also names is carried by some question: one the body never names is a
// disagreement between the two.
func (q *questionSet) complete() *errBodyScope {
	if q.plan == nil {
		return nil
	}

	for _, name := range q.readings.names {
		field, inBody := q.plan.firstField[name]
		if !inBody {
			continue
		}

		for _, value := range q.readings.values[name] {
			if _, ok := q.carried[name][value]; !ok {
				return divergence(name, q.readings.where[name], field)
			}
		}
	}

	return nil
}

func (q *questionSet) tooMany() *errBodyScope {
	locations := make([]string, 0, len(q.readings.names)+1)
	for _, name := range q.readings.names {
		locations = append(locations, q.readings.where[name])
	}

	if q.plan != nil {
		for _, f := range q.plan.fields {
			locations = append(locations, "body field "+strconv.Quote(f))
		}
	}

	return &errBodyScope{message: fmt.Sprintf(
		"the request names more than %d distinct sets of scope values in %s",
		maxBodyScopeQuestions, strings.Join(locations, ", "))}
}

// withEach returns question with name set to each of values, one copy per
// value.
func withEach(question map[string]string, name string, values []string) []map[string]string {
	out := make([]map[string]string, 0, len(values))

	for _, value := range values {
		next := make(map[string]string, len(question)+1)
		for k, v := range question {
			next[k] = v
		}

		next[name] = value
		out = append(out, next)
	}

	return out
}

func containsValue(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}

	return false
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	return keys
}

// sharedAttributes returns the identifiers every question carries with the same
// value: the whole question when there is one.
func sharedAttributes(questions []map[string]string) map[string]string {
	if len(questions) == 0 {
		return nil
	}

	shared := make(map[string]string, len(questions[0]))
	for name, value := range questions[0] {
		shared[name] = value
	}

	for _, question := range questions[1:] {
		for name, value := range shared {
			if question[name] != value {
				delete(shared, name)
			}
		}
	}

	return shared
}
