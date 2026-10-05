package middleware

import (
	"fmt"
	"strconv"
	"strings"
)

// questionSet accumulates the distinct questions of a request in order. Each
// question carries the dimensions the body names for it and the values the
// other carriers name: a dimension those carriers name several values of asks
// one question per value.
//
// The questions are decided in groups: a group is allowed when one of its
// questions is. A question stands alone in its group, except those carrying a
// value resolved with MatchAny, which share a group with the questions
// carrying the other values the same request value resolved to.
type questionSet struct {
	plan      *bodyPlan
	readings  requestValues
	seen      map[string]int
	questions []map[string]string
	// groups are the indexes into questions of each group, in the order made.
	groups [][]int
	// carried records, per dimension the other carriers name, the values the
	// questions carry, so a value they name and the body never does is caught.
	carried map[string]map[string]struct{}
	// resolvedAt locates the resolved value the questions being added carry,
	// "" when they carry none; located holds it per question.
	resolvedAt string
	located    []string
	// unioned holds the dimensions the body and another carrier both name
	// where one of the two is resolved: the values of each are asked, rather
	// than checked for agreement.
	unioned map[string]bool
}

func newQuestionSet(plan *bodyPlan, readings requestValues) *questionSet {
	return &questionSet{
		plan: plan, readings: readings, seen: make(map[string]int), carried: make(map[string]map[string]struct{}),
		resolvedAt: readings.resolvedAt,
	}
}

// add adds the questions one set of body values makes. locations name where in
// the body each of those values was read.
func (q *questionSet) add(values, locations map[string]string) *errBodyScope {
	return q.addGroup([]map[string]string{values}, locations, nil)
}

// addGroup adds the questions one group of alternative sets of body values
// makes: the alternatives name the same dimensions, and the request is allowed
// on one of them. An alternative naming a value another carrier does not name
// for the same dimension is dropped; when every one is, the two disagree.
// resolved names the dimensions whose body values were resolved: those, and
// the dimensions another carrier resolved, are not checked for agreement.
func (q *questionSet) addGroup(alternatives []map[string]string, locations, resolved map[string]string) *errBodyScope {
	alternatives, problem := q.agreeing(alternatives, locations, resolved)
	if problem != nil {
		return problem
	}

	// Each requirement is a group: one of its questions must be allowed.
	requirements := [][]map[string]string{alternatives}
	count := len(alternatives)

	for _, name := range q.readings.names {
		if _, inBody := alternatives[0][name]; inBody {
			continue
		}

		// The values of one carrier are distinct, so every combination is: the
		// count is exact, and refusing past the cap here never builds them.
		perRequirement := q.valueCount(name)
		if count*perRequirement > maxBodyScopeQuestions {
			return q.tooMany()
		}

		count *= perRequirement

		items := q.items(name)
		next := make([][]map[string]string, 0, len(requirements)*len(items))

		for _, requirement := range requirements {
			for _, item := range items {
				next = append(next, withEach(requirement, name, item))
			}
		}

		requirements = next
	}

	for _, requirement := range requirements {
		if err := q.addRequirement(requirement); err != nil {
			return err
		}
	}

	return nil
}

// valueCount is the number of values the other carriers name for name, every
// value of every request value resolved with MatchAny counted.
func (q *questionSet) valueCount(name string) int {
	items, matchAny := q.readings.anyOf[name]
	if !matchAny {
		return len(q.readings.values[name])
	}

	count := 0
	for _, item := range items {
		count += len(item)
	}

	return count
}

// items are the values the other carriers name for name, as the requirements
// they make: one per value of a dimension matching all; one per request value
// of a dimension resolved with MatchAny, its resolved values the alternatives.
func (q *questionSet) items(name string) [][]string {
	if items, matchAny := q.readings.anyOf[name]; matchAny {
		return items
	}

	items := make([][]string, 0, len(q.readings.values[name]))
	for _, value := range q.readings.values[name] {
		items = append(items, []string{value})
	}

	return items
}

// agreeing returns the alternatives whose every value another carrier naming
// the same dimension names too, or the disagreement when there is none. A
// dimension resolved on either side is recorded as unioned instead.
func (q *questionSet) agreeing(alternatives []map[string]string, locations, resolved map[string]string) ([]map[string]string, *errBodyScope) {
	var (
		kept    []map[string]string
		problem *errBodyScope
	)

	for _, values := range alternatives {
		diverges := false

		for _, name := range sortedKeys(values) {
			named, ok := q.readings.values[name]
			if !ok {
				continue
			}

			if _, bodyResolved := resolved[name]; bodyResolved || q.readings.derived[name] {
				q.markUnioned(name)

				continue
			}

			if !containsValue(named, values[name]) {
				if problem == nil {
					problem = divergence(name, q.readings.where[name], locations[name])
				}

				diverges = true

				break
			}
		}

		if !diverges {
			kept = append(kept, values)
		}
	}

	if len(kept) == 0 {
		return nil, problem
	}

	return kept, nil
}

// markUnioned records that the values of name on both sides are asked.
func (q *questionSet) markUnioned(name string) {
	if q.unioned == nil {
		q.unioned = make(map[string]bool)
	}

	q.unioned[name] = true
}

// addRequirement adds the questions of one group and records the group. A
// question several groups share is added once, and decided once.
func (q *questionSet) addRequirement(alternatives []map[string]string) *errBodyScope {
	group := make([]int, 0, len(alternatives))

	for _, question := range alternatives {
		index, err := q.addOne(question)
		if err != nil {
			return err
		}

		group = append(group, index)
	}

	q.groups = append(q.groups, group)

	return nil
}

// addOne adds a question, once, and returns its index.
func (q *questionSet) addOne(question map[string]string) (int, *errBodyScope) {
	key := attributesCacheKey(question)
	if index, dup := q.seen[key]; dup {
		return index, nil
	}

	if len(q.questions) == maxBodyScopeQuestions {
		return 0, q.tooMany()
	}

	q.seen[key] = len(q.questions)
	q.questions = append(q.questions, question)
	q.located = append(q.located, q.resolvedAt)

	for name, value := range question {
		if _, ok := q.readings.values[name]; !ok {
			continue
		}

		if q.carried[name] == nil {
			q.carried[name] = make(map[string]struct{})
		}

		q.carried[name][value] = struct{}{}
	}

	return len(q.questions) - 1, nil
}

// complete checks that every value another carrier names for a dimension the
// body also names is carried by some question: one the body never names is a
// disagreement between the two. When one side of the two is resolved, the
// values of the other carriers are asked instead, on their own questions.
func (q *questionSet) complete() *errBodyScope {
	if q.plan == nil {
		return nil
	}

	union := false

	for _, name := range q.readings.names {
		field, inBody := q.plan.firstField[name]
		if !inBody {
			continue
		}

		if q.unioned[name] {
			union = true

			continue
		}

		// A request value resolved with MatchAny agrees with the body when the
		// body names one of the values it resolved to.
		if items, matchAny := q.readings.anyOf[name]; matchAny {
			for _, item := range items {
				if !q.carriesOne(name, item) {
					return divergence(name, q.readings.where[name], field)
				}
			}

			continue
		}

		for _, value := range q.readings.values[name] {
			if _, ok := q.carried[name][value]; !ok {
				return divergence(name, q.readings.where[name], field)
			}
		}
	}

	if !union {
		return nil
	}

	q.resolvedAt = q.readings.resolvedAt

	return q.add(map[string]string{}, nil)
}

// scopeQuestions are the questions a request makes: the sets of identifiers
// to ask about, where the resolved value each carries was read ("" for none),
// and the groups they are decided in — each the indexes of sets of which one
// must be allowed.
type scopeQuestions struct {
	sets    []map[string]string
	located []string
	groups  [][]int
}

func (q *questionSet) asked() scopeQuestions {
	return scopeQuestions{sets: q.questions, located: q.located, groups: q.groups}
}

// carriesOne reports whether some question carries one of values for name.
func (q *questionSet) carriesOne(name string, values []string) bool {
	for _, value := range values {
		if _, ok := q.carried[name][value]; ok {
			return true
		}
	}

	return false
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

func containsValue(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}

	return false
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
