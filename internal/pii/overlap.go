package pii

import "sort"

// entityTypePriority maps entity types to their overlap resolution priority.
// Lower number = higher priority. Used as tiebreaker when confidence is equal.
var entityTypePriority = map[EntityType]int{
	Email:      0,
	Phone:      1,
	IBAN:       2,
	CreditCard: 3,
	JWT:        4,
	Name:       5,
	Secret:     6,
	PrivateKey: 7,
}

// entityTypePriorityOrder returns the priority of an entity type for overlap
// resolution. Unknown types default to lowest priority.
func entityTypePriorityOrder(t EntityType) int {
	if p, ok := entityTypePriority[t]; ok {
		return p
	}
	return 999
}

// resolveOverlaps resolves overlapping entity spans according to the overlap
// resolution algorithm:
//
//  1. Higher confidence wins
//  2. If confidence equal: entity type priority (EMAIL > PHONE > IBAN > ...)
//  3. If same type: longer span wins
//  4. If same length: first in input order wins
//
// Entities that share boundaries exactly (End_A == Start_B) are NOT overlapping
// and both survive.
//
// The input slice is modified (sorted in-place) and the returned slice may be
// a sub-slice of the input. The input must not be reused after this call.
func resolveOverlaps(entities []Entity) []Entity {
	if len(entities) <= 1 {
		return entities
	}

	// Sort by byte position: start ascending, then end descending (longer first).
	sort.Slice(entities, func(i, j int) bool {
		if entities[i].Start != entities[j].Start {
			return entities[i].Start < entities[j].Start
		}
		return entities[i].End > entities[j].End
	})

	// Resolve overlaps greedily: keep a running list of non-overlapping entities.
	// For each new entity, check if it overlaps with the last kept entity.
	// If it does, resolve using the tiebreaking rules.
	kept := entities[:0]
	for _, e := range entities {
		if len(kept) == 0 {
			kept = append(kept, e)
			continue
		}

		last := &kept[len(kept)-1]

		// No overlap: End_A <= Start_B means they don't overlap.
		if last.End <= e.Start {
			kept = append(kept, e)
			continue
		}

		// Overlap detected: resolve using tiebreaking rules.
		winner := pickWinner(*last, e)
		if winner == e {
			// New entity wins, replace the last kept entity.
			*last = e
		}
		// Otherwise, last entity wins — nothing to do.
	}

	return kept
}

// pickWinner resolves a conflict between two overlapping entities using the
// deterministic tiebreaking rules.
func pickWinner(a, b Entity) Entity {
	// Rule 1: Higher confidence wins.
	if a.Confidence > b.Confidence {
		return a
	}
	if b.Confidence > a.Confidence {
		return b
	}

	// Rule 2: Entity type priority (lower number = higher priority).
	aPriority := entityTypePriorityOrder(a.Type)
	bPriority := entityTypePriorityOrder(b.Type)
	if aPriority < bPriority {
		return a
	}
	if bPriority < aPriority {
		return b
	}

	// Rule 3: Longer span wins (more specific match).
	aLen := a.End - a.Start
	bLen := b.End - b.Start
	if aLen > bLen {
		return a
	}
	if bLen > aLen {
		return b
	}

	// Rule 4: First in registration order — but since both entities are already
	// registered, we use the one that comes first in the sorted input (a is first
	// because it was already in the kept list).
	return a
}
