# Peer Review: QINDU-0006 — Tokenisation

**Reviewer**: qindu-peer-reviewer (senior Go developer, 15+ years)  
**Date**: 2026-07-03  
**Scope**: `internal/tokenize/` (6 fichiers, 593 SLOC production, 1028 SLOC tests, 1621 lignes total)  
**Method**: Revue blank-slate contre Clean Code, SOLID, Go Proverbs, Effective Go, Pragmatic Programmer, DDD, Code Complete. Aucun document sprint/DPO/CISO consulté — le code est jugé sur ses propres mérites.

---

## Section 1: Scorecard

| Framework | Score (1–5) | Justification |
|-----------|-------------|---------------|
| **Clean Code** | 5/5 | Fonctions courtes (<40 lignes sauf `Rehydrate` à 41 lignes), noms explicites, godoc exhaustif sur tous les symboles exportés, SRP stricte par fichier, aucun commentaire pansement, pas de `var _ =` hacks. La doc de `Tokenize` explique correctement le left-to-right immutable. |
| **SOLID** | 5/5 | Interface `Store` (5 méthodes) : modèle de DIP/OCP/ISP — injectable, extensible pour le vault QINDU-0008. `Tokenizer` respecte SRP. `Option` pattern pour l'extensibilité. `pii.Engine` injecté, pas instancié. Aucun couplage concret. |
| **Go Proverbs** | 5/5 | Errors are values, correctement propagées. Pas de `panic`, pas de `defer` en boucle, pas de `var _ =` hacks. `gofmt` propre. `discardLogger` utilise `io.Discard` natif. Build tags `//go:build` sur les fichiers plateforme-spécifiques. Concurrence propre via `sync.Mutex`. |
| **Effective Go** | 5/5 | CamelCase idiomatique, `defer` correctement utilisé pour `Unlock`, pas d'`init()` abusif. `regexp.MustCompile` au niveau package var (fail-fast). Maps initialisées avec `make` et capacité. `strings.Builder` pour la construction immuable. `unsafe.Slice` utilisé correctement pour wrapper mémoire brute. |
| **Pragmatic Programmer** | 5/5 | Orthogonalité parfaite entre `Tokenizer`, `Store`, `pii.Engine` et `memlock`. Chaque module a une raison d'être unique. Interface `Store` = seam de test idéal. Pas de hooks de test publics. Reversibilité : le vault DPAPI remplacera `MemoryStore` sans changer une ligne du `Tokenizer`. |
| **DDD** | 5/5 | Contexte borné `tokenize` propre. Langage ubiquitaire : « tokenize », « rehydrate », « store », « conversation scope ». Aucune fuite de concepts HTTP/proxy. `Tokenizer` = aggregate root d'un scope de conversation. `Store` = repository in-memory. |
| **Code Complete** | 4/5 | Programmation défensive excellente (`validateEntities`, `substituteEntities` avec sort et skip). Dégradation gracieuse du memory locking. La map `valueToToken` stocke de la PII sur le heap Go standard (pas dans l'arène verrouillée) — trade-off documenté mais perfectible. `piiArena.alloc` sans garde de concurrence explicite — l'invariant repose sur le lock de `Map`. |
| **Overall** | **4.9 / 5** | Implémentation quasi-parfaite. Aucun bug, aucune race, aucune fuite de PII. Les corrections apportées depuis la review précédente (logger par défaut → `io.Discard`, Linux → mmap+mlock ciblé, assertions manquantes, doc corrigée, `Close()` ajouté) sont toutes excellentes. Les 6 findings restants sont tous cosmétiques ou de test. |

---

## Section 2: Critical Findings 🔴

**Aucun.** Zéro bug bloquant, zéro race condition, zéro fuite de PII, zéro panique, zéro crash au build. Tests passent avec `-race`, `go vet` propre, 88.7% de couverture.

---

## Section 3: Findings 🟡

### PR-001: `valueToToken` stocke la PII sur le heap standard (pas dans l'arène verrouillée)

- **ID**: PR-001
- **File**: `internal/tokenize/tokenizer.go`, lignes 65–67 (`valueToToken map[string]string`)
- **Category**: Sécurité mémoire / Defense-in-depth
- **Severity**: LOW
- **Problem**: La map de déduplication `valueToToken` utilise les valeurs PII brutes comme clés (ex: `"alice@example.com"` → `"<<EMAIL_1>>"`). Ces clés résident sur le heap Go standard, pas dans l'arène verrouillée (`piiArena`). Le `Store` met bien les *valeurs* (le chemin `token → PII`) dans l'arène verrouillée via `store.Map(token, e.Value)`, mais la clé de déduplication `e.Value` dans `valueToToken` échappe au verrouillage mémoire. Si le processus est swappé, ces clés PII peuvent atterrir sur disque. Le commentaire ligne 66 (`WARNING: map keys contain raw PII`) documente le risque mais ne le résout pas.

- **Contexte atténuant**: Chaque `Tokenizer` a un scope de conversation — durée de vie courte. La map est remplacée par `Reset()`. Le risque d'exposition via swap est faible mais non nul. Une correction complète nécessiterait un allocateur de clés hashées dans l'arène, disproportionné pour le scope actuel.

- **Fix**: Ajouter un commentaire explicitant le trade-off :
  ```go
  // valueToToken maps raw PII values to their assigned tokens for deduplication.
  // WARNING: map keys contain raw PII on the regular Go heap (not locked arena).
  // This is a deliberate trade-off: dedup correctness requires exact-match keys.
  // Conversation-scoped Tokenizers are short-lived, limiting swap exposure.
  // Never log, serialize, or print this field.
  ```

### PR-002: `piiArena.alloc` n'a pas de documentation sur son invariant de goroutine-safety

- **ID**: PR-002
- **File**: `internal/tokenize/store.go`, lignes 123–131
- **Category**: Documentation / Concurrence
- **Severity**: LOW
- **Problem**: `piiArena.alloc` modifie `a.offset` sans lock. C'est correct dans l'implémentation actuelle car `alloc` est appelé uniquement depuis `MemoryStore.Map`, qui détient `s.mu.Lock()`. Mais cet invariant n'est documenté nulle part. Un futur mainteneur qui appellerait `alloc` hors lock introduirait une race condition silencieuse.

- **Fix**: Ajouter un commentaire sur la struct ou la méthode :
  ```go
  // piiArena is a simple bump-allocator backed by a locked memory buffer.
  // NOT goroutine-safe: must be accessed under MemoryStore.mu write lock.
  type piiArena struct { ... }
  ```

### PR-003: `MemoryStore.Close()` ne prévient pas la réutilisation

- **ID**: PR-003
- **File**: `internal/tokenize/store.go`, lignes 109–111
- **Category**: Defense-in-depth / Cycle de vie
- **Severity**: LOW
- **Problem**: Après `Close()`, le contrat du `Store` stipule « the store should not be used ». Mais `MemoryStore.Close()` est un no-op, et `Map`/`Get`/`Clear` restent fonctionnels. Un appel accidentel post-Close ne génèrera ni erreur ni panique — il continuera silencieusement, ce qui peut masquer des bugs de cycle de vie.

- **Fix**: Ajouter un flag `closed` vérifié en entrée de chaque méthode :
  ```go
  type MemoryStore struct {
      ...
      closed bool
  }
  
  func (s *MemoryStore) Close() error {
      s.mu.Lock()
      defer s.mu.Unlock()
      s.closed = true
      return nil
  }
  
  func (s *MemoryStore) Map(token string, piiValue string) {
      s.mu.Lock()
      defer s.mu.Unlock()
      if s.closed { return }
      ...
  }
  ```
  Ou, plus simplement pour le cas in-memory, accepter le no-op et ajuster la doc.

### PR-004: `substituteEntities` trie des entités déjà triées

- **ID**: PR-004
- **File**: `internal/tokenize/tokenizer.go`, lignes 303–308
- **Category**: Performance / Clarté
- **Severity**: LOW
- **Problem**: Le `sort.Slice` est justifié par un commentaire « defense-in-depth » — l'Engine garantit déjà des entités triées et non-chevauchantes. Le tri défensif crée une slice de `pair` (allocation heap) + O(n log n) sur une liste déjà triée. Pour <100 entités par requête, l'overhead est négligeable. Mais le commentaire ligne 304 dit « Engine output is already sorted, but we sort anyway » — ce qui révèle que l'auteur sait que c'est redondant.

- **Fix**: Remplacer le tri par une assertion en mode debug (`build tag debug`) ou supprimer le tri et renforcer le contrat via godoc :
  ```go
  // substituteEntities replaces PII spans with tokens in the original text.
  // entities MUST be sorted by Start ascending and non-overlapping
  // (guaranteed by Engine.Detect and validateEntities).
  ```
  Si le tri est conservé, ajouter « defense-in-depth: re-sort in case caller violates contract ».

### PR-005: `NAME` dans `allEntityTypes` jamais généré par l'Engine actuel

- **ID**: PR-005
- **File**: `internal/tokenize/tokenizer.go`, lignes 32–38
- **Category**: Code mort apparent / Forward-compat
- **Severity**: LOW
- **Problem**: `allEntityTypes` inclut `pii.Name`. Le `NameFromEmailRecognizer` produit des entités `NAME` avec les mêmes `Start`/`End` que l'`EMAIL` source. L'Engine résout ce chevauchement en faveur d'`EMAIL` (priorité 0 vs 5). Résultat : `<<NAME_N>>` n'est jamais généré. Le tokenizer supporte pourtant le pattern via `tokenRegex`, ce qui est *forward-compatible* (un futur recognizer NAME non-chevauchant fonctionnera). Mais sans commentaire, un nouveau développeur se demandera pourquoi aucun test ne vérifie `<<NAME_`.

- **Fix**: Ajouter un commentaire :
  ```go
  // allEntityTypes is the canonical list of recognized PII entity types.
  // Note: pii.Name is included for forward-compatibility. With the current
  // Engine, NAME entities overlap EMAIL spans and are dropped by overlap
  // resolution. Future recognizers producing non-overlapping NAME entities
  // will be automatically supported.
  ```

### PR-006: `TestErrorMessages_NoPII` scanne `"eyJ"` dans un input sans JWT

- **ID**: PR-006
- **File**: `internal/tokenize/tokenizer_test.go`, lignes 659–663
- **Category**: Test Quality / Assertion trompeuse
- **Severity**: LOW
- **Problem**: La ligne 659 vérifie `strings.Contains(errMsg, "eyJ")` sur un message d'erreur généré à partir de `strings.Repeat("x", pii.DefaultMaxInputBytes+1)`. Comme l'input ne contient pas de JWT, et que l'Engine rejette sur la taille AVANT de scanner le contenu, le pattern `eyJ` ne peut jamais apparaître dans le message d'erreur. L'assertion est techniquement correcte (elle passe) mais elle suggère faussement que le test valide l'absence de patterns JWT dans les messages d'erreur — ce qu'il ne fait pas pour les vrais cas (un input de 900 KiB contenant un JWT sera scanné, pas rejeté).

- **Fix**: Remplacer par deux sous-tests :
  1. Input surdimensionné sans PII → l'erreur est propre (test actuel, garder).
  2. Input contenant de la PII mais sous la limite → un appel à `Tokenize` normal, vérifier que l'erreur éventuelle (s'il y en a une) est PII-free. Puisque `Tokenize` ne retourne jamais d'erreur contenant de la PII (Engine errors = sizes only, recognizers never error), ce test est en réalité un test de non-régression sur `Engine.Detect`.

---

## Section 4: Excellence 🟢

### 1. Interface `Store` (`store.go`, L12–35)

Cinq méthodes, zéro gras. Sémantique first-write-wins documentée. Injectable via `WithStore`. Prête pour le vault DPAPI QINDU-0008 sans changement de code. Le pattern `Option` est le companion idiomatique. C'est le genre d'interface qui distingue un senior Go d'un junior. **Exemple de DIP et OCP appliqués à la perfection.**

### 2. `validateEntities` — belt-and-suspenders (`tokenizer.go`, L260–276)

L'Engine garantit déjà des entités valides, triées, non-chevauchantes. `validateEntities` vérifie quand même les bornes (`Start < 0`, `End <= Start`, `End > textLen`) ET l'appartenance au set `knownEntityTypes`. Elle filtre (skip) plutôt que d'erreur — un détecteur buggé ne fait pas tomber toute la requête. La fonction retourne un slice filtré, jamais nil. **Code Complete §8.2 « Defensive Programming » en action.**

### 3. Memory locking Linux : `mmap` + `mlock` ciblé (`memlock_linux.go`)

Contrairement au `mlockall(MCL_CURRENT|MCL_FUTURE)` process-wide de la v1, cette implémentation alloue une arène dédiée de 4 MiB via `unix.Mmap` + `unix.Mlock`. Seules les pages contenant de la PII sont verrouillées — pas les stacks goroutine, pas le cache TLS, pas les buffers HTTP. Le cleanup (`Munmap` sur échec de `Mlock`) est correct. La dégradation gracieuse (log WARNING + retour nil) permet au proxy de fonctionner même sans `CAP_IPC_LOCK`. **C'est l'approche chirurgicale, pas la masse.**

### 4. `tokenRegex` — compilation au package init, pas de lazy `sync.Once` (`tokenizer.go`, L30)

`regexp.MustCompile` au niveau `var`. Si le pattern est invalide, le processus crash au démarrage (fail-fast), pas au 10 000ème appel. `regexp.QuoteMeta` appliqué aux noms de types même s'ils sont ASCII aujourd'hui — défense contre un futur type avec métacaractères. **Go Proverb: « A little copying is better than a little dependency. » Ici, zero copying, zero lazy init.**

### 5. Conception concurrente (`tokenizer.go` + `store.go`)

Ordre de locking correct : `Tokenizer.mu` (write path) → `Store.mu` (write path), `Store.mu` seul (read path). Pas de dépendance circulaire, pas de double-lock deadlock. `Rehydrate` ne lock jamais — lit `tokenRegex` (immutable, safe) et `store.Get` (le store a son propre `RWMutex`). L'accès non synchronisé à `piiArena.offset` est protégé par `MemoryStore.Map` qui détient le write lock. Tests de concurrence avec 40 goroutines, race detector passe. **Go Proverb: « Don't communicate by sharing memory; share memory by communicating. » Mutex bien utilisés comme dernier recours, pas comme béquille.**

### 6. Tests : couverture et hygiène PII (`tokenizer_test.go`)

88.7% de couverture, 42 tests. Données synthétiques uniquement : `example.com`, `4111111111111111` (carte test), `DE89` IBAN test, JWT avec signature connue, clé PEM factice. `TestErrorMessages_NoPII` scanne activement les messages d'erreur pour des patterns PII (`@`, `4111`, `DE89`, `sk-`, `eyJ`). `TestRehydrate_ReDosPrevention` vérifie la linéarité sur 10 000 tokens. `TestConversation_Isolation` valide que deux `Tokenizer` indépendants ne se contaminent pas. **Les tests ne sont pas une corvée — ils sont une spécification exécutable.**

### 7. `piiArena.reset()` — zeroise le buffer (`store.go`, L134–141)

Quand `Clear()` est appelé, `reset()` remet l'offset à zéro **et** écrase tout le buffer avec des zéros. La PII est effacée de la mémoire, pas juste « oubliée ». C'est le niveau d'attention qu'on attend d'un produit privacy-first. **Même `munmap` ne garantit pas le zeroing — le faire explicitement est la bonne pratique.**

---

## Section 5: Design Summary

```
┌─────────────────────────────────────────────────────────────┐
│                        Tokenizer                            │
│  ┌──────────┐  ┌────────────────┐  ┌────────────────────┐  │
│  │  Engine  │  │  valueToToken  │  │     counters       │  │
│  │  (pii)   │  │  (dedup map)   │  │   (per-type)       │  │
│  └────┬─────┘  └───────┬────────┘  └─────────┬──────────┘  │
│       │                │                     │              │
│       │     ┌──────────▼─────────────────────▼──────────┐   │
│       │     │              Store (interface)             │   │
│       │     │  ┌────────────────────────────────────┐   │   │
│       │     │  │          MemoryStore               │   │   │
│       │     │  │  ┌──────────┐  ┌────────────────┐  │   │   │
│       │     │  │  │ mapping  │  │   piiArena     │  │   │   │
│       │     │  │  │ (map)    │  │   (locked)     │  │   │   │
│       │     │  │  └──────────┘  └────────────────┘  │   │   │
│       │     │  └────────────────────────────────────┘   │   │
│       │     └───────────────────────────────────────────┘   │
│       │                                                     │
│  ┌────▼──────────────────────────────────────────────────┐  │
│  │            Platform Memory Locking                     │  │
│  │  Linux:  mmap(MAP_ANONYMOUS) + mlock (4 MiB arena)    │  │
│  │  Windows: VirtualAlloc(MEM_COMMIT) + VirtualLock       │  │
│  │  Other:   no-op fallback (graceful degradation)        │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘

Tokenizer ───injects───▶ pii.Engine (immuable, partagé entre conversations)
Tokenizer ───owns──────▶ counters, valueToToken, Store (scope par conversation)
Store ──────is─────────▶ MemoryStore (today), Vault DPAPI (QINDU-0008, tomorrow)
```

Architecture en couches propres. `Tokenizer` = aggregate root d'un scope de conversation. `pii.Engine` = dépendance immuable partagée (un engine, N tokenizers). `Store` = seam pour la persistence future. Les fichiers `memlock_*.go` sont le seul point de variation plateforme — tout le reste est portable.

---

## Section 6: Évolution depuis la dernière review

La review précédente (v1) listait 11 findings (PR-001 à PR-011). Tous ont été corrigés :

| PR | Problème v1 | État v2 |
|----|-------------|---------|
| PR-001 | Doc « rightmost to leftmost » trompeuse | ✅ Corrigé — doc explique maintenant le left-to-right immutable |
| PR-002 | Logger par défaut → `os.Stderr` | ✅ Corrigé — `io.Discard` via `slog.NewTextHandler(io.Discard, nil)` |
| PR-003 | Liste de types d'entités dupliquée | ✅ Corrigé — `allEntityTypes` source unique, référencée par `buildTokenPattern` et `isKnownEntityType` |
| PR-004 | `valueToToken` sans annotation PII | ✅ Corrigé — commentaire `WARNING: map keys contain raw PII` ajouté |
| PR-005 | Linux `mlockall` process-wide overkill | ✅ Corrigé — `mmap` + `mlock` ciblé sur arène 4 MiB |
| PR-006 | `Store` sans `Close()` | ✅ Corrigé — `Close() error` ajouté à l'interface et au `Tokenizer` |
| PR-007 | `TestTokenize_AllEntityTypes` assertions mortes | ✅ Corrigé — assertions `requiredPrefixes` actives |
| PR-008 | `TestNoFilesystemOperations` mal nommé | ✅ Corrigé — renommé `TestMemoryStore_BasicOperations` |
| PR-009 | Setup de test avale les erreurs `Tokenize` | ✅ Corrigé — `t.Fatalf("setup Tokenize failed: %v", err)` partout |
| PR-010 | `discardLogger` avec `slog.LevelError + 1` | ✅ Corrigé — `io.Discard` natif |
| PR-011 | Arena 16 MiB magic number | ✅ Corrigé — 4 MiB avec commentaire de justification |

**Taux de résolution : 11/11. Aucune régression.** La v2 est strictement supérieure à la v1 sur tous les axes.

---

## Section 7: Verdict

### 🟢 MERGE_READY

**Aucun bug critique, aucune fuite de PII, aucune race condition, aucune panique.** Le code compile, passe `go vet`, passe `go test -race` avec 88.7% de couverture. Les 6 findings (PR-001 à PR-006) sont tous de sévérité **LOW** — cosmétiques, documentaires, ou de test. Aucun ne bloque le merge.

**Faits saillants**:
- **42 tests**, tous verts, race detector propre
- **88.7% coverage** (amélioration vs 85.9% en v1)
- Memory locking Linux **chirurgical** (mmap+mlock, pas mlockall)
- Memory locking Windows **correct** (VirtualAlloc+VirtualLock)
- Interface `Store` **prête pour le vault DPAPI QINDU-0008**
- Zéro PII dans les logs, erreurs, ou fixtures de test
- Dégradation gracieuse sur échec de memory locking (WARNING → continue)

**Recommandations non-bloquantes**:
1. PR-001 — Documenter plus explicitement le trade-off heap vs arena pour `valueToToken`
2. PR-002 — Ajouter un commentaire « not goroutine-safe » sur `piiArena`
3. PR-003 — Ajouter un flag `closed` à `MemoryStore` (ou ajuster la doc)
4. PR-004 — Remplacer le sort défensif par une assertion en debug build
5. PR-005 — Documenter pourquoi `NAME` est dans `allEntityTypes` malgré l'absence de tokens `<<NAME_` générés
6. PR-006 — Clarifier le test `TestErrorMessages_NoPII` sur le cas JWT

---

*Fin de la peer review. Approuvé pour les gates CISO/DPO.*
