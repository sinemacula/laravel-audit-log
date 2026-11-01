# Event Definitions

## Purpose

This note records what an event definition says about a code, and how definitions are registered: the payload
contract's version, the category stored on every row, the field rules that decide what of a payload is kept, how a
path names a field and which rule wins when several match, who owns an encrypted field, and what a code no one defined
gets. Definitions are the application's statement of what each event may carry, so a registered code keeps only what
its rules allow, and an ambiguous or contradictory definition is refused while the application boots rather than
discovered in the data.

## Invariants

- A definition (`EventDefinition`) is for one code, validated as every code is (see `record-model.md`), so no
  definition is for an `audit_log.` code. It is immutable: every fluent method returns a new definition and leaves the
  original as it was.
- Its version is from 1 to 32767 (`EventDefinition::MIN_VERSION`, `EventDefinition::MAX_VERSION`), 1 by default, and
  versions the payload contract, apart from the record's own version. Its category is a slug of 1 to 64 lower-case
  letters, digits or underscores starting with a letter, `general` by default (`EventDefinition::DEFAULT_CATEGORY`).
- The category is stored on every row, so retention by category never consults the definitions when it prunes.
- A field rule (`FieldRule`) gives a path one handling (`FieldHandling`): `retain` keeps the value as captured,
  `redact` stores it as a marker, `pseudonymise` stores a keyed hash, `encrypt` stores it encrypted to its owner, and
  `drop` does not store it. Every handling but `retain` is terminal: it decides the whole branch beneath its path.
- A registered code drops every field no rule names: `unlisted` is `drop` by default, so one rule drops every other
  field. `->unlisted(FieldHandling::RETAIN)` keeps unlisted fields explicitly, and unlisted fields can never be
  encrypted, since an encrypted field names its owner.
- An unregistered code takes the permissive default (`EventDefinition::permissive()`): version 1, `general`, no rules,
  and unlisted fields retained, so recording works with no set-up. `definitions.require_registered` (default `false`)
  makes an unregistered code a programming error instead; the catalogue's `requireRegistered` flag carries it.
- Every `encrypt` rule names its owner: `KeyOwner::ACTOR` (`actor`), `KeyOwner::SUBJECT` (`subject`), or the path of a
  property holding a reference. An owner path names one property, without `*`, and is never the encrypted field
  itself. When the owner is absent or has no key, the field is dropped and diagnosed, never stored in plaintext.
  Erasing an owner's data destroys the owner's key; the plaintext references in the record (actor and subject ids)
  remain, and are pseudonymous rather than erased.
- Global redaction of secret-shaped keys runs before the field rules, and `retain` never un-redacts what it redacted.
- Two rules for one path are refused unless they are identical, which is kept once. A rule that a terminal rule with
  fewer segments may cover is unreachable and refused, in whichever order the two are added.
- Rules are kept in path order, so two definitions built from the same parts in any order are equal (`equals()`).
- Definitions are registered while the application boots, and only then. Registering an identical definition again
  changes nothing; a different definition for a registered code is refused whichever is registered first; and an enum
  registers every case's definition or, when any is refused, none of them.
- A definition describes how a payload is handled; applying the rules to a payload belongs to the redaction pipeline,
  which never applies them to the package's own metadata (`properties._audit`).

## Success Path

- The application declares its codes as a string-backed enum implementing `DefinesAuditEvents`, each case returning
  its definition, and registers the enum at boot. This one keeps the amount and currency of an approval, pseudonymises
  the approver's email address and drops anything else; a failed refund keeps its amount and encrypts the card holder's
  name to the invoice's key.

```php
use SineMacula\Laravel\AuditLog\Contracts\DefinesAuditEvents;
use SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;

enum InvoiceActivity: string implements DefinesAuditEvents
{
    case APPROVED = 'invoice.approved';
    case REFUND_FAILED = 'invoice.refund_failed';

    public function definition(): EventDefinition
    {
        return match ($this) {
            self::APPROVED => EventDefinition::for($this)->category('finance')->version(2)
                ->retain('amount', 'currency')->pseudonymise('approver_email'),
            self::REFUND_FAILED => EventDefinition::for($this)->category('finance')
                ->retain('amount')->encrypt('card_holder', owner: KeyOwner::SUBJECT),
        };
    }
}
```

- The catalogue (`EventCatalogue`) asks every case for its definition, checks them all, then registers them.
- When a record is made, the catalogue gives its code's definition, or the permissive default for a code no one
  defined, and the record takes its event version and category from it.
- For each field of the payload, the most specific rule matching the field or one of its ancestors decides its
  handling; a field no rule matches takes the `unlisted` handling.

## Failure / Edge Cases

- A version outside 1 to 32767, or a category that is not a slug: `\InvalidArgumentException`.
- A malformed path (empty, with an empty segment, or with `*` inside a segment), one of more than eight segments, one
  with control characters or invalid UTF-8, or one with a segment beginning `_audit`: `\InvalidArgumentException`.
- `encrypt` without an owner, an owner on any other handling, an owner path with `*`, or an encrypted field that owns
  itself: `\InvalidArgumentException`.
- A second, different rule for a path, or an unreachable rule: `\InvalidArgumentException`, naming the longer path
  first in either order.
- `->unlisted(FieldHandling::ENCRYPT)`: `\InvalidArgumentException`.
- Registering a class that is not an enum implementing `DefinesAuditEvents`, an enum backed by integers (checked
  before any case is asked for its definition), or a case whose definition is for another code:
  `\InvalidArgumentException`, and none of the enum's cases is registered.
- A conflicting definition for a registered code: `\LogicException`, and none of the enum's cases is registered.
- Registering after the application has booted (the catalogue is frozen): `\LogicException`, checked before anything
  else, so a long-running worker never registers twice.
- An unregistered code while registration is required: `\InvalidArgumentException`.
- A key containing `.` or `*` cannot be written as a literal segment, and is reachable only through `*`.

## Paths and Precedence

A path is dot-separated keys, at most eight (`FieldPath::MAX_SEGMENTS`, the normaliser's depth). `*` alone matches
exactly one key or list index. A literal segment matches a key or a list index whose decimal string equals it, so
`lines.0` names the first line whether the payload holds a list or a map; the comparison is of strings, never numbers,
so `00` does not match the index `0`. A rule on a map covers everything beneath it unless a more specific rule
matches. Of the rules matching a field or one of its ancestors, the one with more segments wins; at equal length,
compared left to right, the first position where one rule has a literal and the other `*` decides, the literal
winning.

With the rules `card` retain, `card.number` redact, `*.email` pseudonymise, `user.email` retain, `lines.*` retain,
`lines.0` redact, `meta.*` drop and `meta.keep` retain:

| Field                                | Winning rule  | Why                                                 |
|--------------------------------------|---------------|-----------------------------------------------------|
| `card.number`                        | `card.number` | more segments                                       |
| `card.holder`                        | `card`        | a rule covers its branch                            |
| `user.email`                         | `user.email`  | equal length, a literal beats `*`                   |
| `admin.email`                        | `*.email`     | the only match                                      |
| `card.number.last4`                  | `card.number` | a terminal rule covers its branch                   |
| `lines.0` (a list index)             | `lines.0`     | a literal digit matches a list index, and beats `*` |
| `lines.1.sku`                        | `lines.*`     | `*` matches an index, and covers its branch         |
| `lines.email`                        | `lines.*`     | compared left to right, `lines` beats `*`           |
| `meta.keep`                          | `meta.keep`   | a literal beats `*`                                 |
| `meta.other`                         | `meta.*`      | the wildcard                                        |
| the single key `card.number`         | none          | a key with a dot is not a path of two               |
| `email` beneath the key `admin.team` | `*.email`     | a key with a dot is reachable through `*`           |
| `other`                              | none          | unlisted                                            |

A rule is unreachable when a terminal rule with fewer segments may cover it: position by position the two are equal
or either is `*`. So `a.b` beneath `a` drop, `a.b.c` beneath `a.*` drop and `*.b` beneath `a` drop are refused, while
`a.b` beneath `a` retain, and `*.b` beside `a.*` redact (they share only a length), are accepted.

## Registration

- The catalogue holds one definition per code. An enum is registered whole: its backing type is checked first, then
  every case's definition is collected and checked against its case's code and against what is registered, and only
  then is anything stored.
- The application registers its definitions while it boots; the package freezes the catalogue once the application
  has booted, and freezing again changes nothing. A frozen catalogue still serves definitions.
- `definitionFor()` serves a registered definition, the permissive default for an unregistered code, or refuses the
  code when registration is required.

## Implementation Anchors

- `src/Definitions/EventDefinition.php`: `for()`, `permissive()`, `rule()`, `unlisted()`, `ruleFor()`,
  `handlingFor()`.
- `src/Definitions/FieldRule.php`; `src/Definitions/FieldPath.php`: `parse()`, `matches()`, `compare()`,
  `mayBeBeneath()`.
- `src/Definitions/Enums/FieldHandling.php`: `RETAIN`, `REDACT`, `PSEUDONYMISE`, `ENCRYPT`, `DROP`, `isTerminal()`.
- `src/Definitions/Enums/KeyOwner.php`: `ACTOR`, `SUBJECT`.
- `src/Contracts/DefinesAuditEvents.php`.
- `src/Definitions/EventCatalogue.php`: `define()`, `definitionFor()`, `freeze()`.

## Authoritative Tests

- `tests/Unit/Definitions/EventDefinitionTest.php` `testTheBoundsAndTheDefaultCategory`,
  `testTheDefaultsOfARegisteredCode`, `testRefusesTheReservedPrefix`, `testRefusesAVersionOutsideItsBounds`,
  `testRefusesACategoryThatIsNotASlug`, `testEachFluentMethodReturnsANewInstanceAndLeavesTheOriginal`,
  `testEncryptRequiresAnOwner`, `testDefinitionsBuiltInAnyOrderAreEqual`, `testASecondRuleForAPathIsRefused`,
  `testRefusesAnUnreachableRule`, `testARuleBeneathARetainedPathIsReachable`,
  `testRulesThatOnlyShareALengthAreReachable`, `testUnlistedFieldsCannotBeEncrypted`,
  `testThePermissiveDefaultRetainsUnlistedFields`, `testTheMostSpecificRuleWins`, `testOneRuleDropsEveryOtherField`
- `tests/Unit/Definitions/FieldPathTest.php` `testRefusesAMalformedPath`, `testRefusesMoreThanEightSegments`,
  `testRefusesAPathWithControlCharacters`, `testRefusesAPathWithAReservedSegment`, `testMatches`,
  `testComparesSpecificity`, `testMayBeBeneath`
- `tests/Unit/Definitions/FieldRuleTest.php` `testAnEncryptedFieldWithoutAnOwnerIsRefused`,
  `testOnlyAnEncryptedFieldNamesAnOwner`, `testAnOwnerPathWithAWildcardIsRefused`,
  `testAnEncryptedFieldCannotOwnItself`
- `tests/Unit/Definitions/Enums/FieldHandlingTest.php` `testTheCasesAndTheirStoredValues`,
  `testOnlyRetainLeavesItsBranchOpen`
- `tests/Unit/Definitions/Enums/KeyOwnerTest.php` `testTheCasesAndTheirStoredValues`
- `tests/Unit/Definitions/EventCatalogueTest.php` `testAnUnregisteredCodeTakesThePermissiveDefault`,
  `testAnUnregisteredCodeIsRefusedWhenRegistrationIsRequired`, `testDefinesEveryCaseOfAnEnum`,
  `testAnIdenticalRegistrationRepeatedIsIdempotent`, `testAConflictingDefinitionThrowsInEitherOrder`,
  `testAConflictingEnumRegistersNoneOfItsCases`, `testRefusesACaseThatDefinesAnotherCode`,
  `testRefusesAnIntegerBackedDefiningEnum`, `testDefiningAfterFreezingThrows`, `testDefinitionsAreServedAfterFreezing`

## Change Triggers

Update this note when any of the following change:

- a definition's defaults, or the bounds of its version or category
- a field handling or key owner, or its stored value
- the path grammar, its segment limit or its reserved prefix
- how the winning rule is chosen, or which rules are unreachable
- what an unregistered code gets, or when it is refused
- when definitions may be registered, or what a conflict is
