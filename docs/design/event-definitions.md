# Event Definitions

## Purpose

This note records what an event definition says about a code, and how definitions are registered: the payload contract's
version, the category stored on every row, the field rules that decide what of a payload is kept, how a path names a
field and which rule wins when several match, who owns an encrypted field, what a code no one defined gets, and what a
disclosure's definition must keep. Definitions are the application's statement of what each event may carry, so a
registered code keeps only what its rules allow, and an ambiguous or contradictory definition is refused while the
application boots rather than discovered in the data.

## Invariants

- A definition (`EventDefinition`) is for one code, validated as every code is (see `record-model.md`), so no
  definition is for an `audit_log.` code. It is immutable: every fluent method returns a new definition and leaves the
  original as it was.
- Its version is from 1 to 32767 (`EventDefinition::MIN_VERSION`, `EventDefinition::MAX_VERSION`), 1 by default, and
  versions the payload contract, apart from the record's own version. Its category is a slug of 1 to 64 lower-case
  letters, digits or underscores starting with a letter, `general` by default (`EventDefinition::DEFAULT_CATEGORY`).
- The category is stored on every row, so retention by category never consults the definitions when it prunes.
- A field rule (`FieldRule`) gives a path one handling (`FieldHandling`): `retain` keeps the value as key redaction left
  it, each string cut to 1024 bytes, `redact` stores it as the marker `[REDACTED]`, `pseudonymise` stores a keyed hash,
  `encrypt` stores it encrypted to its owner, and `drop` does not store it. Every handling but `retain` is terminal: it
  decides the whole branch beneath its path.
- A registered code drops every field no rule names: `unlisted` is `drop` by default, so one rule drops every other
  field. `->unlisted(FieldHandling::RETAIN)` keeps unlisted fields explicitly, and unlisted fields can never be
  encrypted, since an encrypted field names its owner.
- An unregistered code takes the permissive default (`EventDefinition::permissive()`): version 1, `general`, no rules,
  and unlisted fields retained, so recording works with no set-up. `definitions.require_registered` (default `false`)
  makes an unregistered code a programming error instead.
- `definitions.require_registered` is read on every capture, through `DefinitionSettings`, and handed to
  `definitionFor()` as an argument. The catalogue keeps no flag: it is resolved at boot to be frozen, and a malformed
  setting must not stop an application booting before `audit-log:check` can report it. Only a real boolean passes.
- Every `encrypt` rule names its owner: `KeyOwner::ACTOR` (`actor`), `KeyOwner::SUBJECT` (`subject`), or the path of a
  property holding a reference. An owner path names one property, without `*`, and is never the encrypted field
  itself. When the owner is absent or has no key, or a container's canonical JSON is longer than 1024 bytes, the field is
  dropped and diagnosed, never stored in plaintext. Erasing an owner's data destroys the owner's key; the plaintext
  references in the record (actor and subject ids) remain, and are pseudonymous rather than erased.
- Global redaction of secret-shaped keys runs before the field rules, and `retain` never un-redacts what it redacted.
- Two rules for one path are refused unless they are identical, which is kept once. A rule that a terminal rule with
  fewer segments may cover is unreachable and refused, in whichever order the two are added.
- Rules are kept in path order, so two definitions built from the same parts in any order are equal (`equals()`).
- Definitions are registered while the application boots, and only then: the package freezes the catalogue once the
  application has booted, so a long-lived worker registers once. Registering an identical definition again changes
  nothing; a different definition for a registered code is refused whichever is registered first; and an enum registers
  every case's definition or, when any is refused, none of them.
- A disclosure's definition must retain `purpose`, as `EventDefinition::for($this)->retain('purpose')` does, because
  `accessed()` keeps why something was disclosed in `properties.purpose`. `accessed()` refuses a code whose registered
  definition resolves `purpose` to any other handling, by a rule or by `unlisted`. The check is `accessed()`'s alone:
  only it knows a code is a disclosure, so registering such a definition is not refused and `event()` under that code
  is unaffected. An unregistered code is accepted, since the permissive default retains every field.
- A definition describes how a payload is handled, and the rules apply at capture: `Privacy\FieldPolicy` applies them to
  the properties after key redaction and before the byte budget, and never to the context or to the package's own
  metadata (`properties._audit`). See `redaction.md`.
- The walker selects a rule, then transforms the value. It descends through any map or list on the way to a rule beneath
  it, even when the ancestor's own handling is the `unlisted` default, so `retain('customer.email')` with `unlisted`
  `drop` keeps `customer.email` and drops the rest of `customer`. An explicit terminal rule handles its whole branch,
  and a `retain` lets a more specific rule beneath it apply. Removing list elements reindexes the list.

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

- The application registers the enum from a service provider's `boot()`:

```php
public function boot(): void
{
    AuditLog::define(InvoiceActivity::class);
}
```

- The catalogue (`EventCatalogue`) asks every case for its definition, checks them all, then registers them.
- When a record is made, the catalogue gives its code's definition, or the permissive default for a code no one
  defined, and the record takes its event version and category from it.
- For each field of the payload, the most specific rule matching the field or one of its ancestors decides its handling;
  a field no rule matches, with no rule beneath it, takes the `unlisted` handling. What each removal leaves in
  `properties._audit.omitted` is in `redaction.md`.

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
  else, so a long-running worker never registers twice. A request is refused every time, however many came before it.
- An unregistered code while registration is required: `\InvalidArgumentException` from `record()`, before the builder
  is used, so it stays usable and nothing is written.
- A `definitions.require_registered` that is not a real boolean, a set `null` included: every capture fails closed with
  an `\InvalidArgumentException` naming the key and never the value. Booting never reads it, so the application still
  boots, and `audit-log:check` reports it.
- `accessed()` under a code whose registered definition does not retain `purpose`: `\LogicException`, and no builder is
  made, so nothing is written.
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
- The application registers its definitions from a provider's `boot()`, with `AuditLog::define()`. The package freezes
  the catalogue in a `booted()` callback, and freezing again changes nothing. A frozen catalogue still serves
  definitions.
- An application's own `booted()` callback is not the place to register, because whether it runs before the freeze
  depends on the order the callbacks were added in.
- Under Octane the catalogue is made once per worker: what was registered at boot serves every request, and a request
  can register nothing.
- `definitionFor()` serves a registered definition, the permissive default for an unregistered code, or refuses the
  code when the call says registration is required. Nothing of that is kept between calls, so a setting one request
  changes reaches its own captures and no later request's.

## Implementation Anchors

- `src/Definitions/EventDefinition.php`: `for()`, `permissive()`, `rule()`, `unlisted()`, `ruleFor()`, `ruleBeneath()`,
  `handlingFor()`.
- `src/Definitions/FieldRule.php`; `src/Definitions/FieldPath.php`: `parse()`, `matches()`, `compare()`,
  `mayBeBeneath()`.
- `src/Definitions/Enums/FieldHandling.php`: `RETAIN`, `REDACT`, `PSEUDONYMISE`, `ENCRYPT`, `DROP`, `isTerminal()`.
- `src/Definitions/Enums/KeyOwner.php`: `ACTOR`, `SUBJECT`.
- `src/Contracts/DefinesAuditEvents.php`.
- `src/Definitions/EventCatalogue.php`: `define()`, `definitionFor()`, `freeze()`.
- `src/Definitions/DefinitionSettings.php`: `requiresRegistered()`, `validate()`.
- `src/Recorder.php`: `define()`, `accessed()`.
- `src/AuditLogServiceProvider.php`: `freezeRegistrationOnceBooted()`.
- `src/Privacy/FieldPolicy.php`: `apply()`.

## Authoritative Tests

- `tests/Unit/Definitions/EventDefinitionTest.php` `testTheBoundsAndTheDefaultCategory`,
  `testTheDefaultsOfARegisteredCode`, `testRefusesTheReservedPrefix`, `testRefusesAVersionOutsideItsBounds`,
  `testRefusesACategoryThatIsNotASlug`, `testEachFluentMethodReturnsANewInstanceAndLeavesTheOriginal`,
  `testEncryptRequiresAnOwner`, `testDefinitionsBuiltInAnyOrderAreEqual`, `testASecondRuleForAPathIsRefused`,
  `testRefusesAnUnreachableRule`, `testARuleBeneathARetainedPathIsReachable`,
  `testRulesThatOnlyShareALengthAreReachable`, `testUnlistedFieldsCannotBeEncrypted`,
  `testThePermissiveDefaultRetainsUnlistedFields`, `testTheMostSpecificRuleWins`, `testOneRuleDropsEveryOtherField`,
  `testRuleBeneathFindsADescendantRule`, `testRuleBeneathIgnoresARuleAtOrAboveThePath`,
  `testRuleBeneathTakesTheFirstInPathOrder`
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
  `testRefusesAnIntegerBackedDefiningEnum`, `testDefiningAfterFreezingThrows`, `testDefinitionsAreServedAfterFreezing`,
  `testRegistrationIsRequiredPerCall`, `testAFrozenCatalogueStillServesEachCallAsAsked`, `testTheFrozenCheckComesFirst`,
  `testFreezingIsIdempotentAndReported`
- `tests/Unit/Privacy/FieldPolicyTest.php` `testEachHandlingAtALiteralPath`, `testOneRuleDropsEveryOtherField`,
  `testUnlistedRetainKeepsThem`, `testANestedRetainKeepsItAndDropsTheRestOfItsParent`,
  `testAnExplicitTerminalAncestorHandlesTheWholeSubtree`, `testInheritedRetainLetsADescendantRuleApply`,
  `testRemovingListElementsReindexesTheList`, `testTheOwnerIsTheActor`, `testTheOwnerIsTheSubject`,
  `testTheOwnerIsAPropertyHoldingAReference`, `testANoOwnerFieldIsDroppedAndDiagnosed`
- `tests/Unit/Definitions/DefinitionSettingsTest.php` `testDefaultsToFalse`, `testReadsTheSettingOnEveryCall`,
  `testRefusesAnythingButABoolean`, `testNoMessageHoldsTheValue`
- `tests/Feature/RecorderTest.php` `testAnUnregisteredCodeIsRefusedWhenRegistrationIsRequired`,
  `testAMalformedRequireRegisteredFailsClosed`, `testARegisteredDisclosureDefinitionThatRetainsThePurposeIsAccepted`,
  `testARegisteredDisclosureDefinitionThatDoesNotRetainThePurposeIsRefused`,
  `testAnEnumDefinitionThatDoesNotRetainThePurposeIsRefused`, `testAnUnregisteredDisclosureCodeIsAccepted`,
  `testDefineIsRefusedAfterBoot`, `testARegisteredCodeDropsItsUnlistedFields`
- `tests/Feature/Recording/AccessRecordsTest.php` `testAPurposeOfARegisteredDefinitionIsStored`
- `tests/Feature/AuditLogServiceProviderTest.php` `testRegistrationIsFrozenOnceBooted`,
  `testRegistrationInAProvidersBootIsAccepted`, `testAMalformedSettingDoesNotStopBoot`
- `tests/Integration/Octane/RegistrationRequestsTest.php` `testDefinitionsRegisteredAtBootServeEveryRequest`,
  `testDefineInARequestIsRefused`, `testRequiringRegistrationInOneRequestDoesNotReachTheNext`

## Change Triggers

Update this note when any of the following change:

- a definition's defaults, or the bounds of its version or category
- a field handling or key owner, or its stored value
- the path grammar, its segment limit or its reserved prefix
- how the winning rule is chosen, or which rules are unreachable
- how the walker reaches a rule beneath a map or a list
- what an unregistered code gets, or when it is refused
- when definitions may be registered, or what a conflict is
- when `definitions.require_registered` is read, or what a malformed value does
- what a disclosure's definition must retain
