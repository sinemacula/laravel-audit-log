# Redaction

## Purpose

This note records what a record keeps of what it is given: how a secret-shaped key is found, how a definition's field
rules are applied, how a value is hashed or sealed, what the byte budgets omit and what the diagnostics say about it,
and how an IP address is stored. A row is kept for years and read by people who never saw the request, so what must not
be kept has to be gone before anything can hold on to it. All of it happens once, at capture, and what it cannot promise
is in `threat-model.md`.

## Invariants

- Minimising runs once, at capture. `Recorder::write()` takes a fresh snapshot after the contributors have run and gives
  it to `Privacy\RecordMinimiser`, and `AuditRecord::fromPending()` takes the `Privacy\Minimised` value it returns, so
  the captured record, and everything given a record afterwards, holds only minimised values.
- The properties pass through key matching, then the field rules, then the byte budget. The context passes through key
  matching, then the string cap, then its byte budget. No field rule touches the context, and none reaches the package's
  own metadata.
- The marker is `[REDACTED]` (`Redactor::MARKER`). A built-in secret is never un-redacted: a value key matching replaced
  stays the marker under `retain`, `redact`, `pseudonymise` and `encrypt`, and is removed by `drop`, because hashing or
  encrypting the marker would look like evidence of a value.
- `properties._audit` is the last key of the properties and holds `note`, `identifier_hash` and `omitted`, in that order
  and only as present. A caller's key cannot begin `_audit`, so nothing in it can be spoofed through `withProperties()`.
- A sign-in identifier is given with `withIdentifier()`, never as a property, and is stored only at
  `properties._audit.identifier_hash`. It is a normalised, keyed hash under `redaction.identifiers` `hash`, the default,
  and nothing under `drop`, so an `unlisted` `drop` cannot lose it and no column ever holds it.
- Hashes have three domains. The root secret is `redaction.key`, decoded, or else `app.key`, decoded, and each domain
  key is HKDF-SHA256 of it, 32 bytes long, with no salt and its own info: `sinemacula/audit-log:identifier:v1`,
  `sinemacula/audit-log:field:v1` or `sinemacula/audit-log:ip:v1`. A hash in one domain can never equal a hash in
  another, even under one configured key, and `app.previous_keys` is not read.
- A hash is `<fingerprint>:<hmac>`, 81 bytes: the first 16 hex characters of the HMAC-SHA256 of `audit-log:fingerprint`
  under the domain key, a colon, and the 64 hex characters of the HMAC-SHA256 of the value under it. A key change is
  therefore visible in the fingerprint, and a fingerprint differs between domains.
- An identifier or a pseudonymised string is cleaned and trimmed, then lower-cased when it is email-shaped: one `@`,
  with no whitespace and something on each side. Anything else that is pseudonymised is hashed as its canonical
  encoding, with the strings inside it left as they are. An address is hashed in its canonical form, exactly.
- An encrypted value goes through `Contracts\FieldEncrypter`. The package binds `Privacy\SubjectKeyEncrypter`, the
  default encrypter, which seals each value under a key of its owner's unit (the owner, the record's tenant and the
  definition's category) with AES-256-GCM, bound to the entry, the value's path and the log, so an owner's values can
  be erased by destroying the owner's keys; `privacy.md` has the keys and the envelope. `Privacy\NoFieldEncrypter`,
  which holds no key for anyone, is the explicit choice never to encrypt: bound, it drops and diagnoses every encrypted
  field, owned note and encrypted address. Each value is given a `Privacy\FieldContext` naming the entry id, the path,
  the log id, the tenant, the category and every owner the record seals for. An envelope is exactly `{v, k, c}`,
  whatever order they come in, and stored in that order: `v` an integer of at least 1, and `k` and `c` non-empty clean
  strings. The encrypter is resolved for each capture.
- The settings are read from configuration during each capture, never at boot, and a malformed one fails closed with an
  `\InvalidArgumentException` naming the key and never the value. `audit-log:check` reports each by its full path:
  `redaction.keys`, `redaction.identifiers`, `redaction.ip`, `redaction.key`, `redaction.max_bytes` and
  `redaction.max_context_bytes`.
- A map key of more than 1024 bytes (`KeyCeiling::MAX_BYTES`) is never split into tokens, stored or measured. Its whole
  branch is removed before anything else reads a key, at every depth, in the properties and the context alike, whatever
  a rule says and however much room a budget has.
- Every parameter holding a raw value or a raw key carries `#[\SensitiveParameter]`, private helpers included, a concrete
  path and an owner read from the payload among them, and no diagnostic or package exception holds a value or a dynamic
  key.

## Success Path

1. A definition says what its code may carry, and a builder describes the activity:

   ```php
   EventDefinition::for('invoice.approved')
       ->retain('amount', 'api_key', 'approver.name')
       ->pseudonymise('approver.email')
       ->encrypt('card_holder', owner: KeyOwner::SUBJECT);

   AuditLog::event('invoice.approved')
       ->on($invoice)
       ->withProperties([
           'amount'      => 4200,
           'api_key'     => 's3cr3t',
           'approver'    => ['name' => 'Ada', 'email' => ' Ada@Example.test ', 'phone' => '+44 20 7946 0000'],
           'card_holder' => 'Ada Lovelace',
           'memo'        => 'Call back.',
           'lines'       => [['sku' => 'A-1']],
       ])
       ->withIdentifier('Ada@Example.test')
       ->withNote('Approved by phone.')
       ->record();
   ```

2. With `Privacy\NoFieldEncrypter` bound, the record's properties are these. `api_key` is the marker in spite of its
   `retain`; the email is a hash of `ada@example.test`; `card_holder` has no key, so it is removed under its rule's
   path; and `phone`, `memo` and `lines` no rule names, so they are removed under masked paths. With the default
   encrypter `card_holder` is instead an envelope under the invoice's key, and the omission counts 3:

   ```json
   {
       "amount": 4200,
       "api_key": "[REDACTED]",
       "approver": {"name": "Ada", "email": "<fingerprint>:<hmac>"},
       "_audit": {
           "note": "Approved by phone.",
           "identifier_hash": "<fingerprint>:<hmac>",
           "omitted": {"count": 4, "paths": ["*", "*.*", "card_holder"]}
       }
   }
   ```

3. An unregistered code takes the permissive definition, so a record within its budget is stored as it was given, apart
   from its secret-shaped keys and any string over 1024 bytes.

## Failure / Edge Cases

- An owner absent: the field, or the owned note, is removed and diagnosed. A property owner must hold exactly `type` and
  `id`, as `Reference` accepts them, and it is read from what key matching left, so a reference under a secret-shaped
  key is no owner, and neither is one with the marker in it. A rule on the owner's own path does not hide it, because
  owners are read before any field is handled.
- A key absent: an encrypter returning `null` is not a failure. The value is removed and diagnosed, nothing is reported,
  and the next value is still offered to the encrypter. The diagnostic is the path and the count, never a reason, so an
  owner with no key, an absent owner and an erased owner read alike, and no later record discloses an erasure.
- Malformed output: an encrypter returning anything but a valid envelope has failed.
- A throwing encrypter has failed too, for an `\Error` as for an exception. A failure is contained, so the value is
  removed and diagnosed and the record is written. `Privacy\FieldEncryptionFailedException`, which names only the
  encrypter's class and has no previous exception, because what was thrown could hold the plaintext, is reported once,
  so there is one report per capture. The encrypter is called no more for that capture, so a wildcard over 10,000
  elements can neither flood a reporter nor keep sending plaintext to something broken. A reporter that fails too is
  ignored.
- Any other failure while minimising fails the write: it propagates from `record()` with a message naming settings and
  types and never a value, nothing is stored, and the builder stays usable.
- A malformed setting fails the write whatever the record holds, because `redaction.keys`, `redaction.identifiers`,
  `redaction.ip` and both budgets are read before anything is sealed. A malformed `redaction.key`, or a missing or
  malformed `app.key` beneath an empty one, fails only a capture that needs a hash, and never falls back: a malformed
  `redaction.key` is not replaced by `app.key`. `audit-log:check` reports them either way.
- A blank identifier, empty once cleaned and trimmed, stores no hash and no diagnostic: a sign-in form can post one, so
  it is not a programming error. A blank pseudonymised field still hashes.
- `redaction.identifiers` `drop` and `redaction.ip` `drop` are configuration, not loss, and add no diagnostic.
- A value the normaliser never leaves (a float or an object) is a programming error when it reaches `pseudonymise`, and
  fails the write naming only its type.
- A key past the ceiling costs its branch and not the record. A client that chooses a key of many megabytes cannot
  exhaust memory while it is split, and one of more than the 65,535 bytes MySQL allows in JSON cannot fail an insert on
  that engine alone, even under a raised budget. A container left empty stays.

## Key Matching

Key matching is a heuristic. `Privacy\KeyTokenizer` makes a key into lower-case tokens in this order:

1. Format characters (`\p{Cf}`: the byte order mark, zero-width characters and the soft hyphen among them) are removed,
   so a word they sit inside stays whole and `pass\u{200B}word` gives `password`.
2. Every run of characters that are not letters, marks or digits splits it, so `user[password]`, `data:password` and
   `password:new` each hold `password`, as does a key whose invalid byte was repaired to U+FFFD.
3. A boundary between a letter and a digit splits it, in either direction: `password2` gives `password`, `2`.
4. A camel-case boundary splits it, an acronym staying together: `accessToken` gives `access`, `token`, `APIKey` gives
   `api`, `key`, and `HTTP2Token` gives `http`, `2`, `token`.

Tokens are compared whole and never as substrings, so `footprint` and `tokenizer` survive, and so do words joined with
no boundary and not listed, such as `mypassword`. A key with no tokens survives, and a key that is not valid UTF-8 has
none, though the normaliser repairs every key before it reaches the matcher. A configured unit with no tokens is a
malformed setting.

`Privacy\Redactor` holds one table, applied to the tokens in this order:

1. **Exact survivors** survive, compared on all of the key's tokens, so `tokensValidAfter` matches as well:
   `authorization_request`, `tokens_valid_after`, `cookie_consent`, `token_type`, `api_key_type`, `bearer_method`,
   `two_factor_enabled`, `two_factor_required`, `two_factor_method`, `two_factor_type`, `credential_type` and
   `credential_kind`. A further token makes it no survivor, so `x_api_key_type` goes on to the later steps.
2. **Exempt final tokens** survive: a key whose final token is `id`, `ids` or `at`, so `access_token_id`, `secret_id`,
   `credential_id`, `token_expires_at` and `password_changed_at`. `id_token` does not, because its final token is
   `token`, and neither does `token_id2`, because its final token is `2`.
3. **Sensitive units** redact, anywhere in the tokens, a unit of two tokens only when they are adjacent: `password`,
   `passwords`, `passwd`, `passwds`, `passcode`, `passcodes`, `passphrase`, `passphrases`, `pwd`, `pwds`, `secret`,
   `secrets`, `token`, `tokens`, `otp`, `otps`, `totp`, `totps`, `hotp`, `hotps`, `pin`, `pins`, `credential`,
   `credentials`, `authorization`, `authorizations`, `cookie`, `cookies`, `bearer`, `bearers`, `jwt`, `jwts`, `cvv`,
   `cvvs`, `cvc`, `cvcs`, `apikey`, `apikeys`, `privatekey`, `privatekeys`, `secretkey`, `secretkeys`, `accesstoken`,
   `accesstokens`, `authtoken`, `authtokens`, `refreshtoken`, `refreshtokens`, `clientsecret`, `clientsecrets`,
   `twofactor`, `twofactors`, `recoverycode`, `recoverycodes`, `cardnumber`, `cardnumbers`, `pass_word`, `pass_words`,
   `pass_phrase`, `pass_phrases`, `auth_pw`, `auth_pws`, `security_code`, `security_codes`, `api_key`, `api_keys`,
   `private_key`, `private_keys`, `remember_token`, `remember_tokens`, `two_factor`, `two_factors`, `recovery_code`,
   `recovery_codes`, `card_number` and `card_numbers`. A plural is a unit of its own, never stemmed.
   `password_confirmation`, `password_reset_request`, `cookie_request`, `csrf_token`, `password2` and `password:new` are
   redacted, while `remember`, `api_key_id` and `pinned` survive.

A key past the ceiling never reaches the tokeniser, because it is removed first; asked directly, `Privacy\Redactor` calls
it sensitive without splitting it. Each distinct key is split once in a call, however many maps repeat it.

A matching key's whole value becomes the marker, a map or a list included, at any depth and inside lists of maps. A
list's indexes are not keys, so only its elements are walked. A key that survives keeps its scalar, and its map or list
is walked.

`redaction.keys` adds sensitive units only, each tokenised the way a key is, so a configured unit passes through steps 1
and 2 like a built-in, and nothing can remove a built-in.

An exemption assumes non-secret metadata, an exempt container's scalar values are kept, and the remedy is an explicit
field rule: `redact('token_id')` redacts what steps 1 and 2 let through.

## Field Rules

`Privacy\FieldPolicy` selects the policy first and transforms the value after it, so each field is decided before any of
it is cut, hashed or sealed. Which rule wins at a path is in `event-definitions.md`; the walker applies that rule like
so:

- A field an explicit terminal rule decides is handled whole, and nothing beneath it is visited.
- A field a `retain` rule decides, directly or from an ancestor, is retained, and a container is walked, so a more
  specific rule beneath an inherited `retain` still applies.
- A non-empty container no rule decides is walked when a rule names a field beneath it, whatever the `unlisted`
  handling. So `retain('customer.email')` with `unlisted` `drop` keeps `customer.email` and drops the rest of
  `customer`.
- Anything else takes the `unlisted` handling, a scalar or an empty container where a rule expected more included.
- A structural ancestor left empty is removed and not counted itself, since its removed children were; a retained
  container left empty stays, because it was retained.
- Removing list elements reindexes the list, and removing map keys keeps the others in their order.

| Handling       | What is stored                                                   | Over a map or a list                   |
|----------------|------------------------------------------------------------------|----------------------------------------|
| `retain`       | the value as key matching left it, each string cut to 1024 bytes | walked                                 |
| `redact`       | `[REDACTED]`                                                     | one marker for the whole branch        |
| `pseudonymise` | the hash of the complete value, in the field domain, never cut   | one hash of its canonical encoding     |
| `encrypt`      | an envelope of its typed plaintext, at most 1024 bytes           | one envelope of its canonical encoding |
| `drop`         | nothing, and the removal is counted                              | the whole branch is one removal        |

`TextSanitizer::cut()` makes the cut, on a character boundary. Plaintext is typed (`Privacy\TypedPlaintext`): the
canonical JSON of the value for every type, a string included, so the string `"true"` and the boolean `true` seal
apart, and it is measured after encoding, at most `TypedPlaintext::MAX_BYTES` (1024) bytes. A string is cut to the
longest prefix whose encoding fits. A container whose canonical JSON is longer than 1024 bytes is dropped and diagnosed
and never reaches the encrypter, as is any other value whose encoding is, because a cut encoding could never be
decoded. Pseudonymising hashes the complete value, so
long values sharing a prefix never collide. A marker, a pseudonym and an envelope are generated values, and are never
cut.

The context has no rules. Each of its strings is cut to the same 1024 bytes (`FieldPolicy::capped()`).

## Budgets And Omission

`redaction.max_bytes` bounds the encoded properties (default 16384, at least 8192) and `redaction.max_context_bytes` the
encoded context (default 4096, at least 1024). A value below its minimum, or above 16777216, is a malformed setting.
Each is measured on the complete final JSON, with `CanonicalEncoder::JSON_FLAGS`.

- A value within its budget is left alone. Over it, each top-level key's cost is computed once and the keys are sorted
  once, by tier, then largest first, then bytewise on the key, so the pass is linear and the result ignores input order.
  Keys are then omitted in that order until the rest fit.
- Omission stays at the top level and never descends into a key. The row is always kept.
- The tiers of the properties are: keys no rule governs go first; then keys a rule governs, itself or beneath them, so a
  branch holding a rule-governed field goes with them; and the note last of all. The tiers of the context are:
  application keys first, then the fixed package names `route`, `method`, `command`, `job` and `channel`.
- The metadata protected is `identifier_hash` and `omitted`, which are bounded and never omitted. The properties keep
  `ByteBudget::METADATA_RESERVE_BYTES` (4600) free for them at their largest, so the final encoding fits whatever the
  omissions add. A note is not protected. The context has no metadata and no reserve, and `_audit` in it is an ordinary
  key.
- `properties._audit.omitted` is `{count, paths}`, for the context's omissions as well, and absent when nothing was
  removed. `count` counts removed branches: every explicit or unlisted removal, every key a budget omitted, every key
  past the ceiling, a note or an address that was not stored, and every collision (see `record-model.md`), including
  those past the 32 the builder carries by path.
- `paths` holds at most 32 paths, the first in bytewise order, unique. A path longer than 128 bytes once encoded becomes
  `*`.
- A segment is written only from the rule that decides that same field, or failing that the first rule beneath it, and
  never because the word occurs in some other rule. A wildcard in the rule stays `*`, and everything else becomes `*`,
  so a dynamic key, which could be an email address, never reaches the list. A concrete key is never written, and no
  value is.
- A context path is `context.` followed by the first segment when it is a fixed package name, and otherwise by `*`, with
  `*` for every later segment.
- The fixed paths are `$ip` for an address, `_audit.note` for a note, and `context.` plus a masked context path. No rule
  or caller key can begin `_audit`, so `_audit.note` is unambiguous. A key past the ceiling is `*` in the properties and
  `context.*` in the context at every depth, because a path through it says nothing a reader could use.

## IP Modes

`redaction.ip` is read on every capture. Every mode starts from the canonical form, in which an IPv4-mapped address is
its IPv4 address, in every mode including `full`, so one client has one form, one hash and one network.

| Mode       | `203.0.113.7`          | `2001:db8:abcd:12::1`    | `::ffff:203.0.113.7`      | Valid, not stored when                  |
|------------|------------------------|--------------------------|---------------------------|-----------------------------------------|
| `full`     | `203.0.113.7`          | `2001:db8:abcd:12::1`    | `203.0.113.7`             | never (the default)                     |
| `truncate` | `203.0.113.0`, a /24   | `2001:db8:abcd::`, a /48 | `203.0.113.0`, a /24      | never                                   |
| `hash`     | `<fingerprint>:<hmac>` | `<fingerprint>:<hmac>`   | the same hash as its IPv4 | never                                   |
| `drop`     | `null`                 | `null`                   | `null`                    | always, with no diagnostic              |
| `encrypt`  | an envelope            | an envelope              | an envelope of its IPv4   | no actor, no key, a failure or too long |

- An invalid address is `null` in every mode and adds `$ip`, because it is not a client's address. That covers anything
  a mapper or contributor fills, an empty string, an over-long one or one holding control characters among them: the
  builder takes it as it comes, so a bad address never fails the write, and its value reaches neither the 255-byte
  column nor a report.
- A `2002::/16` address truncates to its /40 and not its /48, because 6to4 carries the client's IPv4 address straight
  after its prefix, so a /48 would keep all of it. The /40 keeps that address's /24, as a plain IPv4 address does:
  `2002:cb00:7107:1234::5` gives `2002:cb00:7100::`.
- `encrypt` seals the canonical form under the actor's key and stores the envelope's canonical JSON. It must fit the 255
  bytes of the `ip` column, and is dropped and diagnosed rather than truncated, since a cut envelope cannot be
  decrypted. Each way it cannot store one adds `$ip`.
- No address at all is `null` and adds nothing. The mode is read first, so a malformed mode fails even then.

## Implementation Anchors

- `src/Privacy/RecordMinimiser.php`: `minimise()`; `src/Privacy/Minimised.php`.
- `src/Privacy/KeyCeiling.php`: `properties()`, `context()`, `isExceededBy()`, `MAX_BYTES`.
- `src/Privacy/KeyTokenizer.php`: `tokens()`; `src/Privacy/Redactor.php`: `redact()`, `isSensitive()`, `MARKER`,
  `SURVIVORS`, `EXEMPT_FINAL_TOKENS`, `SENSITIVE_UNITS`.
- `src/Privacy/FieldPolicy.php`: `apply()`, `capped()`, `STRING_MAX_BYTES`; `src/Definitions/EventDefinition.php`:
  `ruleFor()`, `ruleBeneath()`.
- `src/Privacy/ByteBudget.php`: `properties()`, `context()`, `METADATA_RESERVE_BYTES`; `src/Privacy/OmissionLog.php`:
  `add()`, `addCount()`, `toArray()`, `MAX_PATHS`, `MAX_PATH_BYTES`; `src/Privacy/PathMasker.php`: `property()`,
  `context()`, `CONTEXT_NAMES`.
- `src/Privacy/IdentifierHasher.php`: `identifier()`, `field()`, `ip()`, `normalised()`, `IDENTIFIER_INFO`,
  `FIELD_INFO`, `IP_INFO`.
- `src/Privacy/IpMinimiser.php`: `minimise()`, `canonical()`, `COLUMN_BYTES`.
- `src/Privacy/Enums/IpMode.php`: `FULL`, `TRUNCATE`, `HASH`, `DROP`, `ENCRYPT`; `src/Privacy/Enums/IdentifierMode.php`:
  `HASH`, `DROP`.
- `src/Contracts/FieldEncrypter.php`: `encrypt()`; `src/Privacy/NoFieldEncrypter.php`; `src/Privacy/EnvelopeSealer.php`:
  `seal()`; `src/Privacy/FieldEncryptionFailedException.php`: `for()`.
- `src/Privacy/SubjectKeyEncrypter.php`, `src/Privacy/FieldContext.php`, `src/Privacy/SealingScope.php`,
  `src/Privacy/TypedPlaintext.php`: `encode()`, `MAX_BYTES`.
- `src/Privacy/RedactionSettings.php`: `keys()`, `explicitKey()`, `rootKey()`, `identifierMode()`, `ipMode()`,
  `maxBytes()`, `maxContextBytes()`, `validate()`; `src/Config/SecretSetting.php`: `decode()`; `config/audit-log.php`:
  `redaction`.
- `src/Records/Concerns/DescribesTheActivity.php`: `withIdentifier()`; `src/Console/CheckCommand.php`.

## Authoritative Tests

- `tests/Unit/Privacy/KeyCeilingTest.php` `testTheCeilingFallsAtItsLastByte`, `testALongerPropertyKeyGoesWithItsBranch`,
  `testALongerContextKeyGoesWithItsBranch`
- `tests/Unit/Privacy/KeyTokenizerTest.php` `testSplitsTheKeyIntoLowerCaseTokens`, `testMalformedUtf8GivesNoTokens`
- `tests/Unit/Privacy/RedactorTest.php` `testTheMatcherTable`, `testEveryBuiltInUnitRedacts`,
  `testEverySurvivorSurvivesInSnakeAndCamelCase`, `testASurvivorWithAnotherTokenIsNotExact`,
  `testASequenceMustBeAdjacent`, `testAConfiguredUnitIsAddedToTheBuiltIns`, `testConfiguringUnitsRemovesNoBuiltIn`,
  `testAConfiguredUnitIsTokenisedTheSameWay`, `testAConfiguredUnitPassesThroughTheExemptions`,
  `testAMatchingKeysWholeValueBecomesTheMarker`, `testTokensHoldingAListOfSecretStringsIsRedacted`,
  `testMatchesInsideAListOfMaps`, `testMatchesAtDepthFive`, `testAnExemptKeysMapIsStillWalked`,
  `testAnExemptKeysScalarsAreKept`, `testAListIndexIsNeverAKey`, `testAMalformedConfiguredListFailsTheCall`
- `tests/Unit/Privacy/FieldPolicyTest.php` `testEachHandlingAtALiteralPath`, `testRetainOnARedactedValueStaysRedacted`,
  `testAValueStepOneRedactedStaysRedactedUnderEveryHandling`, `testAnExplicitRedactBeatsAnExemption`,
  `testANestedRetainKeepsItAndDropsTheRestOfItsParent`, `testAnExplicitTerminalAncestorHandlesTheWholeSubtree`,
  `testInheritedRetainLetsADescendantRuleApply`, `testALiteralIndexRule`, `testAWildcardListRuleWalksEveryElement`,
  `testAWildcardKeyRule`, `testRemovingListElementsReindexesTheList`, `testRemovingMapKeysKeepsTheOthersAndTheirOrder`,
  `testAStructuralAncestorLeftEmptyIsRemovedAndNotCounted`, `testAStructuralAncestorThatIsAScalarIsUnlisted`,
  `testRetainingEveryDescendantAwayLeavesARetainedEmptyContainer`, `testARetainedStringIsCutTo1024Bytes`,
  `testEncryptCutsThePlaintextToTheCapBeforeEncrypting`, `testAContainerWithinTheCapIsSealedWhole`,
  `testAContainerPastTheCapIsDroppedAndDiagnosed`, `testPseudonymiseHashesTheCompleteValue`,
  `testAContainerIsPseudonymisedAsItsCanonicalEncoding`, `testAContainerIsEncryptedAsItsCanonicalEncoding`,
  `testAPseudonymIsNeverCut`, `testAMarkerIsNeverCut`, `testAnEnvelopeIsNeverCut`, `testCappedCutsEveryPlainString`,
  `testTheOwnerIsTheActor`, `testTheOwnerIsTheSubject`, `testTheOwnerIsAPropertyHoldingAReference`,
  `testAnOwnerPropertyThatIsItselfDroppedStillOwns`, `testANoOwnerFieldIsDroppedAndDiagnosed`,
  `testACustomEncrypterStoresItsEnvelope`, `testNoEncrypterDropsAndDiagnoses`,
  `testAMalformedEnvelopeDropsAndDiagnoses`, `testAThrowingEncrypterDropsAndDiagnoses`,
  `testAnExplicitDropIsCountedWithItsRulePath`, `testAnUnlistedDropIsCountedAsAStar`, `testCountCountsRemovedBranches`,
  `testNoValueOrDynamicKeyReachesTheLog`
- `tests/Unit/Privacy/ByteBudgetTest.php` `testAPayloadWithinBudgetIsUntouched`, `testMetadataComesLastInItsFixedOrder`,
  `testTheLargestKeyGoesFirst`, `testATieBreaksBytewiseOnTheKey`, `testKeysNoRuleNamesGoBeforeRuleGovernedKeys`,
  `testABranchHoldingARuleGovernedFieldGoesLast`, `testTheNoteGoesLastAmongOmittableValues`,
  `testTheIdentifierHashAndOmittedAreNeverOmitted`, `testOmissionStaysAtTheTopLevel`,
  `testTheFinalEncodingFitsTheBudget`, `testTheWorstCaseMetadataFitsTheMinimumBudget`, `testOmissionIsDeterministic`,
  `testOmissionIgnoresTheInputOrderOfKeys`, `testCostsAreMeasuredWithTheFixedFlags`,
  `testTheContextBudgetCountsItsBraces`, `testContextApplicationKeysGoBeforeThePackagesNames`,
  `testContextAuditIsAnOrdinaryKey`, `testAnOmittedNoteIsItsFixedPath`
- `tests/Unit/Privacy/OmissionLogTest.php` `testNothingOmittedIsNull`, `testCountsEveryBranch`,
  `testPathsAreUniqueAndSortedBytewise`, `testKeepsTheFirst32Sorted`, `testAPathOf128BytesIsKept`,
  `testAPathOf129BytesBecomesAStar`, `testLengthIsMeasuredEncoded`
- `tests/Unit/Privacy/PathMaskerTest.php` `testTheMaskTable`, `testTheContextMaskTable`,
  `testAConcreteKeyIsNeverWritten`
- `tests/Unit/Privacy/IdentifierHasherTest.php` `testTheGoldenVectors`, `testTheFormatIsAFingerprintAndAnHmac`,
  `testTheInfoLabelsArePinned`, `testAnApplicationKeyDerivesLikeAnExplicitKeyOfTheSameBytes`,
  `testTheFingerprintChangesWithTheKey`, `testNormalisesAnIdentifier`, `testOnlyAnEmailShapedValueIsLowerCased`,
  `testABlankIdentifierHasNoHash`, `testTheThreeDomainsNeverAgree`, `testAFieldHashesItsCompleteValue`,
  `testAContainerHashesItsCanonicalEncoding`, `testAMalformedExplicitKeyFailsClosedNeverFallingBack`
- `tests/Unit/Privacy/IpMinimiserTest.php` `testTheModeMatrix`, `testTheTruncatedNetworkIsExact`,
  `testAnInvalidAddressIsNullInEveryMode`, `testAnInvalidAddressIsDiagnosed`, `testNoAddressIsNullWithNoDiagnostic`,
  `testDropModeAddsNoDiagnostic`, `testTheEncryptModeStoresTheEnvelopesCanonicalJson`,
  `testEncryptWithNoActorIsNullAndDiagnosed`,
  `testEncryptWithNoKeyIsNullAndDiagnosed`, `testEncryptWithAThrowingEncrypterIsNullAndDiagnosed`,
  `testEncryptWithAMalformedEnvelopeIsNullAndDiagnosed`, `testAnEnvelopeOf255BytesFits`,
  `testAnEnvelopeOf256BytesIsDroppedAndNeverTruncated`, `testAMalformedModeFailsWithNoAddress`
- `tests/Unit/Privacy/EnvelopeSealerTest.php` `testAValidEnvelopeComesBackInItsFixedOrder`,
  `testNoKeyIsNotAFailureAndReportsNothing`, `testAMalformedEnvelopeIsAFailure`, `testAThrowingEncrypterIsContained`,
  `testAnErrorIsContainedToo`, `testAFailureReportsThePayloadFreeExceptionWithNoPrevious`,
  `testAFailureIsReportedOncePerCapture`, `testAfterAFailureTheEncrypterIsNotCalledAgain`,
  `testNoKeyDoesNotStopLaterCalls`, `testAFailingReporterIsIgnored`
- `tests/Unit/Privacy/FieldEncryptionFailedExceptionTest.php` `testNamesOnlyTheEncrypterClass`,
  `testHasNoPreviousException`
- `tests/Unit/Privacy/NoFieldEncrypterTest.php` `testHasNoKeyForAnyOwner`
- `tests/Unit/Privacy/RecordMinimiserTest.php` `testAPermissiveRecordIsUnchanged`,
  `testTheOrderIsRedactThenRulesThenCaps`, `testNoRuleTouchesTheContext`, `testTheContextIsRedactedCappedAndBudgeted`,
  `testContextOmissionsArePrefixedInThePropertiesDiagnostics`, `testAPropertyCollisionIsCountedAndMasked`,
  `testAContextCollisionIsCountedAndMasked`, `testARawCollisionKeyNeverReachesTheDiagnostics`,
  `testALiteralDotInACollisionIsMaskedAsOneSegment`, `testCollisionsPastThe32CarriedStillCount`,
  `testAPlaintextNoteGoesToTheMetadataAfterTheCallersKeys`, `testAnOwnedNoteWithNoEncrypterIsDroppedAndDiagnosed`,
  `testAnOwnedNoteWithAnAbsentOwnerIsDroppedAndDiagnosed`, `testAnOwnedNoteWithAnEncrypterStoresItsEnvelope`,
  `testTheIdentifierHashIsInTheReservedArea`, `testTheIdentifierSurvivesAnUnlistedDrop`,
  `testDropModeStoresNoIdentifier`, `testABlankIdentifierStoresNoHash`, `testAnIdentifierIsNeverInThePlainProperties`,
  `testAnInvalidIpIsNullAndDiagnosed`, `testEveryDiagnosticLandsInOneList`, `testAMalformedSettingFailsTheCall`,
  `testAMalformedKeyFailsOnlyWhenAHashIsNeeded`, `testAFailureMessageHoldsNoPayload`
- `tests/Unit/Privacy/RedactionSettingsTest.php` `testTheDefaultsApplyWhenNothingIsSet`,
  `testEachSettingIsReadOnEveryCall`, `testRefusesMalformedKeys`, `testRefusesAnUnknownIdentifierMode`,
  `testRefusesAnUnknownIpMode`, `testTheByteBudgetsAcceptTheirLimits`, `testRefusesAByteBudgetBelowItsMinimum`,
  `testRefusesAByteBudgetAboveItsMaximum`, `testAMalformedExplicitKeyNeverFallsBackToTheApplicationKey`,
  `testTheRootKeyFallsBackToTheApplicationKey`, `testNoMessageHoldsTheValue`
- `tests/Unit/Privacy/SensitiveParametersTest.php` `testEveryRawValueParameterIsSensitive`,
  `testThePrivacyLayersRawParametersAreAllSensitive`
- `tests/Unit/Documentation/DocumentationTest.php` `testTheRedactionNoteCallsKeyMatchingAHeuristic`,
  `testTheRedactionNoteListsEveryMatcherEntry`, `testEveryRedactionLeafNamesItsEnvVarInTheReadme`
- `tests/Feature/RecorderTest.php` `testMinimisingSeesWhatTheContributorsFilled`,
  `testARegisteredCodeDropsItsUnlistedFields`, `testAnUnregisteredCodeRetainsItsFields`,
  `testAMinimiserFailureFailsTheWriteAndStoresNothing`, `testAMinimiserFailureLeavesTheBuilderUsable`,
  `testAFieldEncrypterBoundAfterBootIsUsed`, `testAThrowingEncrypterDoesNotFailTheWrite`,
  `testWithIdentifierReachesTheRecordHashed`
- `tests/Feature/Console/CheckCommandTest.php` `testEveryNewLeafIsCoveredByACheck`,
  `testEachBadSettingIsReportedByItsFullPath`, `testNoSettingValueIsPrinted`
- `tests/Feature/Privacy/CaptureMinimisationTest.php` `testTheHandlingTableEndToEnd`,
  `testNothingUnminimisedIsStoredWhenMinimisingFails`, `testAnIpModeAppliesToARealRequest`,
  `testAGarbageIpStoresTheRecordWithNoAddress`, `testAContributorsGarbageIpDoesNotFailTheWrite`,
  `testAHostileSpellingOfAKeyHidesNoSecret`, `testAnOwnedNoteIsSealedWithTheDefaultEncrypter`,
  `testAnOwnedNoteIsCountedWhenNothingIsEncrypted`, `testAContributedContextIsRedacted`
- `tests/Feature/Privacy/NoSecretAnywhereTest.php` `testTheStoredRowHoldsNoSecret`, `testNoReportHoldsASecret`,
  `testAThrowingEncrypterHoldsNoSecret`, `testAContainedFailureHasNoPrevious`
- `tests/Integration/Stores/MinimisedEntryRoundTripTest.php` `testARedactedRecordStoresAndVerifies`,
  `testEveryHandlingStoresAndVerifies`, `testAnEncryptedIpFitsItsColumnAndVerifies`, `testAGarbageIpStoresNullAndVerifies`,
  `testOmittedDiagnosticsStoreAndVerify`, `testAListReindexedByARuleStoresAsAList`,
  `testACutMultibyteStringStoresAndVerifies`
- `tests/Integration/Privacy/IdentifierCorrelationTest.php` `testFiveFailuresThenALockoutShareOneHash`,
  `testDifferentCaseAndPaddingShareOneHash`, `testDropModeStoresNoHash`, `testAnUnlistedDropDefinitionKeepsTheHash`
- `tests/Performance/MinimiserLoadTest.php` `testATenMegabyteString`, `testATenThousandElementList`,
  `testAThousandLevelsOfNesting`, `testAHundredThousandKeyWideMap`,
  `testAWildcardEncryptWithAThrowingEncrypterReportsOnce`
- `tests/Performance/RecorderQueryBudgetTest.php` `testMinimisingAddsNoQuery`
- `tests/Unit/Privacy/TypedPlaintextTest.php` `testEveryTypeEncodesAsItsCanonicalJson`,
  `testAStringTrueIsNotTheBooleanTrue`, `testAStringIsCutSoItsEncodingFits`, `testACutNeverSplitsACharacter`,
  `testAnyOtherValueOverTheLimitIsNull`
- `tests/Unit/Privacy/FieldPolicyTest.php` `testThePlaintextIsTyped`, `testAStringIsCutSoItsEncodingFits`,
  `testAnEnvelopeIsSealedWithItsPath`, `testAnEnvelopeInAListIsBoundToItsStoredIndex`
- `tests/Unit/Privacy/RecordMinimiserTest.php` `testTheAddressThenTheNoteThenTheFieldsAreSealed`,
  `testEveryOwnerOfTheRecordIsInEachContext`, `testTheEntryIdAndLogIdReachEveryField`
- `tests/Feature/Privacy/SubjectKeyEncrypterTest.php` `testOneLookupServesEveryOwnerOfTheRecord`,
  `testAnErasedOwnersFieldIsDropped`, `testAnAbsentOwnersFieldIsDropped`

## Change Triggers

Update this note when any of the following change:

- a survivor, an exempt final token or a sensitive unit, or how a key is tokenised
- the order of minimising, or what the context passes through
- how the walker selects a rule, or what a handling stores
- a domain's info string, how a root secret or domain key is derived, or the format of a hash
- what an envelope must hold, what counts as a failure, or how one is reported
- the bound encrypter, what a field's context carries, or how plaintext is typed and measured
- a budget's default, minimum or maximum, how it is measured, or the order of omission
- what `omitted` holds, its bounds or how a path is masked
- an IP mode, the canonical form or the column an encrypted address must fit
- what a malformed redaction setting does, or when it is read
