# Integrity

## Purpose

This note records the per-row part of the audit log's integrity: how every entry is signed when it is finalised, the
one canonical encoding the signature is computed over, the key ring that signs and verifies, and what verifying a
stored row answers. A row's signature lets anyone holding the key show that the row is as it was written, so the
encoding, the columns it covers and the keys that verify it are fixed here and versioned by `integrity_version`; a
change to any of them is a new version, never an edit of the old one.

## Invariants

- Every entry is finalised once, by `Records\RecordFinaliser`, which stamps `recorded_at` from the clock (never before
  `occurred_at`) and signs it; retries and replays reuse the finalised record, never sign again.
- The signature is HMAC-SHA256, as 64 lower-case hex characters in `hmac`, under the ring's signing key, whose id is
  stored in `key_id`. It covers the 35 signed columns, every column but `hmac`: the 32 captured ones, then
  `recorded_at`, `integrity_version` and `key_id`. `integrity_version` is 1, and it is signed too.
- The canonical encoding of version 1 (`Integrity\CanonicalEncoder`) works on decoded stored values and never
  normalises, sanitises, truncates or repairs them. `null`, `true` and `false` are themselves; an integer is its decimal
  digits; a string is JSON with fixed flags (UTF-8 and `/` unescaped, `"` and `\` escaped, controls as `\u00XX`,
  U+2028 and U+2029 escaped); a list keeps its order; a map, a PHP array that is not a list or a decoded JSON object,
  has its keys sorted bytewise and is always written as a map, so `{}` and numeric keys survive. A float, any other
  object and invalid UTF-8 are refused with an `\UnexpectedValueException`: the package stores decimals as strings.
- Every signed column is required to verify, nullable ones included; a missing column is malformed, never `null`.
  Columns a row has beyond the version's list are not signed, and `audit-log:check` reports them.
- The captured-content digest is SHA-256 over the canonical encoding of the 32 captured columns, leaving out the four
  finalisation columns. The store compares it to tell a stored duplicate from a conflict, so a record finalised twice,
  at another time or under another key, is still the same record.
- With `integrity.keys` empty, the key is derived from `app.key`: a `base64:` key is decoded to bytes first, then
  HKDF-SHA256 with the info `sinemacula/audit-log:integrity:v1` gives the 32-byte secret. Its id is a fingerprint,
  `d` followed by the first 16 hex characters of the HMAC-SHA256 of `audit-log:key-id` under the secret, so a rotated
  `app.key` gets a new id. Keys derived from `app.previous_keys` in the same way verify only, never sign.
- With `integrity.keys` set, the ring is exactly those keys, and `integrity.current` names the one that signs. Each id
  is 1 to 32 letters, digits, dots, underscores or hyphens starting with a letter or a digit, so it fits `key_id`;
  each secret, once decoded (`base64:` strictly), is at least 32 bytes and is the HMAC key itself. A malformed ring
  fails closed on every call and never falls back to `app.key`.
- The ring is rebuilt from the settings on every call, so a worker always signs with the configured key. A key's
  secret is never in a message, a stack trace, a dump, a JSON encoding or an export.
- Verification (`RecordSigner::verifies()`) answers `false` only when the signature does not match. A key id that is
  not in the ring is an `Integrity\UnknownKeyException` naming the id; an unsupported `integrity_version`, a missing
  column, a malformed `hmac` or a value with no canonical form is an `\UnexpectedValueException`. Verification keeps the
  evidence as it is and never repairs it.
- A record kept outside the entries table, in the outbox or a spill line, is verified on the way back in, by
  `Records\EnvelopeCodec`. Only one that verifies reaches the store, and it arrives with its own `recorded_at`, key id
  and HMAC. A replay verifies and never re-signs, because a new signature would vouch for bytes nobody can now check, so
  a removed signing key means restoring the key or leaving the record quarantined. A line marked `unsigned` has no
  signature to verify, and is counted and left.
- Removing a key from the ring leaves its rows unverifiable. Verification keys are kept as long as the rows they
  signed, independently of when an encryption key is retired: moving `app.key` into `app.previous_keys` keeps the old
  derived key verifying, and dropping it from there does not. Choose the managed ring before going live, because rows
  signed under a derived key cannot yet be carried into it.
- A row's signature proves that row alone: it shows neither that every entry is present nor that none was deleted.

## Success Path

- With no integrity settings, every entry is signed under the key derived from `app.key` and verifies with it.
- After `app.key` is rotated and the old key moved to `app.previous_keys`, new entries are signed under the new derived
  key and old ones still verify.
- With a managed ring, entries are signed under `integrity.current`; moving `current` to a new key signs new entries
  with it while every key left in the ring still verifies its rows.
- `php artisan audit-log:check` reports a malformed ring, a short secret and a current key that is not in the ring
  before a deploy.

## Failure / Edge Cases

- A malformed `integrity.keys` or `integrity.current`, an empty or short `app.key` with no managed ring, or malformed
  `app.previous_keys` fails closed with an `\InvalidArgumentException` naming the setting, never its value; nothing is
  signed or verified until it is fixed.
- A stored JSON number that is not a PHP integer (a fraction, an exponent or an integer beyond PHP's range) decodes as
  a float and is refused as malformed; it is never decoded as a string, so a string edited into a bare number never
  verifies as the original.
- A tampered column, a nested property or a microsecond fails verification with `false`.
- A row signed under a key the ring no longer holds raises `UnknownKeyException`; the store lets it propagate rather
  than call the row a conflict.
- An envelope in the outbox or a spill line that fails is refused with a distinct `Records\Enums\EnvelopeFailure`:
  `signature_mismatch`, `unknown_key`, `unsupported_version` or `malformed`. The outbox row is failed and kept, and the
  spill line is counted and left in its file; `delivery.md` has every outcome.

## Seams Left

- Membership seals, external anchors and `audit-log:verify`, which prove completeness and report every row.
- Carrying derived keys into a managed ring, and listing the ring's ids for reports.

## Implementation Anchors

- `src/Integrity/CanonicalEncoder.php`: `encode()`, `JSON_FLAGS`.
- `src/Integrity/RecordSigner.php`: `sign()`, `verifies()`, `capturedDigest()`, `SIGNED_COLUMNS`, `CAPTURED_COLUMNS`.
- `src/Integrity/KeyRing.php`: `signingKey()`, `key()`; `src/Integrity/IntegritySettings.php`: `validate()`.
- `src/Integrity/IntegrityKey.php`: `secret()`, `ID_PATTERN`, `MIN_SECRET_BYTES`;
  `src/Integrity/UnknownKeyException.php`: `forKey()`.
- `src/Records/RecordFinaliser.php`: `finalise()`; `src/Records/FinalisedRecord.php`.
- `src/Records/EnvelopeCodec.php`: `decode()`; `src/Delivery/Replayer.php`: `spill()`.
- `config/audit-log.php`: `integrity`.

## Authoritative Tests

- `tests/Unit/Integrity/CanonicalEncoderTest.php` `testEncodesEachGoldenVectorByteForByte`, `testKeysSortBytewise`,
  `testANumericKeyMapStaysAMap`, `testAnEmptyObjectIsNotAnEmptyList`, `testListOrderIsKept`,
  `testNeverRepairsWhatItEncodes`, `testRefusesAFloat`, `testRefusesInvalidUtf8`
- `tests/Unit/Integrity/RecordSignerTest.php` `testTheGoldenEntrySignsByteForByte`,
  `testTamperingAnyColumnFailsVerification`, `testTamperingANestedPropertyOrAMicrosecondFailsVerification`,
  `testAnotherKeyIdInTheRingFailsVerification`, `testAKeyIdOutsideTheRingIsUnknown`, `testARetiredKeyStillVerifiesItsRows`,
  `testAnUnsupportedIntegrityVersionIsUnexpected`, `testAMissingColumnIsMalformedNeverNull`,
  `testAMalformedHmacIsUnexpected`, `testAStringPropertyEditedIntoABareNumberIsMalformedNeverVerified`,
  `testTheCapturedDigestLeavesOutTheFinalisationColumns`, `testVerificationNeverNormalises`
- `tests/Unit/Integrity/KeyRingTest.php` `testTheDefaultDerivesOneSigningKeyFromTheApplicationKey`,
  `testTheDerivedKeyIsStableForAFixedApplicationKey`, `testABase64ApplicationKeyIsDecodedBeforeDerivation`,
  `testARotatedApplicationKeyGetsANewKeyId`, `testPreviousApplicationKeysVerifyButNeverSign`,
  `testAnExplicitRingNeverFallsBackToTheApplicationKey`, `testAMalformedExplicitRingFailsClosedOnEveryCall`
- `tests/Unit/Integrity/IntegritySettingsTest.php` `testAMalformedRingFailsClosedNamingTheSetting`,
  `testAnEmptyCurrentKeyIdReadsAsNone`, `testNoMessageContainsASecret`
- `tests/Unit/Integrity/IntegrityKeyTest.php` `testRefusesAnIdTheColumnCannotHold`,
  `testRefusesASecretShorterThan32Bytes`, `testNoDumperEncodingOrExportShowsTheSecret`
- `tests/Unit/Records/RecordFinaliserTest.php` `testStampsTheClocksTimeAndSigns`,
  `testRecordedAtIsNeverBeforeTheActivityOccurred`, `testFinalisingTwiceAtOneInstantGivesTheSameBytes`
- `tests/Integration/Stores/StoredEntryRoundTripTest.php` `testAStoredRecordVerifiesAfterTheRoundTrip`,
  `testNestedPropertiesTheEngineReordersStillVerify`, `testUnicodeAndHostileTextStillVerify`,
  `testAnEditedStoredRowFailsVerification`
- `tests/Unit/Records/EnvelopeCodecTest.php` `testADecodedRecordVerifies`, `testATamperedValueIsASignatureMismatch`,
  `testAnUnknownKeyIsDistinct`, `testAnUnsupportedIntegrityVersionIsDistinct`,
  `testAnEnvelopeSignedWithARetiredKeyDecodes`
- `tests/Feature/Delivery/ReplayerTest.php` `testNeverResigns`, `testNeverFinalisesAgain`,
  `testAnUnknownKeyIsSkippedAndCounted`, `testAnUnsignedLineIsSkippedAndCounted`
- `tests/Integration/Delivery/SpillReplayEnginesTest.php` `testAReplayedRowVerifies`,
  `testALineUnderARemovedKeyReplaysOnceTheKeyIsBack`
- `tests/Feature/Delivery/OutboxDrainerTest.php` `testAnEnvelopeUnderARemovedSigningKeyIsFailedAndNeverResigned`

## Change Triggers

Update this note when any of the following change:

- a rule of the canonical encoding, or its JSON flags
- the signed or captured columns, or their order
- the integrity version, or the versions verification supports
- the derivation, its info string or the derived key's id
- the key id grammar or the shortest secret
- what verification answers, or which exception it raises
- what a replay verifies, or how a removed key is handled
