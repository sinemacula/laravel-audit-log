<?php

declare(strict_types = 1);

namespace Tests\Feature\Integrity;

use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Contracts\KeyWrapper;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\Enums\KeyState;
use SineMacula\Laravel\AuditLog\Integrity\JournalSigner;
use SineMacula\Laravel\AuditLog\Integrity\KeyStoreVerifier;
use SineMacula\Laravel\AuditLog\Integrity\OwnerFingerprint;
use SineMacula\Laravel\AuditLog\Integrity\SealSettings;
use SineMacula\Laravel\AuditLog\Integrity\SubjectKeySigner;
use SineMacula\Laravel\AuditLog\Integrity\VerificationTally;
use SineMacula\Laravel\AuditLog\Keys\KeyStore;
use SineMacula\Laravel\AuditLog\Keys\KeyUnit;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\MakesSubjectKeys;
use Tests\TestCase;

/**
 * Feature tests for the verification of the owners' key store, with erasures
 * and reinstatements committed by hand.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(KeyStoreVerifier::class)]
final class KeyStoreVerifierTest extends TestCase
{
    use MakesSubjectKeys;

    /** @var string The type of every owner a test makes keys for. */
    private const string OWNER_TYPE = 'App\Models\User';

    /** @var string A category beside the default, for an owner's second unit. */
    private const string BILLING = 'billing';

    /** @var string An id no key, entry or journal row has. */
    private const string UNKNOWN_ID = '01932b4e-0000-7000-8000-00000000dead';

    /** @var string A second id no key or entry has, after the first. */
    private const string OTHER_UNKNOWN_ID = '01932b4e-0000-7000-8000-00000000beef';

    /** @var string The id of a hold that kept a key. */
    private const string HOLD_ID = '01932b4e-d000-7000-8000-000000000001';

    /** @var string The data key of every key a test signs by hand: thirty-two bytes. */
    private const string DATA_KEY = 'kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk';

    /** @var list<string> The columns that hold a key, and that an erasure changes. */
    private const array KEY_COLUMNS = ['state', 'wrapped_key', 'wrap_key_id', 'erasure_id'];

    /**
     * A key a verified erasure row lists as destroyed is clean: the owner's
     * keys are counted as verified and erased, and nothing is found.
     *
     * @return void
     */
    public function testAnErasedKeyListedByAVerifiedRowIsClean(): void
    {
        $owner = self::owner('42');

        $this->makeSubjectKey($owner);
        $this->makeSubjectKey($owner, category: self::BILLING);
        $this->eraseByHand($owner);

        [$summary, $tally] = $this->verify();

        self::assertSame([], self::findingsOf($tally));
        self::assertSame(['keys' => 2, 'erased' => 2, 'findings' => 0, 'skipped' => false, 'encrypter' => null], $summary->toArray());
    }

    /**
     * A live key with a nulled wrapped key, and one tombstoned with an unknown
     * erasure id, are each `key_destroyed_unjournalled`.
     *
     * @return void
     */
    public function testAKeyNulledWithoutAnErasureIsUnjournalled(): void
    {
        [$nulled]    = $this->makeSubjectKey(self::owner('42'));
        [$tombstone] = $this->makeSubjectKey(self::owner('43'));

        $this->changeKey($nulled->id, ['wrapped_key' => null]);
        $this->changeKey($tombstone->id, ['state' => KeyState::ERASED->value, 'wrapped_key' => null, 'erasure_id' => self::UNKNOWN_ID]);

        [$summary, $tally] = $this->verify();

        self::assertSame([Finding::KEY_DESTROYED_UNJOURNALLED->value => [min($nulled->id, $tombstone->id), 2]], self::findingsOf($tally));
        self::assertSame(2, $summary->erased);
        self::assertSame(2, $summary->findings);
    }

    /**
     * A key put back after the erasure that did not keep it is `key_restored`,
     * though its signature and wrapping are its own.
     *
     * @return void
     */
    public function testAKeyListedErasedButLiveIsRestored(): void
    {
        $owner = self::owner('42');

        [$key] = $this->makeSubjectKey($owner);

        $before = $this->storedKey($key->id);

        $this->eraseByHand($owner);
        $this->changeKey($key->id, $before);

        [$summary, $tally] = $this->verify();

        self::assertSame([Finding::KEY_RESTORED->value => [$key->id, 1]], self::findingsOf($tally));
        self::assertSame(0, $summary->erased);
    }

    /**
     * A key created for an erased owner before any reinstatement is
     * `key_restored`, though properly signed and wrapped.
     *
     * @return void
     */
    public function testALiveKeyOfAnErasedOwnerIsRestored(): void
    {
        $owner = self::owner('42');

        $this->makeSubjectKey($owner);
        $this->eraseByHand($owner);

        $late = $this->signedSubjectKey(new KeyUnit($owner, null, self::KEY_CATEGORY), 2, self::DATA_KEY);

        $this->insertSubjectKey($late);

        [$summary, $tally] = $this->verify();

        self::assertSame([Finding::KEY_RESTORED->value => [$late->id, 1]], self::findingsOf($tally));
        self::assertSame(2, $summary->keys);
        self::assertSame(1, $summary->erased);
    }

    /**
     * A key a partial erasure kept is clean while that erasure is the owner's
     * latest transition, as is the unit it destroyed.
     *
     * @return void
     */
    public function testAKeptKeyOfAPartialErasureIsClean(): void
    {
        $owner = self::owner('42');

        $this->makeSubjectKey($owner);

        [$kept] = $this->makeSubjectKey($owner, category: self::BILLING);

        $this->eraseByHand($owner, [$kept->id => ['held:' . self::HOLD_ID]], true);

        [$summary, $tally] = $this->verify();

        self::assertSame([], self::findingsOf($tally));
        self::assertSame(1, $summary->erased);
        self::assertSame(KeyState::LIVE, $this->storedSubjectKeys()[$kept->id]->state);
    }

    /**
     * After a reinstatement, a key at or below the erasure's floor that holds a
     * key again is `key_restored`; a new key above it is clean.
     *
     * @return void
     */
    public function testAKeyAtOrBelowTheFloorAfterReinstatementIsRestored(): void
    {
        $owner = self::owner('42');

        [$key] = $this->makeSubjectKey($owner);

        $before = $this->storedKey($key->id);

        $this->eraseByHand($owner);
        $this->reinstateByHand($owner);

        [$next] = $this->makeSubjectKey($owner);

        $this->changeKey($key->id, $before);

        [, $tally] = $this->verify();

        self::assertSame(2, $next->generation);
        self::assertSame([Finding::KEY_RESTORED->value => [$key->id, 1]], self::findingsOf($tally));
    }

    /**
     * A key the latest erasure kept stays clean after the owner's
     * reinstatement, though at or below the floor.
     *
     * @return void
     */
    public function testAKeptKeyIsCleanAfterTheReinstatement(): void
    {
        $owner = self::owner('42');

        $this->makeSubjectKey($owner);

        [$kept] = $this->makeSubjectKey($owner, category: self::BILLING);

        $erasure = $this->eraseByHand($owner, [$kept->id => ['held:' . self::HOLD_ID]], true);

        $this->reinstateByHand($owner);

        [, $tally] = $this->verify();

        self::assertSame(1, $kept->generation);
        self::assertSame(1, $erasure->payloadMap()['generation_floor'] ?? null);
        self::assertSame([], self::findingsOf($tally));
    }

    /**
     * A key the first erasure kept and a later one did not is `key_restored`
     * while it holds a key: the exemption lasts until the next erasure.
     *
     * @return void
     */
    public function testAKeptKeyIsExemptOnlyUntilTheNextErasure(): void
    {
        $owner = self::owner('42');

        $this->makeSubjectKey($owner);

        [$kept] = $this->makeSubjectKey($owner, category: self::BILLING);

        $this->eraseByHand($owner, [$kept->id => ['held:' . self::HOLD_ID]], true);
        $this->reinstateByHand($owner);

        $before = $this->storedKey($kept->id);

        $this->eraseByHand($owner);
        $this->changeKey($kept->id, $before);

        [, $tally] = $this->verify();

        self::assertSame([Finding::KEY_RESTORED->value => [$kept->id, 1]], self::findingsOf($tally));
    }

    /**
     * A key use naming a key no row has is `key_missing`, once per key at the
     * first by id; one naming an existing key is not.
     *
     * @return void
     */
    public function testAKeyUseWithNoKeyIsMissing(): void
    {
        [$key] = $this->makeSubjectKey(self::owner('42'));

        $this->keyConnection()->table(KeyTables::keyUsesTable())->insert([
            ['key_id' => self::UNKNOWN_ID, 'entry_id' => self::entryId()],
            ['key_id' => self::UNKNOWN_ID, 'entry_id' => self::entryId()],
            ['key_id' => self::OTHER_UNKNOWN_ID, 'entry_id' => self::entryId()],
            ['key_id' => $key->id, 'entry_id' => self::entryId()],
        ]);

        [$summary, $tally] = $this->verify();

        self::assertSame([Finding::KEY_MISSING->value => [self::OTHER_UNKNOWN_ID, 2]], self::findingsOf($tally));
        self::assertSame(2, $summary->findings);
    }

    /**
     * Rows of `[column, value]`: each immutable column of a key row edited, as
     * an attacker with the database's credentials could.
     *
     * @return iterable<string, array{0: string, 1: int|string}>
     */
    public static function provideImmutableEdits(): iterable
    {
        yield from [
            'the generation'        => ['generation', 9],
            'the creation time'     => ['created_at', '2026-01-01 00:00:00.000000'],
            'the owner'             => ['owner_id', '43'],
            'the category'          => ['category', 'another'],
            'the signature'         => ['hmac', str_repeat('e', 64)],
            'a malformed signature' => ['hmac', 'not-a-signature'],
            'the unit'              => ['unit', str_repeat('a', 64)],
        ];
    }

    /**
     * A key row whose immutable column was edited no longer verifies, or no
     * longer reads, and is `key_substituted`.
     *
     * @param  string  $column
     * @param  int|string  $value
     * @return void
     */
    #[DataProvider('provideImmutableEdits')]
    public function testAnEditedImmutableFieldIsSubstituted(string $column, int|string $value): void
    {
        [$key] = $this->makeSubjectKey(self::owner('42'));

        $this->changeKey($key->id, [$column => $value]);

        [, $tally] = $this->verify();

        self::assertSame([Finding::KEY_SUBSTITUTED->value => [$key->id, 1]], self::findingsOf($tally));
    }

    /**
     * A wrapped key copied from another row does not unwrap under its own
     * context, so the row is `key_substituted`; the source is clean.
     *
     * @return void
     */
    public function testAWrappedKeyMovedFromAnotherRowIsSubstituted(): void
    {
        [$source] = $this->makeSubjectKey(self::owner('42'));
        [$target] = $this->makeSubjectKey(self::owner('43'));

        $this->changeKey($target->id, ['wrapped_key' => $source->wrappedKey]);

        [, $tally] = $this->verify();

        self::assertSame([Finding::KEY_SUBSTITUTED->value => [$target->id, 1]], self::findingsOf($tally));
    }

    /**
     * Rows of `[column, value]`: a key row naming a signing key the integrity
     * ring does not hold, and one naming a wrapping key the wrapper does not.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideUnheldKeys(): iterable
    {
        yield from [
            'a signing key'  => ['key_id', 'retired'],
            'a wrapping key' => ['wrap_key_id', 'retired-wrap'],
        ];
    }

    /**
     * A key row signed or wrapped under a key that is not held cannot be
     * judged, and is `key_unverifiable` rather than substituted.
     *
     * @param  string  $column
     * @param  string  $value
     * @return void
     */
    #[DataProvider('provideUnheldKeys')]
    public function testAnUnknownSigningOrWrappingKeyIsUnverifiable(string $column, string $value): void
    {
        [$key] = $this->makeSubjectKey(self::owner('42'));

        $this->changeKey($key->id, [$column => $value]);

        [, $tally] = $this->verify();

        self::assertSame([Finding::KEY_UNVERIFIABLE->value => [$key->id, 1]], self::findingsOf($tally));
    }

    /**
     * With the package's key store not in use, the section is skipped: nothing
     * is read and nothing is found, though a key use names a key no row has.
     *
     * @return void
     */
    public function testACustomEncrypterSkipsTheSection(): void
    {
        $this->keyConnection()->table(KeyTables::keyUsesTable())->insert(['key_id' => self::UNKNOWN_ID, 'entry_id' => self::entryId()]);

        $statements = $this->listen();
        $tally      = new VerificationTally;
        $summary    = $this->verifier()->verify($tally, false);

        self::assertSame([], $statements->getArrayCopy());
        self::assertSame([], $tally->findings());
        self::assertTrue($summary->skipped);
        self::assertSame(['keys' => 0, 'erased' => 0, 'findings' => 0, 'skipped' => true, 'encrypter' => null], $summary->toArray());
    }

    /**
     * Without unwrapping the wrapper is never called, so a moved wrapped key
     * goes unfound; with it, the wrapper is called once per key.
     *
     * @return void
     */
    public function testWithoutUnwrapNoWrapperIsCalled(): void
    {
        $owner = self::owner('42');

        [$source] = $this->makeSubjectKey($owner);
        [$target] = $this->makeSubjectKey(self::owner('43'));

        $before = $this->storedKey($source->id);

        $this->changeKey($target->id, ['wrapped_key' => $source->wrappedKey]);
        $this->eraseByHand($owner);
        $this->changeKey($source->id, $before);

        $wrapper = $this->countingWrapper();

        [, $tally] = $this->verify(unwrap: false, wrapper: $wrapper);

        self::assertSame(0, $wrapper->calls);
        self::assertSame([Finding::KEY_RESTORED->value => [$source->id, 1]], self::findingsOf($tally));

        [, $unwrapped] = $this->verify(wrapper: $wrapper);

        self::assertSame(2, $wrapper->calls);
        self::assertSame([Finding::KEY_SUBSTITUTED->value, Finding::KEY_RESTORED->value], array_keys(self::findingsOf($unwrapped)));
    }

    /**
     * A wrapper that throws, or unwraps to anything but a data key's length,
     * makes the key `key_substituted`.
     *
     * @return void
     */
    public function testAWrapperThatFailsOrAnswersShortSubstitutesTheKey(): void
    {
        [$key] = $this->makeSubjectKey(self::owner('42'));

        $throwing = $this->countingWrapper(fails: true);
        $short    = $this->countingWrapper('short');

        [, $thrown]   = $this->verify(wrapper: $throwing);
        [, $answered] = $this->verify(wrapper: $short);

        self::assertSame([Finding::KEY_SUBSTITUTED->value => [$key->id, 1]], self::findingsOf($thrown));
        self::assertSame([Finding::KEY_SUBSTITUTED->value => [$key->id, 1]], self::findingsOf($answered));
    }

    /**
     * The keys are read in pages of a thousand by id, each page after the last
     * id the one before read, and every key is verified.
     *
     * @return void
     */
    public function testTheKeysArePagedByTheirIds(): void
    {
        $count = KeyStoreVerifier::PAGE + 1;
        $rows  = [];

        for ($index = 0; $index < $count; $index++) {
            $rows[] = $this->signedSubjectKey(new KeyUnit(self::owner((string) $index), null, self::KEY_CATEGORY), 1, self::DATA_KEY)->toRow();
        }

        foreach (array_chunk($rows, 50) as $chunk) {
            $this->keyConnection()->table(KeyTables::subjectKeysTable())->insert($chunk);
        }

        $ids = array_column($rows, 'id');

        sort($ids, SORT_STRING);

        $statements = $this->listen(true);

        [$summary, $tally] = $this->verify();

        $table = KeyTables::subjectKeysTable();
        $pages = array_filter($statements->getArrayCopy(), static fn (array $statement): bool => str_contains($statement[0], $table) && !str_contains($statement[0], 'exists'));
        $pages = array_values($pages);

        self::assertSame([], self::findingsOf($tally));
        self::assertSame($count, $summary->keys);
        self::assertCount(2, $pages);
        self::assertStringContainsString('limit ' . KeyStoreVerifier::PAGE, $pages[0][0]);
        self::assertNotContains($ids[KeyStoreVerifier::PAGE - 1], $pages[0][1]);
        self::assertContains($ids[KeyStoreVerifier::PAGE - 1], $pages[1][1]);
    }

    /**
     * A key tombstoned with the id of a verified erasure that does not list it
     * is `key_destroyed_unjournalled`; the keys it lists are clean.
     *
     * @return void
     */
    public function testAnErasedKeyWhoseErasureIdRowDoesNotListItIsUnjournalled(): void
    {
        $erased = self::owner('42');

        $this->makeSubjectKey($erased);

        [$other] = $this->makeSubjectKey(self::owner('43'));

        $erasure = $this->eraseByHand($erased);

        $this->changeKey($other->id, ['state' => KeyState::ERASED->value, 'wrapped_key' => null, 'erasure_id' => $erasure->id]);

        [, $tally] = $this->verify();

        self::assertSame([Finding::KEY_DESTROYED_UNJOURNALLED->value => [$other->id, 1]], self::findingsOf($tally));
    }

    /**
     * A tombstone is believed only from a verified erasure row: a row of
     * another kind, or with a changed payload, proves nothing.
     *
     * @return void
     */
    public function testATombstoneNeedsAVerifiedErasureRow(): void
    {
        $owner = self::owner('42');

        [$key] = $this->makeSubjectKey($owner);

        $erasure = $this->eraseByHand($owner);
        $listing = ['destroyed' => [['key_id' => $key->id]], 'owner_fingerprint' => str_repeat('a', 64), 'fingerprint_key' => 'any', 'generation_floor' => 1];
        $other   = $this->journalRow(JournalKind::REINSTATE, $listing);

        $this->changeKey($key->id, ['erasure_id' => $other->id]);

        [, $wrongKind] = $this->verify();

        $this->changeKey($key->id, ['erasure_id' => $erasure->id]);
        $this->tamperJournal($erasure->sequence, ['payload' => '{"destroyed":[{"key_id":"' . $key->id . '"}]}']);

        [, $changed] = $this->verify();

        self::assertSame([Finding::KEY_DESTROYED_UNJOURNALLED->value => [$key->id, 1]], self::findingsOf($wrongKind));
        self::assertSame([Finding::KEY_DESTROYED_UNJOURNALLED->value => [$key->id, 1]], self::findingsOf($changed));
    }

    /**
     * An erasure row whose signature fails proves no transition: no key is
     * found restored by it, and its tombstones are not believed.
     *
     * @return void
     */
    public function testAnErasureRowThatFailsItsSignatureFoldsNothing(): void
    {
        $owner = self::owner('42');

        [$key] = $this->makeSubjectKey($owner);

        $before  = $this->storedKey($key->id);
        $erasure = $this->eraseByHand($owner);

        $this->changeKey($key->id, $before);
        $this->tamperJournal($erasure->sequence, ['hmac' => str_repeat('e', 64)]);

        [, $tally] = $this->verify();

        self::assertSame([], self::findingsOf($tally));
    }

    /**
     * The fold keeps no set of destroyed ids: four pages of erasure rows raise
     * the peak memory no more than one page does.
     *
     * @return void
     */
    public function testTheFoldKeepsNoDestroyedIds(): void
    {
        $owner = self::owner('42');

        $this->appendErasures($owner, KeyStoreVerifier::JOURNAL_PAGE);

        $one = $this->peakGrowthOfAVerification();

        $this->keyConnection()->table(LifecycleTables::journalTable())->delete();
        $this->appendErasures($owner, 4 * KeyStoreVerifier::JOURNAL_PAGE);

        $four = $this->peakGrowthOfAVerification();

        self::assertLessThan($one + 512 * 1024, $four, sprintf('Four pages grew the peak by %d bytes, and one by %d.', $four, $one));
    }

    /**
     * The key store verified, with the wrapper given or the container's, and
     * the tally it added its findings to.
     *
     * @param  bool  $unwrap
     * @param  ?\SineMacula\Laravel\AuditLog\Contracts\KeyWrapper  $wrapper
     * @return array{0: \SineMacula\Laravel\AuditLog\Integrity\KeyStoreSummary, 1: \SineMacula\Laravel\AuditLog\Integrity\VerificationTally}
     */
    private function verify(bool $unwrap = true, ?KeyWrapper $wrapper = null): array
    {
        $tally = new VerificationTally;

        return [$this->verifier($wrapper)->verify($tally, true, $unwrap), $tally];
    }

    /**
     * A key store verifier from the container's collaborators, with the wrapper
     * given or the container's.
     *
     * @param  ?\SineMacula\Laravel\AuditLog\Contracts\KeyWrapper  $wrapper
     * @return \SineMacula\Laravel\AuditLog\Integrity\KeyStoreVerifier
     */
    private function verifier(?KeyWrapper $wrapper = null): KeyStoreVerifier
    {
        return new KeyStoreVerifier(
            app(DatabaseManager::class),
            app(KeyStore::class),
            app(SubjectKeySigner::class),
            app(JournalSigner::class),
            app(OwnerFingerprint::class),
            $wrapper ?? $this->keyWrapper(),
            app(SealSettings::class),
        );
    }

    /**
     * A wrapper that counts its unwrapping and answers as the container's
     * wrapper does, or with the answer given, or fails when asked to.
     *
     * @param  ?string  $answer
     * @param  bool  $fails
     * @return object{calls: int}&\SineMacula\Laravel\AuditLog\Contracts\KeyWrapper
     */
    private function countingWrapper(?string $answer = null, bool $fails = false): KeyWrapper
    {
        return new class ($this->keyWrapper(), $answer, $fails) implements KeyWrapper {
            /** @var int How many times a key was unwrapped. */
            public int $calls = 0;

            /**
             * Constructor.
             *
             * @param  \SineMacula\Laravel\AuditLog\Contracts\KeyWrapper  $inner
             * @param  ?string  $answer
             * @param  bool  $fails
             */
            public function __construct(

                /** The wrapper that answers when no answer is given. */
                private readonly KeyWrapper $inner,

                /** The answer every unwrapping gives instead, if any. */
                private readonly ?string $answer,

                /** Whether every unwrapping fails. */
                private readonly bool $fails,
            ) {}

            /**
             * The inner wrapper's current key.
             *
             * @return string
             */
            #[\Override]
            public function currentKeyId(): string
            {
                return $this->inner->currentKeyId();
            }

            /**
             * The inner wrapper's wrapping.
             *
             * @param  string  $dataKey
             * @param  string  $wrapKeyId
             * @param  string  $context
             * @return string
             */
            #[\Override]
            public function wrap(#[\SensitiveParameter] string $dataKey, string $wrapKeyId, string $context): string
            {
                return $this->inner->wrap($dataKey, $wrapKeyId, $context);
            }

            /**
             * Count the call, then fail when asked to, or answer with the
             * answer given or the inner wrapper's.
             *
             * @param  string  $wrapped
             * @param  string  $wrapKeyId
             * @param  string  $context
             * @return string
             *
             * @throws \LogicException
             */
            #[\Override]
            public function unwrap(#[\SensitiveParameter] string $wrapped, string $wrapKeyId, string $context): string
            {
                $this->calls++;

                if ($this->fails) {
                    throw new \LogicException('The wrapper failed.');
                }

                return $this->answer ?? $this->inner->unwrap($wrapped, $wrapKeyId, $context);
            }
        };
    }

    /**
     * Append erasure rows of the owner, each listing two hundred destroyed keys
     * of its own, none of them stored.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @param  int  $rows
     * @return void
     */
    private function appendErasures(Reference $owner, int $rows): void
    {
        [$fingerprintKey, $fingerprint] = app(OwnerFingerprint::class)->of($owner);

        for ($row = 0; $row < $rows; $row++) {
            $destroyed = [];

            for ($key = 0; $key < 200; $key++) {
                $destroyed[] = ['key_id' => Str::uuid7()->toString(), 'unit' => str_repeat('a', 64), 'generation' => 1];
            }

            $this->journalRow(JournalKind::ERASURE, [
                'owner_fingerprint' => $fingerprint,
                'fingerprint_key'   => $fingerprintKey,
                'generation_floor'  => 1,
                'destroyed'         => $destroyed,
                'kept'              => [],
            ]);
        }
    }

    /**
     * How much a verification of the key store grows the peak by, in bytes.
     *
     * @return int
     */
    private function peakGrowthOfAVerification(): int
    {
        $verifier = $this->verifier();
        $tally    = new VerificationTally;

        gc_collect_cycles();
        memory_reset_peak_usage();

        $before = memory_get_usage();

        $verifier->verify($tally, true);

        return memory_get_peak_usage() - $before;
    }

    /**
     * Change the stored key's columns, as raw values, signing nothing again.
     *
     * @param  string  $id
     * @param  array<string, int|string|null>  $columns
     * @return void
     */
    private function changeKey(string $id, array $columns): void
    {
        $this->keyConnection()->table(KeyTables::subjectKeysTable())->where('id', $id)->update($columns);
    }

    /**
     * The stored key's columns that hold a key, as they are stored now.
     *
     * @param  string  $id
     * @return array<string, int|string|null>
     */
    private function storedKey(string $id): array
    {
        $stored = $this->keyConnection()->table(KeyTables::subjectKeysTable())->where('id', $id)->first(self::KEY_COLUMNS);

        self::assertNotNull($stored);

        /** @var array<string, int|string|null> */
        return (array) $stored;
    }

    /**
     * Record every statement the storage connection runs from now on, with its
     * bindings when asked.
     *
     * @param  bool  $bindings
     * @return \ArrayObject<int, array{0: string, 1: list<int|string|null>}>
     */
    private function listen(bool $bindings = false): \ArrayObject
    {
        /** @var \ArrayObject<int, array{0: string, 1: list<int|string|null>}> $statements */
        $statements = new \ArrayObject;

        $this->keyConnection()->listen(static function (QueryExecuted $query) use ($statements, $bindings): void {
            /** @var list<int|string|null> $bound */
            $bound = $bindings ? array_values($query->bindings) : [];

            $statements->append([strtolower($query->sql), $bound]);
        });

        return $statements;
    }

    /**
     * The findings the tally holds, by their value, each with its first id and
     * how many times it was found.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\VerificationTally  $tally
     * @return array<string, array{0: ?string, 1: int}>
     */
    private static function findingsOf(VerificationTally $tally): array
    {
        $findings = [];

        foreach ($tally->findings() as $finding) {
            $findings[$finding->finding->value] = [$finding->firstBadId, $finding->count];
        }

        return $findings;
    }

    /**
     * An owner of the type every test uses, with the id given.
     *
     * @param  string  $id
     * @return \SineMacula\Laravel\AuditLog\Records\Reference
     */
    private static function owner(string $id): Reference
    {
        return Reference::of(self::OWNER_TYPE, $id);
    }

    /**
     * A fresh entry id, as an envelope's entry is named.
     *
     * @return string
     */
    private static function entryId(): string
    {
        return Str::uuid7()->toString();
    }
}
