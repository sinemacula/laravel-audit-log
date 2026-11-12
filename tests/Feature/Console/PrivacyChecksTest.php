<?php

declare(strict_types = 1);

namespace Tests\Feature\Console;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Console\PrivacyChecks;
use SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor;
use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;
use SineMacula\Laravel\AuditLog\Contracts\KeyWrapper;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\JournalRow;
use SineMacula\Laravel\AuditLog\Integrity\KeyStoreVerifier;
use SineMacula\Laravel\AuditLog\Privacy\NoFieldEncrypter;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\MakesSubjectKeys;
use Tests\Concerns\SealsEntries;
use Tests\Fixtures\Integrity\RecordingAnchor;
use Tests\Fixtures\Privacy\RecordingFieldEncrypter;
use Tests\TestCase;

/**
 * Feature tests for the privacy checks of `audit-log:check`, with erasures and
 * restores made by hand.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PrivacyChecks::class)]
final class PrivacyChecksTest extends TestCase
{
    use MakesSubjectKeys, MockeryPHPUnitIntegration, SealsEntries;

    /** @var string The type of every owner a test makes keys for. */
    private const string OWNER_TYPE = 'App\Models\User';

    /** @var string What a missing table is asked to be created by, after its name and connection. */
    private const string PUBLISH = '; publish and run the migrations (`vendor:publish --tag=audit-log-migrations`, then `migrate`).';

    /** @var string The digest an anchor holds that no local seal has. */
    private const string ANCHORED_DIGEST = 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd';

    /** @var string Another digest, which reconciles nothing the anchor holds. */
    private const string OTHER_DIGEST = 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';

    /** @var string What the wrapping keys derived from a missing or malformed application key are refused with. */
    private const string DERIVED_RING = '`app.key` and each of `app.previous_keys` must be at least 32 bytes, or `base64:` followed by the encoding of at least'
        . ' 32 bytes, to derive the wrapping keys when `audit-log.privacy.keys` is empty.';

    /** @var string The problem of a database behind its anchor's head, after the head's sequence. */
    private const string RESTORED_DATABASE = ', so it was restored from a backup or rewritten; re-apply every erasure since with `audit-log:erase --reapply=<file>`,'
        . ' which reconciles the restore, and run `audit-log:verify`.';

    /** @var string What a test's owner id carries, and the output must never hold. */
    private const string SENTINEL = 'sentinel-7f3a9c';

    /**
     * Bind the package's key wrapper, whether or not the provider has.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->keyWrapper();
    }

    /**
     * Rows of `[the leaf under audit-log, a value it refuses]`.
     *
     * @return iterable<string, array{0: string, 1: array<string, string>|int|string}>
     */
    public static function provideLeaves(): iterable
    {
        yield from [
            'the subject keys table'   => ['privacy.subject_keys_table', 'Keys'],
            'the owner erasures table' => ['privacy.owner_erasures_table', 'owner-erasures'],
            'the key uses table'       => ['privacy.key_uses_table', '1uses'],
            'the wrapping ring'        => ['privacy.keys', 'x'],
            'a wrapping secret'        => ['privacy.keys', ['w1' => 'short']],
            'the current wrapping key' => ['privacy.current', 'w1'],
            'the rewrap batch'         => ['privacy.rewrap_batch', 10001],
        ];
    }

    /**
     * Each owners' key setting has a reader that refuses it when malformed.
     *
     * @param  string  $leaf
     * @param  array<string, string>|int|string  $bad
     * @return void
     */
    #[DataProvider('provideLeaves')]
    public function testEveryPrivacyReaderIsListed(string $leaf, array|int|string $bad): void
    {
        $config  = app(ConfigRepository::class);
        $readers = PrivacyChecks::readers($config);

        self::assertCount(7, $readers);
        self::assertSame([], self::refusalsOf($readers));

        $config->set("audit-log.{$leaf}", $bad);

        $refusals = self::refusalsOf(PrivacyChecks::readers($config));

        self::assertNotSame([], $refusals);
        self::assertStringStartsWith("`audit-log.{$leaf}", $refusals[0]);
    }

    /**
     * A healthy install with an owner keyed and another erased has no problem.
     *
     * @return void
     */
    public function testAHealthyInstallHasNoProblem(): void
    {
        $this->makeSubjectKey(self::owner('42'));
        $this->makeSubjectKey(self::owner('43'));
        $this->eraseByHand(self::owner('43'));

        self::assertSame([], $this->checks()->problems());
        self::assertSame([], $this->checks()->notes());
    }

    /**
     * Rows of `[the settings changed, the one problem they cause]`.
     *
     * @return iterable<string, array{0: array<string, array<array-key, string>|int|string|null>, 1: string}>
     */
    public static function provideMalformedRings(): iterable
    {
        $secret = str_repeat('w', 32);

        yield from [
            'a ring that is not a map' => [
                ['audit-log.privacy.keys' => 'x'],
                '`audit-log.privacy.keys` must be a map of key ids to secrets, or empty to derive the wrapping key from `app.key`.',
            ],
            'a ring with a short secret' => [
                ['audit-log.privacy.keys' => ['w1' => 'short'], 'audit-log.privacy.current' => 'w1'],
                '`audit-log.privacy.keys.w1` must be a secret of at least 32 bytes, or `base64:` followed by the encoding of one.',
            ],
            'a ring with a key id of no grammar' => [
                ['audit-log.privacy.keys' => ['-w1' => $secret], 'audit-log.privacy.current' => '-w1'],
                '`audit-log.privacy.keys` has a key id that is not 1 to 32 letters, digits, dots, underscores or hyphens, starting with a letter or a digit.',
            ],
            'a current key the ring does not hold' => [
                ['audit-log.privacy.keys' => ['w1' => $secret], 'audit-log.privacy.current' => 'w2'],
                '`audit-log.privacy.current` must name a key in `audit-log.privacy.keys`.',
            ],
            'a current key beside no ring' => [
                ['audit-log.privacy.current' => 'w1'],
                '`audit-log.privacy.current` names a key, but `audit-log.privacy.keys` is empty; set both, or neither to derive the wrapping key from `app.key`.',
            ],
            'no application key to derive from' => [['app.key' => ''], self::DERIVED_RING],
            'previous keys too short'           => [['app.previous_keys' => ['short']], self::DERIVED_RING],
            'a rewrap batch out of range'       => [['audit-log.privacy.rewrap_batch' => 99], '`audit-log.privacy.rewrap_batch` must be an integer from 100 to 10000.'],
        ];
    }

    /**
     * A malformed wrapping ring is the one problem and stops the rest.
     *
     * @param  array<string, array<array-key, string>|int|string|null>  $settings
     * @param  string  $problem
     * @return void
     */
    #[DataProvider('provideMalformedRings')]
    public function testAMalformedRingIsAProblem(array $settings, string $problem): void
    {
        $this->restoreAKey(self::owner('42'));

        app(ConfigRepository::class)->set($settings);

        self::assertSame([$problem], $this->checks()->problems());
    }

    /**
     * An explicit wrapping ring needs no application key.
     *
     * @return void
     */
    public function testAnExplicitRingNeedsNoApplicationKey(): void
    {
        app(ConfigRepository::class)->set([
            'audit-log.integrity.keys'    => ['k1' => str_repeat('k', 32)],
            'audit-log.integrity.current' => 'k1',
            'audit-log.privacy.keys'      => ['w1' => 'base64:' . base64_encode(str_repeat('w', 32))],
            'audit-log.privacy.current'   => 'w1',
            'app.key'                     => '',
        ]);

        self::assertSame([], $this->checks()->problems());
    }

    /**
     * Rows of `[the table's setting, the absent table it names, its label]`.
     *
     * @return iterable<string, array{0: string, 1: string, 2: string}>
     */
    public static function provideMissingTables(): iterable
    {
        yield from [
            'the subject keys'   => ['privacy.subject_keys_table', 'audit_absent_subject_keys', 'subject keys'],
            'the owner erasures' => ['privacy.owner_erasures_table', 'audit_absent_owner_erasures', 'owner erasures'],
            'the key uses'       => ['privacy.key_uses_table', 'audit_absent_key_uses', 'key uses'],
        ];
    }

    /**
     * A missing key table is named by its label and skips what reads it.
     *
     * @param  string  $setting
     * @param  string  $table
     * @param  string  $label
     * @return void
     */
    #[DataProvider('provideMissingTables')]
    public function testEachKeyTablesShapeIsChecked(string $setting, string $table, string $label): void
    {
        $anchor = (new RecordingAnchor)->holdInstead(4, self::ANCHORED_DIGEST);

        $this->restoreAKey(self::owner('42'));
        $this->app?->instance(CheckpointAnchor::class, $anchor);

        app(ConfigRepository::class)->set("audit-log.{$setting}", $table);

        self::assertSame(["The {$label} table `{$table}` does not exist on connection [" . self::CONNECTION . ']' . self::PUBLISH], $this->checks()->problems());
        self::assertSame([], $anchor->calls());
    }

    /**
     * A key table of the wrong shape is a problem naming what is wrong.
     *
     * @return void
     */
    public function testAKeyTableOfTheWrongShapeIsAProblem(): void
    {
        Schema::table(KeyTables::keyUsesTable(), static function (Blueprint $table): void {
            $table->dropIndex('audit_log_key_uses_entry_index');
        });

        Schema::table(KeyTables::subjectKeysTable(), static function (Blueprint $table): void {
            $table->string('notes')->nullable();
        });

        self::assertSame([
            'Column `notes` is not one the package writes.',
            'Index `audit_log_key_uses_entry_index` is missing.',
        ], $this->checks()->problems());
    }

    /**
     * A restored key of an erased owner is a problem until reapplied.
     *
     * @return void
     */
    public function testARestoredKeyIsAProblemUntilReapplied(): void
    {
        $owner = self::owner('42');
        $key   = $this->restoreAKey($owner);

        self::assertSame([
            "1 key of erased owners holds a key again (`key_restored`, the first `{$key}`); a restore from before an erasure brings its keys back,"
                . ' so re-apply the erasures since with `audit-log:erase --reapply=<file>`.',
        ], $this->checks()->problems());

        $this->eraseByHand($owner);

        self::assertSame([], $this->checks()->problems());
    }

    /**
     * Keys restored for two owners are counted, the first by id named.
     *
     * @return void
     */
    public function testRestoredKeysAreCountedAndTheFirstNamed(): void
    {
        $first  = $this->restoreAKey(self::owner('42'));
        $second = $this->restoreAKey(self::owner('43'));

        self::assertSame([
            sprintf('2 keys of erased owners hold a key again (`key_restored`, the first `%s`); a restore from before an erasure brings its keys back,', min($first, $second))
                . ' so re-apply the erasures since with `audit-log:erase --reapply=<file>`.',
        ], $this->checks()->problems());
    }

    /**
     * A key destroyed without a journalled erasure is a problem.
     *
     * @return void
     */
    public function testAKeyDestroyedWithoutAnErasureIsAProblem(): void
    {
        [$nulled] = $this->makeSubjectKey(self::owner('43'));

        $restored = $this->restoreAKey(self::owner('42'));

        $this->keyConnection()->table(KeyTables::subjectKeysTable())->where('id', $nulled->id)->update(['wrapped_key' => null]);

        $unjournalled = "1 key holds no wrapped key that a verified erasure destroyed (`key_destroyed_unjournalled`, the first `{$nulled->id}`);"
            . ' run `audit-log:verify`, and after a restore re-apply the erasures with `audit-log:erase --reapply=<file>`.';

        $problems = $this->checks()->problems();

        self::assertCount(2, $problems);
        self::assertStringContainsString("(`key_restored`, the first `{$restored}`)", $problems[0]);
        self::assertSame($unjournalled, $problems[1]);

        $this->eraseByHand(self::owner('42'));

        self::assertSame([$unjournalled], $this->checks()->problems());
    }

    /**
     * A key wrapped outside the ring is a problem, found without unwrapping.
     *
     * @return void
     */
    public function testAKeyWrappedOutsideTheRingIsAProblem(): void
    {
        [$first]  = $this->makeSubjectKey(self::owner('42'));
        [$second] = $this->makeSubjectKey(self::owner('43'));

        $this->makeSubjectKey(self::owner('44'));
        $this->eraseByHand(self::owner('44'));

        $table = $this->keyConnection()->table(KeyTables::subjectKeysTable());

        (clone $table)->where('id', $first->id)->update(['wrap_key_id' => 'w1999']);
        (clone $table)->where('id', $second->id)->update(['wrap_key_id' => 'w1998', 'state' => 'superseded']);

        self::assertSame([
            sprintf('2 keys are wrapped under a wrapping key the ring does not hold (the first `%s`), so they cannot be unwrapped;', min($first->id, $second->id))
                . ' put the wrapping key back in `audit-log.privacy.keys` or `app.previous_keys`, then run `audit-log:rewrap`.',
        ], $this->checks()->problems());

        (clone $table)->where('id', $second->id)->update(['wrap_key_id' => $first->wrapKeyId]);

        self::assertSame([
            "1 key is wrapped under a wrapping key the ring does not hold (the first `{$first->id}`), so it cannot be unwrapped;"
                . ' put the wrapping key back in `audit-log.privacy.keys` or `app.previous_keys`, then run `audit-log:rewrap`.',
        ], $this->checks()->problems());

        $this->app?->instance(KeyWrapper::class, \Mockery::spy(KeyWrapper::class));

        self::assertSame([], $this->checks()->problems());
    }

    /**
     * An explicit ring still holds keys wrapped under the derived ring.
     *
     * @return void
     */
    public function testAKeyWrappedUnderTheDerivedRingIsHeldByAnExplicitRing(): void
    {
        [$key] = $this->makeSubjectKey(self::owner('42'));

        $config = app(ConfigRepository::class);

        $config->set('audit-log.privacy.keys', ['w2026' => str_repeat('w', 32)]);
        $config->set('audit-log.privacy.current', 'w2026');

        self::assertSame([], $this->checks()->problems());

        $config->set('app.key', 'base64:' . base64_encode(str_repeat('r', 32)));

        self::assertSame([
            "1 key is wrapped under a wrapping key the ring does not hold (the first `{$key->id}`), so it cannot be unwrapped;"
                . ' put the wrapping key back in `audit-log.privacy.keys` or `app.previous_keys`, then run `audit-log:rewrap`.',
        ], $this->checks()->problems());
    }

    /**
     * A database behind its anchor is a problem until verifiably reconciled.
     *
     * @return void
     */
    public function testARestoreBehindTheAnchorIsAProblemUntilReconciled(): void
    {
        $this->app?->instance(CheckpointAnchor::class, (new RecordingAnchor)->holdInstead(4, self::ANCHORED_DIGEST));

        $problem = ['The database does not hold the seal its anchor holds at sequence 4' . self::RESTORED_DATABASE];

        self::assertSame($problem, $this->checks()->problems());

        $this->reconcile(3, self::ANCHORED_DIGEST);
        $this->reconcile(4, self::OTHER_DIGEST);

        $tampered = $this->reconcile(4, self::ANCHORED_DIGEST);

        $this->tamperJournal($tampered->sequence, ['payload' => str_replace('"owners":1', '"owners":2', $tampered->payload ?? '')]);

        self::assertSame($problem, $this->checks()->problems());

        $this->reconcile(4, self::ANCHORED_DIGEST);

        self::assertSame([], $this->checks()->problems());
    }

    /**
     * A reconciliation naming the head is found behind newer ones.
     *
     * @return void
     */
    public function testAReconciledRestorePasses(): void
    {
        $this->app?->instance(CheckpointAnchor::class, (new RecordingAnchor)->holdInstead(4, self::ANCHORED_DIGEST));

        $this->reconcile(4, self::ANCHORED_DIGEST);

        foreach (range(1, PrivacyChecks::JOURNAL_PAGE) as $later) {
            $this->reconcile(4 + $later, self::OTHER_DIGEST);
        }

        $statements = $this->listen();

        self::assertSame([], $this->checks()->problems());

        $newestFirst = static fn (string $statement): bool => str_contains($statement, 'audit_log_lifecycle') && str_contains($statement, ' desc');
        $pages       = array_filter($statements->getArrayCopy(), $newestFirst);

        self::assertCount(2, $pages);
    }

    /**
     * A seal at the anchor's head with another digest is a restore.
     *
     * @return void
     */
    public function testASealContradictingTheAnchorIsARestore(): void
    {
        $this->storeEntries(3);
        $this->sealAt('2026-11-02 00:00:00');
        $this->sealAll();

        $seals  = $this->seals();
        $head   = array_pop($seals);
        $anchor = new RecordingAnchor;

        self::assertNotNull($head);

        $this->app?->instance(CheckpointAnchor::class, $anchor->holdInstead((int) $head['sequence'], (string) $head['seal_digest']));

        self::assertSame([], $this->checks()->problems());

        $anchor->holdInstead((int) $head['sequence'], self::OTHER_DIGEST);

        $problem = sprintf('The database does not hold the seal its anchor holds at sequence %d', (int) $head['sequence']) . self::RESTORED_DATABASE;

        self::assertSame([$problem], $this->checks()->problems());
    }

    /**
     * Without an anchor that discovers its head no restore is claimed.
     *
     * @return void
     */
    public function testWithoutDiscoveryNoRestoreIsClaimed(): void
    {
        self::assertSame([], $this->checks()->problems());

        $blind = (new RecordingAnchor(false))->holdInstead(4, self::ANCHORED_DIGEST);

        $this->app?->instance(CheckpointAnchor::class, $blind);

        self::assertSame([], $this->checks()->problems());
        self::assertSame([], $blind->calls());

        $empty = new RecordingAnchor;

        $this->app?->instance(CheckpointAnchor::class, $empty);

        self::assertSame([], $this->checks()->problems());
        self::assertSame(['latest'], $empty->calls());
    }

    /**
     * An unreadable anchor is a problem, since a restore cannot be ruled out.
     *
     * @return void
     */
    public function testAnAnchorThatCannotBeReadIsAProblem(): void
    {
        $this->app?->instance(CheckpointAnchor::class, (new RecordingAnchor)->failing(new \RuntimeException(self::SENTINEL)));

        self::assertSame(['The anchor\'s head could not be read (RuntimeException), so a database restored behind it cannot be ruled out.'], $this->checks()->problems());
    }

    /**
     * An unreadable key store is named by its exception class alone.
     *
     * @return void
     *
     * @throws \RuntimeException
     */
    public function testAKeyStoreThatCannotBeReadIsAProblem(): void
    {
        $this->app?->bind(KeyStoreVerifier::class, static fn (): never => throw new \RuntimeException(self::SENTINEL));

        self::assertSame(['The key store could not be read (RuntimeException).'], $this->checks()->problems());
    }

    /**
     * A custom encrypter is a note and its key store is not checked.
     *
     * @return void
     */
    public function testACustomEncrypterIsANote(): void
    {
        $this->restoreAKey(self::owner('42'));

        $this->app?->instance(FieldEncrypter::class, new RecordingFieldEncrypter);

        self::assertSame([
            'The bound field encrypter `' . RecordingFieldEncrypter::class . '` keeps its keys where the package cannot see them, so `audit-log:erase` refuses,'
                . ' `holdingDataOf()` throws, and the key store is neither checked nor verified.',
        ], $this->checks()->notes());
        self::assertSame([], $this->checks()->problems());

        $this->app?->instance(FieldEncrypter::class, new NoFieldEncrypter);

        self::assertSame([], $this->checks()->notes());
        self::assertCount(1, $this->checks()->problems());
    }

    /**
     * An unresolvable encrypter is a problem named by its class, not a note.
     *
     * @return void
     *
     * @throws \RuntimeException
     */
    public function testAnEncrypterThatCannotBeResolvedIsAProblemNotANote(): void
    {
        $this->app?->bind(FieldEncrypter::class, static fn (): never => throw new \RuntimeException(self::SENTINEL));

        self::assertSame(['The key store could not be read (RuntimeException).'], $this->checks()->problems());
        self::assertSame([], $this->checks()->notes());
    }

    /**
     * The checks write nothing and unwrap nothing.
     *
     * @return void
     */
    public function testTheCheckWritesNothingAndUnwrapsNothing(): void
    {
        $this->restoreAKey(self::owner('42'));
        $this->makeSubjectKey(self::owner('43'));
        $this->reconcile(4, self::ANCHORED_DIGEST);
        $this->app?->instance(CheckpointAnchor::class, (new RecordingAnchor)->holdInstead(4, self::ANCHORED_DIGEST));

        $use = ['key_id' => array_key_first($this->storedSubjectKeys()), 'entry_id' => '01932b4e-0000-7000-8000-000000000001'];

        $this->keyConnection()->table(KeyTables::keyUsesTable())->insert($use);

        $before  = $this->keyTables();
        $wrapper = \Mockery::spy(KeyWrapper::class);

        $this->app?->instance(KeyWrapper::class, $wrapper);

        $statements = $this->listen();

        self::assertCount(1, $this->checks()->problems());
        self::assertSame([], $this->checks()->notes());

        $writing = static fn (string $statement): bool => preg_match('/\A\s*(insert|update|delete|replace|create|drop|alter)\b/', $statement) === 1;
        $writes  = array_filter($statements->getArrayCopy(), $writing);

        self::assertNotSame([], $statements->getArrayCopy());
        self::assertSame([], array_values($writes));
        self::assertSame($before, $this->keyTables());

        $wrapper->shouldNotHaveReceived('unwrap');
    }

    /**
     * No problem prints an owner, only key ids and sequences.
     *
     * @return void
     */
    public function testNoOwnerIsPrinted(): void
    {
        $this->restoreAKey(self::owner(self::SENTINEL));

        $problems = $this->checks()->problems();

        self::assertCount(1, $problems);
        self::assertStringNotContainsString(self::SENTINEL, $problems[0]);
        self::assertStringNotContainsString(self::OWNER_TYPE, $problems[0]);
    }

    /**
     * The privacy checks the container builds.
     *
     * @return \SineMacula\Laravel\AuditLog\Console\PrivacyChecks
     */
    private function checks(): PrivacyChecks
    {
        return app(PrivacyChecks::class);
    }

    /**
     * Key the owner, erase it, restore the key's row, and return its id.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @return string
     */
    private function restoreAKey(Reference $owner): string
    {
        [$key] = $this->makeSubjectKey($owner);

        $table  = $this->keyConnection()->table(KeyTables::subjectKeysTable());
        $before = (array) (clone $table)->where('id', $key->id)->first(['state', 'wrapped_key', 'wrap_key_id', 'erasure_id']);

        $this->eraseByHand($owner);

        $table->where('id', $key->id)->update($before);

        return $key->id;
    }

    /**
     * Journal a reconciliation of the head given, as `--reapply` would.
     *
     * @param  int  $sequence
     * @param  string  $digest
     * @return \SineMacula\Laravel\AuditLog\Integrity\JournalRow
     */
    private function reconcile(int $sequence, string $digest): JournalRow
    {
        return $this->journalRow(JournalKind::RESTORE_RECONCILED, [
            'file_sha256'       => str_repeat('f', 64),
            'owners'            => 1,
            'erased'            => 1,
            'already_erased'    => 0,
            'anchored_sequence' => $sequence,
            'anchored_digest'   => $digest,
        ]);
    }

    /**
     * Every row of the three key tables, by table, in key order.
     *
     * @return array<string, list<array<string, scalar|null>>>
     */
    private function keyTables(): array
    {
        $rows = [];

        foreach ([KeyTables::subjectKeysTable() => 'id', KeyTables::ownerErasuresTable() => 'id', KeyTables::keyUsesTable() => 'key_id'] as $table => $key) {

            /** @var list<array<string, scalar|null>> $read */
            $read = array_map(static fn (object $row): array => (array) $row, $this->keyConnection()->table($table)->orderBy($key)->get()->all());

            $rows[$table] = $read;
        }

        return $rows;
    }

    /**
     * Record every storage statement from now on, lower-cased.
     *
     * @return \ArrayObject<int, string>
     */
    private function listen(): \ArrayObject
    {
        /** @var \ArrayObject<int, string> $statements */
        $statements = new \ArrayObject;

        $this->keyConnection()->listen(static function (QueryExecuted $query) use ($statements): void {
            $statements->append(strtolower($query->sql));
        });

        return $statements;
    }

    /**
     * The owner of the id, of the type every test makes keys for.
     *
     * @param  string  $id
     * @return \SineMacula\Laravel\AuditLog\Records\Reference
     */
    private static function owner(string $id): Reference
    {
        return Reference::of(self::OWNER_TYPE, $id);
    }

    /**
     * The message of each reader that refuses what it reads, in order.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  list<\Closure(): mixed>  $readers
     * @return list<string>
     */
    private static function refusalsOf(array $readers): array
    {
        $refusals = [];

        foreach ($readers as $reader) {
            try {
                $reader();
            } catch (\InvalidArgumentException $exception) {
                $refusals[] = $exception->getMessage();
            }
        }

        return $refusals;
    }
}
