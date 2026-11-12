<?php

declare(strict_types = 1);

namespace Tests\Feature\Integrity;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Console\VerifyCommand;
use SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Contracts\PruneLedger;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Events\IntegrityCheckFailed;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\NullAnchor;
use SineMacula\Laravel\AuditLog\Integrity\Enums\KeyState;
use SineMacula\Laravel\AuditLog\Integrity\KeyStoreVerifier;
use SineMacula\Laravel\AuditLog\Integrity\NullPruneLedger;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Integrity\SegmentVerifier;
use SineMacula\Laravel\AuditLog\Lifecycle\Authority;
use SineMacula\Laravel\AuditLog\Lifecycle\Rewrapper;
use SineMacula\Laravel\AuditLog\Privacy\EncryptedField;
use SineMacula\Laravel\AuditLog\Privacy\FieldReading;
use SineMacula\Laravel\AuditLog\Privacy\SubjectKeyFieldReader;
use SineMacula\Laravel\AuditLog\Records\RecordFinaliser;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use Symfony\Component\Console\Output\BufferedOutput;
use Tests\Concerns\MakesSubjectKeys;
use Tests\Concerns\TampersWithTheLog;
use Tests\Fixtures\Records\RecordFactory;
use Tests\Fixtures\Support\FrozenClock;
use Tests\TestCase;

/**
 * Feature tests for what `audit-log:verify` finds once the owners' key store is
 * altered below the package by a database writer.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(VerifyCommand::class)]
#[CoversClass(KeyStoreVerifier::class)]
#[CoversClass(SegmentVerifier::class)]
final class KeyStoreTamperingTest extends TestCase
{
    use MakesSubjectKeys, TampersWithTheLog;

    /** @var string When the log is sealed. */
    private const string SEALED_AT = '2026-11-01 13:00:00';

    /** @var string When a run verifies, and every key is made. */
    private const string VERIFIED_AT = '2026-11-01 14:00:00';

    /** @var string When every encrypted entry occurred and was recorded. */
    private const string RECORDED_AT = '2026-11-01T12:00:00.000000Z';

    /** @var list<int|string> The path every field is sealed at. */
    private const array CARD = ['properties', 'card'];

    /** @var string The value every field seals. */
    private const string SECRET = '4242';

    /** @var list<string> The columns that hold a key, and that an erasure changes. */
    private const array KEY_COLUMNS = ['state', 'wrapped_key', 'wrap_key_id', 'erasure_id'];

    /** @var \ArrayObject<int, \SineMacula\Laravel\AuditLog\Events\IntegrityCheckFailed> Every integrity event dispatched. */
    private \ArrayObject $alarms;

    /**
     * Register the commands, bind no anchor, nothing pruned and the package's
     * own key wrapper, stop the clock, and record every integrity event.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->registerIntegrityCommands();
        $this->keyWrapper();

        $this->alarms = new \ArrayObject;

        app()->instance(CheckpointAnchor::class, new NullAnchor);
        app()->instance(PruneLedger::class, new NullPruneLedger);
        app()->instance(Clock::class, FrozenClock::at(self::VERIFIED_AT));

        $this->sealAt(self::SEALED_AT);

        $alarms = $this->alarms;

        app(Dispatcher::class)->listen(IntegrityCheckFailed::class, static function (IntegrityCheckFailed $event) use ($alarms): void {
            $alarms->append($event);
        });
    }

    /**
     * A key use deleted below the package hides its entry from the owner's
     * erasure, and verify finds it at that entry: `key_use_missing`.
     *
     * @return void
     */
    public function testADeletedKeyUseIsFoundByVerify(): void
    {
        [, $entryId] = $this->storeEncryptedEntry(self::owner('42'));

        $this->sealAll();
        $this->keyConnection()->table(KeyTables::keyUsesTable())->where('entry_id', $entryId)->delete();

        [$exit, $segments, $findings] = $this->verify();

        self::assertSame(1, $exit);
        self::assertSame([['tampered', 'key_use_missing', $entryId]], $segments);
        self::assertSame([], $findings);
        self::assertSame(['key_use_missing', $entryId], $this->alarmNames());
    }

    /**
     * A key tombstoned with no journalled erasure is
     * `key_destroyed_unjournalled`, its fields unreadable, never erased.
     *
     * @return void
     */
    public function testAnUnjournalledDestructionIsFoundAndReadsUnreadable(): void
    {
        [$key, $entryId, $envelope] = $this->storeEncryptedEntry(self::owner('42'));

        $this->sealAll();
        $this->changeKey($key->id, ['state' => KeyState::ERASED->value, 'wrapped_key' => null, 'erasure_id' => (string) Str::uuid7()]);

        [$exit, , $findings] = $this->verify();

        self::assertSame(1, $exit);
        self::assertSame(['key_destroyed_unjournalled' => [$key->id, 1]], $findings);
        self::assertSame('[UNREADABLE]', $this->read($entryId, $envelope)->display());
    }

    /**
     * A key put back after its erasure is `key_restored`, and decrypts again
     * until the erasure is applied again; the erasure still verifies.
     *
     * @return void
     */
    public function testARestoredKeyIsFoundByVerify(): void
    {
        $owner = self::owner('42');

        [$key, $entryId, $envelope] = $this->storeEncryptedEntry($owner);

        $this->sealAll();

        $before = $this->storedKey($key->id);

        $this->eraseByHand($owner);

        [$erased] = $this->verify();

        self::assertSame(0, $erased);
        self::assertSame('[ERASED]', $this->read($entryId, $envelope)->display());

        $this->changeKey($key->id, $before);

        [$exit, , $findings] = $this->verify();

        self::assertSame(1, $exit);
        self::assertSame(['key_restored' => [$key->id, 1]], $findings);
        self::assertSame(self::SECRET, $this->read($entryId, $envelope)->display());
        self::assertSame(['key_restored', $key->id], $this->alarmNames());
    }

    /**
     * A deleted owner marker lets a key be made for an erased owner, but the
     * journal still holds the erasure, so verify finds `key_restored`.
     *
     * @return void
     */
    public function testADeletedOwnerMarkerLetsNoKeyEscapeVerify(): void
    {
        $owner = self::owner('42');

        $this->storeEncryptedEntry($owner);
        $this->sealAll();
        $this->eraseByHand($owner);

        $this->keyConnection()->table(KeyTables::ownerErasuresTable())->where('owner_type', $owner->type)->where('owner_id', $owner->id)->delete();

        [$escaped] = $this->makeSubjectKey($owner);

        [$exit, , $findings] = $this->verify();

        self::assertSame(1, $exit);
        self::assertSame(['key_restored' => [$escaped->id, 1]], $findings);
    }

    /**
     * A key row copied over another's is `key_substituted`, and the deleted
     * source leaves its key use `key_missing`; both fields read unreadable.
     *
     * @return void
     */
    public function testAKeyRowCopiedOverAnotherIsSubstituted(): void
    {
        [$source, $sourceEntry, $sourceEnvelope] = $this->storeEncryptedEntry(self::owner('42'));
        [$target, $targetEntry, $targetEnvelope] = $this->storeEncryptedEntry(self::owner('43'));

        $this->sealAll();

        $copied = $source->toRow();

        unset($copied['id']);

        $this->keyConnection()->table(KeyTables::subjectKeysTable())->where('id', $source->id)->delete();
        $this->changeKey($target->id, $copied);

        [$exit, , $findings] = $this->verify();

        self::assertSame(1, $exit);
        self::assertSame(['key_missing' => [$source->id, 1], 'key_substituted' => [$target->id, 1]], $findings);
        self::assertSame('[UNREADABLE]', $this->read($sourceEntry, $sourceEnvelope)->display());
        self::assertSame('[UNREADABLE]', $this->read($targetEntry, $targetEnvelope)->display());
    }

    /**
     * A key's state flipped outside a rewrap is `key_substituted`, whether to
     * superseded or back to live after a rotation, which is clean.
     *
     * @return void
     */
    public function testAnUnjournalledStateFlipIsFoundByVerify(): void
    {
        [$key] = $this->storeEncryptedEntry(self::owner('42'));

        $this->sealAll();
        $this->changeKey($key->id, ['state' => KeyState::SUPERSEDED->value]);

        [$exit, , $findings] = $this->verify();

        self::assertSame(1, $exit);
        self::assertSame(['key_substituted' => [$key->id, 1]], $findings);

        $this->changeKey($key->id, ['state' => KeyState::LIVE->value]);
        $this->rotate();

        [$exit, , $findings] = $this->verify();

        self::assertSame([0, []], [$exit, $findings]);

        $this->changeKey($key->id, ['state' => KeyState::LIVE->value]);

        [$exit, , $findings] = $this->verify();

        self::assertSame(1, $exit);
        self::assertSame(['key_substituted' => [$key->id, 1]], $findings);
    }

    /**
     * A key's pre-rotation row put back while its old wrapping key is held
     * still unwraps and verifies, but is `key_substituted`.
     *
     * @return void
     */
    public function testAPreRotationKeyRestoredIsFoundByVerify(): void
    {
        [$key] = $this->storeEncryptedEntry(self::owner('42'));

        $this->sealAll();

        $before = $this->storedKey($key->id);
        $config = app(ConfigRepository::class);

        $config->set('audit-log.privacy.keys', ['w2026' => str_repeat('w', 32)]);
        $config->set('audit-log.privacy.current', 'w2026');

        $this->rotate();

        self::assertSame([KeyState::SUPERSEDED->value, 'w2026'], [$this->storedKey($key->id)['state'], $this->storedKey($key->id)['wrap_key_id']]);

        [$exit, , $findings] = $this->verify();

        self::assertSame([0, []], [$exit, $findings]);

        $this->changeKey($key->id, $before);

        [$exit, , $findings] = $this->verify();

        self::assertSame(1, $exit);
        self::assertSame(['key_substituted' => [$key->id, 1]], $findings);
    }

    /**
     * Rewrap every key onto the current wrapping key, superseding every live
     * key, as `audit-log:rewrap --rotate` does.
     *
     * @return void
     */
    private function rotate(): void
    {
        $result = app(Rewrapper::class)->rewrap((string) Str::uuid7(), new Authority(Reference::of('App\Models\User', '7'), 'case.review'), true, false);

        self::assertSame(0, $result->skipped);
    }

    /**
     * Make the owner's key and store an entry with a field sealed under it
     * through the database store; return the key, entry id and envelope.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @return array{0: \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow, 1: string, 2: array{v: int, k: string, c: string}}
     */
    private function storeEncryptedEntry(Reference $owner): array
    {
        [$key, $dataKey] = $this->makeSubjectKey($owner);

        $entryId   = (string) Str::uuid7();
        $envelope  = $this->sealEnvelope($dataKey, $key->id, self::SECRET, $entryId, self::CARD);
        $finaliser = new RecordFinaliser(FrozenClock::at(self::RECORDED_AT), app(RecordSigner::class));

        app(DatabaseAuditStore::class)->store($finaliser->finalise(RecordFactory::captured(['card' => $envelope], $entryId, self::RECORDED_AT)));

        self::assertSame(1, $this->keyConnection()->table(KeyTables::keyUsesTable())->where('entry_id', $entryId)->count());

        return [$key, $entryId, $envelope];
    }

    /**
     * Run `audit-log:verify --json` and return its exit code, each failed
     * segment's integrity, finding and first id, and the run's findings.
     *
     * @return array{0: int, 1: list<array{0: string, 1: string, 2: string}>, 2: array<string, array{0: ?string, 1: int}>}
     */
    private function verify(): array
    {
        $output   = new BufferedOutput;
        $exit     = app(Kernel::class)->call('audit-log:verify', ['--json' => true], $output);
        $segments = [];
        $findings = [];

        foreach (explode("\n", rtrim($output->fetch(), "\n")) as $line) {
            /** @var array{type: string, integrity?: string, finding?: ?string, first_bad_id?: ?string, count?: int} $decoded */
            $decoded = json_decode($line, true, 512, JSON_THROW_ON_ERROR);
            $finding = $decoded['finding'] ?? null;

            if ($finding === null) {
                continue;
            }

            if ($decoded['type'] === 'segment') {
                $segments[] = [$decoded['integrity'] ?? '', $finding, $decoded['first_bad_id'] ?? ''];

                continue;
            }

            $findings[$finding] = [$decoded['first_bad_id'] ?? null, $decoded['count'] ?? 0];
        }

        return [$exit, $segments, $findings];
    }

    /**
     * What the field sealed in the envelope at the entry reads as, through the
     * package's field reader.
     *
     * @param  string  $entryId
     * @param  array{v: int, k: string, c: string}  $envelope
     * @return \SineMacula\Laravel\AuditLog\Privacy\FieldReading
     */
    private function read(string $entryId, array $envelope): FieldReading
    {
        $field = EncryptedField::fromEnvelope($entryId, self::CARD, $envelope);

        self::assertNotNull($field);

        return app(SubjectKeyFieldReader::class)->readAll([$field])[0];
    }

    /**
     * The first finding and first bad id of the one event the verify command
     * dispatched.
     *
     * @return array{0: ?string, 1: ?string}
     */
    private function alarmNames(): array
    {
        self::assertCount(1, $this->alarms);

        $alarm = $this->alarms[0];

        self::assertInstanceOf(IntegrityCheckFailed::class, $alarm);

        $this->alarms->exchangeArray([]);

        return [$alarm->finding, $alarm->firstBadId];
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
     * An owner of the type every test uses, with the id given.
     *
     * @param  string  $id
     * @return \SineMacula\Laravel\AuditLog\Records\Reference
     */
    private static function owner(string $id): Reference
    {
        return Reference::of('App\Models\User', $id);
    }
}
