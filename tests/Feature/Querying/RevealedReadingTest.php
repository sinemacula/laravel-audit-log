<?php

declare(strict_types = 1);

namespace Tests\Feature\Querying;

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Contracts\FieldReader;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Privacy\SubjectKeyFieldReader;
use SineMacula\Laravel\AuditLog\Querying\AuditTrail;
use SineMacula\Laravel\AuditLog\Querying\TrailEntry;
use SineMacula\Laravel\AuditLog\Querying\TrailReader;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Support\ValueNormaliser;
use Tests\Concerns\MakesSubjectKeys;
use Tests\Concerns\ReadsTheTrail;
use Tests\TestCase;

/**
 * Feature tests for reading the trail with the package's field reader: under a
 * scope that reveals the encrypted fields each fragment shows its typed value,
 * `[ERASED]` once its owner's erasure destroyed the key, or `[UNREADABLE]`, and
 * the read's record counts each; under any other scope every fragment shows
 * `[ENCRYPTED]` and no key is read; and an owner's erasure turns its fragments
 * to `[ERASED]` from the next read on, leaving every other owner's revealed,
 * and a reinstatement never brings them back.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TrailReader::class)]
#[CoversClass(SubjectKeyFieldReader::class)]
final class RevealedReadingTest extends TestCase
{
    use MakesSubjectKeys, ReadsTheTrail;

    /** @var string What a fragment shows under a scope that does not reveal it. */
    private const string ENCRYPTED = '[ENCRYPTED]';

    /** @var string What a fragment shows once its owner's key was destroyed. */
    private const string ERASED = '[ERASED]';

    /** @var string What a fragment shows when it cannot be read. */
    private const string UNREADABLE = '[UNREADABLE]';

    /** @var string An id no key has. */
    private const string UNKNOWN_ID = '01932b4e-0000-7000-8000-00000000dead';

    /**
     * Bind the read path with the package's reader.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->keyWrapper();

        app()->bind(FieldReader::class, SubjectKeyFieldReader::class);

        $this->bindReading();
    }

    /**
     * Under a scope that reveals the encrypted fields, an entry shows each
     * marker where it applies: the typed values of a live key, an address as
     * its text, `[ERASED]` for an erased owner's fragment, and `[UNREADABLE]`
     * for a fragment of an unknown key and for an envelope its rules refuse;
     * the read's record counts each state. Under a scope that does not reveal
     * them, every well-formed envelope shows `[ENCRYPTED]`.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testEachMarkerThroughARevealingScope(): void
    {
        $id = $this->seedMarkers();

        $this->revealEverything();

        $entry  = $this->entry($id);
        $fields = self::propertiesOf($this->readRecords('audit_log.trail_read')[0])['fields'];

        self::assertSame('4242', $entry->properties['card']);
        self::assertSame(self::ERASED, $entry->properties['pin']);
        self::assertSame(self::UNREADABLE, $entry->properties['token']);
        self::assertSame(self::UNREADABLE, $entry->properties['broken']);
        self::assertSame(3, $entry->context['attempts']);
        self::assertSame('203.0.113.9', $entry->ip);
        self::assertSameProperties(['encrypted' => 0, 'erased' => 1, 'revealed' => 3, 'unreadable' => 2], $fields);

        $this->allowEverything();

        $sealed = $this->entry($id);
        $record = self::propertiesOf($this->readRecords('audit_log.trail_read')[1]);

        self::assertSame(
            [self::ENCRYPTED, self::ENCRYPTED, self::ENCRYPTED, self::UNREADABLE, self::ENCRYPTED, self::ENCRYPTED],
            [$sealed->properties['card'], $sealed->properties['pin'], $sealed->properties['token'], $sealed->properties['broken'], $sealed->context['attempts'], $sealed->ip],
        );
        self::assertFalse($record['reveal']);
        self::assertSameProperties(['encrypted' => 5, 'erased' => 0, 'revealed' => 0, 'unreadable' => 1], $record['fields']);
    }

    /**
     * Under a scope that does not reveal the encrypted fields the reader is
     * never asked: no key and no erasure row is read, and every envelope shows
     * `[ENCRYPTED]`.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testANonRevealingScopeNeverCallsTheReader(): void
    {
        $id = $this->seedMarkers();

        $this->allowEverything();
        $this->captureQueries();

        $entry = $this->entry($id);
        self::assertSame([], $this->queriesOf(KeyTables::subjectKeysTable()));
        self::assertSame([], $this->queriesOf(LifecycleTables::journalTable()));
        self::assertSame(self::ENCRYPTED, $entry->properties['card']);
        self::assertSame(self::ENCRYPTED, $entry->ip);

        $this->revealEverything();
        $this->captureQueries();

        self::assertSame('4242', $this->entry($id)->properties['card']);
        self::assertCount(1, $this->queriesOf(KeyTables::subjectKeysTable()));
    }

    /**
     * An owner's erasure turns each of its fragments to `[ERASED]` from the
     * next read on, while another owner's fragment in the same entry stays
     * revealed; reinstating the owner never brings an erased fragment back.
     *
     * @return void
     */
    public function testAnErasedOwnersRecordReadsErased(): void
    {
        $owner = Reference::of('App\Models\User', '42');
        $other = Reference::of('App\Models\User', '43');
        $id    = Str::uuid7()->toString();

        [$key, $dataKey]           = $this->makeSubjectKey($owner);
        [$otherKey, $otherDataKey] = $this->makeSubjectKey($other);

        $this->seedEntry(['properties' => [
            'card' => $this->sealEnvelope($dataKey, $key->id, '4242', $id, ['properties', 'card']),
            'note' => $this->sealEnvelope($otherDataKey, $otherKey->id, 'Approved by phone.', $id, ['properties', 'note']),
        ]], id: $id);

        $this->revealEverything();

        $before = $this->entry($id);

        $this->eraseByHand($owner);

        $erased = $this->entry($id);
        $fields = self::propertiesOf($this->readRecords('audit_log.trail_read')[1])['fields'];

        $this->reinstateByHand($owner);

        $reinstated = $this->entry($id);

        self::assertSame(['card' => '4242', 'note' => 'Approved by phone.'], $before->properties);
        self::assertSame(['card' => self::ERASED, 'note' => 'Approved by phone.'], $erased->properties);
        self::assertSameProperties(['encrypted' => 0, 'erased' => 1, 'revealed' => 1, 'unreadable' => 0], $fields);
        self::assertSame(['card' => self::ERASED, 'note' => 'Approved by phone.'], $reinstated->properties);
    }

    /**
     * Seed one entry holding a fragment in each state: a card and an address
     * under a live key, a count in the context under it, a PIN under an erased
     * owner's key, a token under a key no row has, and an envelope whose
     * version its rules refuse; and return its id.
     *
     * @return string
     *
     * @throws \Random\RandomException
     */
    private function seedMarkers(): string
    {
        $owner  = Reference::of('App\Models\User', '42');
        $erased = Reference::of('App\Models\User', '43');
        $id     = Str::uuid7()->toString();

        [$key, $dataKey]   = $this->makeSubjectKey($owner);
        [$gone, $goneData] = $this->makeSubjectKey($erased);

        $this->seedEntry([
            'properties' => [
                'card'   => $this->sealEnvelope($dataKey, $key->id, '4242', $id, ['properties', 'card']),
                'pin'    => $this->sealEnvelope($goneData, $gone->id, '1234', $id, ['properties', 'pin']),
                'token'  => $this->sealEnvelope(random_bytes(32), self::UNKNOWN_ID, 'tok_1', $id, ['properties', 'token']),
                'broken' => ['v' => ValueNormaliser::MAX_SAFE_INTEGER + 1, 'k' => $key->id, 'c' => 'AAAA'],
            ],
            'context' => ['attempts' => $this->sealEnvelope($dataKey, $key->id, 3, $id, ['context', 'attempts'])],
            'ip'      => CanonicalEncoder::encode($this->sealEnvelope($dataKey, $key->id, '203.0.113.9', $id, ['ip'])),
        ], id: $id);

        $this->eraseByHand($erased);

        return $id;
    }

    /**
     * The statements captured that name the table, quoted as an engine's
     * grammar quotes it, as their SQL.
     *
     * @param  string  $table
     * @return list<string>
     */
    private function queriesOf(string $table): array
    {
        $pattern = '/[`"]' . preg_quote($table, '/') . '[`"]/';
        $named   = array_filter($this->capturedQueries(), static fn (QueryExecuted $query): bool => preg_match($pattern, $query->sql) === 1);

        return array_values(array_map(static fn (QueryExecuted $query): string => $query->sql, $named));
    }

    /**
     * The entry with the id, as a page of the trail shows it to the viewer.
     *
     * @param  string  $id
     * @return \SineMacula\Laravel\AuditLog\Querying\TrailEntry
     */
    private function entry(string $id): TrailEntry
    {
        foreach (app(AuditTrail::class)->visibleTo($this->viewer())->inCategory('finance')->cursorPaginate(50)->entries as $entry) {
            if ($entry->id === $id) {
                return $entry;
            }
        }

        self::fail("The page does not show {$id}.");
    }
}
