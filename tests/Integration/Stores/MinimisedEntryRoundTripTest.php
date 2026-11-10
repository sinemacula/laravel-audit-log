<?php

declare(strict_types = 1);

namespace Tests\Integration\Stores;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;
use SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling;
use SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Privacy\IdentifierHasher;
use SineMacula\Laravel\AuditLog\Privacy\KeyCeiling;
use SineMacula\Laravel\AuditLog\Privacy\RecordMinimiser;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Fixtures\Privacy\MalformedFieldEncrypter;
use Tests\Fixtures\Privacy\RecordingFieldEncrypter;
use Tests\TestCase;

/**
 * Integration tests for what minimising leaves of a record, recorded through
 * the facade on the engine the suite runs against: a marker, a pseudonym, an
 * envelope, a hashed or encrypted address, a cut string and the diagnostics all
 * store, read back as what capture returned, and verify, whatever the engine
 * does to its JSON, and an edit to any of them does not.
 *
 * Definitions are registered on a recorder of a test's own, put behind the
 * facade, since the application's has frozen by the time a test runs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecordMinimiser::class)]
#[CoversClass(KeyCeiling::class)]
#[CoversClass(DatabaseAuditStore::class)]
#[CoversClass(RowCodec::class)]
#[CoversClass(RecordSigner::class)]
final class MinimisedEntryRoundTripTest extends TestCase
{
    use InteractsWithAuditStore;

    /** @var string The code every test records. */
    private const string CODE = 'invoice.approved';

    /** @var string The address a test gives the record, unless it gives another. */
    private const string IP = '203.0.113.7';

    /** @var int How many bytes an envelope's canonical JSON adds to its ciphertext, with `k` as its key and 1 as its version. */
    private const int ENVELOPE_FRAME_BYTES = 22;

    /** @var int The most bytes the column holds. */
    private const int IP_COLUMN_BYTES = 255;

    /** @var int A budget with room for a key longer than MySQL allows in JSON. */
    private const int RAISED_BUDGET = 262144;

    /** @var int Bytes in a key longer than the 65,535 MySQL allows in JSON. */
    private const int PAST_ANY_ENGINE_BYTES = 70000;

    /** @var string A hash of the right shape that nothing computed. */
    private const string EDITED_HASH = '0000000000000000:0000000000000000000000000000000000000000000000000000000000000000';

    /**
     * Roll back any transaction a test left open.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $connection = $this->storageConnection();

        while ($connection->transactionLevel() > 0) {
            $connection->rollBack();
        }

        parent::tearDown();
    }

    /**
     * The values of secret-shaped keys are stored as the marker, at any depth,
     * in the properties and the context alike, and the raw values are stored
     * nowhere in the row.
     *
     * @return void
     */
    public function testARedactedRecordStoresAndVerifies(): void
    {
        $pending = AuditLog::event(self::CODE)->withProperties(['password' => 's3cr3t-one', 'customer' => ['api_key' => 's3cr3t-two', 'plan' => 'pro']]);

        $pending->fillContext(['session_token' => 's3cr3t-three', 'plan' => 'pro']);

        $record = $pending->immediately()->record();
        $stored = $this->storedAndVerified($record);

        self::assertSame('{"customer":{"api_key":"[REDACTED]","plan":"pro"},"password":"[REDACTED]"}', CanonicalEncoder::encode($stored['properties']));
        self::assertSame('{"plan":"pro","session_token":"[REDACTED]"}', CanonicalEncoder::encode($stored['context']));
        self::assertStringNotContainsString('s3cr3t', $this->rawRow($record->id));
    }

    /**
     * A retained value, a marker, a pseudonym, an envelope and a removal all
     * store side by side, and the raw value of each handled field is nowhere in
     * the row.
     *
     * @return void
     */
    public function testEveryHandlingStoresAndVerifies(): void
    {
        $encrypter = new RecordingFieldEncrypter;

        app()->instance(FieldEncrypter::class, $encrypter);

        $definition = EventDefinition::for(self::CODE)
            ->retain('amount')
            ->redact('customer')
            ->pseudonymise('email')
            ->encrypt('ssn', KeyOwner::ACTOR)
            ->drop('internal');

        $record = self::underDefinition($definition)
            ->by(Reference::of('user', '7'))
            ->withProperties([
                'amount'   => '1200.00',
                'customer' => ['name' => 'Alice Example'],
                'email'    => 'alice@example.com',
                'ssn'      => '078-05-1120',
                'internal' => 'dropped-by-a-rule',
                'unlisted' => 'dropped-by-the-default',
            ])
            ->immediately()
            ->record();

        $stored    = $this->storedAndVerified($record);
        $pseudonym = app(IdentifierHasher::class)->field('alice@example.com');
        $sealed    = base64_encode('"078-05-1120"');

        $expected = '{"_audit":{"omitted":{"count":2,"paths":["*","internal"]}},"amount":"1200.00","customer":"[REDACTED]",'
            . '"email":"' . $pseudonym . '","ssn":{"c":"' . $sealed . '","k":"key_7","v":1}}';

        self::assertSame($expected, CanonicalEncoder::encode($stored['properties']));
        self::assertCount(1, $encrypter->calls());

        $raw = $this->rawRow($record->id);

        foreach (['Alice Example', 'alice@example.com', '078-05-1120', 'dropped-by-a-rule', 'dropped-by-the-default'] as $value) {
            self::assertStringNotContainsString($value, $raw);
        }
    }

    /**
     * An encrypted address of exactly the column's bytes is stored whole, on
     * the engines whose column would refuse or cut one a byte longer.
     *
     * @return void
     */
    public function testAnEncryptedIpFitsItsColumnAndVerifies(): void
    {
        $ciphertext = str_repeat('a', self::IP_COLUMN_BYTES - self::ENVELOPE_FRAME_BYTES);

        $stored = $this->storedAndVerified($this->recordedWithAnEnvelope($ciphertext));

        self::assertSame('{"c":"' . $ciphertext . '","k":"k","v":1}', $stored['ip']);
        self::assertSame(self::IP_COLUMN_BYTES, strlen($stored['ip']));
        self::assertNull($stored['properties']);
    }

    /**
     * An envelope a byte longer than the column is never cut and never reaches
     * the engine: the address is dropped and diagnosed, and the record stores.
     *
     * @return void
     */
    public function testAnEncryptedIpTooLongForItsColumnIsDroppedAndVerifies(): void
    {
        $stored = $this->storedAndVerified($this->recordedWithAnEnvelope(str_repeat('a', self::IP_COLUMN_BYTES - self::ENVELOPE_FRAME_BYTES + 1)));

        self::assertNull($stored['ip']);
        self::assertSame('{"_audit":{"omitted":{"count":1,"paths":["$ip"]}}}', CanonicalEncoder::encode($stored['properties']));
    }

    /**
     * A garbage address longer than the column reaches no engine: the record
     * stores with no address, `$ip` is in its diagnostics, and it verifies.
     *
     * @return void
     */
    public function testAGarbageIpStoresNullAndVerifies(): void
    {
        $garbage = str_repeat('garbage', 40);

        $record = self::fromAddress($garbage)->immediately()->record();
        $stored = $this->storedAndVerified($record);

        self::assertNull($stored['ip']);
        self::assertSame('{"_audit":{"omitted":{"count":1,"paths":["$ip"]}}}', CanonicalEncoder::encode($stored['properties']));
        self::assertStringNotContainsString('garbage', $this->rawRow($record->id));
    }

    /**
     * An IPv6 address truncates to its /48, in the form a string column keeps
     * as given.
     *
     * @return void
     */
    public function testATruncatedIpv6StoresAndVerifies(): void
    {
        self::config()->set('audit-log.redaction.ip', 'truncate');

        $stored = $this->storedAndVerified(self::fromAddress('2001:db8:abcd:12::1')->immediately()->record());

        self::assertSame('2001:db8:abcd::', $stored['ip']);
    }

    /**
     * A hashed address is its fingerprint and HMAC, and the address is stored
     * nowhere in the row.
     *
     * @return void
     */
    public function testAHashedIpStoresAndVerifies(): void
    {
        self::config()->set('audit-log.redaction.ip', 'hash');

        $record = self::fromAddress(self::IP)->immediately()->record();
        $stored = $this->storedAndVerified($record);

        self::assertSame(app(IdentifierHasher::class)->ip(self::IP), $stored['ip']);
        self::assertMatchesRegularExpression('/\A[0-9a-f]{16}:[0-9a-f]{64}\z/', $stored['ip']);
        self::assertStringNotContainsString(self::IP, $this->rawRow($record->id));
    }

    /**
     * An IPv4-mapped address stores as its IPv4 address, even in full.
     *
     * @return void
     */
    public function testAMappedAddressStoresAsItsIpv4Form(): void
    {
        $stored = $this->storedAndVerified(self::fromAddress('::ffff:' . self::IP)->immediately()->record());

        self::assertSame(self::IP, $stored['ip']);
    }

    /**
     * An address that is not valid stores as nothing, even in full, and is
     * diagnosed.
     *
     * @return void
     */
    public function testAnInvalidAddressStoresAsNullAndVerifies(): void
    {
        $stored = $this->storedAndVerified(self::fromAddress('not-an-ip')->immediately()->record());

        self::assertNull($stored['ip']);
        self::assertSame('{"_audit":{"omitted":{"count":1,"paths":["$ip"]}}}', CanonicalEncoder::encode($stored['properties']));
    }

    /**
     * The diagnostics of an address, a note and more fields than the list holds
     * store together: every removal counted, the first 32 paths sorted
     * bytewise.
     *
     * @return void
     */
    public function testOmittedDiagnosticsStoreAndVerify(): void
    {
        $fields = array_map(static fn (int $index): string => sprintf('field_%02d', $index), range(0, 39));

        $pending = self::underDefinition(EventDefinition::for(self::CODE)->drop(...$fields))
            ->withProperties(array_fill_keys($fields, 'dropped'))
            ->withNote('Erasable.', KeyOwner::ACTOR);

        $pending->fillClient('not-an-ip', null);

        $stored = $this->storedAndVerified($pending->immediately()->record());

        $paths = ['$ip', '_audit.note', ...array_slice($fields, 0, 30)];

        self::assertSame(CanonicalEncoder::encode(['_audit' => ['omitted' => ['count' => 42, 'paths' => $paths]]]), CanonicalEncoder::encode($stored['properties']));
    }

    /**
     * A list a rule removed the first element of stays a list through the
     * engine, not a map keyed from 1, whose canonical encoding would differ.
     *
     * @return void
     */
    public function testAListReindexedByARuleStoresAsAList(): void
    {
        $definition = EventDefinition::for(self::CODE)->unlisted(FieldHandling::RETAIN)->drop('lines.0');

        $stored = $this->storedAndVerified(self::underDefinition($definition)->withProperties(['lines' => ['first', 'second', 'third']])->immediately()->record());

        self::assertSame('{"_audit":{"omitted":{"count":1,"paths":["lines.0"]}},"lines":["second","third"]}', CanonicalEncoder::encode($stored['properties']));

        $properties = $stored['properties'];

        self::assertInstanceOf(\stdClass::class, $properties);
        self::assertSame(['second', 'third'], $properties->lines);
    }

    /**
     * A string of 4-byte emoji, offset so the 1024th byte falls inside one, is
     * cut before that character, so the engine is never given a split sequence.
     *
     * @return void
     */
    public function testACutMultibyteStringStoresAndVerifies(): void
    {
        $emoji = "\u{1F600}";

        $stored = $this->storedAndVerified(AuditLog::event(self::CODE)->withProperties(['text' => 'a' . str_repeat($emoji, 300)])->immediately()->record());

        $properties = $stored['properties'];

        self::assertInstanceOf(\stdClass::class, $properties);
        self::assertSame('a' . str_repeat($emoji, 255), $properties->text);
        self::assertSame(1021, strlen($properties->text));
    }

    /**
     * The identifier's hash stores in the reserved area, and the identifier
     * nowhere in the row, in any case.
     *
     * @return void
     */
    public function testAnIdentifierHashStoresAndVerifies(): void
    {
        $record = AuditLog::event(self::CODE)->withIdentifier('Alice@Example.COM')->failed('invalid_credentials')->immediately()->record();
        $stored = $this->storedAndVerified($record);
        $hash   = app(IdentifierHasher::class)->identifier('alice@example.com');

        self::assertSame('{"_audit":{"identifier_hash":"' . $hash . '"}}', CanonicalEncoder::encode($stored['properties']));
        self::assertStringNotContainsString('alice@example.com', strtolower($this->rawRow($record->id)));
    }

    /**
     * A note with no owner and one sealed under its owner both store in the
     * reserved area, and the sealed note's text is nowhere in the row.
     *
     * @return void
     */
    public function testANoteStoresAndVerifiesPlainOrSealed(): void
    {
        app()->instance(FieldEncrypter::class, new RecordingFieldEncrypter);

        $plain = $this->storedAndVerified(AuditLog::event(self::CODE)->withNote('Approved by phone.')->immediately()->record());

        self::assertSame('{"_audit":{"note":"Approved by phone."}}', CanonicalEncoder::encode($plain['properties']));

        $record = AuditLog::event(self::CODE)->withNote('Erasable.', Reference::of('user', '7'))->immediately()->record();
        $sealed = $this->storedAndVerified($record);

        self::assertSame('{"_audit":{"note":{"c":"' . base64_encode('"Erasable."') . '","k":"key_7","v":1}}}', CanonicalEncoder::encode($sealed['properties']));
        self::assertStringNotContainsString('Erasable.', $this->rawRow($record->id));
    }

    /**
     * Under the package's default encrypter a field and the address sealed for
     * the actor store and verify whatever the engine does to its JSON: each is
     * an envelope naming the actor's one key, the entry has that key's one key
     * use, and neither value is anywhere in the row.
     *
     * @return void
     */
    public function testTheDefaultEncryptersEnvelopesStoreAndVerify(): void
    {
        self::config()->set('audit-log.redaction.ip', 'encrypt');

        $pending = self::underDefinition(EventDefinition::for(self::CODE)->retain('amount')->encrypt('ssn', KeyOwner::ACTOR))
            ->by(Reference::of('user', '7'))
            ->withProperties(['amount' => '1200.00', 'ssn' => '078-05-1120']);

        $pending->fillClient(self::IP, null);

        $record = $pending->immediately()->record();
        $stored = $this->storedAndVerified($record);

        $properties = json_decode(CanonicalEncoder::encode($stored['properties']), true, 8, JSON_THROW_ON_ERROR);
        $ip         = json_decode((string) $record->ip, true, 2, JSON_THROW_ON_ERROR);

        self::assertIsArray($properties);
        self::assertIsArray($properties['ssn'] ?? null);
        self::assertIsArray($ip);
        self::assertSame(['c', 'k', 'v'], array_keys($properties['ssn']));
        self::assertSame(['c', 'k', 'v'], array_keys($ip));
        self::assertSame($ip['k'], $properties['ssn']['k']);

        $uses = $this->storageConnection()->table(KeyTables::keyUsesTable())->where('entry_id', $record->id)->pluck('key_id')->all();

        self::assertSame([$ip['k']], self::strings($uses));
        self::assertStringNotContainsString('078-05-1120', $this->rawRow($record->id));
        self::assertStringNotContainsString(self::IP, $this->rawRow($record->id));
    }

    /**
     * The largest application key of a context over its budget goes, the
     * package's own name stays, and what is left fits, with the removal
     * diagnosed under the context's prefix in the properties.
     *
     * @return void
     */
    public function testAContextOverItsBudgetStoresAndVerifies(): void
    {
        self::config()->set('audit-log.redaction.max_context_bytes', 1024);

        $kept = str_repeat('b', 900);

        $pending = AuditLog::event(self::CODE);

        $pending->fillContext(['big' => str_repeat('a', 1000), 'other' => $kept, 'route' => 'invoices.approve']);

        $stored = $this->storedAndVerified($pending->immediately()->record());

        $context = CanonicalEncoder::encode($stored['context']);

        self::assertSame('{"other":"' . $kept . '","route":"invoices.approve"}', $context);
        self::assertLessThanOrEqual(1024, strlen($context));
        self::assertSame('{"_audit":{"omitted":{"count":1,"paths":["context.*"]}}}', CanonicalEncoder::encode($stored['properties']));
    }

    /**
     * Properties over their budget lose their largest keys and keep the rest,
     * with the metadata beside them, within the budget once stored.
     *
     * @return void
     */
    public function testPropertiesOverTheirBudgetStoreAndVerify(): void
    {
        self::config()->set('audit-log.redaction.max_bytes', 8192);

        $fields = [];

        foreach (range(1, 20) as $index) {
            $fields[sprintf('field_%02d', $index)] = str_repeat('x', 1000);
        }

        $stored = $this->storedAndVerified(AuditLog::event(self::CODE)->withProperties($fields)->withIdentifier('alice@example.com')->immediately()->record());

        $properties = $stored['properties'];

        self::assertInstanceOf(\stdClass::class, $properties);
        self::assertLessThanOrEqual(8192, strlen(CanonicalEncoder::encode($properties)));
        self::assertSame(['count' => 17, 'paths' => ['*']], json_decode((string) json_encode($properties->_audit->omitted), true));

        $kept = array_keys(get_object_vars($properties));

        sort($kept);

        self::assertSame(['_audit', 'field_18', 'field_19', 'field_20'], $kept);
    }

    /**
     * Keys PHP makes integers sit beside the metadata as a map, on the engines
     * that reorder JSON keys and those that keep them.
     *
     * @return void
     */
    public function testNumericKeysBesideTheMetadataStoreAsAMap(): void
    {
        $pending = AuditLog::event(self::CODE)->withProperties(['10' => 'ten', '2' => 'two'])->withIdentifier('alice@example.com');

        $stored = $this->storedAndVerified($pending->immediately()->record());
        $hash   = app(IdentifierHasher::class)->identifier('alice@example.com');

        self::assertSame('{"10":"ten","2":"two","_audit":{"identifier_hash":"' . $hash . '"}}', CanonicalEncoder::encode($stored['properties']));
    }

    /**
     * What is deeper than the deepest kept is stored as its marker, and a
     * retained empty container stays an empty list.
     *
     * @return void
     */
    public function testTruncatedDepthAndEmptyContainersStoreAndVerify(): void
    {
        $nested = 'leaf';

        foreach (range(1, 12) as $ignored) {
            $nested = ['next' => $nested];
        }

        $stored = $this->storedAndVerified(AuditLog::event(self::CODE)->withProperties(['nested' => $nested, 'none' => []])->immediately()->record());

        self::assertSame(
            '{"nested":{"next":{"next":{"next":{"next":{"next":{"next":{"next":"[TRUNCATED]"}}}}}}},"none":[]}',
            CanonicalEncoder::encode($stored['properties']),
        );
    }

    /**
     * A record deferred to a commit stores what capture minimised: a key
     * changed while it waits changes nothing, and nothing raw rests in the row.
     *
     * @return void
     */
    public function testADeferredRecordStoresWhatWasMinimisedAtCapture(): void
    {
        self::config()->set('audit-log.redaction.key', str_repeat('a', 32));

        $hash       = app(IdentifierHasher::class)->identifier('alice@example.com');
        $connection = DB::connection();

        $connection->beginTransaction();

        $record = AuditLog::event(self::CODE)->withProperties(['password' => 's3cr3t'])->withIdentifier('alice@example.com')->record();

        self::assertSame(0, $this->entryCount());

        self::config()->set('audit-log.redaction.key', str_repeat('b', 32));

        $connection->commit();

        $stored = $this->storedAndVerified($record);

        self::assertSame('{"_audit":{"identifier_hash":"' . $hash . '"},"password":"[REDACTED]"}', CanonicalEncoder::encode($stored['properties']));
    }

    /**
     * Rows of `[column, dotted path, value]`: one leaf of what minimising left
     * changed, or one part of it removed where the value is `null`, from the
     * stored value, with everything else and the HMAC left as they were. So a
     * signature that skipped any part fails the row that names it. The address
     * is a plain column, so it has no path.
     *
     * @return iterable<string, array{0: string, 1: ?string, 2: int|string|null}>
     */
    public static function provideEdits(): iterable
    {
        yield from [
            'the identifier hash'             => ['properties', '_audit.identifier_hash', self::EDITED_HASH],
            'the ciphertext of an envelope'   => ['properties', 'ssn.c', 'ZWRpdGVk'],
            'the omission count'              => ['properties', '_audit.omitted.count', 99],
            'the omitted diagnostics removed' => ['properties', '_audit.omitted', null],
            'the identifier hash removed'     => ['properties', '_audit.identifier_hash', null],
            'the metadata removed'            => ['properties', '_audit', null],
            'a retained value'                => ['properties', 'amount', '1.00'],
            'the context'                     => ['context', 'plan', 'free'],
            'the hashed address'              => ['ip', null, self::EDITED_HASH],
        ];
    }

    /**
     * An edit to any one part of a stored minimised value fails verification.
     *
     * @param  string  $column
     * @param  ?string  $path
     * @param  int|string|null  $value
     * @return void
     */
    #[DataProvider('provideEdits')]
    public function testAnEditedMinimisedValueFailsVerification(string $column, ?string $path, int|string|null $value): void
    {
        self::config()->set('audit-log.redaction.ip', 'hash');

        app()->instance(FieldEncrypter::class, new RecordingFieldEncrypter);

        $pending = self::underDefinition(EventDefinition::for(self::CODE)->retain('amount')->encrypt('ssn', KeyOwner::ACTOR))
            ->by(Reference::of('user', '7'))
            ->withProperties(['amount' => '1200.00', 'ssn' => '078-05-1120', 'other' => 'dropped'])
            ->withIdentifier('alice@example.com');

        $pending->fillClient(self::IP, null);
        $pending->fillContext(['plan' => 'pro']);

        $record = $pending->immediately()->record();

        $this->storedAndVerified($record);

        $table = $this->storageConnection()->table(EntrySettings::table())->where('id', $record->id);
        $raw   = (array) $table->first();

        self::assertSame(['count' => 1, 'paths' => ['*']], json_decode($raw['properties'], true, flags: JSON_THROW_ON_ERROR)['_audit']['omitted']);

        $edited = $path === null ? $value : self::editedJson($raw[$column], $path, $value);

        self::assertNotSame($raw[$column], $edited);

        $table->update([$column => $edited]);

        self::assertFalse(app(RecordSigner::class)->verifies($this->storedRow($record->id)));
    }

    /**
     * A key longer than MySQL allows in JSON, with room for it in both budgets,
     * is removed with its branch at every depth, so the record stores and
     * verifies alike on every engine, and only masked paths say that it went.
     *
     * @return void
     */
    public function testAKeyPastWhatAnEngineAllowsStoresAndVerifies(): void
    {
        self::config()->set('audit-log.redaction.max_bytes', self::RAISED_BUDGET);
        self::config()->set('audit-log.redaction.max_context_bytes', self::RAISED_BUDGET);

        $key     = str_repeat('k', self::PAST_ANY_ENGINE_BYTES);
        $pending = AuditLog::event(self::CODE)->withProperties([$key => 'v', 'outer' => [$key => 'v'], 'kept' => 1]);

        $pending->fillContext([$key => 'v', 'outer' => [$key => 'v'], 'kept' => 1]);

        $stored = $this->storedAndVerified($pending->immediately()->record());

        self::assertSame('{"_audit":{"omitted":{"count":4,"paths":["*","context.*"]}},"kept":1,"outer":[]}', CanonicalEncoder::encode($stored['properties']));
        self::assertSame('{"kept":1,"outer":[]}', CanonicalEncoder::encode($stored['context']));
    }

    /**
     * A key at the ceiling is the longest kept, and it stores and verifies on
     * every engine, nested and in the context as well, with no diagnostic.
     *
     * @return void
     */
    public function testAKeyAtTheCeilingStoresAndVerifies(): void
    {
        $key     = str_repeat('k', KeyCeiling::MAX_BYTES);
        $pending = AuditLog::event(self::CODE)->withProperties(['outer' => [$key => 'v']]);

        $pending->fillContext(['outer' => [$key => 'v']]);

        $stored = $this->storedAndVerified($pending->immediately()->record());

        self::assertSame('{"outer":{"' . $key . '":"v"}}', CanonicalEncoder::encode($stored['properties']));
        self::assertSame('{"outer":{"' . $key . '":"v"}}', CanonicalEncoder::encode($stored['context']));
    }

    /**
     * Every field of the record capture returned is what the engine gives back,
     * so what a caller holds and what is stored are one record.
     *
     * @return void
     */
    public function testTheStoredPropertiesEqualTheReturnedRecord(): void
    {
        self::config()->set('audit-log.redaction.ip', 'truncate');

        app()->instance(FieldEncrypter::class, new RecordingFieldEncrypter);

        $pending = self::underDefinition(EventDefinition::for(self::CODE)->retain('amount', 'zeta.*')->pseudonymise('email')->encrypt('ssn', KeyOwner::ACTOR))
            ->by(Reference::of('user', '7'))
            ->withProperties(['zeta' => ['mm' => 1, 'a' => 2], 'amount' => '1200.00', 'email' => 'alice@example.com', 'ssn' => '078-05-1120', 'other' => 'dropped'])
            ->withNote('Approved by phone.')
            ->withIdentifier('alice@example.com');

        $pending->fillClient(self::IP, 'Mozilla/5.0');
        $pending->fillContext(['plan' => 'pro', 'api_key' => 's3cr3t']);

        $record = $pending->immediately()->record();
        $stored = $this->storedAndVerified($record);

        foreach ($record->toArray() as $column => $value) {
            self::assertSame(CanonicalEncoder::encode($value), CanonicalEncoder::encode($stored[$column]), "The column {$column}.");
        }

        self::assertSame('203.0.113.0', $stored['ip']);
    }

    /**
     * Read back the row of a captured record, assert it verifies and holds the
     * properties, context and address capture returned; the decoded row.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @return array<string, mixed>
     */
    private function storedAndVerified(AuditRecord $record): array
    {
        $stored = $this->storedRow($record->id);

        self::assertTrue(app(RecordSigner::class)->verifies($stored));
        self::assertSame(CanonicalEncoder::encode($record->properties), CanonicalEncoder::encode($stored['properties']));
        self::assertSame(CanonicalEncoder::encode($record->context), CanonicalEncoder::encode($stored['context']));
        self::assertSame($record->ip, $stored['ip']);

        return $stored;
    }

    /**
     * The stored JSON with the one part changed, or removed when the value is
     * `null`.
     *
     * @param  string  $json
     * @param  string  $path
     * @param  int|string|null  $value
     * @return string
     */
    private static function editedJson(string $json, string $path, int|string|null $value): string
    {
        $decoded = json_decode($json, true, flags: JSON_THROW_ON_ERROR);

        if ($value === null) {
            Arr::forget($decoded, $path);
        } else {
            Arr::set($decoded, $path, $value);
        }

        return json_encode($decoded, JSON_THROW_ON_ERROR);
    }

    /**
     * The row exactly as the engine gives it, as one string to search.
     *
     * @param  string  $id
     * @return string
     */
    private function rawRow(string $id): string
    {
        return (string) json_encode((array) $this->storageConnection()->table(EntrySettings::table())->where('id', $id)->first(), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    }

    /**
     * Record an address in the `encrypt` mode, under an encrypter returning an
     * envelope with the ciphertext, `k` as its key and 1 as its version.
     *
     * @param  string  $ciphertext
     * @return \SineMacula\Laravel\AuditLog\Records\AuditRecord
     */
    private function recordedWithAnEnvelope(string $ciphertext): AuditRecord
    {
        self::config()->set('audit-log.redaction.ip', 'encrypt');

        app()->instance(FieldEncrypter::class, new MalformedFieldEncrypter(['v' => 1, 'k' => 'k', 'c' => $ciphertext]));

        return self::fromAddress(self::IP)->by(Reference::of('user', '7'))->immediately()->record();
    }

    /**
     * A builder of the code, from the client's address.
     *
     * @param  string  $ip
     * @return \SineMacula\Laravel\AuditLog\Records\PendingRecord
     */
    private static function fromAddress(string $ip): PendingRecord
    {
        $pending = AuditLog::event(self::CODE);

        $pending->fillClient($ip, null);

        return $pending;
    }

    /**
     * A builder of the definition's code, from the facade, behind which is a
     * recorder holding the definition.
     *
     * @param  \SineMacula\Laravel\AuditLog\Definitions\EventDefinition  $definition
     * @return \SineMacula\Laravel\AuditLog\Records\PendingRecord
     */
    private static function underDefinition(EventDefinition $definition): PendingRecord
    {
        $recorder = new Recorder(new EventCatalogue, new ContributorRegistry);

        $recorder->define($definition);

        AuditLog::swap($recorder);

        return AuditLog::event($definition->code);
    }

    /**
     * The application's configuration.
     *
     * @return \Illuminate\Config\Repository
     */
    private static function config(): ConfigRepository
    {
        return app(ConfigRepository::class);
    }
}
