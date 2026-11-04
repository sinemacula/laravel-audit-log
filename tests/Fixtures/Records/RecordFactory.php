<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Records;

use Illuminate\Config\Repository;
use Illuminate\Encryption\Encrypter;
use Illuminate\Support\Str;
use Ramsey\Uuid\Uuid;
use Ramsey\Uuid\UuidInterface;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Integrity\IntegritySettings;
use SineMacula\Laravel\AuditLog\Integrity\KeyRing;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Integrity\SealSettings;
use SineMacula\Laravel\AuditLog\Privacy\EnvelopeSealer;
use SineMacula\Laravel\AuditLog\Privacy\IdentifierHasher;
use SineMacula\Laravel\AuditLog\Privacy\IpMinimiser;
use SineMacula\Laravel\AuditLog\Privacy\Minimised;
use SineMacula\Laravel\AuditLog\Privacy\NoFieldEncrypter;
use SineMacula\Laravel\AuditLog\Privacy\RecordMinimiser;
use SineMacula\Laravel\AuditLog\Privacy\RedactionSettings;
use SineMacula\Laravel\AuditLog\Privacy\Redactor;
use SineMacula\Laravel\AuditLog\Records\Attachment;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\DisclosureManifest;
use SineMacula\Laravel\AuditLog\Records\Enums\ArtifactKind;
use SineMacula\Laravel\AuditLog\Records\Enums\Origin;
use SineMacula\Laravel\AuditLog\Records\EnvelopeKeys;
use SineMacula\Laravel\AuditLog\Records\EventCode;
use SineMacula\Laravel\AuditLog\Records\ExportManifest;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Records\ImportedSource;
use SineMacula\Laravel\AuditLog\Records\Manifest;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;

/**
 * Records for tests: captured records built through the public builder, as an
 * application builds them, records carrying a sealed artifact of any kind, a
 * bulk operation's subjects, a disclosure or an export's manifest, with the
 * canonical forms each kind's builder makes, imported records built as the
 * importer builds them, and records of a shape neither capture nor import ever
 * produces.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordFactory
{
    /** @var string When the activity of every captured record occurred, unless a test gives another time. */
    public const string OCCURRED_AT = '2026-11-01T12:00:00.123456Z';

    /** @var string When a finalised bundle was recorded: after its activity occurred. */
    public const string RECORDED_AT = '2026-11-01T12:00:01.654321Z';

    /** @var string When an imported record was imported, unless a test gives another time. */
    public const string IMPORTED_AT = '2026-11-03T09:30:00.000000Z';

    /** @var string The batch every imported record comes in, unless a test gives another source. */
    public const string IMPORT_BATCH_ID = '0192f1c4-7b8e-7c3a-9d2e-5f6a7b8c9d0e';

    /** @var string The type of every member of a bulk record's manifest. */
    public const string MEMBER_TYPE = 'App\Models\Invoice';

    /** @var string The application key minimising derives any hash from. */
    private const string APP_KEY = '0123456789abcdef0123456789abcdef';

    /** @var string The id of the log a minimised record's values are sealed for. */
    private const string LOG_ID = 'app-eu-1';

    /** @var string The code of the permissive definition minimising defaults to; not the builder's, which may have none. */
    private const string PERMISSIVE_CODE = 'invoice.approved';

    /** @var string The key of the test encrypter: the `app.key` the Feature and Integration tests configure, so their encrypter opens what it sealed. */
    private const string ENCRYPTION_KEY = 'laravel-audit-log test key!!!!!!';

    /** @var int The greatest canonical form a bulk record's manifest may encode to, in bytes: the setting's greatest. */
    private const int BULK_MAX_BYTES = 8388608;

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * A captured record of an approved invoice, built through the builder and
     * the record's one named constructor: by a user, on an invoice, for an
     * organisation, over HTTP, with the properties given. With an id, the UUID
     * factory is pinned to it for this one call and then restored.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $properties
     * @param  ?string  $id
     * @param  string  $occurredAt
     * @return \SineMacula\Laravel\AuditLog\Records\AuditRecord
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public static function captured(array $properties = ['amount' => '1200.00'], ?string $id = null, string $occurredAt = self::OCCURRED_AT): AuditRecord
    {
        if ($id === null) {
            return self::build($properties, $occurredAt);
        }

        Str::createUuidsUsing(static fn (): UuidInterface => Uuid::fromString($id));

        try {
            return self::build($properties, $occurredAt);
        } finally {
            Str::createUuidsNormally();
        }
    }

    /**
     * A captured bulk record of approved invoices, by a user, for an
     * organisation, over HTTP, carrying its manifest sealed under the test
     * encrypter: members `App\Models\Invoice` 1 to the number given, its
     * descriptor at `properties._audit.manifest`.
     *
     * @param  int  $members
     * @return \SineMacula\Laravel\AuditLog\Records\AuditRecord
     *
     * @throws \InvalidArgumentException
     * @throws \JsonException
     * @throws \LogicException
     */
    public static function bundled(int $members = 3): AuditRecord
    {
        return self::carrying('invoice.bulk_approved', Manifest::of(self::members($members), max($members, 1), self::BULK_MAX_BYTES));
    }

    /**
     * A captured record carrying an artifact of the kind, of the canonical form
     * and count given as they are, sealed under the test encrypter: a listing
     * of invoices for a disclosure, an export of them for an export, and a bulk
     * approval for a bulk operation, by a user, for an organisation, over HTTP,
     * its descriptor at `properties._audit.manifest`.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\ArtifactKind  $kind
     * @param  string  $canonical
     * @param  int  $count
     * @return \SineMacula\Laravel\AuditLog\Records\AuditRecord
     *
     * @throws \InvalidArgumentException
     * @throws \JsonException
     * @throws \LogicException
     */
    public static function withArtifact(ArtifactKind $kind, string $canonical, int $count): AuditRecord
    {
        $event = match ($kind) {
            ArtifactKind::BULK       => 'invoice.bulk_approved',
            ArtifactKind::DISCLOSURE => 'invoice.listed',
            ArtifactKind::EXPORT     => 'invoice.exported',
        };

        return self::carrying($event, Manifest::ofContent($kind, $canonical, $count));
    }

    /**
     * The record of `withArtifact()` finalised at `RECORDED_AT` and signed as
     * `finalisedBundle()` signs.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\ArtifactKind  $kind
     * @param  string  $canonical
     * @param  int  $count
     * @return \SineMacula\Laravel\AuditLog\Records\FinalisedRecord
     *
     * @throws \InvalidArgumentException
     * @throws \JsonException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     * @throws \SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException
     */
    public static function finalisedWithArtifact(ArtifactKind $kind, string $canonical, int $count): FinalisedRecord
    {
        return self::signed(self::withArtifact($kind, $canonical, $count));
    }

    /**
     * A canonical form of the kind holding the number of members given, as that
     * kind's builder makes it: `App\Models\Invoice` 1 to that number for a bulk
     * operation, that many entries returned for a disclosure, and that many
     * lines for an export.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\ArtifactKind  $kind
     * @param  int  $count
     * @return string
     *
     * @throws \InvalidArgumentException
     * @throws \JsonException
     */
    public static function canonical(ArtifactKind $kind, int $count): string
    {
        $entries = array_map(static fn (int $index): string => sprintf('01932b4e-8a40-7000-8000-%012d', $index), $count < 1 ? [] : range(1, $count));

        return match ($kind) {
            ArtifactKind::BULK       => Manifest::encode(array_map(static fn (Reference $member): array => [$member->type, $member->id], self::members($count))),
            ArtifactKind::DISCLOSURE => DisclosureManifest::of(
                ['category' => ['finance'], 'event' => null],
                ['denied' => false, 'tenants' => [['organisation', 'org_01']]],
                array_map(static fn (string $id): array => [$id, hash('sha256', $id)], $entries),
            )->canonical,
            ArtifactKind::EXPORT => ExportManifest::canonical(
                'ndjson',
                Reference::of('user', '42'),
                hash('sha256', 'scope'),
                hash('sha256', 'query'),
                ['connection' => 'testing', 'consistency' => 'deferred_read_transaction', 'database' => 'audit', 'engine' => 'sqlite', 'table' => 'audit_log_entries'],
                $count,
                $entries === [] ? null : [self::RECORDED_AT, $entries[0]],
                $entries === [] ? null : [self::RECORDED_AT, $entries[$count - 1]],
                hash('sha256', 'file'),
                hash('sha256', implode('', array_map(static fn (string $id): string => $id . "\n", $entries))),
            ),
        };
    }

    /**
     * The bulk record of `bundled()` finalised at `RECORDED_AT` and signed
     * under the key derived from the `app.key` the Feature and Integration
     * tests configure, so their key ring verifies it.
     *
     * @param  int  $members
     * @return \SineMacula\Laravel\AuditLog\Records\FinalisedRecord
     *
     * @throws \InvalidArgumentException
     * @throws \JsonException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     * @throws \SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException
     */
    public static function finalisedBundle(int $members = 3): FinalisedRecord
    {
        return self::signed(self::bundled($members));
    }

    /**
     * The test encrypter bulk records are sealed under: AES-256-CBC with the
     * `app.key` the Feature and Integration tests configure.
     *
     * @return \Illuminate\Encryption\Encrypter
     *
     * @throws \RuntimeException
     */
    public static function encrypter(): Encrypter
    {
        return new Encrypter(self::ENCRYPTION_KEY, 'aes-256-cbc');
    }

    /**
     * References to `App\Models\Invoice` 1 to the number given, in order.
     *
     * @param  int  $count
     * @return list<\SineMacula\Laravel\AuditLog\Records\Reference>
     *
     * @throws \InvalidArgumentException
     */
    public static function members(int $count): array
    {
        return array_map(static fn (int $id): Reference => Reference::of(self::MEMBER_TYPE, $id), $count < 1 ? [] : range(1, $count));
    }

    /**
     * A record of the base's envelope, or a captured record's, with the fields
     * given (under their stored, snake_case keys) in place of its own, built
     * through the record's private constructor.
     *
     * It stands in for an imported record's fields set one by one, and for
     * values neither capture nor import would ever produce, such as an
     * upper-case id; tests use it for nothing else.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $fields
     * @param  ?\SineMacula\Laravel\AuditLog\Records\AuditRecord  $base
     * @return \SineMacula\Laravel\AuditLog\Records\AuditRecord
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public static function withFields(array $fields, ?AuditRecord $base = null): AuditRecord
    {
        $named = [];

        foreach (array_replace(($base ?? self::captured())->toArray(), $fields) as $key => $value) {
            $named[Str::camel($key)] = $value;
        }

        $construct = \Closure::bind(static fn (array $named): AuditRecord => new AuditRecord(...$named), null, AuditRecord::class);

        return $construct($named);
    }

    /**
     * An imported record of an approved invoice, built as the importer builds
     * it, through the record's named constructor for imports: by a user, on an
     * invoice, for an organisation, with the properties, origin, occurrence
     * time and source given, imported at the time given.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  ?\SineMacula\Laravel\AuditLog\Records\ImportedSource  $source
     * @param  ?string  $origin
     * @param  string  $occurredAt
     * @param  string  $importedAt
     * @param  array<array-key, mixed>  $properties
     * @return \SineMacula\Laravel\AuditLog\Records\AuditRecord
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public static function imported(
        ?ImportedSource $source = null,
        ?string $origin = 'http',
        string $occurredAt = self::OCCURRED_AT,
        string $importedAt = self::IMPORTED_AT,
        array $properties = ['amount' => '1200.00'],
    ): AuditRecord {
        $builder = (new PendingRecord)
            ->event('invoice.approved')
            ->on(Reference::of('invoice', 'inv_0042'))
            ->by(Reference::of('user', '42'))
            ->forTenant(Reference::of('organisation', 'org_01'))
            ->correlatedWith('legacy:ticket-7')
            ->withProperties($properties);

        $builder->fillClient('198.51.100.4', null);
        $builder->fillContext(['route' => 'invoices.approve']);

        $id = Str::uuid7(self::instant($importedAt))->toString();

        return AuditRecord::fromImport($builder, self::minimisedOf($builder, null, $id), 1, 'finance', $occurredAt, $origin, $source ?? self::source(), $id);
    }

    /**
     * The source of an imported record: a legacy application in a region, the
     * record's id there, the batch it came in and the digest given, or one of
     * its id.
     *
     * @param  string  $sourceRecordId
     * @param  ?string  $sourceDigest
     * @return \SineMacula\Laravel\AuditLog\Records\ImportedSource
     *
     * @throws \InvalidArgumentException
     */
    public static function source(string $sourceRecordId = 'legacy-0042', ?string $sourceDigest = null): ImportedSource
    {
        return new ImportedSource('legacy-app', 'eu-west-1', $sourceRecordId, self::IMPORT_BATCH_ID, $sourceDigest ?? hash('sha256', $sourceRecordId));
    }

    /**
     * What the real minimiser leaves of the builder, as the entry of the id
     * given or a fresh one, with nothing but an application key and a log id
     * configured and no field encrypter, so a record built from it proves the
     * permissive pipeline disturbs nothing. The builder stays usable, and needs
     * no code: the default definition has its own, so that building its record
     * is what refuses a builder with none.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingRecord  $pending
     * @param  ?\SineMacula\Laravel\AuditLog\Definitions\EventDefinition  $definition
     * @param  ?string  $entryId
     * @return \SineMacula\Laravel\AuditLog\Privacy\Minimised
     *
     * @throws \InvalidArgumentException
     * @throws \JsonException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     */
    public static function minimisedOf(PendingRecord $pending, ?EventDefinition $definition = null, ?string $entryId = null): Minimised
    {
        $config   = new Repository(['app' => ['key' => self::APP_KEY], 'audit-log' => ['integrity' => ['log_id' => self::LOG_ID]]]);
        $settings = new RedactionSettings($config);
        $hasher   = new IdentifierHasher($settings);
        $sealer   = new EnvelopeSealer(new NoFieldEncrypter, new RecordingExceptionHandler);

        $minimiser = new RecordMinimiser($settings, new Redactor($settings), new IpMinimiser($settings, $hasher), $hasher, $sealer, new SealSettings($config));
        $snapshot  = $pending->snapshot();
        $entryId ??= $snapshot->id ?? Str::uuid7()->toString();

        return $minimiser->minimise($snapshot, $definition ?? EventDefinition::permissive(EventCode::of(self::PERMISSIVE_CODE)), $entryId);
    }

    /**
     * The captured record of the approved invoice.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $properties
     * @param  string  $occurredAt
     * @return \SineMacula\Laravel\AuditLog\Records\AuditRecord
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private static function build(array $properties, string $occurredAt): AuditRecord
    {
        $builder = (new PendingRecord)
            ->event('invoice.approved')
            ->on(Reference::of('invoice', 'inv_0042'))
            ->by(Reference::of('user', '42'))
            ->forTenant(Reference::of('organisation', 'org_01'))
            ->correlatedWith('app:ticket-123')
            ->withProperties($properties);

        $builder->fillOrigin(Origin::HTTP);
        $builder->fillGuard('web');
        $builder->fillClient('203.0.113.7', 'Mozilla/5.0');
        $builder->fillContext(['route' => 'invoices.approve', 'method' => 'POST']);

        $id     = Str::uuid7(self::instant($occurredAt))->toString();
        $record = AuditRecord::fromPending($builder, self::minimisedOf($builder, null, $id), $id, 1, 'finance', self::instant($occurredAt), 'app-eu-1', 'eu-west-2');

        // An envelope among the properties stands for a field the record's own
        // sealer sealed, which minimising removes from what a record is given,
        // so such properties are set on the record as given
        return self::holdsAnEnvelope($properties) ? self::withFields(['properties' => $properties], $record) : $record;
    }

    /**
     * Whether the value is, or holds at any depth, a map that is exactly an
     * encryption envelope.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @return bool
     */
    private static function holdsAnEnvelope(mixed $value): bool
    {
        if (!is_array($value)) {
            return false;
        }

        return EnvelopeKeys::isEnvelope($value) || array_filter($value, self::holdsAnEnvelope(...)) !== [];
    }

    /**
     * A captured record of the code carrying the manifest sealed under the test
     * encrypter, by a user, for an organisation, over HTTP.
     *
     * @param  string  $event
     * @param  \SineMacula\Laravel\AuditLog\Records\Manifest  $manifest
     * @return \SineMacula\Laravel\AuditLog\Records\AuditRecord
     *
     * @throws \InvalidArgumentException
     * @throws \JsonException
     * @throws \LogicException
     */
    private static function carrying(string $event, Manifest $manifest): AuditRecord
    {
        $builder = (new PendingRecord)
            ->event($event)
            ->by(Reference::of('user', '42'))
            ->forTenant(Reference::of('organisation', 'org_01'))
            ->correlatedWith('app:ticket-123')
            ->withProperties(['batch' => 'march'])
            ->withManifest($manifest);

        $builder->fillOrigin(Origin::HTTP);
        $builder->fillGuard('web');
        $builder->fillClient('203.0.113.7', 'Mozilla/5.0');

        $id         = Str::uuid7(self::instant(self::OCCURRED_AT))->toString();
        $minimised  = self::minimisedOf($builder, null, $id);
        $attachment = Attachment::sealed($manifest, self::encrypter());

        return AuditRecord::fromPending($builder, $minimised, $id, 1, 'finance', self::instant(self::OCCURRED_AT), 'app-eu-1', 'eu-west-2', $attachment);
    }

    /**
     * The record finalised at `RECORDED_AT` and signed under the key derived
     * from the `app.key` the Feature and Integration tests configure, so their
     * key ring verifies it.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @return \SineMacula\Laravel\AuditLog\Records\FinalisedRecord
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     * @throws \SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException
     */
    private static function signed(AuditRecord $record): FinalisedRecord
    {
        $config = new Repository(['app' => ['key' => 'base64:' . base64_encode(self::ENCRYPTION_KEY)]]);

        return (new RecordSigner(new KeyRing(new IntegritySettings($config))))->sign($record, self::RECORDED_AT);
    }

    /**
     * The time as an instant, in any form `\DateTimeImmutable` reads.
     *
     * @param  string  $time
     * @return \DateTimeImmutable
     *
     * @throws \InvalidArgumentException
     */
    private static function instant(string $time): \DateTimeImmutable
    {
        return date_create_immutable($time) ?: throw new \InvalidArgumentException(sprintf('The time %s is not a date and time.', $time));
    }
}
