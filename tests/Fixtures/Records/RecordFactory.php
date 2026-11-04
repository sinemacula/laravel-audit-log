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
use SineMacula\Laravel\AuditLog\Records\EventCode;
use SineMacula\Laravel\AuditLog\Records\ExportManifest;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Records\Manifest;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;

/**
 * Records for tests: captured records built through the public builder, as an
 * application builds them, records carrying a sealed artifact of any kind, a
 * bulk operation's subjects, a disclosure or an export's manifest, with the
 * canonical forms each kind's builder makes, and records of a shape capture
 * never produces.
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

    /** @var string The type of every member of a bulk record's manifest. */
    public const string MEMBER_TYPE = 'App\Models\Invoice';

    /** @var string The application key minimising derives any hash from. */
    private const string APP_KEY = '0123456789abcdef0123456789abcdef';

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
     * It stands in for the importer, the only producer of `source_record_id`,
     * and for values capture would never produce, such as an upper-case id;
     * tests use it for nothing else.
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
     * What the real minimiser leaves of the builder, with nothing but an
     * application key configured and no field encrypter, so a record built from
     * it proves the permissive pipeline disturbs nothing. The builder stays
     * usable, and needs no code: the default definition has its own, so that
     * building its record is what refuses a builder with none.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingRecord  $pending
     * @param  ?\SineMacula\Laravel\AuditLog\Definitions\EventDefinition  $definition
     * @return \SineMacula\Laravel\AuditLog\Privacy\Minimised
     *
     * @throws \InvalidArgumentException
     * @throws \JsonException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     */
    public static function minimisedOf(PendingRecord $pending, ?EventDefinition $definition = null): Minimised
    {
        $settings = new RedactionSettings(new Repository(['app' => ['key' => self::APP_KEY]]));
        $hasher   = new IdentifierHasher($settings);
        $sealer   = new EnvelopeSealer(new NoFieldEncrypter, new RecordingExceptionHandler);

        $minimiser = new RecordMinimiser($settings, new Redactor($settings), new IpMinimiser($settings, $hasher), $hasher, $sealer);

        return $minimiser->minimise($pending->snapshot(), $definition ?? EventDefinition::permissive(EventCode::of(self::PERMISSIVE_CODE)));
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

        return AuditRecord::fromPending($builder, self::minimisedOf($builder), 1, 'finance', self::instant($occurredAt), 'app-eu-1', 'eu-west-2');
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

        $minimised  = self::minimisedOf($builder);
        $attachment = Attachment::sealed($manifest, self::encrypter());

        return AuditRecord::fromPending($builder, $minimised, 1, 'finance', self::instant(self::OCCURRED_AT), 'app-eu-1', 'eu-west-2', $attachment);
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
