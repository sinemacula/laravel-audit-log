<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Records;

use Illuminate\Config\Repository;
use Illuminate\Support\Str;
use Ramsey\Uuid\Uuid;
use Ramsey\Uuid\UuidInterface;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Privacy\EnvelopeSealer;
use SineMacula\Laravel\AuditLog\Privacy\IdentifierHasher;
use SineMacula\Laravel\AuditLog\Privacy\IpMinimiser;
use SineMacula\Laravel\AuditLog\Privacy\Minimised;
use SineMacula\Laravel\AuditLog\Privacy\NoFieldEncrypter;
use SineMacula\Laravel\AuditLog\Privacy\RecordMinimiser;
use SineMacula\Laravel\AuditLog\Privacy\RedactionSettings;
use SineMacula\Laravel\AuditLog\Privacy\Redactor;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\Enums\Origin;
use SineMacula\Laravel\AuditLog\Records\EventCode;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;

/**
 * Records for tests: captured records built through the public builder, as an
 * application builds them, and records of a shape capture never produces.
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

    /** @var string The application key minimising derives any hash from. */
    private const string APP_KEY = '0123456789abcdef0123456789abcdef';

    /** @var string The code of the permissive definition minimising defaults to; not the builder's, which may have none. */
    private const string PERMISSIVE_CODE = 'invoice.approved';

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
