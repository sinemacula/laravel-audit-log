<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportLine;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * Unit tests for an import line and its source assertion.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ImportLine::class)]
final class ImportLineTest extends TestCase
{
    /**
     * Every field is kept as given.
     *
     * @return void
     */
    public function testKeepsItsFields(): void
    {
        $line = self::line();

        self::assertSame(7, $line->number);
        self::assertSame('crm-eu', $line->sourceId);
        self::assertSame('eu-west-2', $line->sourceRegion);
        self::assertSame('rec-0042', $line->sourceRecordId);
        self::assertSame('invoice.approved', $line->event);
        self::assertSame('2026-10-01T09:00:00.000001Z', $line->occurredAt);
        self::assertSame(Outcome::FAILURE, $line->outcome);
        self::assertSame('over_limit', $line->reason);
        self::assertSame(['type' => 'user', 'id' => '42'], $line->actor?->toArray());
        self::assertSame(['type' => 'invoice', 'id' => 'inv_0042'], $line->subject?->toArray());
        self::assertNull($line->principal);
        self::assertSame(['type' => 'organisation', 'id' => 'org_01'], $line->tenant?->toArray());
        self::assertSame('finance', $line->category);
        self::assertSame('app:ticket-123', $line->correlationId);
        self::assertSame(['amount' => '1200.00', 'lines' => [1, 2]], $line->properties);
        self::assertSame(['route' => 'invoices.approve'], $line->context);
        self::assertSame('http', $line->origin);
        self::assertSame('203.0.113.7', $line->ip);
        self::assertSame(2, $line->dropped);
    }

    /**
     * The assertion is exactly the asserted fields, references as pairs.
     *
     * @return void
     */
    public function testTheAssertionIsExactlyItsFields(): void
    {
        self::assertSame([
            'v'              => 1,
            'event'          => 'invoice.approved',
            'occurred_at'    => '2026-10-01T09:00:00.000001Z',
            'outcome'        => 'failure',
            'actor'          => ['user', '42'],
            'subject'        => ['invoice', 'inv_0042'],
            'principal'      => null,
            'tenant'         => ['organisation', 'org_01'],
            'reason'         => 'over_limit',
            'correlation_id' => 'app:ticket-123',
            'properties'     => ['amount' => '1200.00', 'lines' => [1, 2]],
            'context'        => ['route' => 'invoices.approve'],
            'origin'         => 'http',
            'ip'             => '203.0.113.7',
        ], self::line()->assertion());
    }

    /**
     * Two lines that differ only in what is not asserted assert the same thing.
     *
     * @return void
     */
    public function testWhatIsNotAssertedLeavesTheAssertionAsItIs(): void
    {
        $other = new ImportLine(
            99,
            'crm-us',
            null,
            'rec-9999',
            'invoice.approved',
            '2026-10-01T09:00:00.000001Z',
            Outcome::FAILURE,
            'over_limit',
            Reference::of('user', 42),
            Reference::of('invoice', 'inv_0042'),
            null,
            Reference::of('organisation', 'org_01'),
            'billing',
            'app:ticket-123',
            ['amount' => '1200.00', 'lines' => [1, 2]],
            ['route' => 'invoices.approve'],
            'http',
            '203.0.113.7',
        );

        self::assertSame(self::line()->assertion(), $other->assertion());
        self::assertSame(0, $other->dropped);
    }

    /**
     * The line every test reads.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ImportLine
     */
    private static function line(): ImportLine
    {
        return new ImportLine(
            number: 7,
            sourceId: 'crm-eu',
            sourceRegion: 'eu-west-2',
            sourceRecordId: 'rec-0042',
            event: 'invoice.approved',
            occurredAt: '2026-10-01T09:00:00.000001Z',
            outcome: Outcome::FAILURE,
            reason: 'over_limit',
            actor: Reference::of('user', '42'),
            subject: Reference::of('invoice', 'inv_0042'),
            principal: null,
            tenant: Reference::of('organisation', 'org_01'),
            category: 'finance',
            correlationId: 'app:ticket-123',
            properties: ['amount' => '1200.00', 'lines' => [1, 2]],
            context: ['route' => 'invoices.approve'],
            origin: 'http',
            ip: '203.0.113.7',
            dropped: 2,
        );
    }
}
