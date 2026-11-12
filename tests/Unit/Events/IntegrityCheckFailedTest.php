<?php

declare(strict_types = 1);

namespace Tests\Unit\Events;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Contracts\AuditLogEvent;
use SineMacula\Laravel\AuditLog\Events\IntegrityCheckFailed;

/**
 * Unit tests for the integrity failure event, which carries no value of an
 * entry.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IntegrityCheckFailed::class)]
final class IntegrityCheckFailedTest extends TestCase
{
    /** @var array<string, int> Counts by integrity status, zero-filled. */
    private const array INTEGRITY = ['valid' => 6, 'pruned' => 0, 'incomplete' => 0, 'unverifiable' => 0, 'tampered' => 1];

    /** @var array<string, int> Counts by anchoring status, zero-filled. */
    private const array ANCHORING = ['anchored' => 5, 'unanchored' => 1, 'unavailable' => 0, 'contradicted' => 1];

    /**
     * The event carries what it is given in eight public properties, none able
     * to hold an object of the log.
     *
     * @return void
     */
    public function testCarriesItsFieldsAndNothingElse(): void
    {
        $event = new IntegrityCheckFailed('verify', self::INTEGRITY, self::ANCHORING, 'chain_broken', '01932b4e-9000-7000-8000-000000000007', 7, 7, true);

        self::assertSame([
            'command'    => 'verify',
            'integrity'  => self::INTEGRITY,
            'anchoring'  => self::ANCHORING,
            'finding'    => 'chain_broken',
            'firstBadId' => '01932b4e-9000-7000-8000-000000000007',
            'head'       => 7,
            'remoteHead' => 7,
            'complete'   => true,
        ], get_object_vars($event));

        $properties = [];

        foreach ((new \ReflectionClass(IntegrityCheckFailed::class))->getProperties() as $property) {
            self::assertTrue($property->isPublic(), $property->getName());

            $properties[$property->getName()] = (string) $property->getType();
        }

        self::assertSame([
            'command'    => 'string',
            'integrity'  => 'array',
            'anchoring'  => 'array',
            'finding'    => '?string',
            'firstBadId' => '?string',
            'head'       => '?int',
            'remoteHead' => '?int',
            'complete'   => 'bool',
        ], $properties);
    }

    /**
     * A run that stopped before it could say carries no finding, no bad id and
     * no heads, and is not complete.
     *
     * @return void
     */
    public function testCarriesAStoppedRun(): void
    {
        $integrity = array_fill_keys(array_keys(self::INTEGRITY), 0);
        $anchoring = array_fill_keys(array_keys(self::ANCHORING), 0);

        $event = new IntegrityCheckFailed('seal', $integrity, $anchoring, null, null, null, null, false);

        self::assertSame('seal', $event->command);
        self::assertSame($integrity, $event->integrity);
        self::assertSame($anchoring, $event->anchoring);
        self::assertNull($event->finding);
        self::assertNull($event->firstBadId);
        self::assertNull($event->head);
        self::assertNull($event->remoteHead);
        self::assertFalse($event->complete);
    }

    /**
     * The event is marked as the package's own, so it is never mapped to a
     * record of itself, and it cannot be changed once dispatched.
     *
     * @return void
     */
    public function testIsAnAuditLogEvent(): void
    {
        $class = new \ReflectionClass(IntegrityCheckFailed::class);

        self::assertInstanceOf(AuditLogEvent::class, new IntegrityCheckFailed('verify', [], [], null, null, null, null, true));
        self::assertTrue($class->isFinal());
        self::assertTrue($class->isReadOnly());
    }
}
