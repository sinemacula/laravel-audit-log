<?php

declare(strict_types = 1);

namespace Tests\Unit\Capture\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Capture\Enums\ModelEvent;
use SineMacula\Laravel\AuditLog\Records\EventCode;

/**
 * Unit tests for the changes of a watched model: the code suffix each is stored
 * under, the code it makes after a model's segment, and the Eloquent event each
 * is listened for by, a restore by none.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ModelEvent::class)]
final class ModelEventTest extends TestCase
{
    /**
     * The stored suffixes, in order, so a renamed, reordered, added or removed
     * change fails here.
     *
     * @return void
     */
    public function testTheValues(): void
    {
        self::assertSame(
            ['created', 'updated', 'deleted', 'restored', 'force_deleted'],
            array_map(static fn (ModelEvent $event): string => $event->value, ModelEvent::cases()),
        );
    }

    /**
     * Rows of `[event, as, code]`: a change of a model watched as the segment,
     * and the code it is stored under.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Capture\Enums\ModelEvent, 1: string, 2: string}>
     */
    public static function provideCodes(): iterable
    {
        yield from [
            'created'                 => [ModelEvent::CREATED, 'invoice', 'invoice.created'],
            'updated'                 => [ModelEvent::UPDATED, 'invoice', 'invoice.updated'],
            'deleted'                 => [ModelEvent::DELETED, 'invoice', 'invoice.deleted'],
            'restored'                => [ModelEvent::RESTORED, 'invoice', 'invoice.restored'],
            'force deleted'           => [ModelEvent::FORCE_DELETED, 'invoice', 'invoice.force_deleted'],
            'a segment of digits too' => [ModelEvent::UPDATED, 'line_item2', 'line_item2.updated'],
        ];
    }

    /**
     * The code is the segment, a dot, then the change's suffix, and is a valid
     * event code.
     *
     * @param  \SineMacula\Laravel\AuditLog\Capture\Enums\ModelEvent  $event
     * @param  string  $as
     * @param  string  $code
     * @return void
     */
    #[DataProvider('provideCodes')]
    public function testCodeForPutsTheSuffixAfterThePrefix(ModelEvent $event, string $as, string $code): void
    {
        self::assertSame($code, $event->codeFor($as));
        self::assertSame($code, EventCode::of($event->codeFor($as))->value);
    }

    /**
     * The longest segment a watch accepts, with the longest suffix, makes a
     * code that still fits the code column.
     *
     * @return void
     */
    public function testTheLongestSegmentFitsTheCodeColumn(): void
    {
        $code = ModelEvent::FORCE_DELETED->codeFor('a' . str_repeat('b', 176));

        self::assertSame(EventCode::MAX_BYTES, strlen($code));
        self::assertSame($code, EventCode::of($code)->value);
    }

    /**
     * Each change is listened for by the Eloquent event of its name, a force
     * delete by `forceDeleted`, and a restore by none, since it is told from an
     * update.
     *
     * @return void
     */
    public function testEachEloquentEvent(): void
    {
        self::assertSame(
            ['created', 'updated', 'deleted', null, 'forceDeleted'],
            array_map(static fn (ModelEvent $event): ?string => $event->eloquentEvent(), ModelEvent::cases()),
        );
    }
}
