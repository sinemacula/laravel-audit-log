<?php

declare(strict_types = 1);

namespace Tests\Unit\Querying\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Contracts\DefinesAuditEvents;
use SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Definitions\FieldRule;
use SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity;
use SineMacula\Laravel\AuditLog\Records\EventCode;

/**
 * Unit tests for the codes the package records of its own read path: the stored
 * values, each under the reserved prefix, every definition version 1 in the
 * `audit` category keeping exactly its evidence and dropping the rest, and
 * which of them is a read.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PackageActivity::class)]
final class PackageActivityTest extends TestCase
{
    /**
     * The stored values, in order, so a renamed, reordered, added or removed
     * code fails here.
     *
     * @return void
     */
    public function testTheStoredValues(): void
    {
        self::assertSame([
            'TRAIL_READ'            => 'audit_log.trail_read',
            'TRAIL_COUNTED'         => 'audit_log.trail_counted',
            'TRAIL_EXPORTED'        => 'audit_log.trail_exported',
            'EXPORT_VERIFIED'       => 'audit_log.export_verified',
            'EXPORT_PUBLISH_FAILED' => 'audit_log.export_publish_failed',
        ], array_column(array_map(static fn (PackageActivity $case): array => [$case->name, $case->value], PackageActivity::cases()), 1, 0));
    }

    /**
     * Rows of `[case]`: every package code.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity}>
     */
    public static function provideCases(): iterable
    {
        foreach (PackageActivity::cases() as $case) {
            yield $case->name => [$case];
        }
    }

    /**
     * Each code is under the reserved prefix, is minted as itself, defines
     * events, and is refused to a caller.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity  $case
     * @return void
     */
    #[DataProvider('provideCases')]
    public function testEachIsUnderTheReservedPrefix(PackageActivity $case): void
    {
        self::assertInstanceOf(DefinesAuditEvents::class, $case);
        self::assertStringStartsWith(EventCode::RESERVED_PREFIX, $case->value);
        self::assertSame($case->value, EventCode::package($case)->value);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The `audit_log.` prefix is reserved for the package\'s own event codes.');

        EventCode::of($case);
    }

    /**
     * Rows of `[case, the properties its record keeps, in the order it gives
     * them]`.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity, 1: list<string>}>
     */
    public static function provideRetained(): iterable
    {
        yield from [
            'a read' => [
                PackageActivity::TRAIL_READ,
                ['purpose', 'query_fingerprint', 'scope_fingerprint', 'fingerprint_key', 'policy', 'page', 'per_page', 'returned', 'outcome'],
            ],
            'a count' => [
                PackageActivity::TRAIL_COUNTED,
                ['purpose', 'query_fingerprint', 'scope_fingerprint', 'fingerprint_key', 'policy', 'returned', 'outcome'],
            ],
            'an export' => [
                PackageActivity::TRAIL_EXPORTED,
                ['purpose', 'query_fingerprint', 'scope_fingerprint', 'fingerprint_key', 'policy', 'format', 'returned', 'file_sha256', 'outcome'],
            ],
            'a verification' => [
                PackageActivity::EXPORT_VERIFIED,
                ['purpose', 'scope_fingerprint', 'fingerprint_key', 'policy', 'export_entry', 'verdict', 'findings', 'outcome'],
            ],
            'a failed publication' => [
                PackageActivity::EXPORT_PUBLISH_FAILED,
                ['export_entry', 'outcome'],
            ],
        ];
    }

    /**
     * Each definition is for its own code, version 1, in the `audit` category,
     * maps to no OCSF class, retains exactly its evidence and drops every other
     * field, and is the same on every call.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity  $case
     * @param  list<string>  $retained
     * @return void
     */
    #[DataProvider('provideRetained')]
    public function testEachDefinitionIsVersionOneInTheAuditCategoryDroppingWhatItDoesNotList(PackageActivity $case, array $retained): void
    {
        $definition = $case->definition();

        sort($retained);

        self::assertSame($case->value, $definition->code);
        self::assertSame(1, $definition->version);
        self::assertSame('audit', $definition->category);
        self::assertSame(FieldHandling::DROP, $definition->unlisted);
        self::assertNull($definition->ocsfMapper);
        self::assertSame(array_fill_keys($retained, FieldHandling::RETAIN), array_map(static fn (FieldRule $rule): FieldHandling => $rule->handling, $definition->rules));
        self::assertSame(FieldHandling::DROP, $definition->handlingFor(['viewer']));
        self::assertTrue($definition->equals($case->definition()));
    }

    /**
     * A property the definition keeps is kept whole, a map beneath it included,
     * so a page's position survives as given.
     *
     * @return void
     */
    public function testAKeptMapIsKeptWhole(): void
    {
        $definition = PackageActivity::TRAIL_READ->definition();

        self::assertSame(FieldHandling::RETAIN, $definition->handlingFor(['page', 'occurred_at']));
        self::assertSame(FieldHandling::RETAIN, $definition->handlingFor(['page', 'id']));
        self::assertSame(FieldHandling::RETAIN, $definition->handlingFor(['outcome']));
    }

    /**
     * Each definition is the one a permissive definition of the minted code
     * becomes through the same chain, so no definition method beyond those a
     * caller sees makes it.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity  $case
     * @param  list<string>  $retained
     * @return void
     */
    #[DataProvider('provideRetained')]
    public function testEachDefinitionIsThePermissiveChain(PackageActivity $case, array $retained): void
    {
        $expected = EventDefinition::permissive(EventCode::package($case))->unlisted(FieldHandling::DROP)->category('audit')->retain(...$retained);

        self::assertTrue($expected->equals($case->definition()));
    }

    /**
     * Every activity but the failed publication reads the trail, an export's
     * verification included.
     *
     * @return void
     */
    public function testOnlyThePublishFailureIsNotARead(): void
    {
        $reads = array_values(array_filter(PackageActivity::cases(), static fn (PackageActivity $case): bool => $case->isRead()));

        self::assertSame([
            PackageActivity::TRAIL_READ,
            PackageActivity::TRAIL_COUNTED,
            PackageActivity::TRAIL_EXPORTED,
            PackageActivity::EXPORT_VERIFIED,
        ], $reads);
        self::assertFalse(PackageActivity::EXPORT_PUBLISH_FAILED->isRead());
    }
}
