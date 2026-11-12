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
 * Unit tests for the codes the package records of its own activity.
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
     * The stored values are pinned, in order.
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
            'PRUNED'                => 'audit_log.pruned',
            'HELD'                  => 'audit_log.held',
            'RELEASED'              => 'audit_log.released',
            'IMPORTED'              => 'audit_log.imported',
            'SUBJECT_ERASED'        => 'audit_log.subject_erased',
            'KEYS_REWRAPPED'        => 'audit_log.keys_rewrapped',
            'KEYS_REINSTATED'       => 'audit_log.keys_reinstated',
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
     * Each code is under the reserved prefix and refused to a caller.
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
     * Rows of `[case, the properties its record keeps, in order]`.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity, 1: list<string>}>
     */
    public static function provideRetained(): iterable
    {
        yield from [
            'a read' => [
                PackageActivity::TRAIL_READ,
                ['purpose', 'query_fingerprint', 'scope_fingerprint', 'fingerprint_key', 'policy', 'page', 'per_page', 'returned', 'reveal', 'fields', 'outcome'],
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
            ...self::lifecycleRetained(),
            ...self::privacyRetained(),
        ];
    }

    /**
     * Each definition is version 1 in `audit` and keeps only its evidence.
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
     * A kept property is kept whole, so a page's position survives as given.
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
     * Each definition matches a permissive one through the same chain.
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
     * Rows of `[case, the properties its record keeps, in order]`.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity, 1: list<string>}>
     */
    public static function provideLifecycleRetained(): iterable
    {
        yield from self::lifecycleRetained();
    }

    /**
     * Each lifecycle definition keeps exactly its properties, in order.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity  $case
     * @param  list<string>  $retained
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    #[DataProvider('provideLifecycleRetained')]
    public function testEachLifecycleDefinitionKeepsExactlyItsProperties(PackageActivity $case, array $retained): void
    {
        $definition = $case->definition();

        self::assertSame($retained, (new \ReflectionMethod(PackageActivity::class, 'retained'))->invoke($case));
        self::assertSame('audit', $definition->category);
        self::assertSame(1, $definition->version);

        foreach ($retained as $property) {
            self::assertSame(FieldHandling::RETAIN, $definition->handlingFor([$property]), $property);
        }

        foreach (['purpose', 'policy', 'export_entry', 'tenant', 'scope', 'reason', 'tenant_id'] as $property) {
            self::assertSame(FieldHandling::DROP, $definition->handlingFor([$property]), $property);
        }
    }

    /**
     * The prune record's categories map is kept whole.
     *
     * @return void
     */
    public function testThePrunesCategoriesAreKeptWhole(): void
    {
        $definition = PackageActivity::PRUNED->definition();

        self::assertSame(FieldHandling::RETAIN, $definition->handlingFor(['categories', 'security']));
        self::assertSame(FieldHandling::RETAIN, $definition->handlingFor(['categories', '_other']));
    }

    /**
     * Rows of `[case, the properties its record keeps, in order]` for privacy.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity, 1: list<string>}>
     */
    public static function providePrivacyRetained(): iterable
    {
        yield from self::privacyRetained();
    }

    /**
     * Each privacy code keeps exactly its properties, in order.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity  $case
     * @param  list<string>  $retained
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    #[DataProvider('providePrivacyRetained')]
    public function testTheErasureCodesKeepExactlyTheirProperties(PackageActivity $case, array $retained): void
    {
        $definition = $case->definition();

        self::assertSame($retained, (new \ReflectionMethod(PackageActivity::class, 'retained'))->invoke($case));
        self::assertSame('audit', $definition->category);
        self::assertSame(1, $definition->version);
        self::assertSame(FieldHandling::DROP, $definition->unlisted);

        foreach ($retained as $property) {
            self::assertSame(FieldHandling::RETAIN, $definition->handlingFor([$property]), $property);
        }

        foreach (['owner', 'owner_type', 'owner_id', 'key_id', 'entry_id', 'hold_id', 'tenant', 'reason', 'destroyed', 'kept'] as $property) {
            self::assertSame(FieldHandling::DROP, $definition->handlingFor([$property]), $property);
        }
    }

    /**
     * The erasure record's blocks map is kept whole.
     *
     * @return void
     */
    public function testTheErasuresBlocksAreKeptWhole(): void
    {
        $definition = PackageActivity::SUBJECT_ERASED->definition();

        self::assertSame(FieldHandling::RETAIN, $definition->handlingFor(['blocked', 'held:0192f5a0-7c1e-7000-8000-00000000000a']));
        self::assertSame(FieldHandling::RETAIN, $definition->handlingFor(['blocked', '_other']));
    }

    /**
     * No privacy code is a read or protected from retention.
     *
     * @return void
     */
    public function testNoPrivacyCodeIsAReadOrProtected(): void
    {
        foreach ([PackageActivity::SUBJECT_ERASED, PackageActivity::KEYS_REWRAPPED, PackageActivity::KEYS_REINSTATED] as $case) {
            self::assertFalse($case->isRead(), $case->value);
            self::assertFalse($case->isProtected(), $case->value);
        }
    }

    /**
     * A page's record keeps its reveal grant and field counts whole.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testTheTrailReadKeepsItsRevealAndFieldCounts(): void
    {
        $retained   = (new \ReflectionMethod(PackageActivity::class, 'retained'))->invoke(PackageActivity::TRAIL_READ);
        $definition = PackageActivity::TRAIL_READ->definition();

        self::assertIsArray($retained);
        self::assertSame(['returned', 'reveal', 'fields', 'outcome'], array_slice($retained, -4));

        foreach (['reveal', 'fields'] as $property) {
            self::assertSame(FieldHandling::RETAIN, $definition->handlingFor([$property]), $property);
        }

        foreach (['encrypted', 'erased', 'revealed', 'unreadable'] as $state) {
            self::assertSame(FieldHandling::RETAIN, $definition->handlingFor(['fields', $state]), $state);
        }

        self::assertSame(FieldHandling::DROP, PackageActivity::TRAIL_COUNTED->definition()->handlingFor(['reveal']));
        self::assertSame(FieldHandling::DROP, PackageActivity::TRAIL_EXPORTED->definition()->handlingFor(['fields']));
    }

    /**
     * Asking a read code for an operation's properties is an error naming it.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testAReadPathsCodeHasNoOperationsProperties(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('`audit_log.trail_read` is not the code of an operation.');

        (new \ReflectionMethod(PackageActivity::class, 'operationRetained'))->invoke(PackageActivity::TRAIL_READ);
    }

    /**
     * Reads, counts, exports and verifications are reads; publication is not.
     *
     * @return void
     */
    public function testTheReadPathsReadsAreReads(): void
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

    /**
     * No lifecycle code is a read.
     *
     * @return void
     */
    public function testNoLifecycleCodeIsARead(): void
    {
        foreach ([PackageActivity::PRUNED, PackageActivity::HELD, PackageActivity::RELEASED, PackageActivity::IMPORTED] as $case) {
            self::assertFalse($case->isRead(), $case->value);
        }
    }

    /**
     * Only the export is protected, so its journal outlives every policy.
     *
     * @return void
     */
    public function testOnlyTheExportIsProtected(): void
    {
        $protected = array_values(array_filter(PackageActivity::cases(), static fn (PackageActivity $case): bool => $case->isProtected()));

        self::assertSame([PackageActivity::TRAIL_EXPORTED], $protected);
    }

    /**
     * The privacy codes and the properties each keeps, in order.
     *
     * @return array<string, array{0: \SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity, 1: list<string>}>
     */
    private static function privacyRetained(): array
    {
        return [
            'an erasure' => [
                PackageActivity::SUBJECT_ERASED,
                [
                    'operation_id', 'erasure_id', 'owner_fingerprint', 'fingerprint_key', 'status', 'keys_destroyed', 'keys_kept',
                    'entries_affected', 'blocked', 'pending_accepted', 'authority_reason', 'outcome',
                ],
            ],
            'a rewrap' => [
                PackageActivity::KEYS_REWRAPPED,
                ['operation_id', 'status', 'keys_rewrapped', 'keys_rotated', 'keys_skipped', 'wrap_key_id', 'batches', 'authority_reason', 'outcome'],
            ],
            'a reinstatement' => [
                PackageActivity::KEYS_REINSTATED,
                ['operation_id', 'reinstatement_id', 'owner_fingerprint', 'fingerprint_key', 'generation_floor', 'authority_reason', 'outcome'],
            ],
        ];
    }

    /**
     * Rows of the lifecycle's codes and the properties each keeps, in order.
     *
     * @return array<string, array{0: \SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity, 1: list<string>}>
     */
    private static function lifecycleRetained(): array
    {
        return [
            'a prune' => [
                PackageActivity::PRUNED,
                ['operation_id', 'status', 'policy_version', 'deleted', 'seals', 'held', 'pending_delivery', 'skipped_seals', 'categories', 'tenants_affected', 'outcome'],
            ],
            'a hold' => [
                PackageActivity::HELD,
                ['operation_id', 'hold_id', 'basis', 'scope_digest', 'review_by', 'authority_reason', 'outcome'],
            ],
            'a release' => [
                PackageActivity::RELEASED,
                ['operation_id', 'hold_id', 'authority_reason', 'outcome'],
            ],
            'an import' => [
                PackageActivity::IMPORTED,
                [
                    'operation_id', 'batch_id', 'source_id', 'format', 'status', 'lines_read', 'imported', 'duplicates', 'conflicts',
                    'rejected', 'hold_id', 'authority_reason', 'outcome',
                ],
            ],
        ];
    }
}
