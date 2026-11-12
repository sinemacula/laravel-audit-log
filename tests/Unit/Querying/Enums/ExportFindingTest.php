<?php

declare(strict_types = 1);

namespace Tests\Unit\Querying\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Querying\Enums\ExportFinding;

/**
 * Unit tests for the findings of an export's verification.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExportFinding::class)]
final class ExportFindingTest extends TestCase
{
    /**
     * The cases and their values are pinned, in chain order.
     *
     * @return void
     */
    public function testTheStoredValuesInChainOrder(): void
    {
        self::assertSame([
            'BUNDLE_MALFORMED'       => 'bundle_malformed',
            'ENTRY_MISSING'          => 'entry_missing',
            'ENTRY_UNVERIFIABLE'     => 'entry_unverifiable',
            'ENTRY_TAMPERED'         => 'entry_tampered',
            'ENTRY_SWAPPED'          => 'entry_swapped',
            'DESCRIPTOR_MISMATCH'    => 'descriptor_mismatch',
            'ARTIFACT_MISSING'       => 'artifact_missing',
            'ARTIFACT_SWAPPED'       => 'artifact_swapped',
            'ARTIFACT_WRONG_KIND'    => 'artifact_wrong_kind',
            'ARTIFACT_MISMATCH'      => 'artifact_mismatch',
            'ARTIFACT_UNDECRYPTABLE' => 'artifact_undecryptable',
            'ARTIFACT_MALFORMED'     => 'artifact_malformed',
            'ARTIFACT_TAMPERED'      => 'artifact_tampered',
            'MANIFEST_MISMATCH'      => 'manifest_mismatch',
            'FILE_MISMATCH'          => 'file_mismatch',
            'MEMBERSHIP_MISMATCH'    => 'membership_mismatch',
            'LINE_MALFORMED'         => 'line_malformed',
            'LINE_UNVERIFIABLE'      => 'line_unverifiable',
            'LINE_TAMPERED'          => 'line_tampered',
        ], array_column(ExportFinding::cases(), 'value', 'name'));
    }

    /**
     * Each value is the lower snake case of its name.
     *
     * @return void
     */
    public function testEachValueIsItsNameInLowerCase(): void
    {
        foreach (ExportFinding::cases() as $finding) {
            self::assertSame(strtolower($finding->name), $finding->value, $finding->name);
        }
    }

    /**
     * Rows of `[artifact finding, export finding]`, one per artifact finding.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding, 1: \SineMacula\Laravel\AuditLog\Querying\Enums\ExportFinding}>
     */
    public static function provideArtifactFindings(): iterable
    {
        yield from [
            'missing'    => [Finding::MANIFEST_MISSING, ExportFinding::ARTIFACT_MISSING],
            'swapped'    => [Finding::MANIFEST_SWAPPED, ExportFinding::ARTIFACT_SWAPPED],
            'wrong kind' => [Finding::MANIFEST_WRONG_KIND, ExportFinding::ARTIFACT_WRONG_KIND],
            'mismatch'   => [Finding::MANIFEST_MISMATCH, ExportFinding::ARTIFACT_MISMATCH],
            'unreadable' => [Finding::MANIFEST_UNREADABLE, ExportFinding::ARTIFACT_UNDECRYPTABLE],
            'malformed'  => [Finding::MANIFEST_MALFORMED, ExportFinding::ARTIFACT_MALFORMED],
            'tampered'   => [Finding::MANIFEST_TAMPERED, ExportFinding::ARTIFACT_TAMPERED],
        ];
    }

    /**
     * Each finding of an artifact maps to its own finding of the export.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding  $finding
     * @param  \SineMacula\Laravel\AuditLog\Querying\Enums\ExportFinding  $expected
     * @return void
     */
    #[DataProvider('provideArtifactFindings')]
    public function testEachArtifactFindingMaps(Finding $finding, ExportFinding $expected): void
    {
        self::assertSame($expected, ExportFinding::fromArtifactFinding($finding));
    }

    /**
     * No two artifact findings map to the same export finding.
     *
     * @return void
     */
    public function testNoTwoArtifactFindingsMapAlike(): void
    {
        $mapped = array_map(static fn (array $row): string => ExportFinding::fromArtifactFinding($row[0])->value, iterator_to_array(self::provideArtifactFindings()));

        self::assertCount(7, array_unique($mapped));
    }

    /**
     * Any finding that is not one of an artifact is refused, naming it.
     *
     * @return void
     */
    public function testAnyOtherFindingIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The entry_hmac finding is not a finding of an artifact.');

        ExportFinding::fromArtifactFinding(Finding::ENTRY_HMAC);
    }
}
