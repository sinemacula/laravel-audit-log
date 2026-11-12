<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Lifecycle\LifecycleEvidence;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use Tests\Fixtures\Records\RecordFactory;

/**
 * Unit tests for the evidence a lifecycle record must keep.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LifecycleEvidence::class)]
final class LifecycleEvidenceTest extends TestCase
{
    /** @var string The operation the evidence names. */
    private const string OPERATION_ID = '019a4b2e-7c10-7000-8000-00000000000a';

    /** @var string Why a record that does not keep the evidence is refused. */
    private const string ALTERED = 'A lifecycle record must keep its evidence exactly.';

    /**
     * The evidence keeps its properties and names their operation.
     *
     * @return void
     */
    public function testKeepsThePropertiesAndTheOperation(): void
    {
        $evidence = new LifecycleEvidence(self::properties());

        self::assertSame(self::properties(), $evidence->properties);
        self::assertSame(self::OPERATION_ID, $evidence->operationId);
        self::assertSame('operation_id', LifecycleEvidence::OPERATION_KEY);
    }

    /**
     * Rows of `[properties]`: no operation id, or one that is not a string.
     *
     * @return iterable<string, array{0: array<string, int|string|null>}>
     */
    public static function provideNamelessEvidence(): iterable
    {
        yield from [
            'no operation'       => [['status' => 'complete']],
            'a null operation'   => [['operation_id' => null]],
            'an empty operation' => [['operation_id' => '']],
            'an integer'         => [['operation_id' => 7]],
        ];
    }

    /**
     * Evidence without an operation id is refused; reconciliation finds by it.
     *
     * @param  array<string, int|string|null>  $properties
     * @return void
     */
    #[DataProvider('provideNamelessEvidence')]
    public function testEvidenceThatNamesNoOperationIsRefused(array $properties): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The evidence of a lifecycle record names its operation under `operation_id`.');

        new LifecycleEvidence($properties);
    }

    /**
     * A record holding exactly the evidence is accepted in any key order.
     *
     * @return void
     */
    public function testARecordThatKeepsTheEvidenceIsAccepted(): void
    {
        $evidence = new LifecycleEvidence(self::properties());

        $evidence->assertKeptBy(self::record(self::properties()));
        $evidence->assertKeptBy(self::record(array_reverse(self::properties())));

        $this->expectNotToPerformAssertions();
    }

    /**
     * Rows of `[properties the record keeps]`: the evidence altered.
     *
     * @return iterable<string, array{0: ?array<string, array<string, int|string>|int|string|null>}>
     */
    public static function provideAlteredProperties(): iterable
    {
        $properties = self::properties();

        $dropped = $properties;

        unset($dropped['held']);

        yield from [
            'a value changed'       => [['deleted' => 41] + $properties],
            'a value retyped'       => [['deleted' => '42'] + $properties],
            'a key dropped'         => [$dropped],
            'a key added'           => [[...$properties, 'extra' => 'value']],
            'a nested value change' => [['categories' => ['audit' => 3, 'finance' => 40]] + $properties],
            'the metadata added'    => [[...$properties, '_audit' => ['removed' => 1]]],
            'no properties'         => [null],
        ];
    }

    /**
     * A record that alters the evidence or carries package metadata is refused.
     *
     * @param  ?array<string, array<string, int|string>|int|string|null>  $kept
     * @return void
     */
    #[DataProvider('provideAlteredProperties')]
    public function testARecordThatAltersTheEvidenceIsRefused(?array $kept): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(self::ALTERED);

        (new LifecycleEvidence(self::properties()))->assertKeptBy(self::record($kept));
    }

    /**
     * A value with no canonical form is refused, not thrown by the encoder.
     *
     * @return void
     */
    public function testAValueWithNoCanonicalFormIsNeverKept(): void
    {
        $properties = [...self::properties(), 'ratio' => 0.5];

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(self::ALTERED);

        (new LifecycleEvidence($properties))->assertKeptBy(self::record($properties));
    }

    /**
     * The properties of a prune's record, in the order of its code.
     *
     * @return array{operation_id: string, status: string, deleted: int, held: int, categories: array<string, int>, outcome: string}
     */
    private static function properties(): array
    {
        return [
            'operation_id' => self::OPERATION_ID,
            'status'       => 'complete',
            'deleted'      => 42,
            'held'         => 0,
            'categories'   => ['audit' => 2, 'finance' => 40],
            'outcome'      => 'success',
        ];
    }

    /**
     * A record keeping the properties, or none.
     *
     * @param  ?array<string, array<string, int|string>|float|int|string|null>  $properties
     * @return \SineMacula\Laravel\AuditLog\Records\AuditRecord
     */
    private static function record(#[\SensitiveParameter] ?array $properties): AuditRecord
    {
        return RecordFactory::withFields(['properties' => $properties]);
    }
}
