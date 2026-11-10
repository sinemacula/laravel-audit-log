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
 * Unit tests for the evidence a lifecycle record must keep: the properties and
 * the operation they name, the evidence a record keeps whatever the order of
 * its keys, and every way a record can fail to keep it, the package's metadata
 * included.
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
     * The evidence keeps its properties as given, and names the operation they
     * name.
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
     * Rows of `[properties]`: evidence that names no operation, or names one by
     * something other than a string.
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
     * Evidence that names no operation by its id is refused, since
     * reconciliation finds a recorded operation by it.
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
     * A record whose properties are exactly the evidence's is accepted,
     * whatever the order of their keys, since both are compared canonically.
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
     * Rows of `[properties the record keeps]`: every way of not keeping the
     * evidence exactly.
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
     * A record that does not keep the evidence exactly, or carries the
     * package's metadata at all, is refused.
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
     * Evidence holding a value with no canonical form is never kept, even by a
     * record holding the very same value, so it is refused rather than thrown
     * as the encoder's failure.
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
