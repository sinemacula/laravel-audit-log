<?php

declare(strict_types = 1);

namespace Tests\Unit\Capture;

use Illuminate\Database\Eloquent\Model;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Capture\Enums\ModelEvent;
use SineMacula\Laravel\AuditLog\Capture\ModelWatch;
use SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling;
use SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Definitions\FieldRule;
use SineMacula\Laravel\AuditLog\Models\AuditEntry;
use SineMacula\Laravel\AuditLog\Records\EventCode;
use Tests\Fixtures\Capture\Events\PortalSignedIn;
use Tests\Fixtures\Capture\Models\PlainLine;
use Tests\Fixtures\Capture\Models\WatchedInvoice;
use Tests\Fixtures\Capture\Models\WatchedInvoiceRevision;

/**
 * Unit tests for what an application watches of a model class: the class, the
 * segment and the fields it accepts and every one it refuses, checked by
 * reflection alone, and the five definitions a watch registers, each ruling the
 * watched fields where its record keeps them and dropping every other.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ModelWatch::class)]
final class ModelWatchTest extends TestCase
{
    /** @var list<string> The values of the five changes, in the order a watch defines them. */
    private const array CHANGES = ['created', 'updated', 'deleted', 'restored', 'force_deleted'];

    /**
     * A field given alone is retained, and one given as a key takes its
     * handling, in the order given; the class and the segment are kept as
     * given.
     *
     * @return void
     */
    public function testListedFieldsAreRetained(): void
    {
        $watch = ModelWatch::of(WatchedInvoice::class, 'invoice', ['number', 'amount' => FieldHandling::REDACT, 'status']);

        self::assertSame(WatchedInvoice::class, $watch->class);
        self::assertSame('invoice', $watch->as);
        self::assertSame(['number' => FieldHandling::RETAIN, 'amount' => FieldHandling::REDACT, 'status' => FieldHandling::RETAIN], $watch->fields);
    }

    /**
     * The class is kept as PHP declares it, so a name given in another case
     * watches the class Eloquent names its events after.
     *
     * @return void
     */
    public function testTheClassIsKeptAsDeclared(): void
    {
        $watch = ModelWatch::of(strtolower(WatchedInvoice::class), 'invoice', ['number']);

        self::assertSame(WatchedInvoice::class, $watch->class);
    }

    /**
     * Each of the five changes is stored under the segment, then the change,
     * and a watch defines one definition for each, keyed by the change.
     *
     * @return void
     */
    public function testTheFiveCodesAreUnderThePrefix(): void
    {
        $watch = self::watch();

        $codes = array_map(static fn (ModelEvent $event): string => $watch->codeOf($event), ModelEvent::cases());

        self::assertSame(['invoice.created', 'invoice.updated', 'invoice.deleted', 'invoice.restored', 'invoice.force_deleted'], $codes);
        self::assertSame(self::CHANGES, array_keys($watch->definitions()));

        foreach ($watch->definitions() as $change => $definition) {
            self::assertSame('invoice.' . $change, $definition->code, $change);
        }
    }

    /**
     * The longest segment's longest code fits the code column, and one byte
     * more is refused.
     *
     * @return void
     */
    public function testTheLongestSegmentsCodesFit(): void
    {
        $segment = 'a' . str_repeat('b', 176);
        $watch   = ModelWatch::of(WatchedInvoice::class, $segment, ['number']);

        self::assertSame(EventCode::MAX_BYTES, strlen($watch->codeOf(ModelEvent::FORCE_DELETED)));
        self::assertCount(5, $watch->definitions());

        $this->expectException(\InvalidArgumentException::class);

        ModelWatch::of(WatchedInvoice::class, $segment . 'b', ['number']);
    }

    /**
     * A creation, a deletion and a force deletion rule each watched field at
     * its name, with its handling, in the `change` category at version 1.
     *
     * @return void
     */
    public function testTheSnapshotDefinitionsRuleEachField(): void
    {
        $definitions = self::watch()->definitions();

        foreach (['created', 'deleted', 'force_deleted'] as $change) {
            $definition = $definitions[$change];

            self::assertSame(['amount' => FieldHandling::REDACT, 'number' => FieldHandling::RETAIN, 'status' => FieldHandling::RETAIN], self::handlingsOf($definition), $change);
            self::assertSame('change', $definition->category, $change);
            self::assertSame(1, $definition->version, $change);
            self::assertNull($definition->ocsfMapper, $change);
        }
    }

    /**
     * An update rules each watched field's value before and after the change,
     * with its handling, and nothing at the field's own name.
     *
     * @return void
     */
    public function testTheUpdateDefinitionRulesBothLeaves(): void
    {
        $definition = self::watch()->definitions()['updated'];

        self::assertSame([
            'changes.amount.after'  => FieldHandling::REDACT,
            'changes.amount.before' => FieldHandling::REDACT,
            'changes.number.after'  => FieldHandling::RETAIN,
            'changes.number.before' => FieldHandling::RETAIN,
            'changes.status.after'  => FieldHandling::RETAIN,
            'changes.status.before' => FieldHandling::RETAIN,
        ], self::handlingsOf($definition));
        self::assertSame('change', $definition->category);
        self::assertSame(1, $definition->version);
    }

    /**
     * A restore rules each watched field at its name and before and after the
     * change.
     *
     * @return void
     */
    public function testTheRestoreDefinitionRulesTheSnapshotAndBothLeaves(): void
    {
        $definition = self::watch()->definitions()['restored'];

        self::assertSame([
            'amount'                => FieldHandling::REDACT,
            'changes.amount.after'  => FieldHandling::REDACT,
            'changes.amount.before' => FieldHandling::REDACT,
            'changes.number.after'  => FieldHandling::RETAIN,
            'changes.number.before' => FieldHandling::RETAIN,
            'changes.status.after'  => FieldHandling::RETAIN,
            'changes.status.before' => FieldHandling::RETAIN,
            'number'                => FieldHandling::RETAIN,
            'status'                => FieldHandling::RETAIN,
        ], self::handlingsOf($definition));
        self::assertSame('change', $definition->category);
    }

    /**
     * A field encrypted is encrypted under the subject's key wherever each
     * definition rules it, and no other field names an owner.
     *
     * @return void
     */
    public function testAnEncryptedFieldIsOwnedByTheSubject(): void
    {
        $watch = ModelWatch::of(WatchedInvoice::class, 'invoice', ['number' => FieldHandling::ENCRYPT, 'status']);

        foreach ($watch->definitions() as $change => $definition) {
            foreach ($definition->rules as $path => $rule) {
                $encrypted = str_contains($path, 'number');

                self::assertSame($encrypted ? FieldHandling::ENCRYPT : FieldHandling::RETAIN, $rule->handling, $change . ' ' . $path);
                self::assertSame($encrypted ? KeyOwner::SUBJECT : null, $rule->owner, $change . ' ' . $path);
            }
        }
    }

    /**
     * Every field the watch does not name is dropped, by every definition, and
     * its handling is dropping it.
     *
     * @return void
     */
    public function testUnlistedFieldsAreDropped(): void
    {
        $watch = self::watch();

        foreach ($watch->definitions() as $change => $definition) {
            self::assertSame(FieldHandling::DROP, $definition->unlisted, $change);
            self::assertSame(FieldHandling::DROP, $definition->handlingFor(['secret_note']), $change);
            self::assertSame(FieldHandling::DROP, $definition->handlingFor(['changes', 'secret_note', 'before']), $change);
        }

        self::assertSame(FieldHandling::DROP, $watch->handlingOf('secret_note'));
        self::assertSame(FieldHandling::REDACT, $watch->handlingOf('amount'));
    }

    /**
     * Only retaining a field as read is not an explicit handling; every other
     * handling is, and so is a field the watch drops by not naming it.
     *
     * @return void
     */
    public function testOnlyRetainIsNotExplicit(): void
    {
        $fields = [];

        foreach (FieldHandling::cases() as $handling) {
            $fields['field_' . $handling->value] = $handling;
        }

        $watch = ModelWatch::of(WatchedInvoice::class, 'invoice', $fields);

        foreach (FieldHandling::cases() as $handling) {
            self::assertSame($handling !== FieldHandling::RETAIN, $watch->isExplicit('field_' . $handling->value), $handling->value);
        }

        self::assertTrue($watch->isExplicit('unwatched'));
    }

    /**
     * Rows of `[class, segment, fields, exception class, message]`: every watch
     * refused, each before anything of the model is built.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: string, 1: string, 2: array<array-key, mixed>, 3: class-string<\Throwable>, 4: string}>
     */
    public static function provideRefusedWatches(): iterable
    {
        $grammar  = 'cannot be watched: a field is a letter or underscore, then up to 63 letters, digits or underscores, and neither `changes` nor beginning `_audit`.';
        $segment  = 'A watched model\'s segment must be a lower-case letter, then up to 176 lower-case letters, digits or underscores.';
        $fields   = 'A watched model keeps from 1 to 64 fields.';
        $invoice  = WatchedInvoice::class;
        $invalid  = \InvalidArgumentException::class;
        $unnamed  = 'A watched field is named by a string, not a `' . FieldHandling::class . '`.';
        $abstract = '`' . Model::class . '` is abstract; a watched model is a class its rows are built as.';
        $tooMany  = array_map(static fn (int $i): string => 'field_' . $i, range(0, 64));

        yield from [
            'an unknown class'                => ['App\Models\Missing', 'invoice', ['number'], $invalid, '`App\Models\Missing` is not an Eloquent model class.'],
            'a class that is not a model'     => [PortalSignedIn::class, 'invoice', ['number'], $invalid, '`' . PortalSignedIn::class . '` is not an Eloquent model class.'],
            'an abstract model'               => [Model::class, 'invoice', ['number'], $invalid, $abstract],
            'the package\'s read model'       => [AuditEntry::class, 'invoice', ['number'], \LogicException::class, 'The package\'s own models are never watched.'],
            'an empty segment'                => [$invoice, '', ['number'], $invalid, $segment],
            'a segment of two segments'       => [$invoice, 'billing.invoice', ['number'], $invalid, $segment],
            'an upper-case segment'           => [$invoice, 'Invoice', ['number'], $invalid, $segment],
            'a segment starting with a digit' => [$invoice, '1invoice', ['number'], $invalid, $segment],
            'a segment ending with a newline' => [$invoice, "invoice\n", ['number'], $invalid, $segment],
            'no field'                        => [$invoice, 'invoice', [], $invalid, $fields],
            'one field too many'              => [$invoice, 'invoice', $tooMany, $invalid, $fields],
            'a field outside the grammar'     => [$invoice, 'invoice', ['line.total'], $invalid, 'The field `line.total` ' . $grammar],
            'a field starting with a digit'   => [$invoice, 'invoice', ['1st'], $invalid, 'The field `1st` ' . $grammar],
            'a field of 65 characters'        => [$invoice, 'invoice', [str_repeat('a', 65)], $invalid, 'The field `' . str_repeat('a', 64) . '` ' . $grammar],
            'a field holding a control'       => [$invoice, 'invoice', ["number\u{0}"], $invalid, 'The field `number` ' . $grammar],
            'the changes key'                 => [$invoice, 'invoice', ['changes'], $invalid, 'The field `changes` ' . $grammar],
            'the metadata key'                => [$invoice, 'invoice', ['_audit'], $invalid, 'The field `_audit` ' . $grammar],
            'a field beginning the metadata'  => [$invoice, 'invoice', ['_audit_note' => FieldHandling::DROP], $invalid, 'The field `_audit_note` ' . $grammar],
            'a field named twice'             => [$invoice, 'invoice', ['number', 'number' => FieldHandling::REDACT], $invalid, 'The field `number` is watched twice.'],
            'a field listed twice'            => [$invoice, 'invoice', ['number', 'number'], $invalid, 'The field `number` is watched twice.'],
            'a handling given as its value'   => [$invoice, 'invoice', ['number' => 'retain'], $invalid, 'The field `number` is given a `string`, not a `FieldHandling`.'],
            'a field that is not a string'    => [$invoice, 'invoice', [FieldHandling::RETAIN], $invalid, $unnamed],
            'a numeric key'                   => [$invoice, 'invoice', ['7' => FieldHandling::DROP], $invalid, $unnamed],
        ];

        foreach (ModelWatch::RESERVED_SEGMENTS as $reserved) {
            yield 'the reserved segment ' . $reserved => [$invoice, $reserved, ['number'], $invalid, 'The segment `' . $reserved . '` is reserved for the package\'s own codes.'];
        }
    }

    /**
     * Each refused watch fails with its exception and message.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $class
     * @param  string  $as
     * @param  array<array-key, mixed>  $fields
     * @param  class-string<\Throwable>  $exception
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideRefusedWatches')]
    public function testRefusesAWatch(string $class, string $as, array $fields, string $exception, string $message): void
    {
        $this->expectException($exception);
        $this->expectExceptionMessage($message);

        ModelWatch::of($class, $as, $fields);
    }

    /**
     * The most fields a watch keeps are accepted, and so is a field of 64
     * characters and one beginning with an underscore.
     *
     * @return void
     */
    public function testTheBoundsAreAccepted(): void
    {
        $fields = array_map(static fn (int $i): string => 'field_' . $i, range(1, ModelWatch::MAX_FIELDS));

        self::assertCount(ModelWatch::MAX_FIELDS, ModelWatch::of(WatchedInvoice::class, 'invoice', $fields)->fields);
        self::assertSame([str_repeat('a', 64), '_note', 'Number'], array_keys(ModelWatch::of(WatchedInvoice::class, 'invoice', [str_repeat('a', 64), '_note', 'Number'])->fields));
    }

    /**
     * Two watches are equal when the class, the segment and every field's
     * handling are, whatever the order the fields were given in, and differ
     * when any of them does.
     *
     * @return void
     */
    public function testEqualsComparesClassPrefixAndFields(): void
    {
        $watch = self::watch();

        self::assertTrue($watch->equals(ModelWatch::of(WatchedInvoice::class, 'invoice', ['status', 'amount' => FieldHandling::REDACT, 'number'])));
        self::assertFalse($watch->equals(ModelWatch::of(WatchedInvoiceRevision::class, 'invoice', ['number', 'amount' => FieldHandling::REDACT, 'status'])));
        self::assertFalse($watch->equals(ModelWatch::of(WatchedInvoice::class, 'bill', ['number', 'amount' => FieldHandling::REDACT, 'status'])));
        self::assertFalse($watch->equals(ModelWatch::of(WatchedInvoice::class, 'invoice', ['number', 'amount' => FieldHandling::DROP, 'status'])));
        self::assertFalse($watch->equals(ModelWatch::of(WatchedInvoice::class, 'invoice', ['number', 'amount' => FieldHandling::REDACT])));
        self::assertFalse($watch->equals(ModelWatch::of(PlainLine::class, 'invoice', ['number', 'amount' => FieldHandling::REDACT, 'status'])));
    }

    /**
     * The watch of the invoices the tests share: the number and the status
     * retained, the amount redacted.
     *
     * @return \SineMacula\Laravel\AuditLog\Capture\ModelWatch
     */
    private static function watch(): ModelWatch
    {
        return ModelWatch::of(WatchedInvoice::class, 'invoice', ['number', 'amount' => FieldHandling::REDACT, 'status']);
    }

    /**
     * The handling of each of the definition's rules, by path.
     *
     * @param  \SineMacula\Laravel\AuditLog\Definitions\EventDefinition  $definition
     * @return array<string, \SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling>
     */
    private static function handlingsOf(EventDefinition $definition): array
    {
        return array_map(static fn (FieldRule $rule): FieldHandling => $rule->handling, $definition->rules);
    }
}
