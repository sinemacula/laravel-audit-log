<?php

declare(strict_types = 1);

namespace Tests\Unit\Records;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Records\CorrelationId;

/**
 * Unit tests for the correlation id check.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CorrelationId::class)]
final class CorrelationIdTest extends TestCase
{
    /**
     * Rows of `[id, valid]`.
     *
     * @return iterable<string, array{0: string, 1: bool}>
     */
    public static function provideIds(): iterable
    {
        yield 'a namespaced id' => ['app:ticket-123', true];
        yield 'a value with spaces after its first character' => ['app:a b', true];
        yield 'a 32-character namespace' => [str_repeat('a', 32) . ':x', true];
        yield 'a 191-character id' => ['app:' . str_repeat('x', 187), true];
        yield 'multibyte characters counted as characters' => ['app:' . str_repeat('é', 187), true];
        yield 'no namespace' => ['ticket-123', false];
        yield 'an empty value' => ['app:', false];
        yield 'a value starting with a space' => ['app: x', false];
        yield 'an upper-case namespace' => ['App:x', false];
        yield 'a namespace starting with a digit' => ['1app:x', false];
        yield 'a 33-character namespace' => [str_repeat('a', 33) . ':x', false];
        yield 'a 192-character id' => ['app:' . str_repeat('x', 188), false];
        yield 'a control character' => ["app:a\nb", false];
        yield 'a bidirectional override' => ["app:a\u{202E}b", false];
        yield 'malformed UTF-8' => ["app:a\xC3", false];
    }

    /**
     * An id is valid exactly when it is namespaced, fits its column and is
     * clean text.
     *
     * @param  string  $id
     * @param  bool  $valid
     * @return void
     */
    #[DataProvider('provideIds')]
    public function testAnIdIsValidOnlyInTheRecordedShape(string $id, bool $valid): void
    {
        self::assertSame($valid, CorrelationId::isValid($id));
    }
}
