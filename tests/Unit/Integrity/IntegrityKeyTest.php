<?php

declare(strict_types = 1);

namespace Tests\Unit\Integrity;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\IntegrityKey;
use Symfony\Component\VarDumper\Cloner\VarCloner;
use Symfony\Component\VarDumper\Dumper\CliDumper;

/**
 * Unit tests for an integrity key.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IntegrityKey::class)]
final class IntegrityKeyTest extends TestCase
{
    /** @var string A secret of exactly the shortest length. */
    private const string SECRET = 'integrity-key-test-secret-32-byt';

    /**
     * The key keeps its id and its secret as given.
     *
     * @return void
     */
    public function testKeepsTheIdAndTheSecret(): void
    {
        $key = new IntegrityKey('primary-2026.v1_a', self::SECRET);

        self::assertSame('primary-2026.v1_a', $key->id);
        self::assertSame(self::SECRET, $key->secret());
    }

    /**
     * Rows of `[id]`: ids of the longest length and of every allowed character,
     * which the key accepts.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideAcceptedIds(): iterable
    {
        yield from [
            'one letter'          => ['a'],
            'one digit'           => ['7'],
            'an upper-case start' => ['Primary'],
            '32 characters'       => [str_repeat('a', 32)],
            'every punctuation'   => ['a.b_c-d'],
            'a trailing hyphen'   => ['a-'],
            'a derived id'        => ['d03d4735ce37bd961'],
        ];
    }

    /**
     * Each id the column can hold is accepted.
     *
     * @param  string  $id
     * @return void
     */
    #[DataProvider('provideAcceptedIds')]
    public function testAcceptsAnIdTheColumnCanHold(string $id): void
    {
        self::assertSame($id, (new IntegrityKey($id, self::SECRET))->id);
    }

    /**
     * Rows of `[id]`: ids that are too long, empty, start with punctuation, or
     * hold a character outside the column-safe set.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideRefusedIds(): iterable
    {
        yield from [
            '33 characters'      => [str_repeat('a', 33)],
            'empty'              => [''],
            'a leading dot'      => ['.a'],
            'a leading hyphen'   => ['-a'],
            'a leading score'    => ['_a'],
            'a space'            => ['a b'],
            'a quote'            => ['a\'b'],
            'a slash'            => ['a/b'],
            'an accented letter' => ['é'],
            'a trailing newline' => ["a\n"],
            'a colon'            => ['a:b'],
        ];
    }

    /**
     * Each id the column cannot hold is refused, never naming the id.
     *
     * @param  string  $id
     * @return void
     */
    #[DataProvider('provideRefusedIds')]
    public function testRefusesAnIdTheColumnCannotHold(string $id): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('An integrity key id must be 1 to 32 letters, digits, dots, underscores or hyphens, starting with a letter or a digit.');

        new IntegrityKey($id, self::SECRET);
    }

    /**
     * A secret of 31 bytes is refused and one of 32 bytes is accepted.
     *
     * @return void
     */
    public function testRefusesASecretShorterThan32Bytes(): void
    {
        self::assertSame(32, IntegrityKey::MIN_SECRET_BYTES);
        self::assertSame(str_repeat("\0", 32), (new IntegrityKey('a', str_repeat("\0", 32)))->secret());

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('An integrity key\'s secret must be at least 32 bytes.');

        new IntegrityKey('a', str_repeat('s', 31));
    }

    /**
     * A secret is counted in bytes, not characters: 16 two-byte characters are
     * 32 bytes and accepted.
     *
     * @return void
     */
    public function testTheSecretIsCountedInBytes(): void
    {
        $secret = str_repeat('é', 16);

        self::assertSame($secret, (new IntegrityKey('a', $secret))->secret());
    }

    /**
     * A dump of the key shows the id, never the secret; `print_r` stands for
     * every dumper that reads `__debugInfo()`.
     *
     * @return void
     */
    public function testDebugOutputNeverShowsTheSecret(): void
    {
        $key = new IntegrityKey('primary', self::SECRET);

        $printed = print_r($key, true);

        self::assertStringContainsString('primary', $printed);
        self::assertStringNotContainsString(self::SECRET, $printed);
        self::assertStringNotContainsString('secret', $printed);
        self::assertSame(['id' => 'primary'], $key->__debugInfo());
    }

    /**
     * Symfony's dumper, `json_encode` and `var_export` never show the secret;
     * the dumper reads properties, not just `__debugInfo()`.
     *
     * @return void
     */
    public function testNoDumperEncodingOrExportShowsTheSecret(): void
    {
        $key = new IntegrityKey('primary', self::SECRET);

        $outputs = [
            'the Symfony dumper' => (string) (new CliDumper)->dump((new VarCloner)->cloneVar($key), true),
            'json_encode()'      => json_encode($key, JSON_THROW_ON_ERROR),
            'var_export()'       => var_export($key, true),
        ];

        foreach ($outputs as $how => $output) {
            self::assertStringContainsString('primary', $output, $how);
            self::assertStringNotContainsString(self::SECRET, $output, $how);
            self::assertStringNotContainsString(bin2hex(self::SECRET), $output, $how);
        }

        self::assertSame('{"id":"primary"}', $outputs['json_encode()']);
        self::assertSame(self::SECRET, $key->secret());
    }

    /**
     * The secret is marked sensitive, so a stack trace through the constructor
     * never shows it.
     *
     * @return void
     */
    public function testTheSecretIsMarkedSensitive(): void
    {
        $parameters = (new \ReflectionMethod(IntegrityKey::class, '__construct'))->getParameters();

        self::assertSame('secret', $parameters[1]->getName());
        self::assertNotSame([], $parameters[1]->getAttributes(\SensitiveParameter::class));
        self::assertSame([], $parameters[0]->getAttributes(\SensitiveParameter::class));
    }
}
