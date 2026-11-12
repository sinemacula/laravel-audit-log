<?php

declare(strict_types = 1);

namespace Tests\Unit\Privacy;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Privacy\KeyTokenizer;

/**
 * Unit tests for the key tokeniser: where a key splits, where it does not, and
 * the key it can give no tokens for.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(KeyTokenizer::class)]
final class KeyTokenizerTest extends TestCase
{
    /**
     * The tokeniser is a utility container and cannot be instantiated.
     *
     * @SuppressWarnings("php:S3011")
     *
     * @return void
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(KeyTokenizer::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(KeyTokenizer::class, $instance);
    }

    /**
     * Rows of `[key, tokens]`: separators, letter-digit and camel-case
     * boundaries, ignored format characters, single tokens and none.
     *
     * @return iterable<string, array{0: string, 1: list<string>}>
     */
    public static function provideKeys(): iterable
    {
        yield from [
            'upper snake case'                                  => ['NEW_PASSWORD', ['new', 'password']],
            'camel case'                                        => ['accessToken', ['access', 'token']],
            'kebab case'                                        => ['x-api-key', ['x', 'api', 'key']],
            'a leading acronym'                                 => ['APIKey', ['api', 'key']],
            'three words'                                       => ['tokensValidAfter', ['tokens', 'valid', 'after']],
            'a short leading acronym'                           => ['IDToken', ['id', 'token']],
            'a trailing acronym'                                => ['userID', ['user', 'id']],
            'an acronym before its word'                        => ['JWTToken', ['jwt', 'token']],
            'a long acronym before its word'                    => ['HTTPCookie', ['http', 'cookie']],
            'pascal case'                                       => ['TwoFactorEnabled', ['two', 'factor', 'enabled']],
            'a dot, a space, a hyphen and an underscore'        => ['a.b c-d_e', ['a', 'b', 'c', 'd', 'e']],
            'leading and trailing separators'                   => ['__x__', ['x']],
            'a colon'                                           => ['password:new', ['password', 'new']],
            'a colon before'                                    => ['data:password', ['data', 'password']],
            'brackets'                                          => ['user[password]', ['user', 'password']],
            'a slash'                                           => ['a/b', ['a', 'b']],
            'a tab'                                             => ["a\tb", ['a', 'b']],
            'a new line'                                        => ["a\nb", ['a', 'b']],
            'a symbol'                                          => ['a$b', ['a', 'b']],
            'the replacement character'                         => ["password\u{FFFD}", ['password']],
            'a non-ASCII space'                                 => ["a\u{00A0}b", ['a', 'b']],
            'a run of mixed separators'                         => ['a_-. :[b', ['a', 'b']],
            'a word holding a token'                            => ['footprint', ['footprint']],
            'a word beginning with a token'                     => ['tokenizer', ['tokenizer']],
            'words joined with no boundary'                     => ['mypassword', ['mypassword']],
            'empty'                                             => ['', []],
            'only separators'                                   => ['_-. _', []],
            'only punctuation'                                  => [':[]/', []],
            'a single capital'                                  => ['A', ['a']],
            'all capitals'                                      => ['ABC', ['abc']],
            'two letters'                                       => ['aB', ['a', 'b']],
            'a trailing digit'                                  => ['password2', ['password', '2']],
            'a leading digit'                                   => ['2password', ['2', 'password']],
            'a digit within a word'                             => ['a2b', ['a', '2', 'b']],
            'a run of digits'                                   => ['x509cert', ['x', '509', 'cert']],
            'a digit before a capital'                          => ['oauth2Token', ['oauth', '2', 'token']],
            'a digit after an acronym'                          => ['HTTP2Token', ['http', '2', 'token']],
            'digits within an acronym'                          => ['X509Cert', ['x', '509', 'cert']],
            'a digit after an exemption'                        => ['token_id2', ['token', 'id', '2']],
            'a numeric key'                                     => ['5', ['5']],
            'a digit of another script'                         => ["password\u{0662}", ['password', "\u{0662}"]],
            'a digit after a mark'                              => ["e\u{0301}2", ["e\u{0301}", '2']],
            'a mark stays within its word'                      => ["cafe\u{0301}_au", ["cafe\u{0301}", 'au']],
            'a byte order mark'                                 => ["\u{FEFF}password", ['password']],
            'a zero-width space'                                => ["pass\u{200B}word", ['password']],
            'a zero-width joiner'                               => ["pass\u{200D}word", ['password']],
            'a soft hyphen'                                     => ["pass\u{00AD}word", ['password']],
            'a word joiner'                                     => ["pass\u{2060}word", ['password']],
            'a run of format characters'                        => ["pass\u{200B}\u{200C}\u{00AD}word", ['password']],
            'only format characters'                            => ["\u{200B}\u{FEFF}", []],
            'a format character hides no capital'               => ["foo\u{200B}Bar", ['foo', 'bar']],
            'a format character hides no digit'                 => ["password\u{200B}2", ['password', '2']],
            'an accented capital is a boundary and lower-cased' => ['motDeÉtat', ['mot', 'de', 'état']],
            'an accented acronym is lower-cased'                => ['ÉTÉ_Chaud', ['été', 'chaud']],
        ];
    }

    /**
     * Each key splits into exactly its tokens, in order and lower-cased.
     *
     * @param  string  $key
     * @param  list<string>  $tokens
     * @return void
     */
    #[DataProvider('provideKeys')]
    public function testSplitsTheKeyIntoLowerCaseTokens(string $key, array $tokens): void
    {
        self::assertSame($tokens, KeyTokenizer::tokens($key));
    }

    /**
     * A key that is not valid UTF-8 has no tokens, wherever the bad byte sits,
     * rather than a warning or a partial list.
     *
     * @return void
     */
    public function testMalformedUtf8GivesNoTokens(): void
    {
        self::assertSame([], KeyTokenizer::tokens("\xFF"));
        self::assertSame([], KeyTokenizer::tokens("password\xFF"));
        self::assertSame([], KeyTokenizer::tokens("api_\xC3_key"));
    }

    /**
     * A long key is split in full, since the regexes neither backtrack over it
     * nor stop at a limit.
     *
     * @return void
     */
    public function testALongKeyIsTokenisedInFull(): void
    {
        $tokens = KeyTokenizer::tokens(str_repeat('aB', 50000));

        self::assertCount(50001, $tokens);
        self::assertSame(['a', 'ba'], array_slice($tokens, 0, 2));
        self::assertSame(['ba', 'b'], array_slice($tokens, -2));
    }
}
