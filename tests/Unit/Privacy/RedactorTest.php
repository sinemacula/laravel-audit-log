<?php

declare(strict_types = 1);

namespace Tests\Unit\Privacy;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Privacy\KeyCeiling;
use SineMacula\Laravel\AuditLog\Privacy\RedactionSettings;
use SineMacula\Laravel\AuditLog\Privacy\Redactor;

/**
 * Unit tests for the one key matcher: every key it must redact and every key it
 * must keep, the order of its steps, the units a configuration adds, and what
 * becomes of a matching key's value at any depth.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Redactor::class)]
final class RedactorTest extends TestCase
{
    /** @var string The value planted under every key that must not keep it. */
    private const string PLANTED = 's3cr3t';

    /** @var string The refusal of a malformed list of configured units. */
    private const string MALFORMED_KEYS = '`audit-log.redaction.keys` must be a list of key names, each of at least one token.';

    /**
     * Rows of `[key, sensitive?]`: the table of `docs/design/redaction.md`,
     * every key on it, then keys that pin each step of the matcher against its
     * neighbours.
     *
     * @return iterable<string, array{0: string, 1: bool}>
     */
    public static function provideKeys(): iterable
    {
        yield from [
            'password_confirmation'     => ['password_confirmation', true],
            'id_token'                  => ['id_token', true],
            'csrf_token'                => ['csrf_token', true],
            'session_token'             => ['session_token', true],
            'client_secret'             => ['client_secret', true],
            'authorization_code'        => ['authorization_code', true],
            'password_reset_request'    => ['password_reset_request', true],
            'tokens'                    => ['tokens', true],
            'cookie_request'            => ['cookie_request', true],
            'NEW_PASSWORD'              => ['NEW_PASSWORD', true],
            'accessToken'               => ['accessToken', true],
            'x-api-key'                 => ['x-api-key', true],
            'APIKey'                    => ['APIKey', true],
            'token_value'               => ['token_value', true],
            'secret_key'                => ['secret_key', true],
            'x_api_key_type'            => ['x_api_key_type', true],
            'remember_token'            => ['remember_token', true],
            'two_factor_secret'         => ['two_factor_secret', true],
            'two_factor_recovery_codes' => ['two_factor_recovery_codes', true],
            'api_keys'                  => ['api_keys', true],
            'card_number'               => ['card_number', true],
            'private_key'               => ['private_key', true],
            'Authorization'             => ['Authorization', true],
            'HTTPCookie'                => ['HTTPCookie', true],
            'oauth2Token'               => ['oauth2Token', true],
            'api_key'                   => ['api_key', true],
            'Set-Cookie'                => ['Set-Cookie', true],
            'token_expires_at'          => ['token_expires_at', false],
            'access_token_id'           => ['access_token_id', false],
            'secret_id'                 => ['secret_id', false],
            'api_key_type'              => ['api_key_type', false],
            'cookie_consent'            => ['cookie_consent', false],
            'bearer_method'             => ['bearer_method', false],
            'tokens_valid_after'        => ['tokens_valid_after', false],
            'tokensValidAfter'          => ['tokensValidAfter', false],
            'authorization_request'     => ['authorization_request', false],
            'remember'                  => ['remember', false],
            'api_key_id'                => ['api_key_id', false],
            'footprint'                 => ['footprint', false],
            'tokenizer'                 => ['tokenizer', false],
            'password_changed_at'       => ['password_changed_at', false],
            'token_type'                => ['token_type', false],
            'two_factor_enabled'        => ['two_factor_enabled', false],
            'two_factor_required'       => ['two_factor_required', false],
            'two_factor_method'         => ['two_factor_method', false],
            'two_factor_type'           => ['two_factor_type', false],
            'token_ids'                 => ['token_ids', false],
            'session_id'                => ['session_id', false],
            'api'                       => ['api', false],
            'key'                       => ['key', false],
            'two'                       => ['two', false],
            'factor'                    => ['factor', false],
            'credential_id'             => ['credential_id', false],
            'credential_type'           => ['credential_type', false],
            'credential_kind'           => ['credential_kind', false],
            'credentialType'            => ['credentialType', false],
            'password2'                 => ['password2', true],
            'password:new'              => ['password:new', true],
            'user[password]'            => ['user[password]', true],
            'data:password'             => ['data:password', true],
            'tokens2'                   => ['tokens2', true],
            'token_id2'                 => ['token_id2', true],
            'HTTP2Token'                => ['HTTP2Token', true],
            'mypassword'                => ['mypassword', false],
            'passwordless'              => ['passwordless', false],

            // A hostile spelling of a key hides nothing
            'a repaired byte'      => ["password\u{FFFD}", true],
            'a byte order mark'    => ["\u{FEFF}password", true],
            'a zero-width space'   => ["pass\u{200B}word", true],
            'a zero-width joiner'  => ["pass\u{200D}word", true],
            'a soft hyphen'        => ["pass\u{00AD}word", true],
            'a repaired byte cuts' => ["pass\u{FFFD}word", true],

            // Each unit added for its joined and abbreviated spellings
            'passwd'             => ['passwd', true],
            'passwds'            => ['passwds', true],
            'passcode'           => ['passcode', true],
            'passcodes'          => ['passcodes', true],
            'pass_word'          => ['pass_word', true],
            'pass_words'         => ['pass_words', true],
            'passWord'           => ['passWord', true],
            'pass_phrase'        => ['pass_phrase', true],
            'pass_phrases'       => ['pass_phrases', true],
            'auth_pw'            => ['auth_pw', true],
            'auth_pws'           => ['auth_pws', true],
            'totp'               => ['totp', true],
            'totps'              => ['totps', true],
            'hotp'               => ['hotp', true],
            'hotps'              => ['hotps', true],
            'pin'                => ['pin', true],
            'pins'               => ['pins', true],
            'pin_code'           => ['pin_code', true],
            'credential'         => ['credential', true],
            'credentials'        => ['credentials', true],
            'apikey'             => ['apikey', true],
            'apikeys'            => ['apikeys', true],
            'privatekey'         => ['privatekey', true],
            'privatekeys'        => ['privatekeys', true],
            'secretkey'          => ['secretkey', true],
            'secretkeys'         => ['secretkeys', true],
            'accesstoken'        => ['accesstoken', true],
            'accesstokens'       => ['accesstokens', true],
            'authtoken'          => ['authtoken', true],
            'authtokens'         => ['authtokens', true],
            'refreshtoken'       => ['refreshtoken', true],
            'refreshtokens'      => ['refreshtokens', true],
            'clientsecret'       => ['clientsecret', true],
            'clientsecrets'      => ['clientsecrets', true],
            'twofactor'          => ['twofactor', true],
            'twofactors'         => ['twofactors', true],
            'recoverycode'       => ['recoverycode', true],
            'recoverycodes'      => ['recoverycodes', true],
            'cardnumber'         => ['cardnumber', true],
            'cardnumbers'        => ['cardnumbers', true],
            'security_code'      => ['security_code', true],
            'security_codes'     => ['security_codes', true],
            'securityCode'       => ['securityCode', true],
            'a pin has its id'   => ['pin_id', false],
            'pass alone'         => ['pass', false],
            'word alone'         => ['word', false],
            'phrase alone'       => ['phrase', false],
            'auth alone'         => ['auth', false],
            'pw alone'           => ['pw', false],
            'security alone'     => ['security', false],
            'code alone'         => ['code', false],
            'a word holding pin' => ['pinned', false],
            'another credential' => ['credential_name', true],

            // An exempt token first or in the middle exempts nothing
            'an id token before a unit' => ['id_password', true],
            'an at token before a unit' => ['at_token', true],
            'an id token between units' => ['token_id_value', true],

            // The final token decides, however it is spelt
            'an upper case exemption' => ['TOKEN_ID', false],
            'a camel case exemption'  => ['tokenIds', false],
            'an acronym exemption'    => ['tokenID', false],
            'a kebab case exemption'  => ['token-at', false],
            'a dotted exemption'      => ['token.ids', false],
            'a split plural acronym'  => ['tokenIDs', true],

            // A unit is found at each place in a key
            'a unit first'                   => ['password_hint', true],
            'a unit in the middle'           => ['old_password_hint', true],
            'a unit last'                    => ['old_password', true],
            'a sequence first'               => ['api_key_value', true],
            'a sequence last'                => ['old_api_key', true],
            'a sequence after a false start' => ['api_api_key', true],

            // Nothing is matched within a token
            'a unit within a word'  => ['tokenised', false],
            'a word holding a unit' => ['footprints', false],
            'nothing sensitive'     => ['email', false],
            'no tokens'             => ['', false],
            'only separators'       => ['_-. _', false],
            'not valid UTF-8'       => ["password\xFF", false],
        ];
    }

    /**
     * The matcher judges each key as the table says.
     *
     * @param  string  $key
     * @param  bool  $sensitive
     * @return void
     */
    #[DataProvider('provideKeys')]
    public function testTheMatcherTable(string $key, bool $sensitive): void
    {
        self::assertSame($sensitive, self::redactor()->isSensitive($key), $key);

        $expected = $sensitive ? Redactor::MARKER : self::PLANTED;

        self::assertSame([$key => $expected, 'other' => 'kept'], self::redactor()->redact([$key => self::PLANTED, 'other' => 'kept']), $key);
    }

    /**
     * The tables are pinned whole and in order, so a removed or an added entry
     * fails here and not only where a row happens to name it.
     *
     * @return void
     */
    public function testTheTablesArePinned(): void
    {
        self::assertSame('[REDACTED]', Redactor::MARKER);
        self::assertSame(['id', 'ids', 'at'], Redactor::EXEMPT_FINAL_TOKENS);
        self::assertSame([
            'authorization_request',
            'tokens_valid_after',
            'cookie_consent',
            'token_type',
            'api_key_type',
            'bearer_method',
            'two_factor_enabled',
            'two_factor_required',
            'two_factor_method',
            'two_factor_type',
            'credential_type',
            'credential_kind',
        ], array_map(self::joined(...), Redactor::SURVIVORS));
        self::assertSame([
            'password', 'passwords', 'passwd', 'passwds', 'passcode', 'passcodes', 'passphrase', 'passphrases',
            'pwd', 'pwds', 'secret', 'secrets', 'token', 'tokens', 'otp', 'otps', 'totp', 'totps', 'hotp', 'hotps',
            'pin', 'pins', 'credential', 'credentials', 'authorization', 'authorizations', 'cookie', 'cookies',
            'bearer', 'bearers', 'jwt', 'jwts', 'cvv', 'cvvs', 'cvc', 'cvcs',
            'apikey', 'apikeys', 'privatekey', 'privatekeys', 'secretkey', 'secretkeys', 'accesstoken', 'accesstokens',
            'authtoken', 'authtokens', 'refreshtoken', 'refreshtokens', 'clientsecret', 'clientsecrets',
            'twofactor', 'twofactors', 'recoverycode', 'recoverycodes', 'cardnumber', 'cardnumbers',
            'pass_word', 'pass_words', 'pass_phrase', 'pass_phrases', 'auth_pw', 'auth_pws', 'security_code', 'security_codes',
            'api_key', 'api_keys', 'private_key', 'private_keys', 'remember_token', 'remember_tokens',
            'two_factor', 'two_factors', 'recovery_code', 'recovery_codes', 'card_number', 'card_numbers',
        ], array_map(self::joined(...), Redactor::SENSITIVE_UNITS));
    }

    /**
     * Rows of `[key]`: every built-in unit, joined by an underscore.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideBuiltInUnits(): iterable
    {
        foreach (Redactor::SENSITIVE_UNITS as $unit) {
            yield self::joined($unit) => [self::joined($unit)];
        }
    }

    /**
     * Every built-in unit redacts on its own and within a longer key.
     *
     * @param  string  $key
     * @return void
     */
    #[DataProvider('provideBuiltInUnits')]
    public function testEveryBuiltInUnitRedacts(string $key): void
    {
        self::assertTrue(self::redactor()->isSensitive($key));
        self::assertTrue(self::redactor()->isSensitive('x_' . $key . '_y'));
        self::assertSame([$key => Redactor::MARKER], self::redactor()->redact([$key => self::PLANTED]));
    }

    /**
     * Rows of `[snake case, camel case]`: every survivor in both spellings.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideSurvivors(): iterable
    {
        foreach (Redactor::SURVIVORS as $survivor) {
            yield self::joined($survivor) => [self::joined($survivor), lcfirst(implode('', array_map(ucfirst(...), $survivor)))];
        }
    }

    /**
     * A survivor is compared on its tokens, so each spelling of it is kept.
     *
     * @param  string  $snakeCase
     * @param  string  $camelCase
     * @return void
     */
    #[DataProvider('provideSurvivors')]
    public function testEverySurvivorSurvivesInSnakeAndCamelCase(string $snakeCase, string $camelCase): void
    {
        self::assertFalse(self::redactor()->isSensitive($snakeCase));
        self::assertFalse(self::redactor()->isSensitive($camelCase));
    }

    /**
     * Rows of `[key]`: survivors with another token before or after them.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideNearSurvivors(): iterable
    {
        yield from [
            'a token before' => ['x_token_type'],
            'a token after'  => ['token_type_value'],
            'cut short'      => ['two_factor'],
        ];
    }

    /**
     * A survivor must be the whole key: another token around it redacts.
     *
     * @param  string  $key
     * @return void
     */
    #[DataProvider('provideNearSurvivors')]
    public function testASurvivorWithAnotherTokenIsNotExact(string $key): void
    {
        self::assertTrue(self::redactor()->isSensitive($key));
    }

    /**
     * Rows of `[key]`: a sequence's tokens apart, reversed or cut short.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideNonAdjacentSequences(): iterable
    {
        yield from [
            'a token between' => ['api_public_key'],
            'reversed'        => ['key_api'],
            'cut short'       => ['private'],
        ];
    }

    /**
     * A sequence matches only as adjacent tokens, in order.
     *
     * @param  string  $key
     * @return void
     */
    #[DataProvider('provideNonAdjacentSequences')]
    public function testASequenceMustBeAdjacent(string $key): void
    {
        self::assertFalse(self::redactor()->isSensitive($key));
    }

    /**
     * A configured unit redacts as a built-in does.
     *
     * @return void
     */
    public function testAConfiguredUnitIsAddedToTheBuiltIns(): void
    {
        $redactor = self::redactor(['ssn']);

        self::assertTrue($redactor->isSensitive('ssn'));
        self::assertTrue($redactor->isSensitive('customer_ssn'));
        self::assertFalse(self::redactor()->isSensitive('customer_ssn'));
        self::assertSame(['ssn' => Redactor::MARKER, 'email' => 'kept'], $redactor->redact(['ssn' => self::PLANTED, 'email' => 'kept']));
    }

    /**
     * A configuration merges with the built-ins and removes none of them.
     *
     * @return void
     */
    public function testConfiguringUnitsRemovesNoBuiltIn(): void
    {
        $redactor = self::redactor(['ssn']);

        foreach (Redactor::SENSITIVE_UNITS as $unit) {
            self::assertTrue($redactor->isSensitive(self::joined($unit)), self::joined($unit));
        }
    }

    /**
     * A configured unit is tokenised as a key is, so its spelling does not
     * matter and a multi-token unit must occur as adjacent tokens.
     *
     * @return void
     */
    public function testAConfiguredUnitIsTokenisedTheSameWay(): void
    {
        $redactor = self::redactor(['ssnNumber']);

        self::assertTrue($redactor->isSensitive('ssn_number'));
        self::assertTrue($redactor->isSensitive('SSN-NUMBER'));
        self::assertTrue($redactor->isSensitive('customer.ssn.number'));
        self::assertFalse($redactor->isSensitive('ssn'));
        self::assertFalse($redactor->isSensitive('ssn_other_number'));
    }

    /**
     * Configuration adds units only, so a configured unit passes through the
     * survivors and the exemption, and configuring `token_id` has no effect.
     *
     * @return void
     */
    public function testAConfiguredUnitPassesThroughTheExemptions(): void
    {
        self::assertFalse(self::redactor(['ssn'])->isSensitive('ssn_id'));
        self::assertFalse(self::redactor(['token_id'])->isSensitive('token_id'));
        self::assertFalse(self::redactor(['token_type'])->isSensitive('token_type'));
    }

    /**
     * Two configured units beginning alike, or beginning like a built-in, are
     * each still found: neither shadows the other in the index.
     *
     * @return void
     */
    public function testUnitsSharingAFirstTokenAreEachFound(): void
    {
        $redactor = self::redactor(['card_holder', 'card_expiry']);

        self::assertTrue($redactor->isSensitive('card_holder'));
        self::assertTrue($redactor->isSensitive('card_expiry'));
        self::assertTrue($redactor->isSensitive('card_number'));
        self::assertFalse($redactor->isSensitive('card_brand'));
    }

    /**
     * The configured units are read on every call, never kept.
     *
     * @return void
     */
    public function testTheConfiguredUnitsAreReadOnEveryCall(): void
    {
        $config   = new Repository(['audit-log' => ['redaction' => ['keys' => []]]]);
        $redactor = new Redactor(new RedactionSettings($config));

        self::assertFalse($redactor->isSensitive('ssn'));

        $config->set('audit-log.redaction.keys', ['ssn']);

        self::assertTrue($redactor->isSensitive('ssn'));
        self::assertSame(['ssn' => Redactor::MARKER], $redactor->redact(['ssn' => self::PLANTED]));
    }

    /**
     * Rows of `[values]`: an empty record, one with no matching key and one
     * with a matching key, all of which read the configured list first.
     *
     * @return iterable<string, array{0: array<string, string>}>
     */
    public static function provideRecords(): iterable
    {
        yield from [
            'empty'           => [[]],
            'no matching key' => [['email' => 'kept']],
            'a matching key'  => [['password' => self::PLANTED]],
        ];
    }

    /**
     * A malformed configured list fails the call, whatever the record holds.
     *
     * @param  array<string, string>  $values
     * @return void
     */
    #[DataProvider('provideRecords')]
    public function testAMalformedConfiguredListFailsTheCall(array $values): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::MALFORMED_KEYS);

        self::malformedRedactor()->redact($values);
    }

    /**
     * Asking about one key reads the configured list too, so it fails alike.
     *
     * @return void
     */
    public function testAMalformedConfiguredListFailsAQuestionAboutAKey(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::MALFORMED_KEYS);

        self::malformedRedactor()->isSensitive('password');
    }

    /**
     * Rows of `[value]`: every type a matching key's value can have.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideWholeValues(): iterable
    {
        yield from [
            'a string'     => ['abc'],
            'an integer'   => [42],
            'a boolean'    => [false],
            'null'         => [null],
            'an empty map' => [[]],
            'a map'        => [['inner' => 'abc', 'deep' => ['x' => 'y']]],
            'a list'       => [['abc', 'def']],
        ];
    }

    /**
     * A matching key's whole value becomes the one marker string.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('provideWholeValues')]
    public function testAMatchingKeysWholeValueBecomesTheMarker(mixed $value): void
    {
        self::assertSame(['password' => Redactor::MARKER], self::redactor()->redact(['password' => $value]));
    }

    /**
     * A list of secret strings under `tokens` is redacted as one value, since
     * no key inside it could have matched.
     *
     * @return void
     */
    public function testTokensHoldingAListOfSecretStringsIsRedacted(): void
    {
        self::assertSame(['tokens' => Redactor::MARKER], self::redactor()->redact(['tokens' => [self::PLANTED, self::PLANTED]]));
    }

    /**
     * Matching reaches the maps inside a list, and lists inside those.
     *
     * @return void
     */
    public function testMatchesInsideAListOfMaps(): void
    {
        $values = [
            'users' => [
                ['name' => 'a', 'password' => self::PLANTED],
                ['name' => 'b', 'nested' => [['accessToken' => self::PLANTED, 'name' => 'c']]],
            ],
        ];

        self::assertSame([
            'users' => [
                ['name' => 'a', 'password' => Redactor::MARKER],
                ['name' => 'b', 'nested' => [['accessToken' => Redactor::MARKER, 'name' => 'c']]],
            ],
        ], self::redactor()->redact($values));
    }

    /**
     * Matching reaches a key five levels down.
     *
     * @return void
     */
    public function testMatchesAtDepthFive(): void
    {
        $values = ['a' => ['b' => ['c' => ['d' => ['password' => self::PLANTED, 'e' => 'kept']]]]];

        self::assertSame(
            ['a' => ['b' => ['c' => ['d' => ['password' => Redactor::MARKER, 'e' => 'kept']]]]],
            self::redactor()->redact($values),
        );
    }

    /**
     * An exempt key's map is still walked, so a secret key inside it redacts.
     *
     * @return void
     */
    public function testAnExemptKeysMapIsStillWalked(): void
    {
        self::assertSame(
            ['token_id' => ['password' => Redactor::MARKER, 'name' => 'kept']],
            self::redactor()->redact(['token_id' => ['password' => self::PLANTED, 'name' => 'kept']]),
        );
    }

    /**
     * An exempt key's scalars are kept, within a list too: that is the limit of
     * the heuristic, and an explicit rule is the remedy.
     *
     * @return void
     */
    public function testAnExemptKeysScalarsAreKept(): void
    {
        self::assertSame(['tokens_valid_after' => ['abc']], self::redactor()->redact(['tokens_valid_after' => ['abc']]));
        self::assertSame(['token_id' => 'abc'], self::redactor()->redact(['token_id' => 'abc']));
    }

    /**
     * A list's index is not a key, even when a configured unit spells it, so
     * its elements are kept and walked.
     *
     * @return void
     */
    public function testAListIndexIsNeverAKey(): void
    {
        $redactor = self::redactor(['0', '1']);

        self::assertSame(['a', 'b'], $redactor->redact(['a', 'b']));
        self::assertSame([['password' => Redactor::MARKER]], $redactor->redact([['password' => self::PLANTED]]));
        self::assertSame(['items' => ['a', 'b']], $redactor->redact(['items' => ['a', 'b']]));
    }

    /**
     * A map's integer key is tested as a string, which is what PHP makes of a
     * numeric key: an array with a gap is a map, so its keys are judged.
     *
     * @return void
     */
    public function testAMapsIntegerKeyIsTestedAsAString(): void
    {
        $redactor = self::redactor(['5']);

        self::assertSame([5 => Redactor::MARKER, 6 => 'kept'], $redactor->redact([5 => self::PLANTED, 6 => 'kept']));
        self::assertSame([1 => 'kept', 0 => ['password' => Redactor::MARKER]], self::redactor()->redact([1 => 'kept', 0 => ['password' => self::PLANTED]]));
    }

    /**
     * A map's order and every value that does not match are kept exactly, of
     * every type, so nothing but the marker changes.
     *
     * @return void
     */
    public function testKeepsOrderAndUnmatchedValues(): void
    {
        $values = ['z' => 'last', 'password' => self::PLANTED, 'a' => 1, 'flag' => true, 'none' => null, 'empty' => [], 'list' => ['x', 2]];

        self::assertSame(
            ['z' => 'last', 'password' => Redactor::MARKER, 'a' => 1, 'flag' => true, 'none' => null, 'empty' => [], 'list' => ['x', 2]],
            self::redactor()->redact($values),
        );
    }

    /**
     * An empty record stays empty.
     *
     * @return void
     */
    public function testAnEmptyRecordStaysEmpty(): void
    {
        self::assertSame([], self::redactor()->redact([]));
    }

    /**
     * The same key in every element of a long list is judged alike each time,
     * both ways, once a decision is held for it: a decision to keep is not
     * mistaken for no decision yet.
     *
     * @return void
     */
    public function testARepeatedKeyIsJudgedAlikeThroughALongList(): void
    {
        $elements = array_fill(0, 10000, ['password' => self::PLANTED, 'email' => 'kept']);

        $redacted = self::redactor()->redact($elements);

        self::assertCount(10000, $redacted);
        self::assertSame(array_fill(0, 10000, ['password' => Redactor::MARKER, 'email' => 'kept']), $redacted);
    }

    /**
     * A key of very many tokens is still judged, and a unit at its very end is
     * found after every false start before it.
     *
     * @return void
     */
    public function testAKeyOfManyTokensIsStillJudged(): void
    {
        $tokens = str_repeat('api_', 250);

        self::assertTrue(self::redactor()->isSensitive($tokens . 'key'));
        self::assertFalse(self::redactor()->isSensitive($tokens . 'other'));
    }

    /**
     * A key at the ceiling is still judged on its tokens, and one byte more is
     * sensitive whatever its tokens would say.
     *
     * @return void
     */
    public function testAKeyPastTheCeilingIsSensitive(): void
    {
        self::assertFalse(self::redactor()->isSensitive(str_repeat('k', KeyCeiling::MAX_BYTES)));
        self::assertTrue(self::redactor()->isSensitive(str_repeat('k', KeyCeiling::MAX_BYTES + 1)));
        self::assertSame([str_repeat('k', KeyCeiling::MAX_BYTES + 1) => Redactor::MARKER], self::redactor()->redact([str_repeat('k', KeyCeiling::MAX_BYTES + 1) => self::PLANTED]));
    }

    /**
     * A key past the ceiling is never split, so one of 8 MiB costs next to
     * nothing where its tokens would cost hundreds of megabytes.
     *
     * @return void
     */
    public function testAKeyPastTheCeilingIsNeverSplit(): void
    {
        $key      = str_repeat('aB', 4194304);
        $redactor = self::redactor();

        memory_reset_peak_usage();

        $before = memory_get_usage();

        self::assertTrue($redactor->isSensitive($key));
        self::assertLessThan(1048576, memory_get_peak_usage() - $before);
    }

    /**
     * A decision once held for a key is what every later occurrence takes, so
     * the key is split once however often it repeats: a held decision to keep
     * is not asked again, and neither is a held decision to redact. Protects
     * against a mutation that decides each occurrence afresh, which gives the
     * same output and costs a pass over the key every time.
     *
     * @SuppressWarnings("php:S3011")
     *
     * @return void
     */
    public function testADecisionHeldForAKeyIsNotMadeAgain(): void
    {
        $walk = new \ReflectionMethod(Redactor::class, 'walk');

        /** @var array<string, bool> $decisions */
        $decisions = ['password' => false, 'plain' => true];

        $walked = $walk->invokeArgs(null, [['password' => self::PLANTED, 'plain' => 'value', 'new' => ['password' => self::PLANTED]], [], &$decisions]);

        self::assertSame(['password' => self::PLANTED, 'plain' => Redactor::MARKER, 'new' => ['password' => self::PLANTED]], $walked);
        self::assertSame(['password' => false, 'plain' => true, 'new' => false], $decisions);
    }

    /**
     * The raw values are marked sensitive through every method they pass, so no
     * frame of a stack trace holds them when the configured list is malformed.
     *
     * @return void
     *
     * @throws \ReflectionException
     */
    public function testTheValuesParameterIsSensitive(): void
    {
        foreach (['redact', 'walk'] as $method) {
            self::assertCount(1, (new \ReflectionParameter([Redactor::class, $method], 'values'))->getAttributes(\SensitiveParameter::class), $method);
        }

        self::assertCount(1, (new \ReflectionParameter([Redactor::class, 'isSensitive'], 'key'))->getAttributes(\SensitiveParameter::class));

        $ignored = ini_set('zend.exception_ignore_args', '0');

        try {
            self::malformedRedactor()->redact(['password' => self::PLANTED]);
            self::fail('Expected the configured list to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertStringNotContainsString(self::PLANTED, print_r($exception->getTrace(), true));

            $frames = array_values(array_filter($exception->getTrace(), static fn (array $frame): bool => $frame['function'] === 'redact'));

            self::assertCount(1, $frames);
            self::assertInstanceOf(\SensitiveParameterValue::class, ($frames[0]['args'] ?? [])[0] ?? null);
        } finally {
            ini_set('zend.exception_ignore_args', (string) $ignored);
        }
    }

    /**
     * A redactor with the configured units.
     *
     * @param  list<string>  $keys
     * @return \SineMacula\Laravel\AuditLog\Privacy\Redactor
     */
    private static function redactor(array $keys = []): Redactor
    {
        return new Redactor(new RedactionSettings(new Repository(['audit-log' => ['redaction' => ['keys' => $keys]]])));
    }

    /**
     * A redactor whose configured list is malformed.
     *
     * @return \SineMacula\Laravel\AuditLog\Privacy\Redactor
     */
    private static function malformedRedactor(): Redactor
    {
        return new Redactor(new RedactionSettings(new Repository(['audit-log' => ['redaction' => ['keys' => 'password']]])));
    }

    /**
     * The tokens joined as a snake-case key.
     *
     * @param  list<string>  $tokens
     * @return string
     */
    private static function joined(array $tokens): string
    {
        return implode('_', $tokens);
    }
}
