<?php

declare(strict_types = 1);

namespace Tests\Integration\Privacy;

use Illuminate\Config\Repository as ConfigRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Privacy\IdentifierHasher;
use SineMacula\Laravel\AuditLog\Privacy\RecordMinimiser;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\TestCase;

/**
 * Integration tests for correlating sign-in activity across stored rows, on the
 * engine the suite runs against: one identifier has one hash however it was
 * typed, a change of key is visible in its fingerprint, and the hash is kept
 * unless the configuration says otherwise, whatever a definition does with the
 * record's other fields. Each row is read back and searched in PHP, as a reader
 * on any engine could, and verifies.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IdentifierHasher::class)]
#[CoversClass(RecordMinimiser::class)]
final class IdentifierCorrelationTest extends TestCase
{
    use InteractsWithAuditStore;

    /** @var string The code of a failed sign-in. */
    private const string FAILED = 'app.sign_in_failed';

    /** @var string The code of the lockout that follows. */
    private const string LOCKED_OUT = 'app.locked_out';

    /** @var string The identifier the tests sign in with. */
    private const string IDENTIFIER = 'alice@example.com';

    /**
     * Five failures and the lockout they lead to carry one hash, so the six
     * rows are found to be one attempt from their JSON alone.
     *
     * @return void
     */
    public function testFiveFailuresThenALockoutShareOneHash(): void
    {
        foreach (range(1, 5) as $ignored) {
            self::failedSignIn(self::IDENTIFIER)->record();
        }

        AuditLog::event(self::LOCKED_OUT)->withIdentifier(self::IDENTIFIER)->failed('too_many_attempts')->immediately()->record();

        $byEvent = [];
        $hashes  = [];

        foreach ($this->storageConnection()->table(EntrySettings::table())->get() as $row) {

            $stored = (new RowCodec)->decode((array) $row);

            self::assertTrue(app(RecordSigner::class)->verifies($stored));

            $event = $stored['event'];

            self::assertIsString($event);

            $byEvent[$event] = ($byEvent[$event] ?? 0) + 1;
            $hashes[]        = self::hashIn($stored);
        }

        self::assertSame([self::FAILED => 5, self::LOCKED_OUT => 1], $byEvent);
        self::assertCount(6, $hashes);
        self::assertSame([app(IdentifierHasher::class)->identifier(self::IDENTIFIER)], array_values(array_unique($hashes)));
    }

    /**
     * What a form may post of one email address, in any case and with any
     * padding, shares one hash.
     *
     * @return void
     */
    public function testDifferentCaseAndPaddingShareOneHash(): void
    {
        $hashes = array_map(fn (string $identifier): ?string => $this->storedHashOf($identifier), [
            self::IDENTIFIER,
            'Alice@Example.COM',
            '  alice@example.com  ',
            "ALICE@EXAMPLE.COM\n",
            "\talice@example.com",
        ]);

        self::assertNotNull($hashes[0]);
        self::assertSame([$hashes[0]], array_values(array_unique($hashes)));
    }

    /**
     * Two identifiers have two hashes, and an identifier that is not an email
     * address keeps its case, because a username's case can matter.
     *
     * @return void
     */
    public function testDifferentIdentifiersKeepDifferentHashes(): void
    {
        self::assertNotSame($this->storedHashOf(self::IDENTIFIER), $this->storedHashOf('bob@example.com'));
        self::assertNotSame($this->storedHashOf('Bob'), $this->storedHashOf('bob'));
    }

    /**
     * The same key gives the same hash, and a changed key changes the
     * fingerprint as well as the HMAC, so what no longer correlates says so.
     * Both rows still verify, since verifying uses another key.
     *
     * @return void
     */
    public function testAChangedKeyChangesTheFingerprint(): void
    {
        self::config()->set('audit-log.redaction.key', str_repeat('a', 32));

        $first = (string) $this->storedHashOf(self::IDENTIFIER);

        self::assertSame($first, $this->storedHashOf(self::IDENTIFIER));

        self::config()->set('audit-log.redaction.key', str_repeat('b', 32));

        $changed = $this->storedHashOf(self::IDENTIFIER);

        self::assertNotSame(substr($first, 0, 16), substr($changed, 0, 16));
        self::assertNotSame(substr($first, 17), substr($changed, 17));
        self::assertMatchesRegularExpression('/\A[0-9a-f]{16}:[0-9a-f]{64}\z/', $changed);
    }

    /**
     * With no key configured the hash derives from the application's, under the
     * identifier's own info: fingerprint, colon, HMAC, each worked out here by
     * hand so nothing of the hasher is taken on trust.
     *
     * @return void
     */
    public function testTheHashDerivesFromTheApplicationKeyWithNoKeyConfigured(): void
    {
        $key = hash_hkdf('sha256', 'laravel-audit-log test key!!!!!!', 32, 'sinemacula/audit-log:identifier:v1');

        $expected = substr(hash_hmac('sha256', 'audit-log:fingerprint', $key), 0, 16) . ':' . hash_hmac('sha256', self::IDENTIFIER, $key);

        self::assertSame($expected, $this->storedHashOf(self::IDENTIFIER));
    }

    /**
     * In `drop` mode no row holds a hash, and because that is configuration and
     * not a loss, none holds a diagnostic either.
     *
     * @return void
     */
    public function testDropModeStoresNoHash(): void
    {
        self::config()->set('audit-log.redaction.identifiers', 'drop');

        $stored = $this->storedAndVerified(self::failedSignIn(self::IDENTIFIER)->record());

        self::assertNull($stored['properties']);

        $kept = $this->storedAndVerified(self::failedSignIn(self::IDENTIFIER)->withProperties(['attempt' => 2])->record());

        self::assertSame('{"attempt":2}', CanonicalEncoder::encode($kept['properties']));
    }

    /**
     * A definition whose unlisted fields are dropped loses the fields, counted,
     * and never the hash, which is not among them.
     *
     * @return void
     */
    public function testAnUnlistedDropDefinitionKeepsTheHash(): void
    {
        $recorder = new Recorder(new EventCatalogue, new ContributorRegistry);

        $recorder->define(EventDefinition::for(self::FAILED));

        AuditLog::swap($recorder);

        $stored = $this->storedAndVerified(self::failedSignIn(self::IDENTIFIER)->withProperties(['attempt' => 2])->record());
        $hash   = app(IdentifierHasher::class)->identifier(self::IDENTIFIER);

        self::assertSame('{"_audit":{"identifier_hash":"' . $hash . '","omitted":{"count":1,"paths":["*"]}}}', CanonicalEncoder::encode($stored['properties']));
    }

    /**
     * A blank identifier, which a form can post, stores no hash and no
     * diagnostic, so it never correlates with another blank.
     *
     * @return void
     */
    public function testABlankIdentifierStoresNoHash(): void
    {
        foreach (['', '   ', "\t\n"] as $blank) {
            self::assertNull($this->storedHashOf($blank));
        }
    }

    /**
     * The identifier is stored in no column of the row, in any case.
     *
     * @return void
     */
    public function testTheIdentifierIsStoredInNoColumn(): void
    {
        $record = self::failedSignIn('Alice@Example.COM')->record();

        $row = $this->storageConnection()->table(EntrySettings::table())->where('id', $record->id)->first();

        self::assertStringNotContainsString(self::IDENTIFIER, strtolower((string) json_encode((array) $row, JSON_UNESCAPED_SLASHES)));
    }

    /**
     * The hash stored for a failed sign-in under the identifier, once the row
     * has verified.
     *
     * @param  string  $identifier
     * @return ?string
     */
    private function storedHashOf(string $identifier): ?string
    {
        return self::hashIn($this->storedAndVerified(self::failedSignIn($identifier)->record()));
    }

    /**
     * A builder of a failed sign-in with the identifier, written at once.
     *
     * @param  string  $identifier
     * @return \SineMacula\Laravel\AuditLog\Records\PendingRecord
     */
    private static function failedSignIn(string $identifier): PendingRecord
    {
        return AuditLog::event(self::FAILED)->withIdentifier($identifier)->failed('invalid_credentials')->immediately();
    }

    /**
     * Read back the row of a captured record and assert it verifies; the
     * decoded row.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @return array<string, mixed>
     */
    private function storedAndVerified(AuditRecord $record): array
    {
        $stored = $this->storedRow($record->id);

        self::assertTrue(app(RecordSigner::class)->verifies($stored));

        return $stored;
    }

    /**
     * The identifier hash a decoded row holds, read from its JSON in PHP.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $stored
     * @return ?string
     */
    private static function hashIn(array $stored): ?string
    {
        $properties = json_decode((string) json_encode($stored['properties']), true);
        $hash       = is_array($properties) ? ($properties['_audit']['identifier_hash'] ?? null) : null;

        return is_string($hash) ? $hash : null;
    }

    /**
     * The application's configuration.
     *
     * @return \Illuminate\Config\Repository
     */
    private static function config(): ConfigRepository
    {
        return app(ConfigRepository::class);
    }
}
