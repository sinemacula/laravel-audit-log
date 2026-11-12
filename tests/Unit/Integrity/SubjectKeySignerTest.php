<?php

declare(strict_types = 1);

namespace Tests\Unit\Integrity;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Integrity\IntegritySettings;
use SineMacula\Laravel\AuditLog\Integrity\JournalSigner;
use SineMacula\Laravel\AuditLog\Integrity\KeyRing;
use SineMacula\Laravel\AuditLog\Integrity\OwnerFingerprint;
use SineMacula\Laravel\AuditLog\Integrity\SealSigner;
use SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow;
use SineMacula\Laravel\AuditLog\Integrity\SubjectKeySigner;
use SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * Unit tests for the key row signer.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SubjectKeySigner::class)]
final class SubjectKeySignerTest extends TestCase
{
    /** @var string The golden key row vector. */
    private const string GOLDEN = __DIR__ . '/../../Fixtures/Integrity/subject-key-v1.json';

    /** @var string The golden secret, the ring key `k2026`. */
    private const string SECRET = 'audit-log golden key 0123456789!';

    /** @var string A retired key's secret, the ring key `k2025`. */
    private const string RETIRED_SECRET = 'audit-log retired key 0123456789';

    /**
     * The key row key is HKDF-SHA256 of the secret under its pinned info with
     * an empty salt, unlike any other key.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheKeyIsDerivedUnderItsOwnInfo(): void
    {
        $key = SubjectKeySigner::key(self::SECRET);

        self::assertSame('sinemacula/audit-log:subject-key:v1', SubjectKeySigner::DERIVATION_INFO);
        self::assertSame("audit-log:subject-key:v1\n", SubjectKeySigner::LABEL);
        self::assertSame(32, strlen($key));
        self::assertSame(hash_hkdf('sha256', self::SECRET, 32, 'sinemacula/audit-log:subject-key:v1', ''), $key);
        self::assertSame(self::golden()['subject_key'], bin2hex($key));
        self::assertNotSame(self::SECRET, $key);
        self::assertNotSame(SealSigner::sealKey(self::SECRET), $key);
        self::assertNotSame(JournalSigner::key(self::SECRET), $key);
        self::assertNotSame(OwnerFingerprint::key(self::SECRET), $key);
        self::assertNotSame(SubjectKeySigner::key(self::RETIRED_SECRET), $key);
    }

    /**
     * The golden row signs to the golden HMAC under the golden key, and
     * verifies.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheGoldenHmacReproduces(): void
    {
        $golden = self::golden();
        $signer = self::signer('k2026');
        $signed = $signer->sign(self::draft());

        self::assertSame('k2026', $signed->keyId);
        self::assertSame($golden['canonical'], CanonicalEncoder::encode($signed->signedFields()));
        self::assertSame($golden['digest'], SubjectKeySigner::digest($signed));
        self::assertSame($golden['hmac'], $signed->hmac);
        self::assertSame(hash_hmac('sha256', $golden['label'] . $golden['digest'], (string) hex2bin($golden['subject_key'])), $signed->hmac);
        self::assertTrue($signer->verifies($signed));
        self::assertTrue($signer->verifies(SubjectKeyRow::fromRow($signed->toRow())));
    }

    /**
     * Verification selects the key the row names, so a row signed before a
     * rotation still verifies.
     *
     * @return void
     */
    public function testVerificationSelectsTheKeyByTheStoredId(): void
    {
        $retired = self::signer('k2025')->sign(self::draft());
        $rotated = self::signer('k2026');

        self::assertSame('k2025', $retired->keyId);
        self::assertTrue($rotated->verifies($retired));
        self::assertNotSame($retired->hmac, $rotated->sign(self::draft())->hmac);
    }

    /**
     * Rows of `[what changes, the stored columns it changes]`: each immutable
     * field, the unit kept consistent.
     *
     * @return iterable<string, array{0: array<string, int|string|null>}>
     */
    public static function provideImmutableChanges(): iterable
    {
        yield from [
            'another id'          => [['id' => '01932b4e-e000-7000-8000-000000000002']],
            'another owner type'  => [['owner_type' => 'App\Models\Admin', 'unit' => SubjectKeyRow::unitOf('App\Models\Admin', '7', 'App\Models\Team', '3', 'security')]],
            'another owner'       => [['owner_id' => '8', 'unit' => self::unitOf('8', 'App\Models\Team', '3', 'security')]],
            'another tenant'      => [['tenant_id' => '4', 'unit' => self::unitOf('7', 'App\Models\Team', '4', 'security')]],
            'no tenant'           => [['tenant_type' => null, 'tenant_id' => null, 'unit' => self::unitOf('7', null, null, 'security')]],
            'another category'    => [['category' => 'billing', 'unit' => self::unitOf('7', 'App\Models\Team', '3', 'billing')]],
            'another generation'  => [['generation' => 2]],
            'another time'        => [['created_at' => '2026-11-02 09:30:00.000001']],
            'another signing key' => [['key_id' => 'k2025']],
        ];
    }

    /**
     * A row with any immutable field changed no longer verifies: a key moved to
     * another owner, tenant, category or generation is caught.
     *
     * @param  array<string, int|string|null>  $changes
     * @return void
     *
     * @throws \JsonException
     */
    #[DataProvider('provideImmutableChanges')]
    public function testAnyChangedImmutableFieldFailsVerification(array $changes): void
    {
        $signer = self::signer('k2026');
        $stored = $changes + $signer->sign(self::draft())->toRow();

        self::assertFalse($signer->verifies(SubjectKeyRow::fromRow($stored)));
    }

    /**
     * Changing a mutable field leaves the signature alone; the wrap context and
     * journal bind those.
     *
     * @return void
     */
    public function testTheMutableFieldsLeaveTheSignatureAlone(): void
    {
        $signer = self::signer('k2026');
        $stored = $signer->sign(self::draft())->toRow();

        self::assertTrue($signer->verifies(SubjectKeyRow::fromRow(['state' => 'superseded', 'wrapped_key' => 'rewrapped', 'wrap_key_id' => 'w2027'] + $stored)));
        self::assertTrue($signer->verifies(SubjectKeyRow::fromRow(['state' => 'erased', 'wrapped_key' => null, 'erasure_id' => '01932b4e-f000-7000-8000-000000000001'] + $stored)));
    }

    /**
     * A row signed under a key the ring no longer holds cannot be verified: the
     * ring's refusal propagates, never a `false`.
     *
     * @return void
     */
    public function testAnUnknownKeyPropagates(): void
    {
        $signed = self::signer('k2025')->sign(self::draft());
        $signer = new SubjectKeySigner(self::ring(['k2026' => self::SECRET], 'k2026'));

        try {
            $signer->verifies($signed);

            self::fail('Expected the unknown key to be refused.');
        } catch (UnknownKeyException $exception) {
            self::assertSame('k2025', $exception->keyId);
        }
    }

    /**
     * An unsigned row is refused rather than answered `false`.
     *
     * @return void
     */
    public function testAnUnsignedRowIsRefused(): void
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('Only a signed subject key row is verified.');

        self::signer('k2026')->verifies(self::draft());
    }

    /**
     * A row is signed under a ring derived from `app.key` as well, naming the
     * derived key.
     *
     * @return void
     */
    public function testADerivedRingSigns(): void
    {
        $settings = new IntegritySettings(new Repository(['app' => ['key' => 'base64:' . base64_encode(str_repeat('a', 32))]]));
        $signer   = new SubjectKeySigner(new KeyRing($settings));
        $signed   = $signer->sign(self::draft());

        self::assertStringStartsWith('d', $signed->keyId);
        self::assertTrue($signer->verifies($signed));
    }

    /**
     * The row and the ring key are marked sensitive wherever they pass.
     *
     * @return void
     */
    public function testTheKeyAndTheRowsAreMarkedSensitive(): void
    {
        foreach ([['key', 'secret'], ['digest', 'keyRow'], ['sign', 'draft'], ['verifies', 'signed'], ['hmac', 'keyRow'], ['hmac', 'key']] as [$method, $parameter]) {
            $reflected = new \ReflectionParameter([SubjectKeySigner::class, $method], $parameter);

            self::assertCount(1, $reflected->getAttributes(\SensitiveParameter::class), "{$method}() \${$parameter}");
        }
    }

    /**
     * A signer over a ring of the golden and the retired keys, signing with the
     * one named.
     *
     * @param  string  $current
     * @return \SineMacula\Laravel\AuditLog\Integrity\SubjectKeySigner
     */
    private static function signer(string $current): SubjectKeySigner
    {
        return new SubjectKeySigner(self::ring(['k2025' => self::RETIRED_SECRET, 'k2026' => self::SECRET], $current));
    }

    /**
     * A ring of the keys given, signing with the one named.
     *
     * @param  array<string, string>  $keys
     * @param  string  $current
     * @return \SineMacula\Laravel\AuditLog\Integrity\KeyRing
     */
    private static function ring(array $keys, string $current): KeyRing
    {
        return new KeyRing(new IntegritySettings(new Repository(['audit-log' => ['integrity' => ['keys' => $keys, 'current' => $current]]])));
    }

    /**
     * The digest of a unit of the golden owner's type.
     *
     * @param  string  $ownerId
     * @param  ?string  $tenantType
     * @param  ?string  $tenantId
     * @param  string  $category
     * @return string
     */
    private static function unitOf(string $ownerId, ?string $tenantType, ?string $tenantId, string $category): string
    {
        return SubjectKeyRow::unitOf('App\Models\User', $ownerId, $tenantType, $tenantId, $category);
    }

    /**
     * The golden draft.
     *
     * @return \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow
     *
     * @throws \JsonException
     */
    private static function draft(): SubjectKeyRow
    {
        $row = self::golden()['row'];

        return SubjectKeyRow::draft(
            $row['id'],
            Reference::of($row['owner_type'], $row['owner_id']),
            Reference::of((string) $row['tenant_type'], (string) $row['tenant_id']),
            $row['category'],
            $row['generation'],
            $row['wrapped_key'],
            $row['wrap_key_id'],
            $row['created_at'],
        );
    }

    /**
     * The golden vector.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return array{subject_key: string, row: array{id: string, owner_type: string, owner_id: string, tenant_type: ?string, tenant_id: ?string, category: string, generation: int, wrapped_key: string, wrap_key_id: string, created_at: string}, canonical: string, digest: string, label: string, hmac: string}
     *
     * @throws \JsonException
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private static function golden(): array
    {
        // phpcs:disable Generic.Files.LineLength.TooLong
        /** @var array{subject_key: string, row: array{id: string, owner_type: string, owner_id: string, tenant_type: ?string, tenant_id: ?string, category: string, generation: int, wrapped_key: string, wrap_key_id: string, created_at: string}, canonical: string, digest: string, label: string, hmac: string} */
        return json_decode((string) file_get_contents(self::GOLDEN), true, 8, JSON_THROW_ON_ERROR);
        // phpcs:enable Generic.Files.LineLength.TooLong
    }
}
