<?php

declare(strict_types = 1);

namespace Tests\Unit\Integrity;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\IntegritySettings;
use SineMacula\Laravel\AuditLog\Integrity\JournalRow;
use SineMacula\Laravel\AuditLog\Integrity\JournalSigner;
use SineMacula\Laravel\AuditLog\Integrity\KeyRing;
use SineMacula\Laravel\AuditLog\Integrity\SealSigner;
use SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException;

/**
 * Unit tests for the journal signer: the HKDF journal key under its own info,
 * the golden HMACs reproduced, a row signed as one kind never verifying as
 * another, every signed field covered, verification that selects the key by the
 * stored id, and the refusals of an unknown key and a malformed HMAC.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JournalSigner::class)]
final class JournalSignerTest extends TestCase
{
    /** @var string The golden journal vectors. */
    private const string GOLDEN = __DIR__ . '/../../Fixtures/Integrity/journal-v1.json';

    /** @var string The golden secret, the ring key `k2026`. */
    private const string SECRET = 'audit-log golden key 0123456789!';

    /** @var string A retired key's secret, the ring key `k2025`. */
    private const string RETIRED_SECRET = 'audit-log retired key 0123456789';

    /** @var string The HMAC of the row before the second. */
    private const string PREVIOUS = 'b7569d64198e4df1c121883d6a23213915ecb232d574c31a3e2b50daae590429';

    /**
     * The derivation's info is pinned, and the journal key is HKDF-SHA256 of
     * the secret under it with an empty salt: neither the secret, nor the seal
     * key, nor any other key the ring's secret gives.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheKeyIsDerivedUnderItsOwnInfo(): void
    {
        $key = JournalSigner::key(self::SECRET);

        self::assertSame('sinemacula/audit-log:lifecycle:v1', JournalSigner::DERIVATION_INFO);
        self::assertSame(32, strlen($key));
        self::assertSame(hash_hkdf('sha256', self::SECRET, 32, 'sinemacula/audit-log:lifecycle:v1', ''), $key);
        self::assertSame(self::golden()['journal_key'], bin2hex($key));
        self::assertNotSame(SealSigner::sealKey(self::SECRET), $key);
        self::assertNotSame(self::SECRET, $key);
        self::assertNotSame(SealSigner::DERIVATION_INFO, JournalSigner::DERIVATION_INFO);
        self::assertNotSame(JournalSigner::key(self::RETIRED_SECRET), $key);
    }

    /**
     * The golden rows sign to the golden HMACs under the golden key, each the
     * HMAC of its kind's label and its digest, and each verifies.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheGoldenHmacsReproduce(): void
    {
        $golden = self::golden();
        $signer = self::signer('k2026');
        $key    = (string) hex2bin($golden['journal_key']);

        foreach ([self::hold(), self::release()] as $index => $draft) {
            $vector = $golden['rows'][$index];
            $signed = $signer->sign($draft);

            self::assertSame('k2026', $signed->keyId, (string) $index);
            self::assertSame($vector['hmac'], $signed->hmac, (string) $index);
            self::assertSame($vector['digest'], $signed->digest(), (string) $index);
            self::assertSame(hash_hmac('sha256', $vector['label'] . $vector['digest'], $key), $signed->hmac, (string) $index);
            self::assertTrue($signer->verifies($signed), (string) $index);
        }
    }

    /**
     * Signing names the ring's signing key, and verification selects the key
     * the row names, so a row signed before a rotation verifies while its key
     * stays in the ring, and never under another key.
     *
     * @return void
     */
    public function testVerificationSelectsTheKeyByTheStoredId(): void
    {
        $retired = self::signer('k2025')->sign(self::hold());

        self::assertSame('k2025', $retired->keyId);
        self::assertTrue(self::signer('k2026')->verifies($retired));
        self::assertFalse(self::signer('k2026')->verifies($retired->withSignature('k2026', $retired->hmac)));
        self::assertNotSame($retired->hmac, self::signer('k2026')->sign(self::hold())->hmac);
    }

    /**
     * A row signed as one kind never verifies as another, even with every other
     * field the same, since each kind signs under its own label.
     *
     * @return void
     */
    public function testARowSignedAsOneKindNeverVerifiesAsAnother(): void
    {
        $signer = self::signer('k2026');
        $signed = $signer->sign(self::hold())->toRow();

        foreach (JournalKind::cases() as $kind) {
            $relabelled = JournalRow::fromRow([...$signed, 'kind' => $kind->value], true);

            self::assertSame($kind === JournalKind::HOLD, $signer->verifies($relabelled), $kind->value);
        }
    }

    /**
     * Rows of `[column, another value]`: every signed column, each given a
     * value it may hold.
     *
     * @return iterable<string, array{0: string, 1: int|string|null}>
     */
    public static function provideChangedFields(): iterable
    {
        yield from [
            'id'                 => ['id', '01932b4e-b000-7000-8000-000000000009'],
            'sequence'           => ['sequence', 3],
            'log_id'             => ['log_id', 'app-eu-2'],
            'operation_id'       => ['operation_id', '01932b4e-c000-7000-8000-000000000009'],
            'occurred_at'        => ['occurred_at', '2026-10-31 23:50:00.000001'],
            'authority_type'     => ['authority_type', 'App\Models\Admin'],
            'authority_id'       => ['authority_id', '8'],
            'reason'             => ['reason', 'case.reopened'],
            'external_reference' => ['external_reference', 'CASE-2026-002'],
            'seal_id'            => ['seal_id', '01932b4e-9000-7000-8000-000000000001'],
            'hold_id'            => ['hold_id', '01932b4e-d000-7000-8000-000000000002'],
            'payload_digest'     => ['payload_digest', str_repeat('a', 64)],
            'previous_hmac'      => ['previous_hmac', str_repeat('c', 64)],
            'key_id'             => ['key_id', 'k2025'],
            'the hmac'           => ['hmac', str_repeat('d', 64)],
        ];
    }

    /**
     * Changing any one signed column of a signed row, or its HMAC, fails its
     * verification: `false`, never an exception.
     *
     * @param  string  $column
     * @param  int|string|null  $value
     * @return void
     */
    #[DataProvider('provideChangedFields')]
    public function testAnyChangedFieldFailsVerification(string $column, int|string|null $value): void
    {
        $signer = self::signer('k2026');
        $signed = $signer->sign(self::release());
        $stored = [...$signed->toRow(), $column => $value];

        self::assertTrue($signer->verifies($signed));
        self::assertFalse($signer->verifies(JournalRow::fromRow($stored, false)), $column);
    }

    /**
     * The payload is covered through its digest alone: a row read with another
     * payload, its digest column unchanged, still verifies, for the chain to
     * compare the payload with its digest.
     *
     * @return void
     */
    public function testThePayloadIsCoveredThroughItsDigest(): void
    {
        $signer = self::signer('k2026');
        $stored = [...$signer->sign(self::release())->toRow(), 'payload' => '{"hold_id":"01932b4e-d000-7000-8000-000000000002"}'];
        $read   = JournalRow::fromRow($stored, true);

        self::assertTrue($signer->verifies($read));
        self::assertFalse($read->hasPayloadOfItsDigest());
    }

    /**
     * A row naming a key the ring does not hold is unverifiable, never reported
     * as forged.
     *
     * @return void
     */
    public function testAnUnknownKeyIsRefused(): void
    {
        $signed = self::signer('k2026')->sign(self::hold());

        try {
            self::signer('k2026')->verifies($signed->withSignature('k2024', $signed->hmac));
            self::fail('Expected the unknown key to be refused.');
        } catch (UnknownKeyException $exception) {
            self::assertSame('k2024', $exception->keyId);
        }
    }

    /**
     * An HMAC no key could have made is refused before any key is looked up, so
     * an unsigned draft, which names no key, is malformed rather than of an
     * unknown key.
     *
     * @return void
     */
    public function testAMalformedHmacIsRefused(): void
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('A journal row\'s `hmac` must be 64 lower-case hexadecimal characters.');

        self::signer('k2026')->verifies(self::hold());
    }

    /**
     * Neither the journal key nor the secret is ever passed unmarked: the
     * secret and every row and key through the signer are sensitive, so a trace
     * through them shows none.
     *
     * @return void
     */
    public function testTheKeyAndTheRowsAreMarkedSensitive(): void
    {
        $marked = [
            'key'      => ['secret'],
            'sign'     => ['draft'],
            'verifies' => ['signed'],
            'hmac'     => ['journalRow', 'key'],
        ];

        foreach ($marked as $method => $parameters) {
            foreach ((new \ReflectionMethod(JournalSigner::class, $method))->getParameters() as $parameter) {
                $name = $parameter->getName();

                self::assertSame(in_array($name, $parameters, true), $parameter->getAttributes(\SensitiveParameter::class) !== [], $method . '.' . $name);
            }
        }
    }

    /**
     * The golden hold, unsigned.
     *
     * @return \SineMacula\Laravel\AuditLog\Integrity\JournalRow
     */
    private static function hold(): JournalRow
    {
        $scope = ['v' => 1, 'tenants' => null, 'tenantless' => true, 'about' => null, 'categories' => ['security'], 'from' => null, 'to' => null, 'import_batch' => null];

        return JournalRow::draft(
            '01932b4e-b000-7000-8000-000000000001',
            1,
            'app-eu-1',
            JournalKind::HOLD,
            '01932b4e-c000-7000-8000-000000000001',
            '2026-10-31T23:42:00.000000Z',
            ['App\Models\User', '7'],
            'case.review',
            'CASE-2026-001',
            null,
            '01932b4e-d000-7000-8000-000000000001',
            ['hold_id' => '01932b4e-d000-7000-8000-000000000001', 'scope' => $scope, 'basis' => 'legal_claim', 'review_by' => null],
            null,
        );
    }

    /**
     * The golden release, unsigned.
     *
     * @return \SineMacula\Laravel\AuditLog\Integrity\JournalRow
     */
    private static function release(): JournalRow
    {
        return JournalRow::draft(
            '01932b4e-b000-7000-8000-000000000002',
            2,
            'app-eu-1',
            JournalKind::RELEASE,
            '01932b4e-c000-7000-8000-000000000002',
            '2026-10-31T23:50:00.000000Z',
            ['App\Models\User', '7'],
            'case.closed',
            null,
            null,
            '01932b4e-d000-7000-8000-000000000001',
            ['hold_id' => '01932b4e-d000-7000-8000-000000000001'],
            self::PREVIOUS,
        );
    }

    /**
     * A signer over the golden key as `k2026` and a retired key as `k2025`,
     * signing under the key named.
     *
     * @param  string  $current
     * @return \SineMacula\Laravel\AuditLog\Integrity\JournalSigner
     */
    private static function signer(string $current): JournalSigner
    {
        return new JournalSigner(self::ring(['keys' => ['k2026' => self::SECRET, 'k2025' => self::RETIRED_SECRET], 'current' => $current]));
    }

    /**
     * A ring over the integrity settings given.
     *
     * @param  array<string, array<string, string>|string>  $integrity
     * @return \SineMacula\Laravel\AuditLog\Integrity\KeyRing
     */
    private static function ring(array $integrity): KeyRing
    {
        return new KeyRing(new IntegritySettings(new Repository(['audit-log' => ['integrity' => $integrity]])));
    }

    /**
     * The golden journal vectors, decoded: the journal key and each row's
     * label, digest and HMAC.
     *
     * @return array{journal_key: string, rows: list<array{label: string, digest: string, hmac: string}>}
     *
     * @throws \JsonException
     */
    private static function golden(): array
    {
        $golden = json_decode((string) file_get_contents(self::GOLDEN), true, 512, JSON_THROW_ON_ERROR);
        $rows   = is_array($golden) && is_array($golden['rows'] ?? null) ? $golden['rows'] : [];

        $vectors = array_map(static fn (mixed $row): array => [
            'label'  => self::text($row, 'label'),
            'digest' => self::text($row, 'digest'),
            'hmac'   => self::text($row, 'hmac'),
        ], array_values($rows));

        return ['journal_key' => self::text($golden, 'journal_key'), 'rows' => $vectors];
    }

    /**
     * The string under the key of the decoded golden value, failing the test
     * otherwise.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @param  string  $key
     * @return string
     */
    private static function text(mixed $value, string $key): string
    {
        $text = is_array($value) ? $value[$key] ?? null : null;

        return is_string($text) ? $text : self::fail(sprintf('The golden journal has no `%s`.', $key));
    }
}
