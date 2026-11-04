<?php

declare(strict_types = 1);

namespace Tests\Unit\Integrity;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Integrity\IntegritySettings;
use SineMacula\Laravel\AuditLog\Integrity\KeyRing;
use SineMacula\Laravel\AuditLog\Integrity\PruneRecord;
use SineMacula\Laravel\AuditLog\Integrity\SealEnvelope;
use SineMacula\Laravel\AuditLog\Integrity\SealSigner;
use SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException;
use Symfony\Component\VarDumper\Cloner\VarCloner;
use Symfony\Component\VarDumper\Dumper\CliDumper;
use Tests\Concerns\SearchesForSecrets;

/**
 * Unit tests for the seal signer: the HKDF seal key, of an explicit ring and a
 * derived one, and the seal and prune signatures, each pinned by the golden
 * vectors; the prune label of version 2; the separation of a seal key from a
 * row key and of a seal signature from a row HMAC and a prune signature, and of
 * a record of one set of members from one of another; verification that selects
 * the key by the stored id, refuses an unknown key and a malformed signature,
 * and fails a tampered one; and a seal key that no dump or trace shows.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SealSigner::class)]
final class SealSignerTest extends TestCase
{
    use SearchesForSecrets;

    /** @var string The golden seal vectors. */
    private const string GOLDEN = __DIR__ . '/../../Fixtures/Integrity/seal-v1.json';

    /** @var string The golden prune vectors. */
    private const string GOLDEN_PRUNE = __DIR__ . '/../../Fixtures/Integrity/prune-v2.json';

    /** @var string The golden row HMAC of the golden entry, under the golden secret as the row key. */
    private const string ROW_HMAC = '17f75986893136cb37b1d7889e603528c11b8862566b52eaee3b576f4b7faf41';

    /** @var string The retired key's secret, as its own 32 bytes. */
    private const string RETIRED_SECRET = 'seal-signer retired secret, 32b!';

    /** @var string Why a malformed signature is refused. */
    private const string MALFORMED_SIGNATURE = 'A seal\'s `signature` must be 64 lower-case hexadecimal characters.';

    /**
     * The seal key's derivation and the labels are pinned: a change to any is a
     * new version of the seal, never an edit of this one.
     *
     * @return void
     */
    public function testTheDerivationAndLabelsArePinned(): void
    {
        self::assertSame('sinemacula/audit-log:seal:v1', SealSigner::DERIVATION_INFO);
        self::assertSame("audit-log:seal:v1\n", SealSigner::SEAL_LABEL);
    }

    /**
     * The prune label is of version 2, the version of the record it signs, so
     * no record of another version ever verifies as one of this.
     *
     * @return void
     */
    public function testThePruneLabelIsVersionTwo(): void
    {
        self::assertSame("audit-log:prune:v2\n", SealSigner::PRUNE_LABEL);
        self::assertSame(2, PruneRecord::VERSION);
        self::assertStringContainsString(':v' . PruneRecord::VERSION . "\n", SealSigner::PRUNE_LABEL);
    }

    /**
     * The golden secret gives the golden seal key: HKDF-SHA256 with an empty
     * salt, the seal info string and 32 bytes.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheGoldenSealKeyIsReproduced(): void
    {
        $sealKey = SealSigner::sealKey(self::golden('secret'));

        self::assertSame(32, strlen($sealKey));
        self::assertSame(self::golden('seal_key'), bin2hex($sealKey));
        self::assertSame(hash_hkdf('sha256', self::golden('secret'), 32, 'sinemacula/audit-log:seal:v1', ''), $sealKey);
    }

    /**
     * With no explicit ring, the key derived from the test `app.key` signs,
     * under the golden id, and its seal key is HKDF over the derived secret, as
     * the golden vector pins.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheDerivedRingsSealKeyIsReproduced(): void
    {
        $ring   = self::ring([], ['key' => self::golden('app_key')]);
        $signer = new SealSigner($ring);
        $id     = self::golden('derived_key_id');

        self::assertSame($id, $signer->signingKeyId());
        self::assertSame(self::golden('derived_seal_key'), bin2hex(SealSigner::sealKey($ring->key($id)->secret())));

        $seal = self::seal('seal_1', ['key_id' => $id]);

        self::assertSame(hash_hmac('sha256', "audit-log:seal:v1\n" . $seal->digest(), (string) hex2bin(self::golden('derived_seal_key'))), $signer->sign($seal));
        self::assertTrue($signer->verifies($seal, $signer->sign($seal)));
    }

    /**
     * The golden seals sign to the golden signatures under the golden key, and
     * each verifies.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheGoldenSignaturesAreReproduced(): void
    {
        $signer = self::goldenSigner();

        foreach (['seal_1', 'seal_2'] as $name) {
            $seal      = self::seal($name);
            $signature = self::golden($name . '_signature');

            self::assertSame($signature, $signer->sign($seal), $name);
            self::assertSame($signature, hash_hmac('sha256', "audit-log:seal:v1\n" . self::golden($name . '_digest'), (string) hex2bin(self::golden('seal_key'))), $name);
            self::assertTrue($signer->verifies($seal, $signature), $name);
        }
    }

    /**
     * The seal key is never the ring key that signs rows: it differs from the
     * secret, and the HMAC of the golden canonical seal, or of its labelled
     * digest, under the row secret is not the seal's signature.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheSealKeyIsNotTheRowKey(): void
    {
        $secret    = self::golden('secret');
        $signature = self::golden('seal_1_signature');

        self::assertNotSame($secret, SealSigner::sealKey($secret));
        self::assertNotSame(bin2hex($secret), bin2hex(SealSigner::sealKey($secret)));
        self::assertNotSame($signature, hash_hmac('sha256', self::golden('seal_1_canonical'), $secret));
        self::assertNotSame($signature, hash_hmac('sha256', "audit-log:seal:v1\n" . self::golden('seal_1_digest'), $secret));
    }

    /**
     * A row's HMAC never verifies as a seal's signature: neither the golden
     * entry's HMAC nor an HMAC of the seal made under the row key.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testARowHmacIsNeverASealSignature(): void
    {
        $signer = self::goldenSigner();
        $seal   = self::seal('seal_1');

        self::assertFalse($signer->verifies($seal, self::ROW_HMAC));
        self::assertFalse($signer->verifies($seal, hash_hmac('sha256', self::golden('seal_1_canonical'), self::golden('secret'))));
        self::assertFalse($signer->verifies($seal, hash_hmac('sha256', "audit-log:seal:v1\n" . $seal->digest(), self::golden('secret'))));
    }

    /**
     * A prune signature never verifies as a seal's signature, even one made
     * over the seal's own digest under the same seal key: the labels differ.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAPruneSignatureIsNeverASealsSignature(): void
    {
        $signer  = self::goldenSigner();
        $seal    = self::seal('seal_1');
        $sealKey = SealSigner::sealKey(self::golden('secret'));

        self::assertFalse($signer->verifies($seal, self::goldenPrune('prune_first_signature')));
        self::assertFalse($signer->verifies($seal, self::goldenPrune('prune_second_signature')));
        self::assertFalse($signer->verifies($seal, hash_hmac('sha256', "audit-log:prune:v2\n" . $seal->digest(), $sealKey)));
        self::assertFalse($signer->verifies($seal, hash_hmac('sha256', $seal->digest(), $sealKey)));
        self::assertTrue($signer->verifies($seal, hash_hmac('sha256', "audit-log:seal:v1\n" . $seal->digest(), $sealKey)));
    }

    /**
     * Verification takes the key the seal names, never the current one: a seal
     * signed under the retired key verifies while the current key signs, and
     * its signature fails for the same seal claiming the current key.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testVerificationSelectsTheKeyByTheStoredId(): void
    {
        $signer  = self::twoKeySigner('k2026');
        $retired = self::seal('seal_1', ['key_id' => 'k2025']);

        $signature = self::twoKeySigner('k2025')->sign($retired);

        self::assertSame('k2026', $signer->signingKeyId());
        self::assertSame(hash_hmac('sha256', "audit-log:seal:v1\n" . $retired->digest(), SealSigner::sealKey(self::RETIRED_SECRET)), $signature);
        self::assertTrue($signer->verifies($retired, $signature));
        self::assertFalse($signer->verifies(self::seal('seal_1', ['key_id' => 'k2026']), $signature));
    }

    /**
     * Signing an envelope uses the key the envelope names, whichever key is
     * current; the sealer names the current key through `signingKeyId()`.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testSigningUsesTheEnvelopesKeyId(): void
    {
        $signer = self::twoKeySigner('k2026');
        $seal   = self::seal('seal_1', ['key_id' => 'k2025']);

        self::assertSame('k2026', $signer->signingKeyId());
        self::assertSame(hash_hmac('sha256', "audit-log:seal:v1\n" . $seal->digest(), SealSigner::sealKey(self::RETIRED_SECRET)), $signer->sign($seal));
        self::assertSame(self::golden('seal_1_signature'), $signer->sign(self::seal('seal_1')));
        self::assertSame('k2025', self::twoKeySigner('k2025')->signingKeyId());
    }

    /**
     * A seal or a prune record naming a key the ring does not hold can be
     * neither signed nor verified: it is unknown, never reported as failing.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAnUnknownKeyIsUnknown(): void
    {
        $signer = self::goldenSigner();
        $seal   = self::seal('seal_1', ['key_id' => 'k2024']);
        $record = self::pruneRecord('first', ['key_id' => 'k2024']);

        $calls = [
            'signing'                    => static fn () => $signer->sign($seal),
            'verifying'                  => static fn () => $signer->verifies($seal, self::golden('seal_1_signature')),
            'verifying the prune record' => static fn () => $signer->verifiesPrune($record),
        ];

        foreach ($calls as $what => $call) {
            try {
                $call();
                self::fail(sprintf('Expected %s to refuse the unknown key.', $what));
            } catch (UnknownKeyException $exception) {
                self::assertSame('k2024', $exception->keyId, $what);
            }
        }
    }

    /**
     * Rows of `[signature]`: signatures no seal key could have made.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMalformedSignatures(): iterable
    {
        yield from [
            'empty'           => [''],
            'short'           => [str_repeat('a', 63)],
            'long'            => [str_repeat('a', 65)],
            'upper case'      => [strtoupper('df1a710fe895b10b4d0c1297a85fd6ef1bb2fdb3e619f497243f403379b0ca66')],
            'not hex'         => [str_repeat('g', 64)],
            'with a new line' => ["df1a710fe895b10b4d0c1297a85fd6ef1bb2fdb3e619f497243f403379b0ca66\n"],
        ];
    }

    /**
     * A signature that is not 64 lower-case hex is malformed, refused before
     * any key is looked up, so even a seal naming an unknown key reports it.
     *
     * @param  string  $signature
     * @return void
     *
     * @throws \JsonException
     */
    #[DataProvider('provideMalformedSignatures')]
    public function testAMalformedSignatureIsUnexpected(string $signature): void
    {
        foreach (['k2026', 'k2024'] as $keyId) {
            try {
                self::goldenSigner()->verifies(self::seal('seal_1', ['key_id' => $keyId]), $signature);
                self::fail('Expected the signature to be refused.');
            } catch (\UnexpectedValueException $exception) {
                self::assertSame(self::MALFORMED_SIGNATURE, $exception->getMessage(), $keyId);
            }
        }
    }

    /**
     * A signature changed in one character, or another seal's signature, does
     * not verify: `false`, never an exception.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testATamperedSignatureFails(): void
    {
        $signer    = self::goldenSigner();
        $seal      = self::seal('seal_1');
        $signature = self::golden('seal_1_signature');

        self::assertFalse($signer->verifies($seal, substr($signature, 0, -1) . ($signature[-1] === '0' ? '1' : '0')));
        self::assertFalse($signer->verifies($seal, '0' . substr($signature, 1)));
        self::assertFalse($signer->verifies($seal, self::golden('seal_2_signature')));
        self::assertFalse($signer->verifies(self::seal('seal_1', ['sealed_at' => '2026-10-31T23:40:00.000001Z']), $signature));
    }

    /**
     * The golden seal's two disjoint records sign to their golden digests and
     * signatures under the ring's signing key, each the HMAC of the prune label
     * and its digest under the golden seal key, and each verifies.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheGoldenPruneSignaturesReproduce(): void
    {
        $signer = self::goldenSigner();

        self::assertSame(self::golden('seal_key'), self::goldenPrune('seal_key'));

        foreach (['first', 'second'] as $name) {
            $record = self::signGolden($signer, $name);

            self::assertSame('k2026', $record->keyId, $name);
            self::assertSame(self::goldenPrune('prune_' . $name . '_canonical'), CanonicalEncoder::encode($record->toArray()), $name);
            self::assertSame(self::goldenPrune('prune_' . $name . '_digest'), $record->digest(), $name);
            self::assertSame(self::goldenPrune('prune_' . $name . '_signature'), $record->signature, $name);
            $label = "audit-log:prune:v2\n" . self::goldenPrune('prune_' . $name . '_digest');

            self::assertSame(hash_hmac('sha256', $label, (string) hex2bin(self::golden('seal_key'))), $record->signature, $name);
            self::assertTrue($signer->verifiesPrune($record), $name);
            self::assertEquals(self::pruneRecord($name), $record, $name);
        }
    }

    /**
     * A record signed for one set of a seal's members never verifies for
     * another: the golden records' bitmaps swapped, their counts with them, or
     * a bitmap widened to every member, fail under the signature they carry.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testARecordSignedForOneSubsetNeverVerifiesForAnother(): void
    {
        $signer = self::goldenSigner();
        $first  = self::pruneRecord('first');
        $second = self::pruneRecord('second');

        $forgeries = [
            'the first under the second\'s members' => self::pruneRecord('first', ['pruned' => $second->pruned, 'pruned_count' => $second->prunedCount]),
            'the second under the first\'s members' => self::pruneRecord('second', ['pruned' => $first->pruned, 'pruned_count' => $first->prunedCount]),
            'the first widened to every member'     => self::pruneRecord('first', ['pruned' => 'Bw', 'pruned_count' => 3]),
            'the second widened to every member'    => self::pruneRecord('second', ['pruned' => 'Bw', 'pruned_count' => 3]),
        ];

        foreach ($forgeries as $what => $record) {
            self::assertFalse($signer->verifiesPrune($record), $what);
        }

        self::assertTrue($signer->verifiesPrune($first));
        self::assertTrue($signer->verifiesPrune($second));
    }

    /**
     * A prune record whose any bound field differs from what was signed, or
     * whose signature is changed or a seal's, fails; one signed under a key
     * since retired still verifies by the id it names.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAForgedPruneRecordFails(): void
    {
        $signer = self::goldenSigner();

        $forgeries = [
            'log id'       => ['log_id' => 'app-eu-2'],
            'seal id'      => ['seal_id' => '01932b4e-9000-7000-8000-000000000002'],
            'seal digest'  => ['seal_digest' => self::golden('seal_2_digest')],
            'member count' => ['member_count' => 4],
            'operation id' => ['operation_id' => '01932b4e-a000-7000-8000-000000000009'],
            'pruned at'    => ['pruned_at' => '2027-11-01T00:00:00.000001Z'],
            'signature'    => ['signature' => self::golden('seal_1_signature')],
            'the other'    => ['signature' => self::goldenPrune('prune_second_signature')],
        ];

        foreach ($forgeries as $what => $changes) {
            self::assertFalse($signer->verifiesPrune(self::pruneRecord('first', $changes)), $what);
        }

        $golden  = self::pruneRecord('first');
        $retired = self::twoKeySigner('k2025')->signPrune('app-eu-1', $golden->sealId, $golden->sealDigest, 3, 'BQ', 2, $golden->operationId, $golden->prunedAt);

        self::assertSame('k2025', $retired->keyId);
        self::assertTrue(self::twoKeySigner('k2026')->verifiesPrune($retired));
        self::assertFalse($signer->verifiesPrune(self::pruneRecord('first', ['signature' => $retired->signature])));
    }

    /**
     * Signing refuses a record that is not well formed before any signature is
     * made: a count that is not the bitmap's.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testSigningRefusesAMalformedRecord(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A prune record\'s `pruned_count` must be the number of members its bitmap sets, at least 1.');

        self::goldenSigner()->signPrune(
            'app-eu-1',
            '01932b4e-9000-7000-8000-000000000003',
            self::goldenPrune('seal_digest'),
            3,
            'BQ',
            1,
            '01932b4e-a000-7000-8000-000000000001',
            '2027-11-01T00:00:00.000000Z',
        );
    }

    /**
     * The seal key is derived on every call and kept nowhere: no dump of the
     * signer shows it, nor anything signing gives back, and a refusal while
     * signing holds neither it nor the planted secret. The secret and every key
     * passed between methods are marked sensitive, so a trace through them
     * shows neither.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testNoDumpOrTraceShowsTheSealKey(): void
    {
        $secret  = str_pad(self::SECRET, 32, '-');
        $sealKey = SealSigner::sealKey($secret);
        $signer  = new SealSigner(self::ring(['keys' => ['k2026' => $secret], 'current' => 'k2026']));
        $record  = self::signGolden($signer, 'first');

        $outputs = [
            'the Symfony dumper' => (string) (new CliDumper)->dump((new VarCloner)->cloneVar($signer), true),
            'var_export()'       => var_export($signer, true),
            'json_encode()'      => json_encode($signer, JSON_THROW_ON_ERROR),
            'a signature'        => $signer->sign(self::seal('seal_1')),
            'a prune record'     => var_export($record, true),
        ];

        foreach ($outputs as $where => $output) {
            self::assertStringNotContainsString(bin2hex($sealKey), $output, $where);
            self::assertStringNotContainsString($sealKey, $output, $where);
        }

        try {
            $signer->sign(self::seal('seal_1', ['key_id' => 'k2024']));
            self::fail('Expected the unknown key to be refused.');
        } catch (UnknownKeyException $exception) {
            self::assertHoldsNoSecret($exception, 'a refusal while signing');
            self::assertFalse(self::holdsText($exception, bin2hex($sealKey)));
        }

        self::assertTrue(self::holdsText(new \RuntimeException($secret), self::SECRET));
        self::assertMarkedSensitive(SealSigner::class, 'sealKey', 'secret');
        self::assertMarkedSensitive(SealSigner::class, 'signature', 'key');
    }

    /**
     * Fail unless the method's parameter carries the sensitive-parameter
     * attribute.
     *
     * @param  class-string  $class
     * @param  string  $method
     * @param  string  $parameter
     * @return void
     */
    private static function assertMarkedSensitive(string $class, string $method, string $parameter): void
    {
        foreach ((new \ReflectionMethod($class, $method))->getParameters() as $candidate) {
            if ($candidate->getName() === $parameter) {
                self::assertNotSame([], $candidate->getAttributes(\SensitiveParameter::class), sprintf('%s::%s() does not mark $%s.', $class, $method, $parameter));

                return;
            }
        }

        self::fail(sprintf('%s::%s() has no $%s.', $class, $method, $parameter));
    }

    /**
     * The golden record named, signed by the signer given.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealSigner  $signer
     * @param  'first'|'second'  $name
     * @return \SineMacula\Laravel\AuditLog\Integrity\PruneRecord
     *
     * @throws \JsonException
     */
    private static function signGolden(SealSigner $signer, string $name): PruneRecord
    {
        $fields = self::pruneFields($name);

        return $signer->signPrune(
            (string) $fields['log_id'],
            (string) $fields['seal_id'],
            (string) $fields['seal_digest'],
            (int) $fields['member_count'],
            (string) $fields['pruned'],
            (int) $fields['pruned_count'],
            (string) $fields['operation_id'],
            (string) $fields['pruned_at'],
        );
    }

    /**
     * The golden record named, under its golden signature, with the fields
     * given changed.
     *
     * @param  'first'|'second'  $name
     * @param  array<string, int|string>  $changes
     * @return \SineMacula\Laravel\AuditLog\Integrity\PruneRecord
     *
     * @throws \JsonException
     */
    private static function pruneRecord(string $name, array $changes = []): PruneRecord
    {
        $fields = [...self::pruneFields($name), 'signature' => self::goldenPrune('prune_' . $name . '_signature'), ...$changes];

        return new PruneRecord(
            (string) $fields['log_id'],
            (string) $fields['seal_id'],
            (string) $fields['seal_digest'],
            (int) $fields['member_count'],
            (string) $fields['pruned'],
            (int) $fields['pruned_count'],
            (string) $fields['operation_id'],
            (string) $fields['pruned_at'],
            (string) $fields['key_id'],
            (string) $fields['signature'],
        );
    }

    /**
     * The golden fields of the record named.
     *
     * @param  'first'|'second'  $name
     * @return array<string, int|string>
     *
     * @throws \JsonException
     */
    private static function pruneFields(string $name): array
    {
        $vectors = json_decode((string) file_get_contents(self::GOLDEN_PRUNE), true, 512, JSON_THROW_ON_ERROR);
        $fields  = is_array($vectors) ? ($vectors['prune_' . $name] ?? null) : null;

        /** @var array<string, int|string> */
        return is_array($fields) ? $fields : self::fail(sprintf('The golden prune vectors have no `prune_%s`.', $name));
    }

    /**
     * The golden prune string under the key given.
     *
     * @param  string  $field
     * @return string
     *
     * @throws \JsonException
     */
    private static function goldenPrune(string $field): string
    {
        $vectors = json_decode((string) file_get_contents(self::GOLDEN_PRUNE), true, 512, JSON_THROW_ON_ERROR);
        $value   = is_array($vectors) ? ($vectors[$field] ?? null) : null;

        return is_string($value) ? $value : self::fail(sprintf('The golden prune vectors have no `%s`.', $field));
    }

    /**
     * A golden seal with the fields given changed.
     *
     * @param  'seal_1'|'seal_2'  $name
     * @param  array<string, string>  $overrides
     * @return \SineMacula\Laravel\AuditLog\Integrity\SealEnvelope
     *
     * @throws \JsonException
     */
    private static function seal(string $name, array $overrides = []): SealEnvelope
    {
        $fields = self::goldenFields($name);

        return new SealEnvelope(
            $overrides['log_id'] ?? 'app-eu-1',
            self::field($fields, 'id'),
            $name === 'seal_1' ? 1 : 2,
            $name === 'seal_1' ? null : self::field($fields, 'previous_id'),
            $name === 'seal_1' ? null : self::field($fields, 'previous_digest'),
            $name === 'seal_1' ? 2 : 1,
            self::field($fields, 'members_digest'),
            self::field($fields, 'first_recorded_at'),
            self::field($fields, 'last_recorded_at'),
            $overrides['sealed_at'] ?? self::field($fields, 'sealed_at'),
            $overrides['key_id']    ?? self::field($fields, 'key_id'),
            journalSequence: $name === 'seal_1' ? null : 1,
            journalHead: $name     === 'seal_1' ? null : self::field($fields, 'journal_head'),
        );
    }

    /**
     * The string field of a golden seal.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $fields
     * @param  string  $field
     * @return string
     */
    private static function field(array $fields, string $field): string
    {
        $value = $fields[$field] ?? null;

        return is_string($value) ? $value : self::fail(sprintf('The golden seal has no `%s`.', $field));
    }

    /**
     * A golden seal's fields.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  'seal_1'|'seal_2'  $name
     * @return array<array-key, mixed>
     *
     * @throws \JsonException
     */
    private static function goldenFields(string $name): array
    {
        $fields = self::vectors()[$name] ?? null;

        return is_array($fields) ? $fields : self::fail(sprintf('The golden seal has no `%s`.', $name));
    }

    /**
     * The golden string under the key given.
     *
     * @param  string  $field
     * @return string
     *
     * @throws \JsonException
     */
    private static function golden(string $field): string
    {
        $value = self::vectors()[$field] ?? null;

        return is_string($value) ? $value : self::fail(sprintf('The golden seal has no `%s`.', $field));
    }

    /**
     * The golden seal vectors, decoded.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return array<array-key, mixed>
     *
     * @throws \JsonException
     */
    private static function vectors(): array
    {
        $vectors = json_decode((string) file_get_contents(self::GOLDEN), true, 512, JSON_THROW_ON_ERROR);

        return is_array($vectors) ? $vectors : self::fail('The golden seal vectors are not a map.');
    }

    /**
     * A signer whose one key is the golden key.
     *
     * @return \SineMacula\Laravel\AuditLog\Integrity\SealSigner
     *
     * @throws \JsonException
     */
    private static function goldenSigner(): SealSigner
    {
        return new SealSigner(self::ring(['keys' => [self::golden('key_id') => self::golden('secret')], 'current' => self::golden('key_id')]));
    }

    /**
     * A signer over the golden key as `k2026` and a retired key as `k2025`,
     * with the current key named.
     *
     * @param  string  $current
     * @return \SineMacula\Laravel\AuditLog\Integrity\SealSigner
     *
     * @throws \JsonException
     */
    private static function twoKeySigner(string $current): SealSigner
    {
        return new SealSigner(self::ring(['keys' => ['k2026' => self::golden('secret'), 'k2025' => self::RETIRED_SECRET], 'current' => $current]));
    }

    /**
     * A ring over the integrity and application settings given.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $integrity
     * @param  array<string, mixed>  $app
     * @return \SineMacula\Laravel\AuditLog\Integrity\KeyRing
     */
    private static function ring(array $integrity, array $app = []): KeyRing
    {
        return new KeyRing(new IntegritySettings(new Repository(['audit-log' => ['integrity' => $integrity], 'app' => $app])));
    }
}
