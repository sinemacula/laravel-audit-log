<?php

declare(strict_types = 1);

namespace Tests\Unit\Integrity;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\Enums\KeyState;
use SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * Unit tests for an owner's key row.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SubjectKeyRow::class)]
final class SubjectKeyRowTest extends TestCase
{
    /** @var string The golden key row vector. */
    private const string GOLDEN = __DIR__ . '/../../Fixtures/Integrity/subject-key-v1.json';

    /** @var string An erasure id. */
    private const string ERASURE_ID = '01932b4e-f000-7000-8000-000000000001';

    /** @var string Why an empty or malformed key id is refused. */
    private const string BAD_KEY_ID = 'A subject key row\'s `key_id` must be 1 to 32 letters, digits, dots, underscores or hyphens, starting with a letter or a digit.';

    /** @var string A well-formed HMAC. */
    private const string HMAC = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

    /**
     * The unit digest is the unkeyed SHA-256 of the canonical owner, tenant and
     * category.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheUnitDigestIsTheCanonicalUnit(): void
    {
        $golden = self::golden();

        self::assertSame('["App\\\Models\\\User","7","App\\\Models\\\Team","3","security"]', $golden['unit_canonical']);
        self::assertSame(hash('sha256', $golden['unit_canonical']), $golden['unit']);
        self::assertSame($golden['unit'], SubjectKeyRow::unitOf('App\Models\User', '7', 'App\Models\Team', '3', 'security'));
        self::assertSame($golden['unit'], self::draft()->unit);
    }

    /**
     * A tenantless unit has a digest of its own, never a tenant's, and the
     * owner's, the tenant's and the category's parts never run into each other.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testATenantlessUnitHasItsOwnDigest(): void
    {
        $golden     = self::golden();
        $tenantless = SubjectKeyRow::unitOf('App\Models\User', '7', null, null, 'security');

        self::assertSame($golden['tenantless_unit'], $tenantless);
        self::assertSame(hash('sha256', '["App\\\Models\\\User","7",null,null,"security"]'), $tenantless);
        self::assertNotSame($golden['unit'], $tenantless);
        self::assertNotSame(SubjectKeyRow::unitOf('a', 'bc', null, null, 'security'), SubjectKeyRow::unitOf('ab', 'c', null, null, 'security'));
        self::assertNotSame(SubjectKeyRow::unitOf('a', '7', 'null', 'null', 'security'), SubjectKeyRow::unitOf('a', '7', null, null, 'security'));
        self::assertNotSame(SubjectKeyRow::unitOf('a', '7', null, null, 'security'), SubjectKeyRow::unitOf('a', '7', null, null, 'billing'));
        self::assertSame($tenantless, self::draft(tenanted: false)->unit);
    }

    /**
     * A draft is live and unsigned, holds its wrapped key and the wrapping
     * key's id, and no erasure.
     *
     * @return void
     */
    public function testADraftIsLiveAndUnsigned(): void
    {
        $draft = self::draft();

        self::assertSame(KeyState::LIVE, $draft->state);
        self::assertSame('01932b4e-e000-7000-8000-000000000001', $draft->id);
        self::assertSame(['App\Models\User', '7'], [$draft->ownerType, $draft->ownerId]);
        self::assertSame(['App\Models\Team', '3'], [$draft->tenantType, $draft->tenantId]);
        self::assertSame(['security', 1], [$draft->category, $draft->generation]);
        self::assertSame('w2026', $draft->wrapKeyId);
        self::assertSame('2026-11-02T09:30:00.000000Z', $draft->createdAt);
        self::assertNull($draft->erasureId);
        self::assertSame('', $draft->keyId);
        self::assertSame('', $draft->hmac);
    }

    /**
     * Rows of `[draft argument, the field named]`: each draft argument
     * malformed in turn.
     *
     * @return iterable<string, array{0: array{id?: string, category?: string, generation?: int, wrapped?: string, wrapKeyId?: string, createdAt?: string}, 1: string}>
     */
    public static function provideMalformedDrafts(): iterable
    {
        yield from [
            'an upper-case id'          => [['id' => '01932B4E-E000-7000-8000-000000000001'], 'id'],
            'a category in capitals'    => [['category' => 'Security'], 'category'],
            'a category with a space'   => [['category' => 'secu rity'], 'category'],
            'generation zero'           => [['generation' => 0], 'generation'],
            'a generation past the int' => [['generation' => 2147483648], 'generation'],
            'an empty wrapped key'      => [['wrapped' => ''], 'wrapped_key'],
            'a wrapped key with a NUL'  => [['wrapped' => "a\0b"], 'wrapped_key'],
            'a wrapped key too long'    => [['wrapped' => str_repeat('a', 65536)], 'wrapped_key'],
            'an empty wrapping key id'  => [['wrapKeyId' => ''], 'wrap_key_id'],
            'a wrapping key id space'   => [['wrapKeyId' => 'w 2026'], 'wrap_key_id'],
            'a wrapping key id too big' => [['wrapKeyId' => str_repeat('w', 192)], 'wrap_key_id'],
            'a time without its zone'   => [['createdAt' => '2026-11-02T09:30:00.000000'], 'created_at'],
            'a stored time'             => [['createdAt' => '2026-11-02 09:30:00.000000'], 'created_at'],
        ];
    }

    /**
     * Each malformed draft argument is refused naming its field, never its
     * value.
     *
     * @param  array{id?: string, category?: string, generation?: int, wrapped?: string, wrapKeyId?: string, createdAt?: string}  $argument
     * @param  string  $field
     * @return void
     */
    #[DataProvider('provideMalformedDrafts')]
    public function testRefusesEachMalformedDraft(array $argument, string $field): void
    {
        $value = implode('', $argument);

        try {
            self::draft(...$argument);

            self::fail('Expected the draft to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertStringStartsWith("A subject key row's `{$field}`", $exception->getMessage());
            self::assertStringNotContainsString($value === '' ? "\0" : $value, $exception->getMessage());
        }
    }

    /**
     * The longest generation, wrapped key, wrapping key id, owner and tenant
     * the columns hold are accepted, a reference counted in characters.
     *
     * @return void
     */
    public function testTheLongestValuesTheColumnsHoldAreAccepted(): void
    {
        $draft = self::draft(generation: 2147483647, wrapped: str_repeat('a', 65535), wrapKeyId: 'arn:aws:kms/' . str_repeat('k', 179));

        self::assertSame(2147483647, $draft->generation);
        self::assertSame(65535, strlen((string) $draft->wrappedKey));
        self::assertSame(191, strlen((string) $draft->wrapKeyId));

        $owner = Reference::of(str_repeat('t', 191), str_repeat('é', 191));
        $row   = SubjectKeyRow::draft('01932b4e-e000-7000-8000-000000000001', $owner, $owner, 'security', 1, 'wrapped', 'w2026', '2026-11-02T09:30:00.000000Z');

        self::assertSame(str_repeat('é', 191), $row->ownerId);
        self::assertSame(str_repeat('t', 191), $row->tenantType);
    }

    /**
     * Rows of `[column, stored value]`: each stored column malformed in turn,
     * the unit kept its columns' digest.
     *
     * @return iterable<string, array{0: string, 1: int|string|null}>
     */
    public static function provideMalformedColumns(): iterable
    {
        yield from [
            'an id that is not a UUID'      => ['id', 'key-1'],
            'an empty owner type'           => ['owner_type', ''],
            'an owner id with a control'    => ['owner_id', "7\n"],
            'an owner id too long'          => ['owner_id', str_repeat('7', 192)],
            'a null owner id'               => ['owner_id', null],
            'an empty tenant type'          => ['tenant_type', ''],
            'a category too long'           => ['category', str_repeat('a', 65)],
            'a unit in capitals'            => ['unit', strtoupper(hash('sha256', 'x'))],
            'a generation that is not one'  => ['generation', '1.0'],
            'a negative generation'         => ['generation', -1],
            'a state that is not one'       => ['state', 'revoked'],
            'a null state'                  => ['state', null],
            'a wrapped key with a control'  => ['wrapped_key', "abc\x07"],
            'a wrapping key id with a dot'  => ['wrap_key_id', '.w2026'],
            'a time that is not one'        => ['created_at', 'yesterday'],
            'a time that is an integer'     => ['created_at', 1700000000],
            'an erasure id that is not one' => ['erasure_id', 'erasure'],
            'a key id too long'             => ['key_id', str_repeat('k', 33)],
            'an HMAC in capitals'           => ['hmac', strtoupper(self::HMAC)],
            'an empty HMAC'                 => ['hmac', ''],
        ];
    }

    /**
     * Each malformed stored column is refused naming the column, never its
     * value.
     *
     * @param  string  $column
     * @param  int|string|null  $value
     * @return void
     */
    #[DataProvider('provideMalformedColumns')]
    public function testRefusesEachMalformedField(string $column, int|string|null $value): void
    {
        $stored = [$column => $value] + self::stored();

        if (in_array($column, ['owner_type', 'owner_id', 'tenant_type', 'category'], true) && is_string($value)) {
            $tenant = [self::optional($stored['tenant_type']), self::optional($stored['tenant_id'])];

            $stored['unit'] = SubjectKeyRow::unitOf((string) $stored['owner_type'], (string) $stored['owner_id'], $tenant[0], $tenant[1], (string) $stored['category']);
        }

        self::assertStoredRefused($stored, $column);
    }

    /**
     * A unit that is not its columns' digest is refused: one of another owner,
     * one taken without the tenant, and one of another category.
     *
     * @return void
     */
    public function testRefusesAUnitThatIsNotItsColumnsDigest(): void
    {
        foreach (
            [
                SubjectKeyRow::unitOf('App\Models\User', '8', 'App\Models\Team', '3', 'security'),
                SubjectKeyRow::unitOf('App\Models\User', '7', null, null, 'security'),
                SubjectKeyRow::unitOf('App\Models\User', '7', 'App\Models\Team', '3', 'billing'),
            ] as $unit
        ) {
            self::assertStoredRefused(['unit' => $unit] + self::stored(), 'unit');
        }
    }

    /**
     * A tenant names its type and its id together; one without the other is
     * refused as the tenant id.
     *
     * @return void
     */
    public function testATenantNamesItsTypeAndIdTogether(): void
    {
        foreach ([['App\Models\Team', null], [null, '3']] as [$type, $id]) {
            $stored = ['tenant_type' => $type, 'tenant_id' => $id] + self::stored();

            $stored['unit'] = SubjectKeyRow::unitOf('App\Models\User', '7', $type, $id, 'security');

            self::assertStoredRefused($stored, 'tenant_id');
        }
    }

    /**
     * Rows of `[state, wrapped key, wrapping key id, erasure id, the field
     * named]`: each way a stored row's fields can disagree with its state.
     *
     * @return iterable<string, array{0: string, 1: ?string, 2: ?string, 3: ?string, 4: string}>
     */
    public static function provideStatesBroken(): iterable
    {
        yield from [
            'live without a wrapped key'       => ['live', null, 'w2026', null, 'wrapped_key'],
            'superseded without a wrapped key' => ['superseded', null, 'w2026', null, 'wrapped_key'],
            'erased with a wrapped key'        => ['erased', 'wrapped', 'w2026', self::ERASURE_ID, 'wrapped_key'],
            'live without a wrapping key id'   => ['live', 'wrapped', null, null, 'wrap_key_id'],
            'erased without an erasure id'     => ['erased', null, 'w2026', null, 'erasure_id'],
            'live with an erasure id'          => ['live', 'wrapped', 'w2026', self::ERASURE_ID, 'erasure_id'],
            'superseded with an erasure id'    => ['superseded', 'wrapped', 'w2026', self::ERASURE_ID, 'erasure_id'],
        ];
    }

    /**
     * A stored row whose wrapped key or erasure id disagrees with its state is
     * refused naming the field.
     *
     * @param  string  $state
     * @param  ?string  $wrapped
     * @param  ?string  $wrapKeyId
     * @param  ?string  $erasureId
     * @param  string  $field
     * @return void
     */
    #[DataProvider('provideStatesBroken')]
    public function testAStoredRowMustAgreeWithItsState(string $state, ?string $wrapped, ?string $wrapKeyId, ?string $erasureId, string $field): void
    {
        self::assertStoredRefused(['state' => $state, 'wrapped_key' => $wrapped, 'wrap_key_id' => $wrapKeyId, 'erasure_id' => $erasureId] + self::stored(), $field);
    }

    /**
     * An erased row holds no wrapped key and names its erasure; a superseded
     * row reads like a live one.
     *
     * @return void
     */
    public function testEachStateIsReadWithTheFieldsItAllows(): void
    {
        $erased     = SubjectKeyRow::fromRow(['state' => 'erased', 'wrapped_key' => null, 'erasure_id' => self::ERASURE_ID] + self::stored());
        $dropped    = SubjectKeyRow::fromRow(['state' => 'erased', 'wrapped_key' => null, 'wrap_key_id' => null, 'erasure_id' => self::ERASURE_ID] + self::stored());
        $superseded = SubjectKeyRow::fromRow(['state' => 'superseded'] + self::stored());

        self::assertSame([KeyState::ERASED, null, 'w2026', self::ERASURE_ID], [$erased->state, $erased->wrappedKey, $erased->wrapKeyId, $erased->erasureId]);
        self::assertNull($dropped->wrapKeyId);
        self::assertSame(KeyState::SUPERSEDED, $superseded->state);
        self::assertNull($erased->wrappedDigest());
    }

    /**
     * A stored row without a column is refused naming the column.
     *
     * @return void
     */
    public function testAStoredRowMissingAColumnIsRefused(): void
    {
        foreach (array_keys(self::stored()) as $column) {
            $stored = self::stored();

            unset($stored[$column]);

            try {
                SubjectKeyRow::fromRow($stored);

                self::fail("Expected the row without `{$column}` to be refused.");
            } catch (\UnexpectedValueException $exception) {
                self::assertSame("A stored subject key row has no `{$column}` column; every column is required to read it.", $exception->getMessage());
            }
        }
    }

    /**
     * The wrap context binds the domain, generation, row id, unit and wrapping
     * key id.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheWrapContextBindsKeyUnitGenerationAndWrappingKey(): void
    {
        $golden  = self::golden();
        $draft   = self::draft();
        $context = $draft->wrapContext();

        self::assertSame($golden['wrap_context'], $context);
        $expected = '{"d":"sinemacula/audit-log:wrap:v1","generation":1,"k":"01932b4e-e000-7000-8000-000000000001","unit":"' . $golden['unit'] . '",'
            . '"wrap_key_id":"w2026"}';

        self::assertSame($expected, $context);
        self::assertSame($context, SubjectKeyRow::wrapContextOf($draft->id, $draft->unit, 1, 'w2026'));

        $others = [
            SubjectKeyRow::wrapContextOf('01932b4e-e000-7000-8000-000000000002', $draft->unit, 1, 'w2026'),
            SubjectKeyRow::wrapContextOf($draft->id, $golden['tenantless_unit'], 1, 'w2026'),
            SubjectKeyRow::wrapContextOf($draft->id, $draft->unit, 2, 'w2026'),
            SubjectKeyRow::wrapContextOf($draft->id, $draft->unit, 1, 'w2025'),
        ];

        self::assertCount(5, array_unique([$context, ...$others]));
    }

    /**
     * A row that names no wrapping key has no wrap context.
     *
     * @return void
     */
    public function testARowNamingNoWrappingKeyHasNoWrapContext(): void
    {
        $erased = SubjectKeyRow::fromRow(['state' => 'erased', 'wrapped_key' => null, 'wrap_key_id' => null, 'erasure_id' => self::ERASURE_ID] + self::stored());

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A subject key row that names no wrapping key has no wrap context.');

        $erased->wrapContext();
    }

    /**
     * The state and wrapping fields are left out of the signature, so a row
     * signs the same in every state.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheMutableFieldsAreNotSigned(): void
    {
        $live   = SubjectKeyRow::fromRow(self::stored());
        $erased = SubjectKeyRow::fromRow(['state' => 'erased', 'wrapped_key' => null, 'wrap_key_id' => null, 'erasure_id' => self::ERASURE_ID] + self::stored());
        $moved  = SubjectKeyRow::fromRow(['state' => 'superseded', 'wrapped_key' => 'rewrapped', 'wrap_key_id' => 'w2027'] + self::stored());

        $signed = ['v', 'id', 'owner_type', 'owner_id', 'tenant_type', 'tenant_id', 'category', 'unit', 'generation', 'created_at', 'key_id'];

        self::assertSame($signed, array_keys($live->signedFields()));
        self::assertSame(self::golden()['signed_fields'], $live->signedFields());
        self::assertSame($live->signedFields(), $erased->signedFields());
        self::assertSame($live->signedFields(), $moved->signedFields());
    }

    /**
     * The digest of the wrapped key is the lower-case hex SHA-256 of the text
     * stored.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheWrappedDigestIsTheDigestOfTheStoredText(): void
    {
        $golden = self::golden();

        self::assertSame($golden['wrapped_digest'], self::draft()->wrappedDigest());
        self::assertSame(hash('sha256', $golden['row']['wrapped_key']), self::draft()->wrappedDigest());
    }

    /**
     * A signed row stores every column in table order and reads back from any
     * engine's form.
     *
     * @return void
     */
    public function testItRoundTripsItsRow(): void
    {
        $signed = self::draft()->withSignature('k2026', self::HMAC);
        $row    = $signed->toRow();

        $unit    = ['id', 'owner_type', 'owner_id', 'tenant_type', 'tenant_id', 'category', 'unit', 'generation'];
        $mutable = ['state', 'wrapped_key', 'wrap_key_id', 'created_at', 'erasure_id'];

        self::assertSame([...$unit, ...$mutable, 'key_id', 'hmac'], array_keys($row));
        self::assertSame('2026-11-02 09:30:00.000000', $row['created_at']);
        self::assertSame('live', $row['state']);
        self::assertSame(['k2026', self::HMAC], [$row['key_id'], $row['hmac']]);
        self::assertEquals($signed, SubjectKeyRow::fromRow($row));
        self::assertEquals($signed, SubjectKeyRow::fromRow(['generation' => '1', 'created_at' => '2026-11-02 09:30:00'] + $row));
    }

    /**
     * An unsigned row is never stored, and a row is never signed with an empty
     * key id.
     *
     * @return void
     */
    public function testAnUnsignedRowIsNeverStored(): void
    {
        try {
            self::draft()->withSignature('', self::HMAC);

            self::fail('Expected an empty key id to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame(self::BAD_KEY_ID, $exception->getMessage());
        }

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Only a signed subject key row is stored.');

        self::draft()->toRow();
    }

    /**
     * A signature is checked as it is given: a key id with an HMAC that is not
     * 64 lower-case hex is refused.
     *
     * @return void
     */
    public function testASignatureIsChecked(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A subject key row\'s `hmac` must be 64 lower-case hexadecimal characters.');

        self::draft()->withSignature('k2026', '');
    }

    /**
     * Every parameter that holds an owner, a tenant, a wrapped key or a stored
     * row is marked sensitive.
     *
     * @return void
     */
    public function testTheOwnerAndTheWrappedKeyAreMarkedSensitive(): void
    {
        foreach ([['draft', 'owner'], ['draft', 'tenant'], ['draft', 'wrapped'], ['fromRow', 'stored'], ['unitOf', 'ownerId']] as [$method, $parameter]) {
            $reflected = new \ReflectionParameter([SubjectKeyRow::class, $method], $parameter);

            self::assertCount(1, $reflected->getAttributes(\SensitiveParameter::class), "{$method}() \${$parameter}");
        }
    }

    /**
     * Refuse the stored row, naming the column.
     *
     * @param  array<string, int|string|null>  $stored
     * @param  string  $column
     * @return void
     */
    private static function assertStoredRefused(array $stored, string $column): void
    {
        try {
            SubjectKeyRow::fromRow($stored);

            self::fail("Expected the row to be refused for `{$column}`.");
        } catch (\UnexpectedValueException $exception) {
            self::assertSame("A stored subject key row's `{$column}` is malformed.", $exception->getMessage());
        }
    }

    /**
     * The golden draft, or one with an argument changed.
     *
     * @param  string  $id
     * @param  bool  $tenanted
     * @param  string  $category
     * @param  int  $generation
     * @param  ?string  $wrapped
     * @param  string  $wrapKeyId
     * @param  string  $createdAt
     * @return \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     * @throws \JsonException
     */
    private static function draft(
        string $id = '01932b4e-e000-7000-8000-000000000001',
        bool $tenanted = true,
        string $category = 'security',
        int $generation = 1,
        ?string $wrapped = null,
        string $wrapKeyId = 'w2026',
        string $createdAt = '2026-11-02T09:30:00.000000Z',
    ): SubjectKeyRow {
        $wrapped ??= self::golden()['row']['wrapped_key'];
        $tenant = $tenanted ? Reference::of('App\Models\Team', 3) : null;

        return SubjectKeyRow::draft($id, Reference::of('App\Models\User', 7), $tenant, $category, $generation, $wrapped, $wrapKeyId, $createdAt);
    }

    /**
     * The golden row as the database stores it, signed with a well-formed HMAC.
     *
     * @return array<string, int|string|null>
     *
     * @throws \JsonException
     */
    private static function stored(): array
    {
        $golden = self::golden();

        return [
            'id'          => $golden['row']['id'],
            'owner_type'  => 'App\Models\User',
            'owner_id'    => '7',
            'tenant_type' => 'App\Models\Team',
            'tenant_id'   => '3',
            'category'    => 'security',
            'unit'        => $golden['unit'],
            'generation'  => 1,
            'state'       => 'live',
            'wrapped_key' => $golden['row']['wrapped_key'],
            'wrap_key_id' => 'w2026',
            'created_at'  => '2026-11-02 09:30:00.000000',
            'erasure_id'  => null,
            'key_id'      => 'k2026',
            'hmac'        => $golden['hmac'],
        ];
    }

    /**
     * The value as an optional string.
     *
     * @param  int|string|null  $value
     * @return ?string
     */
    private static function optional(int|string|null $value): ?string
    {
        return $value === null ? null : (string) $value;
    }

    /**
     * The golden vector.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return array{row: array{id: string, wrapped_key: string}, unit_canonical: string, unit: string, tenantless_unit: string, signed_fields: array<string, int|string|null>, hmac: string, wrap_context: string, wrapped_digest: string}
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
        /** @var array{row: array{id: string, wrapped_key: string}, unit_canonical: string, unit: string, tenantless_unit: string, signed_fields: array<string, int|string|null>, hmac: string, wrap_context: string, wrapped_digest: string} */
        return json_decode((string) file_get_contents(self::GOLDEN), true, 8, JSON_THROW_ON_ERROR);
        // phpcs:enable Generic.Files.LineLength.TooLong
    }
}
