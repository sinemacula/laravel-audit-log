<?php

declare(strict_types = 1);

namespace Tests\Feature\Querying;

use Carbon\CarbonImmutable;
use Illuminate\Translation\ArrayLoader;
use Illuminate\Translation\Translator;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Privacy\SealedFieldReader;
use SineMacula\Laravel\AuditLog\Querying\Describer;
use SineMacula\Laravel\AuditLog\Querying\Description;
use SineMacula\Laravel\AuditLog\Querying\EntryProjector;
use SineMacula\Laravel\AuditLog\Querying\StoredEntry;
use SineMacula\Laravel\AuditLog\Querying\TrailEntry;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Records\Enums\Provenance;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Records\RecordFactory;
use Tests\TestCase;

/**
 * Feature tests for describing an entry: its title, reason and properties.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Describer::class)]
#[CoversClass(Description::class)]
final class DescriberTest extends TestCase
{
    /** @var string The application's language path in these tests. */
    private const string LANG_PATH = __DIR__ . '/../../Fixtures/Querying/lang';

    /** @var string The package's own translations. */
    private const string PACKAGE_LANG = __DIR__ . '/../../../lang';

    /** @var string The entry's id. */
    private const string ID = '01932b4e-8a40-7000-8000-000000000001';

    /** @var string A key id as a derived key's fingerprint gives it. */
    private const string KEY_ID = 'd03d4735ce37bd961';

    /** @var string An HMAC-SHA256 in lower-case hex. */
    private const string HMAC = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

    /** @var ?string A directory of JSON translations a test wrote, removed after it. */
    private ?string $jsonPath = null;

    /**
     * Load the package's translations under their namespace.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->translator()->addNamespace(Describer::NAMESPACE, self::PACKAGE_LANG);
    }

    /**
     * Remove any JSON translations a test wrote.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        if ($this->jsonPath !== null) {
            array_map(unlink(...), glob($this->jsonPath . '/*.json') ?: []);
            rmdir($this->jsonPath);
        }

        parent::tearDown();
    }

    /**
     * A package code takes its title from the package's file.
     *
     * @return void
     */
    public function testAPackageCodeIsTranslated(): void
    {
        self::assertSame('Signed in', $this->describe('authentication.signed_in')->title);
        self::assertSame('Audit trail read', $this->describe('audit_log.trail_read')->title);
    }

    /**
     * An application's code takes its title from its vendor override.
     *
     * @return void
     */
    public function testAnApplicationCodeFromItsOverride(): void
    {
        self::assertSame('Invoice approved', $this->describe('invoice.approved')->title);
    }

    /**
     * An application's override of a package code wins; other titles stay.
     *
     * @return void
     */
    public function testAnOverrideOfAPackageCodeWins(): void
    {
        self::assertSame('Signed out of the application', $this->describe('authentication.signed_out')->title);
        self::assertSame('Signed in', $this->describe('authentication.signed_in')->title);
    }

    /**
     * A locale with no titles falls back to the fallback locale's.
     *
     * @return void
     */
    public function testAnUntranslatedLocaleFallsBackToEnglish(): void
    {
        self::assertSame('Invoice approved', $this->describe('invoice.approved', 'de')->title);
        self::assertSame('Signed in', $this->describe('authentication.signed_in', 'de')->title);
    }

    /**
     * A locale's title is used, and an untranslated code falls back.
     *
     * @return void
     */
    public function testATranslatedLocaleIsUsed(): void
    {
        self::assertSame('Facture approuvée', $this->describe('invoice.approved', 'fr')->title);
        self::assertSame('Signed in', $this->describe('authentication.signed_in', 'fr')->title);
    }

    /**
     * Without a locale, the application's current locale is used.
     *
     * @return void
     */
    public function testTheApplicationsLocaleIsTheDefault(): void
    {
        $this->translator()->setLocale('fr');

        self::assertSame('Facture approuvée', $this->describe('invoice.approved')->title);
    }

    /**
     * The fallback is the configured fallback locale, whatever it is.
     *
     * @return void
     */
    public function testTheFallbackIsTheConfiguredFallbackLocale(): void
    {
        $this->translator()->setFallback('fr');

        self::assertSame('Facture approuvée', $this->describe('invoice.approved', 'de')->title);
        self::assertSame('invoice.voided', $this->describe('invoice.voided', 'de')->title);
    }

    /**
     * A code no file translates is its own title, in any locale.
     *
     * @return void
     */
    public function testAnUnknownCodeIsTheCodeItself(): void
    {
        self::assertSame('invoice.unknown', $this->describe('invoice.unknown')->title);
        self::assertSame('invoice.unknown', $this->describe('invoice.unknown', 'fr')->title);
    }

    /**
     * An array translation is never a title: the code is.
     *
     * @return void
     */
    public function testAnArrayTranslationIsNeverShown(): void
    {
        self::assertSame('invoice.refunded', $this->describe('invoice.refunded')->title);
        self::assertSame('invoice.refunded', $this->describe('invoice.refunded', 'fr')->title);
    }

    /**
     * An empty line is no title: the fallback, or else the code, is used.
     *
     * @return void
     */
    public function testAnEmptyTranslationIsNeverShown(): void
    {
        self::assertSame('Voided :amount', $this->describe('invoice.voided', 'fr')->title);
        self::assertSame('invoice.drafted', $this->describe('invoice.drafted')->title);
    }

    /**
     * A code and a longer code under it each keep their own title.
     *
     * @return void
     */
    public function testRelatedCodesDoNotCollide(): void
    {
        self::assertSame('Invoice approved', $this->describe('invoice.approved')->title);
        self::assertSame('Invoice approved twice', $this->describe('invoice.approved.twice')->title);
        self::assertSame('Facture approuvée', $this->describe('invoice.approved', 'fr')->title);
        self::assertSame('Invoice approved twice', $this->describe('invoice.approved.twice', 'fr')->title);
    }

    /**
     * A placeholder stays as written, so no stored value reaches a title.
     *
     * @return void
     */
    public function testNoStoredValueIsReplacedIntoATitle(): void
    {
        $description = $this->describer()->describe(self::entry('invoice.voided', properties: ['amount' => '1200.00', 'Amount' => '1200.00', 'AMOUNT' => '1200.00']));

        self::assertSame('Voided :amount', $description->title);
        self::assertSame(['amount' => '1200.00', 'Amount' => '1200.00', 'AMOUNT' => '1200.00'], $description->properties);
    }

    /**
     * A concealed reason is `null` in the description.
     *
     * @return void
     */
    public function testAConcealedReasonIsNeverShown(): void
    {
        $stored      = self::stored('{"concealed":true,"attempts":3}', 'account_rate_limited');
        $description = $this->describer()->describe(self::project($stored));

        self::assertNull($description->reason);
        self::assertNull($description->toArray()['reason']);
        self::assertSame(['concealed' => true, 'attempts' => 3], $description->properties);
        self::assertStringNotContainsString('account_rate_limited', (string) json_encode($description->toArray()));
    }

    /**
     * A reason the stored properties do not conceal is shown as stored.
     *
     * @return void
     */
    public function testAReasonIsShownWhenNotConcealed(): void
    {
        $description = $this->describer()->describe(self::project(self::stored('{"concealed":false}', 'over_limit')));

        self::assertSame('over_limit', $description->reason);
        self::assertSame(Outcome::FAILURE, $description->outcome);
    }

    /**
     * The description holds the entry's code, outcome, reason and properties.
     *
     * @return void
     */
    public function testTheDescriptionHoldsTheEntrysFields(): void
    {
        $properties  = ['amount' => '[ENCRYPTED]', 'lines' => [['sku' => 'A1']]];
        $description = $this->describer()->describe(self::entry('invoice.approved', Outcome::DENIED, 'over_limit', $properties));

        self::assertSame([
            'title'      => 'Invoice approved',
            'code'       => 'invoice.approved',
            'outcome'    => 'denied',
            'reason'     => 'over_limit',
            'properties' => $properties,
        ], $description->toArray());
    }

    /**
     * Rows of `[locale]`: locales with no file, the empty locale among them.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMissingLocales(): iterable
    {
        yield from [
            'an unknown language' => ['xx'],
            'a region'            => ['en_GB'],
            'empty'               => [''],
        ];
    }

    /**
     * A locale with no file never throws and falls back.
     *
     * @param  string  $locale
     * @return void
     */
    #[DataProvider('provideMissingLocales')]
    public function testAMissingLocaleNeverThrows(string $locale): void
    {
        self::assertSame('Invoice approved', $this->describe('invoice.approved', $locale)->title);
        self::assertSame('invoice.unknown', $this->describe('invoice.unknown', $locale)->title);
    }

    /**
     * Rows of `[locale]`: locales holding a separator, parent directory or NUL.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideUnsafeLocales(): iterable
    {
        yield from [
            'a relative path'    => ['../tests/Fixtures/Querying/lang/vendor/audit-log/fr'],
            'a separator'        => ['vendor/fr'],
            'a backslash'        => ['vendor\fr'],
            'a parent directory' => ['fr..'],
            'a NUL byte'         => ["fr\0"],
        ];
    }

    /**
     * A locale that could name another directory is never looked up.
     *
     * @param  string  $locale
     * @return void
     */
    #[DataProvider('provideUnsafeLocales')]
    public function testALocaleNamingAnotherDirectoryIsNeverLookedUp(string $locale): void
    {
        $loader = new ArrayLoader;

        $loader->addMessages('en', Describer::GROUP, ['invoice.approved' => 'Invoice approved'], Describer::NAMESPACE);
        $loader->addMessages($locale, Describer::GROUP, ['invoice.approved' => 'Facture approuvée'], Describer::NAMESPACE);
        $loader->addMessages($locale, '*', ['audit-log::codes.invoice.approved' => 'Facture approuvée'], '*');

        $translator = new Translator($loader, 'en');

        $translator->setFallback('en');

        $describer = new Describer($translator);

        self::assertSame('Invoice approved', $describer->describe(self::entry('invoice.approved'), $locale)->title);
        self::assertSame('Invoice approved', $this->describe('invoice.approved', $locale)->title);
    }

    /**
     * A missing-key handler's answer is never a title.
     *
     * @return void
     */
    public function testAMissingKeyHandlerIsNeverATitle(): void
    {
        $asked = [];

        $this->translator()->handleMissingKeysUsing(static function (string $key) use (&$asked): string {
            $asked[] = $key;

            return 'A missing title';
        });

        self::assertSame('Invoice approved', $this->describe('invoice.approved', 'de')->title);
        self::assertSame('invoice.unknown', $this->describe('invoice.unknown')->title);
        self::assertSame([], $asked);
    }

    /**
     * A JSON line equal to the namespaced key is never shown as a title.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheNamespacedKeyIsNeverShown(): void
    {
        $this->jsonPath = sys_get_temp_dir() . '/audit-log-describer-' . bin2hex(random_bytes(8));

        mkdir($this->jsonPath);
        file_put_contents($this->jsonPath . '/en.json', (string) json_encode([
            'audit-log::codes.invoice.shipped' => 'Invoice shipped',
            'audit-log::codes.invoice.held'    => 'audit-log::codes.invoice.held',
        ]));

        $this->translator()->addJsonPath($this->jsonPath);

        self::assertSame('Invoice shipped', $this->describe('invoice.shipped')->title);
        self::assertSame('invoice.held', $this->describe('invoice.held')->title);
    }

    /**
     * Set the fixture directory as the application's language path.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        app()->useLangPath(self::LANG_PATH);
    }

    /**
     * The description of an entry of the code, in the locale given.
     *
     * @param  string  $code
     * @param  ?string  $locale
     * @return \SineMacula\Laravel\AuditLog\Querying\Description
     */
    private function describe(string $code, ?string $locale = null): Description
    {
        return $this->describer()->describe(self::entry($code), $locale);
    }

    /**
     * The describer the container builds.
     *
     * @return \SineMacula\Laravel\AuditLog\Querying\Describer
     */
    private function describer(): Describer
    {
        return app(Describer::class);
    }

    /**
     * The application's translator.
     *
     * @return \Illuminate\Translation\Translator
     */
    private function translator(): Translator
    {
        return app(Translator::class);
    }

    /**
     * A shown entry of the code, with the outcome, reason and properties given.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $code
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Outcome  $outcome
     * @param  ?string  $reason
     * @param  array<array-key, mixed>  $properties
     * @return \SineMacula\Laravel\AuditLog\Querying\TrailEntry
     */
    private static function entry(string $code, Outcome $outcome = Outcome::SUCCESS, ?string $reason = null, array $properties = []): TrailEntry
    {
        $time = new CarbonImmutable('2026-11-01 12:00:00.123456', 'UTC');

        return new TrailEntry(
            id: self::ID,
            event: $code,
            eventVersion: 1,
            recordVersion: 1,
            integrityVersion: 1,
            category: 'finance',
            outcome: $outcome,
            reason: $reason,
            actor: null,
            subject: null,
            principal: null,
            tenant: null,
            credentialId: null,
            guard: null,
            sessionId: null,
            requestId: null,
            traceId: null,
            correlationId: null,
            origin: null,
            provenance: Provenance::CAPTURED,
            sourceId: 'app-eu-1',
            sourceRegion: null,
            sourceRecordId: null,
            importBatchId: null,
            sourceDigest: null,
            ip: null,
            userAgent: null,
            context: [],
            properties: $properties,
            occurredAt: $time,
            recordedAt: $time,
            keyId: self::KEY_ID,
            hmac: self::HMAC,
            manifest: null,
        );
    }

    /**
     * The shown entry of the stored entry, through the package's field reader.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\StoredEntry  $stored
     * @return \SineMacula\Laravel\AuditLog\Querying\TrailEntry
     */
    private static function project(StoredEntry $stored): TrailEntry
    {
        return (new EntryProjector(new SealedFieldReader, new RecordingExceptionHandler, app(RecordSigner::class)))->project([$stored], false)->entries[0];
    }

    /**
     * A stored entry of a failed invoice approval, with the properties given.
     *
     * @param  string  $properties
     * @param  string  $reason
     * @return \SineMacula\Laravel\AuditLog\Querying\StoredEntry
     */
    private static function stored(string $properties, string $reason): StoredEntry
    {
        $record    = RecordFactory::withFields(['id' => self::ID, 'outcome' => 'failure', 'reason' => $reason], RecordFactory::captured(id: self::ID));
        $finalised = new FinalisedRecord($record, RecordFactory::RECORDED_AT, 1, self::KEY_ID, self::HMAC);

        return StoredEntry::fromRow(['properties' => $properties] + (new RowCodec)->encode($finalised), new RowCodec);
    }
}
