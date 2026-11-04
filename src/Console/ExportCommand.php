<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Console;

use Illuminate\Console\Command;
use SineMacula\Laravel\AuditLog\Export\Enums\ExportFormat;
use SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException;
use SineMacula\Laravel\AuditLog\Querying\AuditTrail;
use SineMacula\Laravel\AuditLog\Querying\ExportFile;
use SineMacula\Laravel\AuditLog\Querying\ExportResult;
use SineMacula\Laravel\AuditLog\Querying\ExportVerification;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Support\TextSanitizer;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Formatter\OutputFormatter;

/**
 * `audit-log:export`: exports the entries a viewer may see to a file, in
 * NDJSON, OCSF or CEF, with its bundle beside it, or with `--verify` verifies
 * an export for the viewer, exactly as the trail's `export()` and
 * `verifyExport()` do, each authorised by the bound access policy and recorded
 * before anything is published or shown.
 *
 * The viewer is the reference `--viewer-type` and `--viewer-id` name together.
 * It is an assertion made by whoever runs the command, and proves nothing of
 * who that is: the access policy decides what the viewer may see, and a viewer
 * it denies is given an empty export. Without both options, with a viewer that
 * cannot be referenced, or with a format other than `ndjson`, `ocsf` or `cef`,
 * the command says why and exits with `INVALID` before anything is read.
 *
 * An export prints how many entries it holds and where, the id of the entry
 * that journals it and how that entry was acknowledged, the SHA-256 of its file
 * and where its bundle is. A verification prints each finding, then whether the
 * export verified, and exits with `FAILURE` on any finding. A target that
 * exists without `--force`, or that cannot be written to, exits with `INVALID`,
 * and a read that is refused or cannot be recorded with `FAILURE`; each prints
 * its message, which never holds the path or a value of an entry. Nothing else
 * is caught, so what an access policy throws reaches the console as it was
 * thrown.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[AsCommand(name: 'audit-log:export')]
final class ExportCommand extends Command
{
    /** @var string The name and signature of the console command. */
    protected $signature = 'audit-log:export'
        . ' {file : The export to write, or with --verify the export to check}'
        . ' {--viewer-type= : The type of the viewer the export is made for}'
        . ' {--viewer-id= : The id of the viewer the export is made for}'
        . ' {--format=ndjson : ndjson, ocsf or cef}'
        . ' {--force : Replace an existing file}'
        . ' {--verify : Verify the file instead of writing one}';

    /** @var string The console command description. */
    protected $description = 'Export the audit trail a viewer may see to a file, or verify an export';

    /**
     * Export the trail the viewer may see to the file, or verify the export
     * there, once the options are known to be well formed.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\AuditTrail  $trail
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function handle(AuditTrail $trail): int
    {
        try {
            $trail  = $trail->visibleTo($this->viewer());
            $format = $this->format();
        } catch (\InvalidArgumentException $refusal) {
            // Each refusal names the option or the part, never what was given
            $this->error($refusal->getMessage());

            return self::INVALID;
        }

        /** @var string $path */
        $path = $this->argument('file');

        return $this->perform($trail, $path, $format);
    }

    /**
     * Export the trail to the path in the format, or verify the export there,
     * and return the exit code the run earns: a refused read fails, and a
     * refused target is invalid.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\AuditTrail  $trail
     * @param  string  $path
     * @param  \SineMacula\Laravel\AuditLog\Export\Enums\ExportFormat  $format
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function perform(AuditTrail $trail, string $path, ExportFormat $format): int
    {
        try {
            return $this->option('verify') === true
                ? $this->verified($trail->verifyExport($path))
                : $this->exported($trail->export($path, $format, $this->option('force') === true));
        } catch (AuditReadRefusedException $refusal) {
            // The refusal names classes and connections alone
            $this->error($refusal->getMessage());

            return self::FAILURE;
        } catch (\InvalidArgumentException $refusal) {
            return $this->refusedTarget($refusal);
        }
    }

    /**
     * Print what the export published and return the exit code it earns.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\ExportResult  $result
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    private function exported(ExportResult $result): int
    {
        $this->line(sprintf('Exported %d entries to %s.', $result->lines, self::shown($result->path)));
        $this->line(sprintf('Journal entry: %s (%s).', $result->entryId, $result->acknowledgement->value));
        $this->line(sprintf('SHA-256: %s.', $result->fileSha256));
        $this->line(sprintf('Manifest: %s.', self::shown($result->manifestPath)));

        return self::SUCCESS;
    }

    /**
     * Print each finding of the verification, then whether the export verified,
     * and return the exit code it earns.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\ExportVerification  $verification
     * @return int
     */
    private function verified(ExportVerification $verification): int
    {
        foreach ($verification->findings as $finding) {
            $this->line($finding->value);
        }

        if (!$verification->isVerified()) {
            $this->error('Not verified.');

            return self::FAILURE;
        }

        $this->info('Verified.');

        return self::SUCCESS;
    }

    /**
     * Print the refusal of the target and return `INVALID`, or rethrow any
     * other refusal, which is not the command's to catch.
     *
     * @param  \InvalidArgumentException  $refusal
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    private function refusedTarget(\InvalidArgumentException $refusal): int
    {
        if (!self::isTargetRefusal($refusal)) {
            throw $refusal;
        }

        // The refusal names what is wrong with the target, never the path
        $this->error($refusal->getMessage());

        return self::INVALID;
    }

    /**
     * The viewer the two options name together.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\Reference
     *
     * @throws \InvalidArgumentException
     */
    private function viewer(): Reference
    {
        $type = $this->option('viewer-type');
        $id   = $this->option('viewer-id');

        if (!is_string($type) || !is_string($id)) {
            throw new \InvalidArgumentException('Name the viewer the export is made for with both --viewer-type and --viewer-id.');
        }

        return Reference::of($type, $id);
    }

    /**
     * The format the option names.
     *
     * @return \SineMacula\Laravel\AuditLog\Export\Enums\ExportFormat
     *
     * @throws \InvalidArgumentException
     */
    private function format(): ExportFormat
    {
        $format = $this->option('format');

        return (is_string($format) ? ExportFormat::tryFrom($format) : null)
            ?? throw new \InvalidArgumentException('The --format option must be ndjson, ocsf or cef.');
    }

    /**
     * The path as a line of text shows it: repaired and stripped of control
     * characters, with nothing in it read as a style.
     *
     * @param  string  $path
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private static function shown(string $path): string
    {
        return OutputFormatter::escape(TextSanitizer::clean($path));
    }

    /**
     * Whether the refusal is the target's own: a directory that does not exist
     * or cannot be written to, a target that is a directory, or a target that
     * exists without `--force`. Only the export's file raises one, so it is
     * told apart by where it was raised, and never by its text.
     *
     * @param  \InvalidArgumentException  $refusal
     * @return bool
     */
    private static function isTargetRefusal(\InvalidArgumentException $refusal): bool
    {
        return ($refusal->getTrace()[0]['class'] ?? null) === ExportFile::class;
    }
}
