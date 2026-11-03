<?php

declare(strict_types = 1);

/*
 * Builds the pinned OCSF schema beside this script from a checkout of the
 * upstream tag, which must be detached at the tag's commit. Fetch it into a
 * scratch directory outside the repository and pass its path; nothing in it is
 * run, only its JSON and licence files are read:
 *
 *     git clone --depth 1 --branch 1.9.0 https://github.com/ocsf/ocsf-schema.git <scratch>/ocsf-schema
 *     php tests/Fixtures/Export/ocsf/build.php <scratch>/ocsf-schema
 *
 * See `Tests\Fixtures\Export\OcsfSchemaBuilder` for what is kept and why.
 */

use Tests\Fixtures\Export\OcsfSchemaBuilder;

require __DIR__ . '/../../../../vendor/autoload.php';

$upstream = $argv[1] ?? null;

if (!is_string($upstream) || !is_dir($upstream)) {
    fwrite(STDERR, "Usage: php tests/Fixtures/Export/ocsf/build.php <checkout of the upstream tag>\n");

    exit(1);
}

$target = __DIR__ . '/' . OcsfSchemaBuilder::TAG;

foreach (array_keys(OcsfSchemaBuilder::build($upstream, $target)) as $path) {
    fwrite(STDOUT, $target . '/' . $path . "\n");
}
