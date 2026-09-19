<?php

declare(strict_types=1);

/**
 * Every file the package ships or tests with must compile silently.
 *
 * A PHP compile-time warning (the classic one: `use Foo;` for a global class in
 * a file that has no namespace) is written before a single test runs, and
 * phpunit.xml sets failOnWarning, so the whole suite exits non-zero while every
 * test still prints a tick. That combination is invisible to anyone who pipes
 * the run through `tail`, which is exactly how it survived until CI said no.
 *
 * @return list<string>
 */
function ssoPhpFiles(): array
{
    $root = dirname(__DIR__, 2);
    $files = [];

    foreach (['src', 'tests', 'config', 'database'] as $dir) {
        $path = $root.'/'.$dir;

        if (! is_dir($path)) {
            continue;
        }

        /** @var iterable<SplFileInfo> $found */
        $found = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path));

        foreach ($found as $file) {
            if ($file->isFile() && $file->getExtension() === 'php') {
                $files[] = $file->getPathname();
            }
        }
    }

    sort($files);

    return $files;
}

it('compiles every shipped and test file without a single PHP diagnostic', function () {
    $files = ssoPhpFiles();

    expect($files)->not->toBeEmpty();

    $noisy = [];

    foreach ($files as $file) {
        $process = proc_open(
            [PHP_BINARY, '-d', 'error_reporting=E_ALL', '-d', 'display_errors=1', '-l', $file],
            [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes,
        );

        if (! is_resource($process)) {
            throw new RuntimeException("Could not lint {$file}.");
        }

        $stdout = (string) stream_get_contents($pipes[1]);
        $stderr = (string) stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        proc_close($process);

        $output = trim($stdout."\n".$stderr);

        foreach (explode("\n", $output) as $line) {
            $line = trim($line);

            if ($line === '' || str_starts_with($line, 'No syntax errors detected')) {
                continue;
            }

            $noisy[] = str_replace(dirname(__DIR__, 2).'/', '', $file).': '.$line;
        }
    }

    expect($noisy)->toBe([]);
});
