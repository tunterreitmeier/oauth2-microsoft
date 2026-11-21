<?php

declare(strict_types=1);

$finder = PhpCsFixer\Finder::create()
    ->in(['src', 'tests']);

return (new PhpCsFixer\Config())
    ->setUnsupportedPhpVersionAllowed(true)
    ->setRules([
        '@PER-CS' => true,
    ])
    ->setCacheFile('./cache/.php-cs-fixer.cache')
    ->setFinder($finder)
    ->setRiskyAllowed(true);
