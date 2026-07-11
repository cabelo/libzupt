#!/usr/bin/env php
<?php

declare(strict_types=1);
require_once __DIR__ . '/Zupt.php';

try {
    $zupt = new ZuptFFI();

    echo str_repeat('=', 60), PHP_EOL;
    echo "libzupt - Aleatoriedade e hashes PHP/FFI", PHP_EOL;
    echo str_repeat('=', 60), PHP_EOL, PHP_EOL;

    echo "1. Gerando 32 bytes aleatórios...", PHP_EOL;
    $random = $zupt->randomBytes(32);
    echo '   ', bin2hex($random), PHP_EOL, PHP_EOL;

    echo "2. Gerando nonce AES...", PHP_EOL;
    $nonce = $zupt->randomBytes(ZuptFFI::AES_NONCE_SIZE);
    echo '   ', bin2hex($nonce), PHP_EOL, PHP_EOL;

    $data = 'Hello, Post-Quantum World!';
    echo "3. SHA-256 de '{$data}'...", PHP_EOL;
    echo '   ', bin2hex($zupt->sha256($data)), PHP_EOL, PHP_EOL;

    echo "4. SHA3-512 de '{$data}'...", PHP_EOL;
    echo '   ', bin2hex($zupt->sha3_512($data)), PHP_EOL, PHP_EOL;

    echo "5. Simulando derivação simples...", PHP_EOL;
    $salt = $zupt->randomBytes(16);
    $derived = $zupt->sha256($salt . 'my-secret-password');
    echo '   Salt: ', bin2hex($salt), PHP_EOL;
    echo '   Chave derivada: ', bin2hex($derived), PHP_EOL;

    echo PHP_EOL, str_repeat('=', 60), PHP_EOL;
    echo "Exemplo de aleatoriedade concluído!", PHP_EOL;
    echo str_repeat('=', 60), PHP_EOL;
} catch (Throwable $error) {
    fwrite(STDERR, 'ERRO: ' . $error->getMessage() . PHP_EOL);
    exit(1);
}
