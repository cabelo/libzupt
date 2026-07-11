#!/usr/bin/env php
<?php

declare(strict_types=1);
require_once __DIR__ . '/Zupt.php';

try {
    $zupt = new ZuptFFI();

    echo str_repeat('=', 60), PHP_EOL;
    echo "libzupt - SecureBuffer PHP/FFI", PHP_EOL;
    echo str_repeat('=', 60), PHP_EOL, PHP_EOL;

    echo "1. Criando SecureBuffer com conteúdo...", PHP_EOL;
    $secretText = 'My secret password123';
    $secretBuffer = new ZuptSecureBuffer($secretText);
    unset($secretText);
    echo '   Tamanho: ', $secretBuffer->size(), " bytes", PHP_EOL;
    echo '   Conteúdo: ', $secretBuffer->toString(), PHP_EOL, PHP_EOL;

    echo "2. Criando SecureBuffer vazio de 64 bytes...", PHP_EOL;
    $emptyBuffer = new ZuptSecureBuffer(64);
    echo '   Tamanho: ', $emptyBuffer->size(), " bytes", PHP_EOL;
    echo '   Zerado: ', $emptyBuffer->isZeroized() ? 'sim' : 'não', PHP_EOL, PHP_EOL;

    echo "3. Criptografando diretamente do SecureBuffer...", PHP_EOL;
    $keyPair = $zupt->generateKeyPair();
    $encrypted = $zupt->encryptSecure($keyPair['publicKey'], $secretBuffer);
    echo '   Ciphertext: ', strlen($encrypted['ciphertext']), " bytes", PHP_EOL, PHP_EOL;

    echo "4. Descriptografando para SecureBuffer...", PHP_EOL;
    $decryptedBuffer = $zupt->decryptSecure(
        $keyPair['secretKey'],
        $encrypted['ciphertext'],
        $encrypted['encHeader']
    );
    echo '   Tamanho: ', $decryptedBuffer->size(), " bytes", PHP_EOL;
    echo '   Conteúdo: ', $decryptedBuffer->toString(), PHP_EOL, PHP_EOL;

    if (!hash_equals($secretBuffer->toString(), $decryptedBuffer->toString())) {
        throw new RuntimeException('O conteúdo do SecureBuffer não corresponde após descriptografia.');
    }
    echo "5. Verificação: SUCESSO", PHP_EOL, PHP_EOL;

    echo "6. Zerando o buffer original...", PHP_EOL;
    $secretBuffer->zeroize();
    echo '   Zerado: ', $secretBuffer->isZeroized() ? 'sim' : 'não', PHP_EOL;

    echo PHP_EOL, str_repeat('=', 60), PHP_EOL;
    echo "Exemplo de SecureBuffer concluído!", PHP_EOL;
    echo str_repeat('=', 60), PHP_EOL;
} catch (Throwable $error) {
    fwrite(STDERR, 'ERRO: ' . $error->getMessage() . PHP_EOL);
    exit(1);
}
