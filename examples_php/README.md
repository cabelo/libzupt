# libzupt — exemplos PHP com FFI

Esta pasta contém exemplos PHP equivalentes aos exemplos de `examples_python`, usando diretamente a ABI C da `libzupt` por meio da extensão PHP FFI.

## Requisitos

- Linux ou macOS;
- PHP 8.1 ou superior;
- extensão `FFI` carregada;
- `libzupt.so`/`libzupt.dylib` compilada ou instalada;
- símbolos da ABI C definidos em `include/zupt_cxx.h`.

Verifique o ambiente:

```bash
php -v
php -m | grep -i '^FFI$'
```

## Compilar a libzupt

A partir da raiz do projeto:

```bash
mkdir -p build
cmake -S . -B build
cmake --build build -j"$(nproc)"
```

O wrapper procura automaticamente, nesta ordem:

1. caminho informado ao construtor de `ZuptFFI`;
2. variável `LIBZUPT_PATH`;
3. `build/libzupt.so` na raiz do projeto;
4. caminhos comuns do sistema e nomes disponíveis pelo carregador dinâmico.

Para informar explicitamente o arquivo:

```bash
export LIBZUPT_PATH="$PWD/build/libzupt.so"
```

Se a biblioteca foi instalada em um diretório não padrão, também pode ser necessário:

```bash
export LD_LIBRARY_PATH="$(dirname "$LIBZUPT_PATH"):${LD_LIBRARY_PATH:-}"
```

## Executar

```bash
cd examples_php
php -d ffi.enable=1 example_basic.php
php -d ffi.enable=1 example_file.php
php -d ffi.enable=1 example_keygen.php
php -d ffi.enable=1 example_random.php
php -d ffi.enable=1 example_secure_buffer.php
```

Ou todos de uma vez:

```bash
./run_all.sh
```

## Exemplos

- `example_basic.php`: geração de chaves e criptografia/descriptografia em memória;
- `example_file.php`: criptografia e restauração de arquivo;
- `example_keygen.php`: salvar, carregar e exportar chaves;
- `example_random.php`: bytes aleatórios, SHA-256 e SHA3-512;
- `example_secure_buffer.php`: buffer nativo zerável para reduzir a permanência de dados sensíveis;
- `Zupt.php`: wrapper FFI reutilizável.

## Uso mínimo

```php
<?php
require_once __DIR__ . '/Zupt.php';

$zupt = new ZuptFFI();
$keys = $zupt->generateKeyPair();

$encrypted = $zupt->encrypt($keys['publicKey'], 'mensagem secreta');
$plaintext = $zupt->decrypt(
    $keys['secretKey'],
    $encrypted['ciphertext'],
    $encrypted['encHeader']
);

echo $plaintext, PHP_EOL;
```

## Formato e tamanhos usados

Os valores abaixo seguem a implementação atual da ABI C:

- chave pública híbrida: `1224` bytes;
- chave privada híbrida: `3656` bytes;
- header de criptografia: `1137` bytes;
- composição: ML-KEM-768 + X25519.

O ciphertext e o header são dados binários. Não use funções de texto que possam alterar bytes ou codificação.

## Segurança do `ZuptSecureBuffer`

`ZuptSecureBuffer` aloca memória nativa e a preenche com zeros quando `zeroize()` é chamado ou quando o objeto é destruído. Isso reduz a permanência do conteúdo naquele buffer específico.

O PHP pode manter cópias temporárias em strings, logs, exceções ou estruturas internas. Portanto, o exemplo não oferece uma garantia absoluta de eliminação de todos os vestígios da informação no processo.

## Observação sobre Windows

A ABI atual retorna buffers alocados por `malloc()` e não fornece uma função pública `zupt_free()`. Para evitar liberar memória com um runtime C incompatível, estes exemplos bloqueiam a execução no Windows. Uma evolução recomendada da ABI é exportar:

```c
void zupt_free(void *ptr);
```

Assim PHP, Node.js e outras linguagens poderão devolver buffers à mesma biblioteca de forma portátil.

## Licença

SPDX-License-Identifier: MIT
