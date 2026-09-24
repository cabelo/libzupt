# Histórico de Alterações do libzupt

## v1.0.14 (2026-09-24)

- Authenticate empty messages and reject missing ciphertext, forged zero-length
  terminators, reordered/replayed blocks and changes to the header nonce.
- Check record bounds before allocating or decrypting payloads.
- Keep POSIX private-key writes on one checked descriptor with mode 0600;
  reject symbolic links, hard links and nonregular files.
- Wipe SecureBuffer storage before move assignment and leave moved-from buffers empty.
- Report the libzupt version consistently and install usable CMake imported targets.
- Keep test assertions enabled in Release builds; add authentication, key-storage,
  secure-buffer and relocated-package regression coverage.
- Validate release tags, restrict CI permissions, pin actions and report actual
  build/test results. Package signed-tag sources with level-9 solid compression,
  archive comments, extraction verification and SHA-256 checksums.
- Add English and Brazilian Portuguese build, API, security and release guides.

Compatibility: empty messages now require a 52-byte authenticated ciphertext;
legacy zero-byte ciphertext is rejected. Nonempty record layouts are unchanged.
The format still cannot detect removal of complete trailing blocks; applications
requiring completeness need independently authenticated length/digest metadata.
This release is not a cryptographic certification or a complete binding audit.


## Não lançado

### Segurança
- Chaves não são mais gravadas em arquivos temporários previsíveis em `/tmp`
  durante a criptografia/descriptografia em memória. As funções de
  criptografia/descriptografia agora derivam as chaves diretamente do buffer
  em memória (`zupt_hybrid_encrypt_init_mem` / `zupt_hybrid_decrypt_init_mem`),
  eliminando um vetor de ataque por symlink e o vazamento da chave privada em
  disco (que anulava a proteção `mlock`).
- Arquivos de chave privada gerados agora são criados com permissões `0600`
  (somente o dono), tanto na API C (`zupt_hybrid_keygen`) quanto na API C++
  (`KeyGenerator::saveKeyPair`), em vez de herdar o modo padrão do `umask`.

### Correções
- Corrigida extensão de sinal/comportamento indefinido na leitura do tamanho
  do bloco durante a descriptografia: cada byte é convertido para `size_t`
  antes do deslocamento, evitando um `block_len` inválido (enorme).
- Removidas as funções mortas e incorretas `zupt_hybrid_derive_keys` (que
  ignorava o segredo X25519, produzindo chaves que o lado de descriptografia
  nunca reproduziria) e `zupt_hybrid_decrypt_derive_keys`, ambas sem uso.

## v1.5.0 (2026-03-29)

### Novidades
- Versão inicial do libzupt como biblioteca dinâmica C++
- Suporte completo para criptografia híbrida pós-quântica (ML-KEM-768 + X25519)
- API C++ moderna com exceções e RAII
- Suporte para criptografia de arquivos e memória
- Classe `SecureBuffer` para armazenamento seguro de dados sensíveis

### Funcionalidades
- Geração de chaves híbridas (ML-KEM-768 + X25519)
- Exportação de chaves públicas
- Salvar/carregar chaves de arquivos
- Criptografia de dados em memória
- Criptografia de arquivos
- Descriptografia de dados em memória
- Descriptografia de arquivos
- Limpagem segura de memória

### Especificações
- **Tamanho da chave pública**: 1224 bytes
- **Tamanho da chave privada**: 2504 bytes
- **Tamanho do header de criptografia**: 1137 bytes
- **Tamanho do ciphertext do ML-KEM**: 1088 bytes

### Algoritmos
- **ML-KEM-768**: Algoritmo de encapsulamento de chave pós-quântico (FIPS 203)
- **X25519**: Diffie-Hellman elíptico de curva 25519 (RFC 7748)
- **SHA3-512**: Derivação de chaves
- **AES-256-CTR**: Criptografia de dados
- **HMAC-SHA256**: Autenticação de mensagens

## Detalhes da Implementação

### Arquitetura
```
libzupt/
├── include/
│   ├── zupt.hpp      # C++ API principal
│   └── zupt_cxx.h    # C API para wrappers
├── src/
│   ├── zupt_crypto.cpp  # Implementação C++ da API
│   └── zupt_cxx.c       # Wrapper C para funções C++
├── examples/          # Exemplos de uso
├── tests/            # Suite de testes
├── CMakeLists.txt    # Build configuration
└── README.md         # Documentação
```

### Segurança
- Limpagem automática de memória sensível
- Comparação constante para prevenir ataques de tempo
- Encapsulamento implícito (implicit rejection)
- CSPRNG do sistema para aleatoriedade criptográfica