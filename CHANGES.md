# Histórico de Alterações do libzupt

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