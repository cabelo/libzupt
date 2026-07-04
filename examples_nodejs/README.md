# libzupt Node.js Examples

Este diretório contém exemplos de uso da biblioteca **libzupt** em Node.js.

A libzupt é uma biblioteca de criptografia híbrida pós-quanto (ML-KEM-768 + X25519) para compactação e criptografia de arquivos.

## Requisitos

- Node.js >= 14.0.0
- npm

## Instalação

```bash
cd examples_nodejs

rm -rf build
rm -rf node_modules
rm -f package-lock.json

# Instalar dependências (opcional para exemplos puro-JS)
npm install
npm run build

```

## Exemplos

### 1. Exemplo Básico (`example_basic.js`)

Demonstra geração de chaves, criptografia e descriptografia de dados em memória.

```bash
node example_basic.js
```

### 2. Exemplo de Arquivo (`example_file.js`)

Demonstra criptografia e descriptografia de arquivos.

```bash
# Gerar chaves
node example_file.js genkey key.pem

# Criptografar arquivo
node example_file.js encrypt key.pem.pub input.txt encrypted.zupt

# Descriptografar arquivo
node example_file.js decrypt key.pem encrypted.zupt decrypted.txt

# Executar teste completo
node example_file.js test
```

### 3. Exemplo de Geração de Chaves (`example_keygen.js`)

Demonstra como gerar, salvar, carregar e gerenciar pares de chaves.

```bash
node example_keygen.js
```

### 4. Exemplo de SecureBuffer (`example_secure_buffer.js`)

Demonstra o uso de `SecureBuffer` para dados sensíveis que devem ser limpos da memória.

```bash
node example_secure_buffer.js
```

### 5. Exemplo de Números Aleatórios (`example_random.js`)

Demonstra geração de bytes aleatórios criptograficamente seguros.

```bash
node example_random.js
```

## API

### zupt.SecureBuffer

```javascript
const zupt = require('./index');

// Criar SecureBuffer com tamanho específico
const buf = new zupt.SecureBuffer(256);

// Criar SecureBuffer e copiar dados
const buf = new zupt.SecureBuffer(256);
buf.copy(sensitiveData);

// Copiar dados
buf.copy(data);

// Ler como Buffer
const data = buf.toBuffer();

// Tamanho
const size = buf.size;

// Limpar buffer (zeroize)
buf.zeroize();

// Destruir buffer
buf.destroy();
```

### zupt.KeyGenerator

```javascript
const zupt = require('./index');
const keygen = new zupt.KeyGenerator();

// Gerar novo par de chaves
const keypair = keygen.generateKeyPair();
// keypair = { publicKey: Buffer, secretKey: Buffer }

// Salvar chaves em arquivo
keygen.saveKeyPair(keypair, 'filename.key');

// Carregar chaves de arquivo
const keypair = keygen.loadKeyPair('filename.key');

// Exportar chave pública
keygen.exportPublicKey('private.key', 'public.key');

// Carregar chave pública
const publicKey = keygen.loadPublicKey('public.key');
```

### zupt.Encryptor

```javascript
const zupt = require('./index');
const encryptor = new zupt.Encryptor(publicKey);

// Criptografar dados em memória
const { ciphertext, encHeader } = encryptor.encryptMemory(data);

// Criptografar arquivo
const { ciphertext, encHeader } = encryptor.encryptFile('filename');

// Tamanho do header de criptografia
const headerSize = zupt.Encryptor.getEncryptionHeaderSize(); // 1137 bytes
```

### zupt.Decryptor

```javascript
const zupt = require('./index');
const decryptor = new zupt.Decryptor(privateKey);

// Descriptografar dados em memória
const decrypted = decryptor.decryptMemory(ciphertext, encHeader);

// Descriptografar arquivo
const decrypted = decryptor.decryptFile('encrypted.zupt', encHeader);

// Descriptografar com SecureBuffer
const secureDecrypted = decryptor.decryptMemorySecure(ciphertext, encHeader);
```

### zupt.randomBytes(size)

```javascript
const zupt = require('./index');
const randomBytes = zupt.randomBytes(32);
```

### zupt.getVersion()

```javascript
const zupt = require('./index');
const version = zupt.getVersion(); // '2.1.5'
```

## Formato das Chaves

As chaves são armazenadas no formato `.zupt-key`:

```
[4B]  "ZKEY" - Número mágico
[1B]  Versão (0x01)
[1B]  Flags (bit 0 = 1 se tem chave privada)
[2B]  Reservado
[1184B] Chave Pública ML-KEM-768
[32B]   Chave Pública X25519
[2400B] Chave Secreta ML-KEM-768 (chave privada)
[32B]   Chave Secreta X25519 (chave privada)
[8B]  Checksum XXH64
```

Tamanho total:
- Chave pública: 1224 bytes
- Chave privada: 3664 bytes

## Estrutura do Projeto

```
examples_nodejs/
├── index.js              # Módulo principal (JavaScript)
├── example_basic.js      # Exemplo básico de criptografia
├── example_file.js       # Exemplo de criptografia de arquivos
├── example_keygen.js     # Exemplo de geração de chaves
├── example_secure_buffer.js  # Exemplo de SecureBuffer
├── example_random.js     # Exemplo de geração de números aleatórios
└── README.md
```

## Notas sobre o Binding C++

Para usar a criptografia real com o libzupt (ML-KEM-768 + X25519), você precisa compilar o binding C++:

```bash
# Compilar o binding (opcional, se desejar usar a criptografia real)
node-gyp rebuild

# O binding gerará o arquivo build/Release/zupt.node
```

Os exemplos acima usam a implementação JavaScript como placeholder. Para usar a criptografia real, o binding C++ precisa ser compilado e carregado dinamicamente.

## Licença

MIT License - veja o arquivo LICENSE para detalhes.
