package main

/*
#cgo CFLAGS: -I../include -D_DEFAULT_SOURCE
#cgo LDFLAGS: -L../build -lzupt

#include <stdlib.h>
#include "zupt_cxx.h"
#include "zupt.h"
#include "zupt_keccak.h"
*/
import "C"

import (
	"errors"
	"unsafe"
)

const (
	MLKEMPublicKeyBytes  = 1184
	MLKEMSecretKeyBytes  = 2400
	MLKEMCiphertextBytes = 1088
	MLKEMSSBytes         = 32

	X25519KeyBytes = 32

	HybridPubKeySize    = 1224
	HybridPrivKeySize   = 3656
	HybridEncHeaderSize = 1137

	AESKeySize   = 32
	AESNonceSize = 16
	HMACSize     = 32
)

type KeyPair struct {
	PublicKey []byte
	SecretKey []byte
}

type KeyGenerator struct{}

func NewKeyGenerator() *KeyGenerator {
	return &KeyGenerator{}
}

func (g *KeyGenerator) GenerateKeyPair() (*KeyPair, error) {
	pub := make([]byte, HybridPubKeySize)
	priv := make([]byte, HybridPrivKeySize)
	if C.zupt_hybrid_keygen_c(
		(*C.uint8_t)(unsafe.Pointer(&pub[0])),
		(*C.uint8_t)(unsafe.Pointer(&priv[0])),
	) != 0 {
		return nil, errors.New("failed to generate key pair")
	}
	return &KeyPair{PublicKey: pub, SecretKey: priv}, nil
}

func (g *KeyGenerator) SaveKeyPair(kp *KeyPair, filename string) error {
	return WriteFile(filename, kp.SecretKey)
}

func (g *KeyGenerator) LoadKeyPair(filename string) (*KeyPair, error) {
	priv, err := ReadFile(filename)
	if err != nil {
		return nil, err
	}
	if len(priv) < HybridPrivKeySize {
		return nil, errors.New("key file too small for a private key")
	}
	pub, err := exportPublicKeyBytes(priv)
	if err != nil {
		return nil, err
	}
	return &KeyPair{PublicKey: pub, SecretKey: priv}, nil
}

func (g *KeyGenerator) LoadPublicKey(filename string) ([]byte, error) {
	data, err := ReadFile(filename)
	if err != nil {
		return nil, err
	}
	if len(data) < HybridPubKeySize {
		return nil, errors.New("key file too small for a public key")
	}
	return data[:HybridPubKeySize], nil
}

func (g *KeyGenerator) ExportPublicKey(privFile, pubFile string) error {
	priv, err := ReadFile(privFile)
	if err != nil {
		return err
	}
	if len(priv) < HybridPrivKeySize {
		return errors.New("private key file too small")
	}
	pub, err := exportPublicKeyBytes(priv)
	if err != nil {
		return err
	}
	return WriteFile(pubFile, pub)
}

func exportPublicKeyBytes(privKey []byte) ([]byte, error) {
	if len(privKey) < HybridPrivKeySize {
		return nil, errors.New("private key too small")
	}
	pub := make([]byte, HybridPubKeySize)
	if C.zupt_hybrid_export_pubkey_c(
		(*C.uint8_t)(unsafe.Pointer(&privKey[0])),
		(*C.uint8_t)(unsafe.Pointer(&pub[0])),
	) != 0 {
		return nil, errors.New("failed to export public key")
	}
	return pub, nil
}

type Encryptor struct {
	publicKey []byte
}

func NewEncryptor(publicKey []byte) (*Encryptor, error) {
	if len(publicKey) != HybridPubKeySize {
		return nil, errors.New("invalid public key size")
	}
	return &Encryptor{publicKey: publicKey}, nil
}

func (e *Encryptor) HeaderSize() int {
	return HybridEncHeaderSize
}

func (e *Encryptor) Encrypt(data []byte) ([]byte, []byte, error) {
	encHeader := make([]byte, HybridEncHeaderSize)
	hdrLen := C.size_t(len(encHeader))
	var ctLen C.size_t

	var p *C.uint8_t
	if len(data) > 0 {
		p = (*C.uint8_t)(unsafe.Pointer(&data[0]))
	}

	ctPtr := C.zupt_hybrid_encrypt(
		(*C.uint8_t)(unsafe.Pointer(&e.publicKey[0])),
		C.size_t(len(e.publicKey)),
		p,
		C.size_t(len(data)),
		(*C.uint8_t)(unsafe.Pointer(&encHeader[0])),
		&hdrLen,
		&ctLen,
	)
	if ctPtr == nil {
		return nil, nil, errors.New("encryption failed")
	}
	defer C.free(unsafe.Pointer(ctPtr))
	ciphertext := C.GoBytes(unsafe.Pointer(ctPtr), C.int(ctLen))
	return ciphertext, encHeader[:int(hdrLen)], nil
}

func (e *Encryptor) EncryptFile(filename string) ([]byte, []byte, error) {
	data, err := ReadFile(filename)
	if err != nil {
		return nil, nil, err
	}
	return e.Encrypt(data)
}

func (e *Encryptor) EncryptSecure(buffer *SecureBuffer) ([]byte, []byte, error) {
	return e.Encrypt(buffer.Data())
}

type Decryptor struct {
	privateKey []byte
}

func NewDecryptor(privateKey []byte) (*Decryptor, error) {
	if len(privateKey) != HybridPrivKeySize {
		return nil, errors.New("invalid private key size")
	}
	return &Decryptor{privateKey: privateKey}, nil
}

func (d *Decryptor) Decrypt(ciphertext, encHeader []byte) ([]byte, error) {
	var ptLen C.size_t

	var pCt *C.uint8_t
	if len(ciphertext) > 0 {
		pCt = (*C.uint8_t)(unsafe.Pointer(&ciphertext[0]))
	}
	var pHdr *C.uint8_t
	if len(encHeader) > 0 {
		pHdr = (*C.uint8_t)(unsafe.Pointer(&encHeader[0]))
	}

	ptPtr := C.zupt_hybrid_decrypt(
		(*C.uint8_t)(unsafe.Pointer(&d.privateKey[0])),
		C.size_t(len(d.privateKey)),
		pCt,
		C.size_t(len(ciphertext)),
		pHdr,
		C.size_t(len(encHeader)),
		&ptLen,
	)
	if ptPtr == nil {
		return nil, errors.New("decryption failed (wrong key or corrupted data)")
	}
	defer C.free(unsafe.Pointer(ptPtr))
	return C.GoBytes(unsafe.Pointer(ptPtr), C.int(ptLen)), nil
}

func (d *Decryptor) DecryptFile(filename string, encHeader []byte) ([]byte, error) {
	ciphertext, err := ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return d.Decrypt(ciphertext, encHeader)
}

func (d *Decryptor) DecryptSecure(ciphertext, encHeader []byte) (*SecureBuffer, error) {
	plaintext, err := d.Decrypt(ciphertext, encHeader)
	if err != nil {
		return nil, err
	}
	return NewSecureBuffer(plaintext), nil
}

type SecureBuffer struct {
	data []byte
}

func NewSecureBuffer(data []byte) *SecureBuffer {
	buf := make([]byte, len(data))
	copy(buf, data)
	return &SecureBuffer{data: buf}
}

func NewSecureBufferSize(size int) *SecureBuffer {
	return &SecureBuffer{data: make([]byte, size)}
}

func (b *SecureBuffer) Data() []byte {
	return b.data
}

func (b *SecureBuffer) Size() int {
	return len(b.data)
}

func (b *SecureBuffer) Len() int {
	return len(b.data)
}

func (b *SecureBuffer) ToBytes() []byte {
	out := make([]byte, len(b.data))
	copy(out, b.data)
	return out
}

func (b *SecureBuffer) String() string {
	return string(b.data)
}

func (b *SecureBuffer) Zeroize() {
	for i := range b.data {
		b.data[i] = 0
	}
}

func RandomBytes(size int) []byte {
	buf := make([]byte, size)
	if size > 0 {
		C.zupt_random_bytes((*C.uint8_t)(unsafe.Pointer(&buf[0])), C.size_t(size))
	}
	return buf
}

func Sha256(data []byte) []byte {
	hash := make([]byte, 32)
	var p *C.uint8_t
	if len(data) > 0 {
		p = (*C.uint8_t)(unsafe.Pointer(&data[0]))
	}
	C.zupt_sha256(p, C.size_t(len(data)), (*C.uint8_t)(unsafe.Pointer(&hash[0])))
	return hash
}

func Sha3_512(data []byte) []byte {
	hash := make([]byte, 64)
	var p *C.uint8_t
	if len(data) > 0 {
		p = (*C.uint8_t)(unsafe.Pointer(&data[0]))
	}
	C.zupt_sha3_512(p, C.size_t(len(data)), (*C.uint8_t)(unsafe.Pointer(&hash[0])))
	return hash
}

func SecureWipe(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

func ReadFile(path string) ([]byte, error) {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	var size C.size_t
	data := C.zupt_read_file(cPath, &size)
	if data == nil {
		return nil, errors.New("failed to read file: " + path)
	}
	defer C.free(unsafe.Pointer(data))
	return C.GoBytes(unsafe.Pointer(data), C.int(size)), nil
}

func WriteFile(path string, data []byte) error {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	var pData *C.uint8_t
	if len(data) > 0 {
		pData = (*C.uint8_t)(unsafe.Pointer(&data[0]))
	}
	if C.zupt_write_file(cPath, pData, C.size_t(len(data))) != 0 {
		return errors.New("failed to write file: " + path)
	}
	return nil
}
