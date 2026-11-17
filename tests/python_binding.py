import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(sys.argv[1]).resolve()))
import zupt

assert issubclass(zupt.ZuptError, RuntimeError)
keys = zupt.KeyGenerator().generate_keypair()
encryptor = zupt.Encryptor(keys.public_key)
decryptor = zupt.Decryptor(keys.secret_key)
for message in [b"", b"\x00", bytes(range(256))]:
    ciphertext, header = encryptor.encrypt(message)
    assert decryptor.decrypt(ciphertext, list(header)) == message
    altered = bytearray(ciphertext)
    altered[-1] ^= 1
    try:
        decryptor.decrypt(bytes(altered), list(header))
    except zupt.ZuptError:
        pass
    else:
        raise AssertionError("Altered ciphertext accepted")
print("Python binding: binary/empty roundtrips and typed authentication failures passed")
