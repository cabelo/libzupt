/*
 * libzupt - Python bindings with pybind11
 * SPDX-License-Identifier: MIT
 */

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/iostream.h>

#include "zupt.hpp"

namespace py = pybind11;

PYBIND11_MODULE(zupt, m) {
    m.doc() = "libzupt - Hybrid Post-Quantum Encryption Library";

    // Error codes
    py::enum_<zupt::ErrorCode>(m, "ErrorCode")
        .value("OK", zupt::ErrorCode::OK)
        .value("ERR_IO", zupt::ErrorCode::ERR_IO)
        .value("ERR_CORRUPT", zupt::ErrorCode::ERR_CORRUPT)
        .value("ERR_BAD_MAGIC", zupt::ErrorCode::ERR_BAD_MAGIC)
        .value("ERR_BAD_VERSION", zupt::ErrorCode::ERR_BAD_VERSION)
        .value("ERR_BAD_CHECKSUM", zupt::ErrorCode::ERR_BAD_CHECKSUM)
        .value("ERR_NOMEM", zupt::ErrorCode::ERR_NOMEM)
        .value("ERR_OVERFLOW", zupt::ErrorCode::ERR_OVERFLOW)
        .value("ERR_INVALID", zupt::ErrorCode::ERR_INVALID)
        .value("ERR_NOT_FOUND", zupt::ErrorCode::ERR_NOT_FOUND)
        .value("ERR_UNSUPPORTED", zupt::ErrorCode::ERR_UNSUPPORTED)
        .value("ERR_AUTH_FAIL", zupt::ErrorCode::ERR_AUTH_FAIL)
        .export_values();

    // ZuptError exception - create a simple Python exception class
    // Since we can't capture in register_exception_translator, we'll use RuntimeError
    // for all exceptions and provide a code() method on the exception object
    py::class_<zupt::ZuptError>(m, "ZuptError")
        .def(py::init<const zupt::ErrorCode, const std::string&>(), py::arg("code"), py::arg("msg") = "")
        .def("code", &zupt::ZuptError::code);

    // Register exception translator - simple RuntimeError for all exceptions
    // This allows catching RuntimeError in Python
    py::register_exception_translator([](std::exception_ptr p) {
        try {
            if (p) std::rethrow_exception(p);
        } catch (const zupt::ZuptError& e) {
            PyErr_SetString(PyExc_RuntimeError, e.what());
        } catch (const std::exception& e) {
            PyErr_SetString(PyExc_RuntimeError, e.what());
        }
    });

    // Constants
    m.attr("MLKEM_PUBLICKEYBYTES") = zupt::MLKEM_PUBLICKEYBYTES;
    m.attr("MLKEM_SECRETKEYBYTES") = zupt::MLKEM_SECRETKEYBYTES;
    m.attr("MLKEM_CIPHERTEXTBYTES") = zupt::MLKEM_CIPHERTEXTBYTES;
    m.attr("MLKEM_SSBYTES") = zupt::MLKEM_SSBYTES;
    m.attr("X25519_KEYBYTES") = zupt::X25519_KEYBYTES;
    m.attr("HYBRID_PUB_KEY_SIZE") = zupt::HYBRID_PUB_KEY_SIZE;
    m.attr("HYBRID_PRIV_KEY_SIZE") = zupt::HYBRID_PRIV_KEY_SIZE;
    m.attr("HYBRID_ENC_HEADER_SIZE") = zupt::HYBRID_ENC_HEADER_SIZE;
    m.attr("AES_KEY_SIZE") = zupt::AES_KEY_SIZE;
    m.attr("AES_NONCE_SIZE") = zupt::AES_NONCE_SIZE;
    m.attr("HMAC_SIZE") = zupt::HMAC_SIZE;

    // SecureBuffer class
    py::class_<zupt::SecureBuffer>(m, "SecureBuffer")
        .def(py::init<size_t>())
        .def(py::init([](py::object data) {
            // Try to handle bytes first
            try {
                py::bytes data_bytes = data.cast<py::bytes>();
                std::string data_str = data_bytes.cast<std::string>();
                return new zupt::SecureBuffer(
                    reinterpret_cast<const uint8_t*>(data_str.data()),
                    data_str.size()
                );
            } catch (...) {
                // Fall back to list of integers
                py::list data_list = data.cast<py::list>();
                std::vector<uint8_t> vec(data_list.size());
                for (size_t i = 0; i < data_list.size(); ++i) {
                    vec[i] = py::cast<uint8_t>(data_list[i]);
                }
                return new zupt::SecureBuffer(vec);
            }
        }))
        .def("size", &zupt::SecureBuffer::size)
        .def("data_ptr", (uint8_t*(zupt::SecureBuffer::*)()) &zupt::SecureBuffer::data)
        .def("data_ptr_const", (const uint8_t*(zupt::SecureBuffer::*)() const) &zupt::SecureBuffer::data)
        .def("to_bytes", &zupt::SecureBuffer::toVector)
        .def("to_string", &zupt::SecureBuffer::toString)
        .def("zeroize", &zupt::SecureBuffer::zeroize)
        .def("__len__", &zupt::SecureBuffer::size)
        .def("__repr__", [](const zupt::SecureBuffer& self) {
            return "<SecureBuffer size=" + std::to_string(self.size()) + ">";
        });

    // KeyPair struct
    py::class_<zupt::KeyPair>(m, "KeyPair")
        .def(py::init<>())
        .def_readonly("public_key", &zupt::KeyPair::public_key)
        .def_readonly("secret_key", &zupt::KeyPair::secret_key);

    // KeyGenerator class
    py::class_<zupt::KeyGenerator>(m, "KeyGenerator")
        .def(py::init<>())
        .def("generate_keypair", &zupt::KeyGenerator::generateKeyPair)
        .def("load_keypair", &zupt::KeyGenerator::loadKeyPair)
        .def("load_public_key", &zupt::KeyGenerator::loadPublicKey)
        .def("export_public_key", &zupt::KeyGenerator::exportPublicKey)
        .def("save_keypair", &zupt::KeyGenerator::saveKeyPair);

    // Encryptor class
    py::class_<zupt::Encryptor>(m, "Encryptor")
        .def(py::init<const std::vector<uint8_t>&>())
        .def("encrypt", [](zupt::Encryptor& self, py::object data) {
            py::bytes data_bytes = data.cast<py::bytes>();
            std::string data_str = data_bytes.cast<std::string>();
            auto result = self.encryptMemory(reinterpret_cast<const uint8_t*>(data_str.data()), data_str.size());
            return py::make_tuple(
                py::bytes(reinterpret_cast<const char*>(result.first.data()), result.first.size()),
                py::bytes(reinterpret_cast<const char*>(result.second.data()), result.second.size())
            );
        })
        .def("encrypt_memory", [](zupt::Encryptor& self, const uint8_t* data, size_t size) {
            auto result = self.encryptMemory(data, size);
            return py::make_tuple(
                py::bytes(reinterpret_cast<const char*>(result.first.data()), result.first.size()),
                py::bytes(reinterpret_cast<const char*>(result.second.data()), result.second.size())
            );
        })
        .def("encrypt_secure", [](zupt::Encryptor& self, const zupt::SecureBuffer& buffer) {
            return self.encryptMemory(buffer);
        })
        .def("encrypt_file", [](zupt::Encryptor& self, const std::string& filename) {
            auto [ciphertext, enc_header] = self.encryptFile(filename);
            return py::make_tuple(
                py::bytes(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size()),
                py::bytes(reinterpret_cast<const char*>(enc_header.data()), enc_header.size())
            );
        })
        .def_property_readonly_static("HEADER_SIZE", [](py::object) {
            return zupt::Encryptor::getEncryptionHeaderSize();
        });

    // Decryptor class
    py::class_<zupt::Decryptor>(m, "Decryptor")
        .def(py::init<const std::vector<uint8_t>&>())
        .def("decrypt", [](zupt::Decryptor& self, py::object ciphertext_obj, const std::vector<uint8_t>& enc_header) {
            py::bytes data_bytes;
            try {
                data_bytes = ciphertext_obj.cast<py::bytes>();
            } catch (...) {
                py::list data_list = ciphertext_obj.cast<py::list>();
                std::string data_str(data_list.size(), 0);
                for (size_t i = 0; i < data_list.size(); ++i) {
                    data_str[i] = static_cast<char>(py::cast<uint8_t>(data_list[i]));
                }
                data_bytes = py::bytes(data_str);
            }
            std::string data_str = data_bytes.cast<std::string>();
            std::vector<uint8_t> result = self.decryptMemory(reinterpret_cast<const uint8_t*>(data_str.data()), data_str.size(), enc_header);
            return py::bytes(reinterpret_cast<const char*>(result.data()), result.size());
        })
        .def("decrypt_memory", [](zupt::Decryptor& self, const uint8_t* ciphertext, size_t ciphertextSize,
                                   const std::vector<uint8_t>& enc_header) {
            return self.decryptMemory(ciphertext, ciphertextSize, enc_header);
        })
        .def("decrypt_secure", [](zupt::Decryptor& self, const std::vector<uint8_t>& ciphertext,
                                   const std::vector<uint8_t>& enc_header) {
            return self.decryptMemorySecure(ciphertext, enc_header);
        })
        .def("decrypt_file", [](zupt::Decryptor& self, const std::string& filename, py::object enc_header_obj) {
            std::vector<uint8_t> enc_header;
            try {
                py::bytes header_bytes = enc_header_obj.cast<py::bytes>();
                std::string header_str = header_bytes.cast<std::string>();
                enc_header.assign(header_str.begin(), header_str.end());
            } catch (...) {
                py::list header_list = enc_header_obj.cast<py::list>();
                enc_header.reserve(header_list.size());
                for (size_t i = 0; i < header_list.size(); ++i) {
                    enc_header.push_back(py::cast<uint8_t>(header_list[i]));
                }
            }
            std::vector<uint8_t> result = self.decryptFile(filename, enc_header);
            return py::bytes(reinterpret_cast<const char*>(result.data()), result.size());
        });

    // Helper functions
    m.def("random_bytes", &zupt::randomBytes);
    m.def("sha256", [](const std::vector<uint8_t>& data) {
        return zupt::sha256(data.data(), data.size());
    });
    m.def("sha3_512", &zupt::sha3_512);
    m.def("secure_wipe", &zupt::secureWipe);

    // Version info
    m.attr("__version__") = zupt::getVersion();
    m.attr("LIBRARY_NAME") = zupt::getLibraryName();
}