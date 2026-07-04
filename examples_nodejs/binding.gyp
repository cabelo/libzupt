{
  "targets": [
    {
      "target_name": "zupt",
      "type": "loadable_module",
      "sources": [
        "src/zupt_napi.cpp",
        "../src/zupt_crypto.cpp",
        "../src/zupt_crypto.c",
        "../src/zupt_mlkem.c",
        "../src/zupt_x25519.c",
        "../src/zupt_sha256.c",
        "../src/zupt_keccak.c",
        "../src/zupt_aes256.c",
        "../src/zupt_xxh.c",
        "../src/zupt_mlock.c"
      ],
      "include_dirs": [
        "<!@(node -p \"require('node-addon-api').include\")",
        "../include"
      ],
      "dependencies": [
        "<!(node -p \"require('node-addon-api').gyp\")"
      ],
      "cflags!": [ "-fno-exceptions" ],
      "cflags_cc!": [ "-fno-exceptions" ],
      "defines": [ "NAPI_DISABLE_CPP_EXCEPTIONS" ],
      "conditions": [
        ["OS=='mac'", {
          "xcode_settings": {
            "GCC_ENABLE_CPP_EXCEPTIONS": "YES",
            "CLANG_CXX_LIBRARY": "libc++"
          }
        }]
      ]
    }
  ]
}
