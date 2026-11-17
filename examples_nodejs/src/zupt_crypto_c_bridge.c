/* Keep the C and C++ crypto translation units on distinct object basenames.
 * Otherwise make/node-gyp may rebuild zupt_crypto.o from the newer .cpp file. */
#include "../../src/zupt_crypto.c"
