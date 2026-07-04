/*
 * Bridge file for node-gyp.
 *
 * Do not compile ../src/zupt_crypto.cpp directly together with
 * ../src/zupt_crypto.c because both can generate the same object name
 * zupt_crypto.o in node-gyp.
 */

#include "../../src/zupt_crypto.cpp"
