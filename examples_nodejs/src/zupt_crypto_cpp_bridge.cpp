/*
 * Bridge file for node-gyp.
 *
 * Both C and C++ crypto units use distinct bridge basenames, avoiding
 * node-gyp/make collisions between zupt_crypto.c and zupt_crypto.cpp.
 */

#include "../../src/zupt_crypto.cpp"
