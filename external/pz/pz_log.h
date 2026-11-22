#pragma once
#include <cstdio>
#ifndef PZ_LOG
#define PZ_LOG(fmt, ...) printf("[pz_viewer] " fmt "\n", __VA_ARGS__)
#endif