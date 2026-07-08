#pragma once
#ifndef Log
#define Log(Arg, ...) (printf("[unturned] " Arg "\n", __VA_ARGS__))
#endif
