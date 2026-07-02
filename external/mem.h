#pragma once
#include <windows.h>
#include <cstdint>
#include <iostream>
#include <string>
#include <memory>
#include <cstring>

#include "log.h"

#ifndef DMA_BUILD

extern DWORD64 baseAddress;

template <class dataType>
inline dataType read(DWORD64 addressToRead)
{
	dataType rpmBuffer{};
	__try {
		rpmBuffer = *(dataType*)addressToRead;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {}
	return rpmBuffer;
}

template <class dataType>
inline void write(dataType valToWrite, DWORD64 addressToWrite)
{
	__try {
		*(dataType*)addressToWrite = valToWrite;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {}
}

inline void read_buffer(DWORD64 addressToRead, void* buffer, size_t size)
{
	__try {
		memcpy(buffer, (void*)addressToRead, size);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		memset(buffer, 0, size);
	}
}

namespace Memory
{
	extern void init();
}

#endif
