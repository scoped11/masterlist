#ifndef UNITY_H
#define UNITY_H

#include "../unturned.h"
#include "transform.h"

// ---------------------------------------------------------------------------
// Unity engine type wrappers — thin C++ classes mirroring Unity's internal
// managed/native objects as they appear in process memory.
//
// Key chain for getting a world position from any MonoBehaviour:
//   MonoBehaviour -> gameObject() -> GameObject -> transform() -> TransformInternal
//   TransformInternal::position() walks the parent hierarchy to produce
//   the final world-space position (see transform.h for the full algorithm).
// ---------------------------------------------------------------------------

namespace Unity
{
	class Transform;
	class GameObject;

	// -----------------------------------------------------------------------
	// Array<T> — mirrors System.Collections.Generic.List<T> in Mono memory.
	//
	// Mono List<T> layout (64-bit):
	//   +0x00  MonoObject header
	//   +0x10  T[] _items        (managed array pointer)
	//   +0x18  int _size         (element count)
	//
	// The _items managed array itself has:
	//   +0x00  MonoObject header (16 bytes)
	//   +0x10  int length
	//   +0x18  padding
	//   +0x20  T[0], T[1], ...   (first element starts at offset 0x20)
	// -----------------------------------------------------------------------
	template <typename T>
	class Array
	{
	public:
		// Returns the number of elements in the list (_size field).
		inline uint32_t Count()
		{
			return read<uint32_t>(THISPTR + 0x18);
		}

		// Returns element at 'index' from the backing array.
		// Reads the _items pointer, then indexes into the managed array
		// (elements start at offset 0x20 past the managed array header).
		inline T Get(uint32_t index)
		{
			return read<T>(read<uintptr_t>(THISPTR + 0x10) + 0x20 + (index * sizeof(T)));
		}

		// youd prob want a method to just read the whole array into a vector here
	};

	// -----------------------------------------------------------------------
	// GameObject — Unity's base scene object.
	//
	// transform() walks the native object store:
	//   this+0x30 -> NativeObjectStore -> +0x08 -> Transform native ptr
	// The returned TransformInternal wraps the native transform and provides
	// position(), rotation(), forward(), etc. entirely via memory reads.
	// -----------------------------------------------------------------------
	class GameObject
	{
	public:
		TransformInternal transform();
	};
}

#endif
