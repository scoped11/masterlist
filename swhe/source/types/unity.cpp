#include "unity.h"
#include <emmintrin.h>

// ---------------------------------------------------------------------------
// GameObject::transform()
//
// Navigates Unity's internal native object layout to reach the Transform:
//   1. this+0x30  ->  NativeObjectStore (array of component native ptrs)
//   2. store+0x08 ->  first component = Transform native pointer
//
// The result is wrapped in a TransformInternal which reads the
// TransformHierarchy (localTransforms / parentIndices buffers) to compute
// world-space position and rotation without calling any engine functions.
// ---------------------------------------------------------------------------

namespace Unity
{
	TransformInternal GameObject::transform()
	{
		auto components = read<uintptr_t>(THISPTR + 0x30);
		return TransformInternal(read<uintptr_t>(components + 0x8));
	}
}
