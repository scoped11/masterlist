#pragma once
#include <cstdint>
#include <corecrt_math.h>

// ---------------------------------------------------------------------------
// Transform internals — rebuilt from Unity's native TransformHierarchy.
//
// Reference: https://www.unknowncheats.me/forum/escape-from-tarkov/618045-rebuilt-transform-methods.html
//
// Unity stores transform data in SoA (Structure-of-Arrays) buffers inside
// a TransformHierarchy.  Each transform has an index into these buffers:
//   - localTransforms[index] = trsX { translation, rotation (quat), scale }
//   - parentIndices[index]   = parent's index (-1 for root)
//
// To compute a world position from a local position, we walk the parent
// chain applying each parent's rotation, scale, and translation until we
// reach the root (index == -1).
//
// IMPORTANT: make sure your vector multiplication operators match the ones
// here.  The quaternion-vector multiply (vector4 * vector3) must produce
// the correct rotated vector, or positions will be wrong.
// ---------------------------------------------------------------------------

// optional: use your own vector3/vector4 structs
// IMPORTANT: make sure your multiplication operators are the same, if theyre not you might get funky values

// ---------------------------------------------------------------------------
// vector3 — 3D float vector with basic arithmetic and normalization.
// ---------------------------------------------------------------------------
struct vector3
{
	float x, y, z;

	inline vector3 operator*(float rhs) const { return { x * rhs, y * rhs, z * rhs }; }
	inline vector3 operator+(const vector3& rhs) const { return { x + rhs.x, y + rhs.y, z + rhs.z }; }
	inline vector3 operator-(const vector3& rhs) const { return { x - rhs.x, y - rhs.y, z - rhs.z }; }
	inline vector3 operator*(const vector3& rhs) const { return { x * rhs.x, y * rhs.y, z * rhs.z }; }
	inline vector3 operator/(const vector3& rhs) const { return { x / rhs.x, y / rhs.y, z / rhs.z }; }
	inline vector3 operator-() const { return { -x, -y, -z }; }

	// normalized
	inline vector3 normalized() const
	{
		float len = sqrtf(x * x + y * y + z * z);
		return { x / len, y / len, z / len };
	}

	std::string toString()
	{
		return "(" + std::to_string(x) + ", " + std::to_string(y) + ", " + std::to_string(z) + ")";
	}
};

// ---------------------------------------------------------------------------
// vector4 — quaternion / 4D vector.
//
// The vector4 * vector4 operator implements Hamilton quaternion multiplication
// (used for composing rotations up the parent chain).
//
// The vector4 * vector3 operator rotates a vector3 by this quaternion using
// the expanded rotation matrix form (avoids the double-cross-product formula
// for better numerical precision with external reads).
//
// conjugate() returns the inverse rotation (for InverseTransformDirection).
// ---------------------------------------------------------------------------
struct vector4
{
	float x, y, z, w;
	inline vector4 operator*(float rhs) const { return { x * rhs, y * rhs, z * rhs, w * rhs }; }
	inline vector4 operator+(const vector4& rhs) const { return { x + rhs.x, y + rhs.y, z + rhs.z, w + rhs.w }; }
	inline vector4 operator-(const vector4& rhs) const { return { x - rhs.x, y - rhs.y, z - rhs.z, w - rhs.w }; }
	inline vector4 operator/(const vector4& rhs) const { return { x / rhs.x, y / rhs.y, z / rhs.z, w / rhs.w }; }
	inline vector4 operator-() const { return { -x, -y, -z, -w }; }

	// Hamilton product: composes two quaternion rotations.
	inline vector4 operator*(const vector4& rhs) const
	{
		return {
			w * rhs.x + x * rhs.w + y * rhs.z - z * rhs.y,
			w * rhs.y + y * rhs.w + z * rhs.x - x * rhs.z,
			w * rhs.z + z * rhs.w + x * rhs.y - y * rhs.x,
			w * rhs.w - x * rhs.x - y * rhs.y - z * rhs.z
		};
	}

	// Rotate a vector3 by this quaternion (expanded rotation matrix form).
	inline vector3 operator*(const vector3& rhs) const
	{
		float x = this->x * 2.0F;
		float y = this->y * 2.0F;
		float z = this->z * 2.0F;
		float xx = this->x * x;
		float yy = this->y * y;
		float zz = this->z * z;
		float xy = this->x * y;
		float xz = this->x * z;
		float yz = this->y * z;
		float wx = this->w * x;
		float wy = this->w * y;
		float wz = this->w * z;

		vector3 res;
		res.x = (1.0f - (yy + zz)) * rhs.x + (xy - wz) * rhs.y + (xz + wy) * rhs.z;
		res.y = (xy + wz) * rhs.x + (1.0f - (xx + zz)) * rhs.y + (yz - wx) * rhs.z;
		res.z = (xz - wy) * rhs.x + (yz + wx) * rhs.y + (1.0f - (xx + yy)) * rhs.z;

		return res;
	}

	// Quaternion conjugate = inverse rotation (for unit quaternions).
	inline vector4 conjugate() const { return { -x, -y, -z, w }; }
};

// ---------------------------------------------------------------------------
// TransformInternal — wraps a Unity native Transform pointer and provides
// position/rotation/direction methods entirely through memory reads.
//
// Construction:
//   TransformInternal t(nativeTransformPtr);
//   - Reads TransformAccess (hierarchy pointer + index) from ptr+0x38
//   - Reads localTransforms buffer address from hierarchy+0x18
//   - Reads parentIndices buffer address from hierarchy+0x20
//
// position() and rotation() walk the parent chain from this transform's
// index up to the root, accumulating transforms at each level.
// ---------------------------------------------------------------------------
class TransformInternal
{
#pragma region Internal Structs
	// TransformAccess — read from the native Transform at offset 0x38.
	// hierarchyAddr points to the TransformHierarchy that owns this transform.
	// index is this transform's slot in the hierarchy's SoA buffers.
	struct TransformAccess
	{
		uintptr_t hierarchyAddr;
		int index;
	};

	// trsX — one element of the localTransforms buffer.
	// Layout matches Unity's internal TransformData struct:
	//   vector3 translation  (12 bytes)
	//   4 bytes padding
	//   vector4 rotation     (16 bytes) — quaternion
	//   vector3 scale        (12 bytes)
	//   4 bytes padding
	// Total: 48 bytes per transform.
	class trsX
	{
	public:
		vector3 t;          // local translation
	private:
		char pad_000C[4];
	public:
		vector4 q;          // local rotation (quaternion)
		vector3 s;          // local scale
	private:
		char pad_0014[4];
	};
#pragma endregion
#pragma region List
	// ResizableBuffer<T> — growable host-side buffer that bulk-reads
	// transform data from the target process.  Avoids per-element RPM
	// calls by reading the entire hierarchy in one read_buffer() call.
	template <typename T>
	class ResizableBuffer
	{
	public:
		T* buffer;
		int capacity;

		inline ResizableBuffer() : buffer(nullptr), capacity(100)
		{
			buffer = new T[capacity];
		}

		// Reads 'capacity' elements from 'address' into the local buffer,
		// growing the buffer if needed.
		inline void updateBuffer(uintptr_t address, int capacity)
		{
			if (capacity > this->capacity)
			{
				if (buffer)
					delete[] buffer;

				buffer = new T[capacity];
				this->capacity = capacity;
			}

			read_buffer(address, (void*)buffer, sizeof(T) * capacity);
		}

		inline T& operator[](int index)
		{
			if (index >= capacity)
				printf("index out of bounds: forgot to call updateBuffer?\n");
			return buffer[index];
		}
	};
#pragma endregion
	// Shared buffers for all TransformInternal instances.
	// NOTE: not thread-safe — if multithreaded, add a mutex or per-thread buffers.
	static inline ResizableBuffer<trsX> trsBuffer;
	static inline ResizableBuffer<int> parentIndicesBuffer;

	uintptr_t address;              // native Transform pointer in target process

	TransformAccess transformAccess;
	uintptr_t localTransforms;      // pointer to the trsX[] buffer in target
	uintptr_t parentIndices;        // pointer to the int[] parent index buffer

	// Bulk-read the trsX buffer up to (and including) this transform's index.
	// might be beneficial to call these yourself instead of in every function, if you happen to use multiple functions that call this?
	inline void updateTrsXBuffer()
	{
		// feel free to change how new max cap is calc'd. could be index * 2 or something to avoid reallocs
		trsBuffer.updateBuffer(localTransforms, transformAccess.index + 1);
	}

	// Bulk-read the parent indices buffer.
	inline void updateParentIndicesBuffer()
	{
		parentIndicesBuffer.updateBuffer(parentIndices, transformAccess.index + 1);
	}

public:
	// Construct from a native Transform pointer.
	// Reads the TransformAccess struct and resolves the hierarchy buffer addresses.
	inline TransformInternal(uintptr_t address)
	{
		this->address = address;
		this->transformAccess = read<TransformAccess>(address + 0x38);
		this->localTransforms = read<uintptr_t>(transformAccess.hierarchyAddr + 0x18);
		this->parentIndices = read<uintptr_t>(transformAccess.hierarchyAddr + 0x20);
	}

	// ------------------------------
	// actual methods
	// ------------------------------

	// Read this transform's local position directly (single element read).
	inline vector3 localPosition()
	{
		return read<trsX>(localTransforms + transformAccess.index * sizeof(trsX)).t;
	}

	// Write a new local position for this transform.
	inline void setLocalPosition(vector3 pos)
	{
		write<vector3>(pos, localTransforms + transformAccess.index * sizeof(trsX));
	}

	// Read this transform's local scale.
	inline vector3 localScale()
	{
		return read<trsX>(localTransforms + transformAccess.index * sizeof(trsX)).s;
	}

	// Read this transform's local rotation quaternion.
	inline vector4 localRotation()
	{
		return read<trsX>(localTransforms + transformAccess.index * sizeof(trsX)).q;
	}

	// Compute world-space position by walking the parent chain.
	//
	// Algorithm:
	//   1. Start with this transform's local translation
	//   2. Walk up parentIndices until root (-1)
	//   3. At each parent: rotate by parent.q, scale by parent.s, translate by parent.t
	//
	// This reproduces what Unity's Transform.position getter does internally.
	inline vector3 position()
	{
		updateTrsXBuffer();
		updateParentIndicesBuffer();

		vector3 worldPos = trsBuffer[transformAccess.index].t;
		int index = parentIndicesBuffer[transformAccess.index];
		while (index >= 0)
		{
			auto parent = trsBuffer[index];

			worldPos = parent.q * worldPos;   // rotate by parent's quaternion
			worldPos = worldPos * parent.s;   // scale by parent's scale
			worldPos = worldPos + parent.t;   // translate by parent's position

			index = parentIndicesBuffer[index];
		}

		return worldPos;
	}

	// Compute world-space rotation by composing quaternions up the parent chain.
	inline vector4 rotation()
	{
		updateTrsXBuffer();
		updateParentIndicesBuffer();

		vector4 worldRot = trsBuffer[transformAccess.index].q;
		int index = parentIndicesBuffer[transformAccess.index];
		while (index >= 0)
		{
			auto parent = trsBuffer[index];

			worldRot = parent.q * worldRot;   // compose parent rotation

			index = parentIndicesBuffer[index];
		}

		return worldRot;
	}


	// World-space right axis (+X local rotated into world).
	inline vector3 right()
	{
		static vector3 right = { 1, 0, 0 };
		return rotation() * right;
	}

	// World-space up axis (+Y local rotated into world).
	inline vector3 up()
	{
		static vector3 up = { 0, 1, 0 };
		return rotation() * up;
	}

	// World-space forward axis (+Z local rotated into world).
	inline vector3 forward()
	{
		static vector3 forward = { 0, 0, 1 };
		return rotation() * forward;
	}

	// local to world — rotates a direction vector from local space to world space.
	inline vector3 TransformDirection(vector3 localDirection)
	{
		return rotation() * localDirection;
	}

	// world to local — rotates a direction vector from world space to local space
	// using the conjugate (inverse) of the world rotation.
	inline vector3 InverseTransformDirection(vector3 worldDirection)
	{
		return rotation().conjugate() * worldDirection;
	}

	// local to world — transforms a point (applies scale, rotation, translation
	// at every level of the hierarchy starting from this transform).
	inline vector3 TransformPoint(vector3 localPoint)
	{
		updateTrsXBuffer();
		updateParentIndicesBuffer();

		vector3 worldPos = localPoint;
		int index = transformAccess.index;
		while (index >= 0)
		{
			auto parent = trsBuffer[index];

			worldPos = worldPos * parent.s;   // scale
			worldPos = parent.q * worldPos;   // rotate
			worldPos = worldPos + parent.t;   // translate

			index = parentIndicesBuffer[index];
		}

		return worldPos;
	}

	// world to local — inverse of TransformPoint: removes world transform
	// to express a world-space point in this transform's local space.
	inline vector3 InverseTransformPoint(vector3 worldPoint)
	{
		updateTrsXBuffer();
		updateParentIndicesBuffer();

		vector3 worldPos = trsBuffer[transformAccess.index].t;
		vector4 worldRot = trsBuffer[transformAccess.index].q;

		vector3 localScale = trsBuffer[transformAccess.index].s;

		int index = parentIndicesBuffer[transformAccess.index];
		while (index >= 0)
		{
			auto parent = trsBuffer[index];

			worldPos = parent.q * worldPos;
			worldPos = worldPos * parent.s;
			worldPos = worldPos + parent.t;

			worldRot = parent.q * worldRot;

			index = parentIndicesBuffer[index];
		}

		// Undo world rotation then divide by local scale
		vector3 local = worldRot.conjugate() * (worldPoint - worldPos);
		return local / localScale;

		return worldPos;
	}
};
