#pragma once
#include <cmath>
#include "mem.h"
#include "types/transform.h"

#ifndef M_PI
#define M_PI 3.14159265358979323846f
#endif

// Degree/radian conversion macros.
#define DEG2RAD(x) ((x) * (float)M_PI / 180.0f)
#define RAD2DEG(x) ((x) * 180.0f / (float)M_PI)

// ---------------------------------------------------------------------------
// Math utilities — distance, angle calculation, and world-to-screen projection
// for Unturned's coordinate system and camera convention.
//
// Unturned angle convention:
//   Pitch: 90 = horizontal, 0 = straight up, 180 = straight down
//   Yaw:   0 = north (+Z), increases clockwise toward east (+X)
// ---------------------------------------------------------------------------

namespace Math
{
	// 3D Euclidean distance between two points.
	inline float Distance(vector3 a, vector3 b)
	{
		vector3 d = a - b;
		return sqrtf(d.x * d.x + d.y * d.y + d.z * d.z);
	}

	// Horizontal distance (XZ plane only, ignoring height difference).
	inline float Distance2D(vector3 a, vector3 b)
	{
		float dx = a.x - b.x;
		float dz = a.z - b.z;
		return sqrtf(dx * dx + dz * dz);
	}

	// Calculate the pitch/yaw angles from src to dst in Unturned convention.
	// Returns: { pitch (90=horiz), yaw (0=north), 0 }
	// Returns angles in Unturned convention: pitch 90=horizontal, 0=up, 180=down
	inline vector3 CalcAngle(vector3 src, vector3 dst)
	{
		vector3 delta = dst - src;
		float hyp = sqrtf(delta.x * delta.x + delta.z * delta.z);
		float pitch = 90.0f - RAD2DEG(atan2f(delta.y, hyp));
		float yaw = RAD2DEG(atan2f(delta.x, delta.z));
		return { pitch, yaw, 0 };
	}

	// Normalize an angle to the [-180, 180] range.
	inline float NormalizeAngle(float angle)
	{
		while (angle > 180.0f) angle -= 360.0f;
		while (angle < -180.0f) angle += 360.0f;
		return angle;
	}

	// Calculate the angular distance (in degrees) between the current view
	// direction and the direction from src to dst.  Used for FOV-based
	// aimbot target selection (smaller = closer to crosshair).
	inline float AngleDiffFOV(vector3 src, vector3 dst, float yaw, float pitch)
	{
		vector3 desired = CalcAngle(src, dst);
		float dy = NormalizeAngle(desired.y - yaw);
		float dp = NormalizeAngle(desired.x - pitch);
		return sqrtf(dy * dy + dp * dp);
	}

	// Linearly interpolate between current and target angle with a smoothing
	// factor (higher = slower movement).  Used for smooth aimbot.
	inline float SmoothAngle(float current, float target, float smooth)
	{
		float diff = NormalizeAngle(target - current);
		return current + diff / smooth;
	}

	// Project a world-space point onto screen coordinates.
	//
	// Inputs:
	//   world    — 3D world position to project
	//   camPos   — camera world position (from local player transform)
	//   yaw      — camera yaw (Unturned convention)
	//   pitch    — camera pitch (Unturned convention: 90 = horizontal)
	//   fov      — vertical field of view in degrees
	//   screenW/H — viewport dimensions in pixels
	//
	// Output:
	//   out.x, out.y = screen position; out.z = depth (distance along forward)
	//
	// Returns false if the point is behind the camera (z < 0.1).
	// pitch param is Unturned convention (90=horizontal, 0=up, 180=down)
	inline bool WorldToScreen(vector3 world, vector3 camPos, float yaw, float pitch,
		float fov, int screenW, int screenH, vector3& out)
	{
		vector3 delta = world - camPos;

		// Convert Unturned pitch (90=horiz) to standard (0=horiz)
		float stdPitch = 90.0f - pitch;

		// Build camera basis vectors from yaw/pitch.
		float sy = sinf(DEG2RAD(yaw)), cy = cosf(DEG2RAD(yaw));
		float sp = sinf(DEG2RAD(stdPitch)), cp = cosf(DEG2RAD(stdPitch));

		vector3 forward = { cp * sy, sp, cp * cy };
		vector3 right = { cy, 0.0f, -sy };
		vector3 up = { -sp * sy, cp, -sp * cy };

		// Project delta onto camera axes.
		float z = delta.x * forward.x + delta.y * forward.y + delta.z * forward.z;
		if (z < 0.1f) return false;   // behind camera

		float x = delta.x * right.x + delta.y * right.y + delta.z * right.z;
		float y = delta.x * up.x + delta.y * up.y + delta.z * up.z;

		// Perspective divide with FOV and aspect ratio.
		float aspect = (float)screenW / (float)screenH;
		float tanHalfFov = tanf(DEG2RAD(fov * 0.5f));

		out.x = (screenW * 0.5f) * (1.0f + x / (z * tanHalfFov * aspect));
		out.y = (screenH * 0.5f) * (1.0f - y / (z * tanHalfFov));
		out.z = z;

		return true;
	}
}
