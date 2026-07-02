#pragma once
#include <cmath>
#include "mem.h"
#include "types/transform.h"

#ifndef M_PI
#define M_PI 3.14159265358979323846f
#endif

#define DEG2RAD(x) ((x) * (float)M_PI / 180.0f)
#define RAD2DEG(x) ((x) * 180.0f / (float)M_PI)

namespace Math
{
	inline float Distance(vector3 a, vector3 b)
	{
		vector3 d = a - b;
		return sqrtf(d.x * d.x + d.y * d.y + d.z * d.z);
	}

	inline float Distance2D(vector3 a, vector3 b)
	{
		float dx = a.x - b.x;
		float dz = a.z - b.z;
		return sqrtf(dx * dx + dz * dz);
	}

	inline vector3 CalcAngle(vector3 src, vector3 dst)
	{
		vector3 delta = dst - src;
		float hyp = sqrtf(delta.x * delta.x + delta.z * delta.z);
		float pitch = 90.0f - RAD2DEG(atan2f(delta.y, hyp));
		float yaw = RAD2DEG(atan2f(delta.x, delta.z));
		return { pitch, yaw, 0 };
	}

	inline float NormalizeAngle(float angle)
	{
		while (angle > 180.0f) angle -= 360.0f;
		while (angle < -180.0f) angle += 360.0f;
		return angle;
	}

	inline float AngleDiffFOV(vector3 src, vector3 dst, float yaw, float pitch)
	{
		vector3 desired = CalcAngle(src, dst);
		float dy = NormalizeAngle(desired.y - yaw);
		float dp = NormalizeAngle(desired.x - pitch);
		return sqrtf(dy * dy + dp * dp);
	}

	inline float SmoothAngle(float current, float target, float smooth)
	{
		float diff = NormalizeAngle(target - current);
		return current + diff / smooth;
	}

	inline bool WorldToScreen(vector3 world, vector3 camPos, float yaw, float pitch,
		float fov, int screenW, int screenH, vector3& out)
	{
		vector3 delta = world - camPos;

		float stdPitch = 90.0f - pitch;

		float sy = sinf(DEG2RAD(yaw)), cy = cosf(DEG2RAD(yaw));
		float sp = sinf(DEG2RAD(stdPitch)), cp = cosf(DEG2RAD(stdPitch));

		vector3 forward = { cp * sy, sp, cp * cy };
		vector3 right = { cy, 0.0f, -sy };
		vector3 up = { -sp * sy, cp, -sp * cy };

		float z = delta.x * forward.x + delta.y * forward.y + delta.z * forward.z;
		if (z < 0.1f) return false;

		float x = delta.x * right.x + delta.y * right.y + delta.z * right.z;
		float y = delta.x * up.x + delta.y * up.y + delta.z * up.z;

		float aspect = (float)screenW / (float)screenH;
		float tanHalfFov = tanf(DEG2RAD(fov * 0.5f));

		out.x = (screenW * 0.5f) * (1.0f + x / (z * tanHalfFov * aspect));
		out.y = (screenH * 0.5f) * (1.0f - y / (z * tanHalfFov));
		out.z = z;

		return true;
	}
}
