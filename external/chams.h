#pragma once
#include "types/game.h"
#include "config.h"

namespace Chams
{
	typedef void* (__cdecl* mono_runtime_invoke_t)(void* method, void* obj, void** params, void** exc);
	typedef void* (__cdecl* mono_class_get_method_from_name_t)(void* klass, const char* name, int param_count);
	typedef void* (__cdecl* mono_string_new_t)(void* domain, const char* text);
	typedef void* (__cdecl* mono_class_get_type_t)(void* klass);
	typedef void* (__cdecl* mono_type_get_object_t)(void* domain, void* type);
	typedef void* (__cdecl* mono_thread_attach_t)(void* domain);
	typedef void* (__cdecl* mono_get_root_domain_t)();

	inline mono_runtime_invoke_t p_invoke = nullptr;
	inline mono_class_get_method_from_name_t p_get_method = nullptr;
	inline mono_string_new_t p_string_new = nullptr;
	inline mono_class_get_type_t p_class_get_type = nullptr;
	inline mono_type_get_object_t p_type_get_object = nullptr;
	inline mono_thread_attach_t p_thread_attach = nullptr;
	inline mono_get_root_domain_t p_get_root_domain = nullptr;

	// Chams
	inline void* m_getComponentsInChildren = nullptr;
	inline void* m_getComponent = nullptr;
	inline void* m_get_material = nullptr;
	inline void* m_get_shader = nullptr;
	inline void* m_mat_set_shader = nullptr;
	inline void* m_setInt = nullptr;
	inline void* m_setColor = nullptr;
	inline void* rendererTypeObj = nullptr;
	inline void* wallhackShader = nullptr;
	inline void* defaultShader = nullptr;

	// Rigidbody (vehicle fly)
	inline void* rigidbodyTypeObj = nullptr;
	inline void* m_rb_set_isKinematic = nullptr;
	inline void* m_rb_set_useGravity = nullptr;
	inline void* m_rb_set_velocity = nullptr;
	inline void* cachedVehicleRB = nullptr;
	inline void* lastVehicleObj = nullptr;

	// Fullbright (LevelLighting.time)
	inline uintptr_t ll_staticData = 0;
	inline uintptr_t ll_timeOffset = 0;

	// RenderSettings fallback
	inline void* m_rs_set_ambientIntensity = nullptr;
	inline void* m_rs_set_ambientLight = nullptr;
	inline void* m_rs_set_fog = nullptr;

	inline bool initialized = false;
	inline void* cachedDomain = nullptr;

	struct Color { float r, g, b, a; };

	inline void* invoke_safe(void* method, void* obj, void** args)
	{
		if (!method || !p_invoke) return nullptr;
		void* result = nullptr;
		__try
		{
			void* exc = nullptr;
			result = p_invoke(method, obj, args, &exc);
			if (exc) result = nullptr;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			result = nullptr;
		}
		return result;
	}

	inline void* string_safe(const char* text)
	{
		if (!p_string_new || !cachedDomain) return nullptr;
		void* result = nullptr;
		__try
		{
			result = p_string_new(cachedDomain, text);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			result = nullptr;
		}
		return result;
	}

	inline bool Init()
	{
		HMODULE hMono = GetModuleHandleA("mono-2.0-bdwgc.dll");
		if (!hMono) { Log("Chams: mono DLL not found"); return false; }

		p_invoke = (mono_runtime_invoke_t)GetProcAddress(hMono, "mono_runtime_invoke");
		p_get_method = (mono_class_get_method_from_name_t)GetProcAddress(hMono, "mono_class_get_method_from_name");
		p_string_new = (mono_string_new_t)GetProcAddress(hMono, "mono_string_new");
		p_class_get_type = (mono_class_get_type_t)GetProcAddress(hMono, "mono_class_get_type");
		p_type_get_object = (mono_type_get_object_t)GetProcAddress(hMono, "mono_type_get_object");
		p_thread_attach = (mono_thread_attach_t)GetProcAddress(hMono, "mono_thread_attach");
		p_get_root_domain = (mono_get_root_domain_t)GetProcAddress(hMono, "mono_get_root_domain");

		if (!p_invoke || !p_get_method || !p_string_new || !p_class_get_type || !p_type_get_object)
		{
			Log("Chams: Missing mono API exports");
			return false;
		}

		if (p_thread_attach && p_get_root_domain)
		{
			cachedDomain = p_get_root_domain();
			if (cachedDomain)
			{
				p_thread_attach(cachedDomain);
				Log("Chams: Thread attached to mono");
			}
			else
			{
				Log("Chams: Failed to get root domain");
				return false;
			}
		}
		else
		{
			Log("Chams: Missing thread_attach/get_root_domain");
			return false;
		}

		// --- Find classes ---
		auto componentClass = mono::find_class("UnityEngine.CoreModule", "UnityEngine.Component");
		if (!componentClass) componentClass = mono::find_class("UnityEngine", "UnityEngine.Component");

		auto rendererClass = mono::find_class("UnityEngine.CoreModule", "UnityEngine.Renderer");
		if (!rendererClass) rendererClass = mono::find_class("UnityEngine", "UnityEngine.Renderer");

		auto materialClass = mono::find_class("UnityEngine.CoreModule", "UnityEngine.Material");
		if (!materialClass) materialClass = mono::find_class("UnityEngine", "UnityEngine.Material");

		auto shaderClass = mono::find_class("UnityEngine.CoreModule", "UnityEngine.Shader");
		if (!shaderClass) shaderClass = mono::find_class("UnityEngine", "UnityEngine.Shader");

		auto rigidbodyClass = mono::find_class("UnityEngine.PhysicsModule", "UnityEngine.Rigidbody");
		if (!rigidbodyClass) rigidbodyClass = mono::find_class("UnityEngine", "UnityEngine.Rigidbody");

		auto renderSettingsClass = mono::find_class("UnityEngine.CoreModule", "UnityEngine.RenderSettings");
		if (!renderSettingsClass) renderSettingsClass = mono::find_class("UnityEngine", "UnityEngine.RenderSettings");

		Log("Chams: Comp:%p Rend:%p Mat:%p Shd:%p RB:%p RS:%p",
			componentClass, rendererClass, materialClass, shaderClass, rigidbodyClass, renderSettingsClass);

		// --- Chams methods ---
		if (componentClass && rendererClass && materialClass)
		{
			m_getComponentsInChildren = p_get_method(componentClass, "GetComponentsInChildren", 1);
			m_getComponent = p_get_method(componentClass, "GetComponent", 1);
			m_get_material = p_get_method(rendererClass, "get_material", 0);
			m_get_shader = p_get_method(materialClass, "get_shader", 0);
			m_setInt = p_get_method(materialClass, "SetInt", 2);
			m_setColor = p_get_method(materialClass, "SetColor", 2);
			m_mat_set_shader = p_get_method(materialClass, "set_shader", 1);

			void* rendererMonoType = p_class_get_type(rendererClass);
			if (rendererMonoType)
				rendererTypeObj = p_type_get_object(cachedDomain, rendererMonoType);

			Log("Chams: GCI:%p GM:%p getShd:%p setShd:%p SI:%p SC:%p RT:%p",
				m_getComponentsInChildren, m_get_material, m_get_shader, m_mat_set_shader,
				m_setInt, m_setColor, rendererTypeObj);
		}

		// --- Find wallhack shader (no depth test) ---
		if (shaderClass)
		{
			auto m_shader_find = p_get_method(shaderClass, "Find", 1);
			if (m_shader_find)
			{
				const char* shaderNames[] = {
					"GUI/Text Shader",
					"Hidden/Internal-Colored",
					"Sprites/Default",
					"Unlit/Color"
				};

				for (auto name : shaderNames)
				{
					void* nameStr = string_safe(name);
					if (!nameStr) continue;
					void* findArgs[] = { nameStr };
					void* shader = invoke_safe(m_shader_find, nullptr, findArgs);
					if (shader && (uintptr_t)shader > 0x10000)
					{
						wallhackShader = shader;
						Log("Chams: Wallhack shader '%s' -> %p", name, shader);
						break;
					}
				}

				if (!wallhackShader)
					Log("Chams: No wallhack shader found");
			}
		}

		// --- Rigidbody methods ---
		if (rigidbodyClass && componentClass)
		{
			m_rb_set_isKinematic = p_get_method(rigidbodyClass, "set_isKinematic", 1);
			m_rb_set_useGravity = p_get_method(rigidbodyClass, "set_useGravity", 1);
			m_rb_set_velocity = p_get_method(rigidbodyClass, "set_velocity", 1);

			void* rbMonoType = p_class_get_type(rigidbodyClass);
			if (rbMonoType)
				rigidbodyTypeObj = p_type_get_object(cachedDomain, rbMonoType);

			Log("Chams: RB setK:%p setG:%p setV:%p type:%p",
				m_rb_set_isKinematic, m_rb_set_useGravity, m_rb_set_velocity, rigidbodyTypeObj);
		}

		// --- Fullbright: find LevelLighting.time field ---
		if (Classes::LevelLighting)
		{
			auto timeField = Classes::LevelLighting->find_field("time");
			if (!timeField) timeField = Classes::LevelLighting->find_field("_time");
			if (!timeField) timeField = Classes::LevelLighting->find_field("Time");
			if (!timeField) timeField = Classes::LevelLighting->find_field("<time>k__BackingField");
			if (!timeField) timeField = Classes::LevelLighting->find_field("_localTime");
			if (!timeField) timeField = Classes::LevelLighting->find_field("offset");

			if (timeField)
			{
				ll_timeOffset = timeField->offset();
				auto vtable = Classes::LevelLighting->get_vtable(mono::get_root_domain());
				if (vtable)
					ll_staticData = vtable->get_static_field_data();

				Log("Chams: LL time offset=0x%X staticData=%p", (uint32_t)ll_timeOffset, (void*)ll_staticData);
			}
			else
				Log("Chams: LevelLighting.time field not found");

			int nf = Classes::LevelLighting->num_fields();
			Log("=== LevelLighting has %d fields ===", nf);
			for (int i = 0; i < nf && i < 40; i++)
			{
				auto f = Classes::LevelLighting->get_field(i);
				if (f) Log("  LL [%d] '%s' offset=0x%X", i, f->name().c_str(), f->offset());
			}
			Log("==================================");
		}

		// --- RenderSettings fallback ---
		if (renderSettingsClass)
		{
			m_rs_set_ambientIntensity = p_get_method(renderSettingsClass, "set_ambientIntensity", 1);
			m_rs_set_ambientLight = p_get_method(renderSettingsClass, "set_ambientLight", 1);
			m_rs_set_fog = p_get_method(renderSettingsClass, "set_fog", 1);
		}

		initialized = true;
		Log("Chams: Init OK");
		return true;
	}

	// ---- CHAMS ----

	inline void ModifyRenderers(void* obj, bool wallhack, Color* color)
	{
		if (!initialized || !obj || (uintptr_t)obj < 0x10000) return;
		if (!m_getComponentsInChildren || !m_get_material || !rendererTypeObj) return;

		void* gcArgs[] = { rendererTypeObj };
		void* rendererArray = invoke_safe(m_getComponentsInChildren, obj, gcArgs);
		if (!rendererArray || (uintptr_t)rendererArray < 0x10000) return;

		int count = 0;
		__try { count = *(int*)((uintptr_t)rendererArray + 0x18); }
		__except (EXCEPTION_EXECUTE_HANDLER) { return; }
		if (count <= 0 || count > 100) return;

		for (int i = 0; i < count; i++)
		{
			void* renderer = nullptr;
			__try { renderer = *(void**)((uintptr_t)rendererArray + 0x20 + i * 8); }
			__except (EXCEPTION_EXECUTE_HANDLER) { continue; }
			if (!renderer || (uintptr_t)renderer < 0x10000) continue;

			void* material = invoke_safe(m_get_material, renderer, nullptr);
			if (!material || (uintptr_t)material < 0x10000) continue;

			if (wallhack && m_mat_set_shader && wallhackShader)
			{
				if (!defaultShader && m_get_shader)
				{
					defaultShader = invoke_safe(m_get_shader, material, nullptr);
					if (defaultShader && (uintptr_t)defaultShader > 0x10000)
						Log("Chams: Cached original shader %p", defaultShader);
					else
						defaultShader = nullptr;
				}

				void* shaderArgs[] = { wallhackShader };
				invoke_safe(m_mat_set_shader, material, shaderArgs);
			}
			else if (!wallhack && m_mat_set_shader && defaultShader)
			{
				void* shaderArgs[] = { defaultShader };
				invoke_safe(m_mat_set_shader, material, shaderArgs);
			}

			if (color && m_setColor)
			{
				void* colorStr = string_safe("_Color");
				if (colorStr)
				{
					void* setColorArgs[] = { colorStr, color };
					invoke_safe(m_setColor, material, setColorArgs);
				}
			}
		}
	}

	inline void Apply(void* obj, bool isTarget)
	{
		Color col = isTarget ? Color{ 1.0f, 1.0f, 0.0f, 1.0f } : Color{ 1.0f, 0.0f, 0.0f, 1.0f };
		ModifyRenderers(obj, true, &col);
	}

	inline void ApplyZombie(void* obj)
	{
		Color col = { 0.0f, 1.0f, 0.0f, 1.0f };
		ModifyRenderers(obj, true, &col);
	}

	inline void Reset(void* obj)
	{
		ModifyRenderers(obj, false, nullptr);
	}

	// ---- VEHICLE FLY (Rigidbody) ----

	inline void* GetVehicleRigidbody(void* vehicleObj)
	{
		if (!m_getComponent || !rigidbodyTypeObj) return nullptr;
		if (!vehicleObj || (uintptr_t)vehicleObj < 0x10000) return nullptr;

		void* gcArgs[] = { rigidbodyTypeObj };
		return invoke_safe(m_getComponent, vehicleObj, gcArgs);
	}

	inline void UpdateVehicleFly(void* vehicleObj)
	{
		if (!initialized) return;
		if (!vehicleObj || (uintptr_t)vehicleObj < 0x10000) return;

		if (vehicleObj != lastVehicleObj)
		{
			cachedVehicleRB = GetVehicleRigidbody(vehicleObj);
			lastVehicleObj = vehicleObj;

			if (cachedVehicleRB && (uintptr_t)cachedVehicleRB > 0x10000)
			{
				if (m_rb_set_isKinematic)
				{
					int val = 1;
					void* args[] = { &val };
					invoke_safe(m_rb_set_isKinematic, cachedVehicleRB, args);
				}
				if (m_rb_set_useGravity)
				{
					int val = 0;
					void* args[] = { &val };
					invoke_safe(m_rb_set_useGravity, cachedVehicleRB, args);
				}
				Log("Vehicle fly: RB cached %p, kinematic set", cachedVehicleRB);
			}
			else
				Log("Vehicle fly: No rigidbody found on vehicle");
		}

		if (cachedVehicleRB && (uintptr_t)cachedVehicleRB > 0x10000 && m_rb_set_velocity)
		{
			vector3 zero = { 0, 0, 0 };
			void* args[] = { &zero };
			invoke_safe(m_rb_set_velocity, cachedVehicleRB, args);
		}
	}

	inline void RestoreVehiclePhysics()
	{
		if (cachedVehicleRB && (uintptr_t)cachedVehicleRB > 0x10000)
		{
			if (m_rb_set_isKinematic)
			{
				int val = 0;
				void* args[] = { &val };
				invoke_safe(m_rb_set_isKinematic, cachedVehicleRB, args);
			}
			if (m_rb_set_useGravity)
			{
				int val = 1;
				void* args[] = { &val };
				invoke_safe(m_rb_set_useGravity, cachedVehicleRB, args);
			}
		}
		cachedVehicleRB = nullptr;
		lastVehicleObj = nullptr;
	}

	// ---- FULLBRIGHT ----

	inline void SetFullbright(bool enabled)
	{
		if (!initialized) return;

		if (enabled)
		{
			if (ll_staticData && ll_timeOffset)
			{
				__try
				{
					write<float>(0.25f, ll_staticData + ll_timeOffset);
				}
				__except (EXCEPTION_EXECUTE_HANDLER) {}
			}

			if (m_rs_set_ambientIntensity)
			{
				float intensity = 5.0f;
				void* args[] = { &intensity };
				invoke_safe(m_rs_set_ambientIntensity, nullptr, args);
			}

			if (m_rs_set_ambientLight)
			{
				Color white = { 1.0f, 1.0f, 1.0f, 1.0f };
				void* args[] = { &white };
				invoke_safe(m_rs_set_ambientLight, nullptr, args);
			}

			if (m_rs_set_fog)
			{
				int fogOff = 0;
				void* args[] = { &fogOff };
				invoke_safe(m_rs_set_fog, nullptr, args);
			}
		}
	}
}
