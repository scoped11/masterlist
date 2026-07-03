// ============================================================================
// mono.h -- Mono Runtime Reflection System (External)
// ============================================================================
//
// This header implements an external (out-of-process) Mono metadata reader
// for Unity games. Unity uses the Mono runtime to execute C# code, and this
// file reads Mono's internal data structures directly from the target
// process's memory to resolve classes, fields, and methods without injection.
//
// The overall workflow:
//   1. find_root_domain_offset() locates the global MonoDomain pointer by
//      pattern-scanning the mono_get_root_domain export in mono-2.0-bdwgc.dll.
//   2. From the root domain, walk the assembly list to find a named assembly
//      (e.g. "Assembly-CSharp").
//   3. From the assembly, get the MonoImage (metadata container).
//   4. From the image, iterate the type definition table to find classes by
//      fully-qualified name.
//   5. From a class, enumerate fields (for offsets) or methods (for JIT
//      addresses).
//
// Struct hierarchy (mirrors Mono internals):
//   mono_root_domain_t  -- the global AppDomain; owns the assembly list
//     -> mono_assembly_t   -- a loaded .dll (e.g. Assembly-CSharp.dll)
//       -> mono_image_t    -- the PE/metadata image backing that assembly
//         -> mono_class_t  -- a single C# class definition
//           -> mono_class_field_t -- a field within a class (name + offset)
//           -> mono_method_t      -- a method within a class (name)
//
// Key concepts:
//   - The OFFSET macro generates a one-liner accessor that reads a value at
//     (this + offset) from the target process. Every struct "field" here is
//     really a remote memory read.
//   - init_functions() builds a lookup table mapping Mono method metadata
//     pointers to their JIT-compiled native code addresses, enabling calls
//     to C# methods from external code.
//
// Based on: https://github.com/reahly/mono-external-lib
// ============================================================================

#pragma once
#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING
#pragma warning(push)
#pragma warning(disable: 4312 4311 4302 4996)
#include <Windows.h>
#include <codecvt>
#include <unordered_map>
#include "mem.h"

// https://github.com/reahly/mono-external-lib
// NOTE: most of this has been updated to latest unity ver, but only functions used in the repo have been tested (the most important stuff)

// ── OFFSET macro ──────────────────────────────────────────────────────────
// Generates a member function that reads a value of `type` from the target
// process at (this + offset). Since "this" is really a remote pointer, the
// read<T>() call fetches the value across process boundaries via SWHE.
// Example: OFFSET(data(), uintptr_t, 0x0) expands to:
//   uintptr_t data() { return read<uintptr_t>((uintptr_t)this + 0x0); }
#define OFFSET(func, type, offset) type func { return read<type>( reinterpret_cast<uintptr_t>( this ) + offset ); }

// Global offset from mono-2.0-bdwgc.dll base to the root domain pointer.
// Populated once by find_root_domain_offset() at startup.
inline uintptr_t GET_ROOT_DOMAIN_OFFSET = 0;

// ── find_root_domain_offset() ─────────────────────────────────────────────
// Pattern-scans the "mono_get_root_domain" export to extract the RVA of the
// global MonoDomain* variable. The export is a tiny function that either:
//   - mov rax, [rip+disp32]  (48 8B 05 XX XX XX XX) -- dereferences the ptr
//   - lea rax, [rip+disp32]  (48 8D 05 XX XX XX XX) -- loads the address
// We decode the RIP-relative displacement to compute the absolute VA of the
// global, then subtract baseAddress to get the RVA we'll use for all future
// domain lookups.
inline uintptr_t find_root_domain_offset()
{
	// Read the DOS header to validate this is a PE image
	IMAGE_DOS_HEADER dosHeader;
	read_buffer(baseAddress, &dosHeader, sizeof(dosHeader));
	if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) return 0;

	// Read NT headers to locate the export directory
	IMAGE_NT_HEADERS64 ntHeaders;
	read_buffer(baseAddress + dosHeader.e_lfanew, &ntHeaders, sizeof(ntHeaders));

	auto& exportEntry = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (!exportEntry.VirtualAddress) return 0;

	IMAGE_EXPORT_DIRECTORY exportDir;
	read_buffer(baseAddress + exportEntry.VirtualAddress, &exportDir, sizeof(exportDir));

	// Walk the export name table looking for "mono_get_root_domain"
	for (DWORD i = 0; i < exportDir.NumberOfNames; i++)
	{
		DWORD nameRva = read<DWORD>(baseAddress + exportDir.AddressOfNames + i * sizeof(DWORD));
		char name[64] = {};
		read_buffer(baseAddress + nameRva, name, 63);

		if (strcmp(name, "mono_get_root_domain") == 0)
		{
			// Resolve the function's RVA via the ordinal table
			WORD ordinal = read<WORD>(baseAddress + exportDir.AddressOfNameOrdinals + i * sizeof(WORD));
			DWORD funcRva = read<DWORD>(baseAddress + exportDir.AddressOfFunctions + ordinal * sizeof(DWORD));
			uintptr_t funcAddr = baseAddress + funcRva;

			// Read the first few bytes of the function to decode the pattern
			uint8_t code[16] = {};
			read_buffer(funcAddr, code, sizeof(code));

			// Pattern 1: 48 8B 05 XX XX XX XX = mov rax, [rip+disp32]
			if (code[0] == 0x48 && code[1] == 0x8B && code[2] == 0x05)
			{
				int32_t disp = *(int32_t*)&code[3];
				uintptr_t globalAddr = funcAddr + 7 + disp; // RIP + instruction length + displacement
				Log("Auto-found root domain offset: 0x%llX", globalAddr - baseAddress);
				return globalAddr - baseAddress;
			}

			// Pattern 2: 48 8D 05 XX XX XX XX = lea rax, [rip+disp32]
			if (code[0] == 0x48 && code[1] == 0x8D && code[2] == 0x05)
			{
				int32_t disp = *(int32_t*)&code[3];
				uintptr_t globalAddr = funcAddr + 7 + disp;
				Log("Auto-found root domain offset: 0x%llX", globalAddr - baseAddress);
				return globalAddr - baseAddress;
			}

			Log("mono_get_root_domain: unrecognized pattern %02X %02X %02X", code[0], code[1], code[2]);
			return 0;
		}
	}

	Log("mono_get_root_domain export not found in DLL");
	return 0;
}

// ── JIT function lookup table ─────────────────────────────────────────────
// Maps Mono method metadata pointers -> their JIT-compiled native addresses.
// Populated by mono::init_functions() at startup.
inline std::unordered_map<uintptr_t, uintptr_t> functions;

// ── String helpers ────────────────────────────────────────────────────────
// Mono stores names as UTF-8 internally. These helpers convert and read them.

inline unsigned short utf8_to_utf16(const char* val)
{
	std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> convert;
	std::u16string dest = convert.from_bytes(val);
	return *reinterpret_cast<unsigned short*>(&dest[0]);
}

// Reads a null-terminated string from the target process at `address`.
inline std::string read_widechar(const std::uintptr_t address, const std::size_t size)
{
	const auto buffer = std::make_unique<char[]>(size);
	read_buffer(address, buffer.get(), size);
	return std::string(buffer.get());
}

// ============================================================================
// Mono internal structures -- each mirrors a Mono C struct.
// Fields are accessed via OFFSET() which reads remotely from the target.
// ============================================================================

// GList: Mono's generic singly-linked list node (GLib-style).
// data() -> the payload pointer, next() -> next node in list.
struct glist_t
{
	OFFSET(data(), uintptr_t, 0x0)
		OFFSET(next(), uintptr_t, 0x8)
};

// MonoDomain (root domain): the top-level container for a Mono runtime.
// - domain_assemblies() returns the head of the linked list of loaded assemblies
// - domain_id() returns this domain's numeric ID (used for vtable lookups)
// - jitted_function_table() points to the hash table of JIT-compiled methods
struct mono_root_domain_t
{
	OFFSET(domain_assemblies(), glist_t*, 0xA0)
		OFFSET(domain_id(), int, 0x94)
		OFFSET(jitted_function_table(), uintptr_t, 0x120) // tested and epic
};

// MonoTableInfo: metadata table descriptor from the PE/CLI image.
// get_rows() returns the number of rows (type definitions, methods, etc.)
// by masking the lower 24 bits of the size field.
struct mono_table_info_t
{
	int get_rows()
	{
		auto count = read<int>(reinterpret_cast<uintptr_t>(this) + 0x8) & 0xFFFFFF;
		//printf("count: %d\n", count);
		return count;
	}
};

// MonoMethod: a C# method's metadata entry.
// name() reads the method name string from offset 0x18.
struct mono_method_t
{
	std::string name()
	{
		auto name = read_widechar(read<uintptr_t>(reinterpret_cast<uintptr_t>(this) + 0x18), 128);
		if (static_cast<std::uint8_t>(name[0]) == 0xEE)
		{
			char name_buff[32];
			sprintf_s(name_buff, 32, "\\u%04X", utf8_to_utf16(const_cast<char*>(name.c_str())));
			name = name_buff;
		}

		return name;
	}
};

// MonoClassField: a single field within a class.
// - offset() returns the field's byte offset within instances of the class
// - name() reads the field name string from offset 0x8
struct mono_class_field_t
{
	OFFSET(offset(), int, 0x18)

		std::string name()
	{
		auto name = read_widechar(read<uintptr_t>(reinterpret_cast<uintptr_t>(this) + 0x8), 128);
		if (static_cast<std::uint8_t>(name[0]) == 0xEE)
		{
			char name_buff[32];
			sprintf_s(name_buff, 32, "\\u%04X", utf8_to_utf16(const_cast<char*>(name.c_str())));
			name = name_buff;
		}

		return name;
	}
};

// MonoClassRuntimeInfo: per-class runtime state.
// max_domain() is the highest domain ID this class has been loaded in.
struct mono_class_runtime_info_t
{
	OFFSET(max_domain(), int, 0x0)
};

// MonoVTable: the virtual method table for a class in a specific domain.
// get_static_field_data() retrieves the pointer to the class's static field
// storage. This is how we read static fields like Provider._clients.
// The implementation mirrors mono_vtable_get_static_field_data() from Mono:
//   if bit 2 of the flags at offset 48 is set, the static data pointer is
//   stored at vtable[klass->vtable_size] (the slot right after the vtable).
struct mono_vtable_t
{
	//OFFSET(flags(), byte, 0x2E)

		/*


void *__fastcall mono_vtable_get_static_field_data(MonoVTable *vt)
{
  if ( (*(vt + 48) & 4) != 0 )
	return vt->vtable[vt->klass->vtable_size];
  else
	return 0i64;
}

		*/

	uintptr_t get_static_field_data()
	{
		if (((read<uintptr_t>(reinterpret_cast<uintptr_t>(this) + 48)) & 4) != 0)
			return read<uintptr_t>(reinterpret_cast<uintptr_t>(this) + 0x48 + 8 * read<int>(read<uintptr_t>(reinterpret_cast<uintptr_t>(this) + 0x0) + 0x5c));

		return 0;
	}
};

// MonoClass: a C# class definition.
// This is the central structure -- from here we access fields, methods,
// vtables, parent classes, and the class name/namespace.
//
// Key members:
//   - num_fields()    -> number of declared fields
//   - runtime_info()  -> per-domain runtime state (for vtable lookup)
//   - parent()        -> base class pointer (for inheritance chain walking)
//   - name()          -> class name string (e.g. "Player")
//   - namespace_name()-> namespace string (e.g. "SDG.Unturned")
//
// Field/method access:
//   - get_field(i)        -> i-th field (each entry is 0x20 bytes)
//   - get_method(i)       -> i-th method pointer
//   - find_field(name)    -> linear scan for a field by name
//   - find_field_recursive(name) -> walks the inheritance chain up to 10
//     levels looking for a field (handles inherited fields)
//   - find_method(name)   -> finds a method by name and returns its
//     JIT-compiled address from the `functions` map
struct mono_class_t
{
	OFFSET(num_fields(), int, 0x100)
		OFFSET(runtime_info(), mono_class_runtime_info_t*, 0xD0)
		OFFSET(parent(), mono_class_t*, 0x30)

		std::string name()
	{
		auto name = read_widechar(read<uintptr_t>(reinterpret_cast<uintptr_t>(this) + 0x48), 128);
		if (static_cast<std::uint8_t>(name[0]) == 0xEE)
		{
			char name_buff[32];
			sprintf_s(name_buff, 32, "\\u%04X", utf8_to_utf16(const_cast<char*>(name.c_str())));
			name = name_buff;
		}

		return name;
	}

	std::string namespace_name()
	{
		auto name = read_widechar(read<uintptr_t>(reinterpret_cast<uintptr_t>(this) + 0x50), 128);
		if (static_cast<std::uint8_t>(name[0]) == 0xEE)
		{
			char name_buff[32];
			sprintf_s(name_buff, 32, ("\\u%04X"), utf8_to_utf16(const_cast<char*>(name.c_str())));
			name = name_buff;
		}

		return name;
	}

	// Returns the number of methods, reading the class kind field to determine
	// which internal layout is in use (interface, array, generic, etc.)
	int get_num_methods()
	{
		const auto v2 = (read<int>(reinterpret_cast<uintptr_t>(this) + 0x2a) & 7) - 1;
		switch (v2)
		{
		case 0:
		case 1:
			return read<int>(reinterpret_cast<uintptr_t>(this) + 0xFC);

		case 3:
		case 5:
			return 0;

		case 4u:
			return read<int>(reinterpret_cast<uintptr_t>(this) + 0xF0);

		default: break;
		}

		return 0;
	}

	// Returns the i-th method metadata pointer from the methods array at +0xA0.
	mono_method_t* get_method(const int i)
	{
		return reinterpret_cast<mono_method_t*>(read<uintptr_t>(read<uintptr_t>(reinterpret_cast<uintptr_t>(this) + 0xA0) + 0x8 * i));
	}

	// Returns the i-th field descriptor. Fields are stored as a flat array
	// at the pointer in +0x98, each entry 0x20 (32) bytes apart.
	mono_class_field_t* get_field(const int i)
	{
		return reinterpret_cast<mono_class_field_t*>(read<uintptr_t>(reinterpret_cast<uintptr_t>(this) + 0x98) + 0x20 * i);
	}

	// Looks up the vtable for this class in the given domain.
	// The vtable is stored in runtime_info at index [domain_id].
	mono_vtable_t* get_vtable(mono_root_domain_t* domain)
	{
		const auto runtime_info = this->runtime_info();
		if (!runtime_info)
			return nullptr;

		const auto domain_id = domain->domain_id();
		if (runtime_info->max_domain() < domain_id)
			return nullptr;

		return reinterpret_cast<mono_vtable_t*>(read<uintptr_t>(reinterpret_cast<uintptr_t>(runtime_info) + 8 * domain_id + 8));
	}

	// Finds a method by name and returns its JIT-compiled native address.
	// First finds the Mono metadata pointer, then looks it up in the
	// `functions` map (populated by init_functions()) to get the actual
	// executable code address.
	mono_method_t* find_method(const char* method_name)
	{
		auto mono_ptr = uintptr_t();
		for (auto i = 0; i < this->get_num_methods(); i++)
		{
			const auto method = this->get_method(i);
			if (!method)
				continue;

			if (!strcmp(method->name().c_str(), method_name))
				mono_ptr = reinterpret_cast<uintptr_t>(method);
		}

		return reinterpret_cast<mono_method_t*>(functions[mono_ptr]);
	}

	// Searches this class's fields by name. Returns nullptr if not found.
	mono_class_field_t* find_field(const char* field_name)
	{
		for (auto i = 0; i < this->num_fields(); i++)
		{
			const auto field = this->get_field(i);
			if (!field)
				continue;

			if (!strcmp(field->name().c_str(), field_name))
				return field;
		}

		return nullptr;
	}

	// Walks the inheritance chain (up to 10 levels) looking for a field.
	// This handles fields declared in base classes (e.g. a field on
	// MonoBehaviour that is accessed through a Player subclass).
	mono_class_field_t* find_field_recursive(const char* field_name)
	{
		auto klass = this;
		for (int depth = 0; depth < 10 && klass && (uintptr_t)klass > 0x10000; depth++)
		{
			auto field = klass->find_field(field_name);
			if (field) return field;
			klass = klass->parent();
		}
		return nullptr;
	}
};

// MonoHashTable: Mono's internal hash table used for type definition lookups.
// The image stores classes in a hash table keyed by their type token
// (0x02000000 | row_index). lookup<T>() walks the bucket chain to find
// the entry matching the given key.
struct mono_hash_table_t
{
	OFFSET(size(), uint32_t, 0x18)
		OFFSET(data(), uintptr_t, 0x20)
		OFFSET(next_value(), void*, 0x108)
		OFFSET(key_extract(), unsigned int, 0x58)

		template<typename T>
	T* lookup(void* key)
	{
		auto v4 = static_cast<mono_hash_table_t*>(read<void*>(data() + 0x8 * (reinterpret_cast<unsigned int>(key) % this->size())));
		if (!v4)
			return nullptr;

		while (reinterpret_cast<void*>(v4->key_extract()) != key)
		{
			v4 = static_cast<mono_hash_table_t*>(v4->next_value());
			if (!v4)
				return nullptr;
		}

		return reinterpret_cast<T*>(v4);
	}
};

// MonoImage: the metadata image for a loaded assembly (.dll).
// - get_table_info(table_id) returns the metadata table descriptor.
//   Table 2 (0x02) is the TypeDef table -- we use table_id=3 here
//   because of how the offset math works internally.
// - get() retrieves a class by its type definition token (0x02XXXXXX).
struct mono_image_t
{
	OFFSET(flags(), int, 0x1C)

		mono_table_info_t* get_table_info(const int table_id)
	{
		if (table_id > 55)
			return nullptr;
		return reinterpret_cast<mono_table_info_t*>(reinterpret_cast<uintptr_t>(this) + 0x10 /*size?*/ * (static_cast<int>(table_id) + 0xE));
	}

	mono_class_t* get(const int type_id)
	{
		if ((this->flags() & 0x20) != 0)
			return nullptr;

		if ((type_id & 0xFF000000) != 0x2000000)
			return nullptr;

		return reinterpret_cast<mono_hash_table_t*>(this + 0x4D0)->lookup<mono_class_t>(reinterpret_cast<void*>(type_id));
	}
};

// MonoAssembly: a loaded assembly. The main thing we need is the
// MonoImage pointer at offset 0x60, which gives access to all metadata.
struct mono_assembly_t
{
	OFFSET(mono_image(), mono_image_t*, 0x60)
};

// ============================================================================
// mono namespace -- high-level API for Mono reflection
// ============================================================================
namespace mono
{
	// Returns the root MonoDomain* by reading the global pointer found by
	// find_root_domain_offset(). This is the entry point into all Mono data.
	inline mono_root_domain_t* get_root_domain()
	{
		return reinterpret_cast<mono_root_domain_t*>(read<uintptr_t>(baseAddress + GET_ROOT_DOMAIN_OFFSET));
	}

	// ── init_functions() ──────────────────────────────────────────────────
	// Builds the Mono method pointer -> JIT native address lookup table.
	// Walks the domain's jitted_function_table (a two-level array):
	//   Level 1: array of bucket pointers (at jit_table + 0x10, count at +0x8)
	//   Level 2: each bucket has entries (at bucket + 0x18, count at +0x4)
	//   Each entry stores: mono_method* at +0x0, jitted_code* at +0x10
	// After this runs, functions[mono_ptr] = native_code_addr for every
	// JIT-compiled method in the domain.
	// Credits: niceone1 (https://www.unknowncheats.me/forum/3434741-post11.html)
	inline void init_functions()
	{
		const auto jitted_table = get_root_domain()->jitted_function_table();
		for (auto i = 0; i < read<int>(jitted_table + 0x8); i++)
		{
			const auto entry = read<uintptr_t>(jitted_table + 0x10 + i * 0x8);
			if (!entry)
				continue;

			for (auto j = 0; j < read<int>(entry + 0x4); j++)
			{
				const auto function = read<uintptr_t>(entry + 0x18 + j * 0x8);
				if (!function)
					continue;

				const auto mono_ptr = read<uintptr_t>(function + 0x0);
				const auto jitted_ptr = read<uintptr_t>(function + 0x10);
				functions[mono_ptr] = jitted_ptr;
			}
		}
	}

	// ── domain_assembly_open() ────────────────────────────────────────────
	// Walks the root domain's assembly linked list to find an assembly by
	// name (e.g. "Assembly-CSharp"). Each node in the GList contains a
	// MonoAssembly pointer; we read the assembly's name at +0x10 and compare.
	inline mono_assembly_t* domain_assembly_open(mono_root_domain_t* domain, const char* name)
	{
		auto domain_assemblies = domain->domain_assemblies();
		if (!domain_assemblies)
			return nullptr;

		auto data = uintptr_t();
		int maxIter = 512; // safety limit to prevent infinite loops on corrupt data
		while (maxIter-- > 0)
		{
			data = domain_assemblies->data();
			if (!data)
			{
				domain_assemblies = reinterpret_cast<glist_t*>(domain_assemblies->next());
				if (!domain_assemblies)
					break;
				continue;
			}

			const auto data_name = read_widechar(read<uintptr_t>(data + 0x10), 128);
			if (!strcmp(data_name.c_str(), name))
				break;

			domain_assemblies = reinterpret_cast<glist_t*>(domain_assemblies->next());
			if (!domain_assemblies)
			{
				data = 0;
				break;
			}
		}

		return reinterpret_cast<mono_assembly_t*>(data);
	}

	// ── find_class() ──────────────────────────────────────────────────────
	// Resolves a C# class by assembly name and fully-qualified class name.
	// Steps:
	//   1. Get the root domain
	//   2. Find the named assembly in the domain's assembly list
	//   3. Get the MonoImage from the assembly
	//   4. Get the TypeDef metadata table (table index 3)
	//   5. Iterate every row in the TypeDef table, constructing a type token
	//      (0x02000000 | row_index) and looking it up in the image's class
	//      hash table
	//   6. Compare the fully-qualified name (namespace.classname) against
	//      the target
	// Returns the mono_class_t* on match, nullptr on failure.
	inline mono_class_t* find_class(const char* assembly_name, const char* class_name)
	{
		const auto root_domain = get_root_domain();
		if (!root_domain)
			return nullptr;
		const auto domain_assembly = domain_assembly_open(root_domain, assembly_name);
		if (!domain_assembly)
			return nullptr;

		const auto mono_image = domain_assembly->mono_image();
		if (!mono_image)
			return nullptr;

		//printf("mono_image: 0x%p\n", mono_image);

		const auto table_info = mono_image->get_table_info(3); // 3 now?
		if (!table_info)
			return nullptr;
		//printf("table_info: 0x%p\n", table_info);
		auto tbl = static_cast<mono_hash_table_t*>(reinterpret_cast<void*>(mono_image + 0x4D0));
		for (int i = 0; i < table_info->get_rows(); i++)
		{
			//printf("i: %d\n", i);
			//printf("tbl: 0x%p\n", tbl);

			// Construct the TypeDef token: table 0x02, row (i+1)
			const auto ptr = tbl->lookup<mono_class_t>(reinterpret_cast<void*>(0x02000000 | i + 1));
			//printf("ptr: 0x%p\n", ptr);
			if (!ptr)
				continue;

			// Build the fully-qualified name (namespace.classname)
			auto name = ptr->name();
			if (!ptr->namespace_name().empty())
				name = ptr->namespace_name().append(".").append(ptr->name());
			//printf("name: %s\n", name.c_str());

			if (!strcmp(name.c_str(), class_name))
				return ptr;
		}

		return nullptr;
	}
}
#pragma warning(pop)
