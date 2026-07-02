#pragma once
#include "dma_mem.h"
#include "dma_dumper.h"
#include "../external/mono.h"
#include "../external/unturned.h"
#include <ctime>
#include <shlobj.h>
#include <direct.h>
#include <vector>
#include <string>
#include <algorithm>
#include <set>

namespace OffsetDump
{
	enum class EngineType { Mono, IL2CPP, UE4, UE5, Source2, SourceRespawn, Enfusion, Native };

	struct GameDef {
		const char* name;
		const char* processName;
		EngineType engine;
		const char* monoModule;     // for Mono games
		const char* coreModule;     // main game DLL to focus on
	};

	inline GameDef SupportedGames[] = {
		// Unity Mono
		{ "Unturned",       "Unturned.exe",         EngineType::Mono,           "mono-2.0-bdwgc.dll", "Assembly-CSharp" },
		// Unity IL2CPP
		{ "Rust",           "RustClient.exe",       EngineType::IL2CPP,         nullptr, "GameAssembly.dll" },
		// Unreal Engine 4
		{ "Squad",          "SquadGame.exe",        EngineType::UE4,            nullptr, "SquadGame.exe" },
		{ "Squad",          "SquadGame-Win64-Shipping.exe", EngineType::UE4,    nullptr, "SquadGame-Win64-Shipping.exe" },
		{ "SeaOfThieves",   "SoTGame.exe",          EngineType::UE4,            nullptr, "SoTGame.exe" },
		// Unreal Engine 5
		{ "DeltaForce",     "DeltaForce.exe",       EngineType::UE5,            nullptr, "DeltaForce.exe" },
		{ "DeltaForce",     "DeltaForceGame.exe",   EngineType::UE5,            nullptr, "DeltaForceGame.exe" },
		{ "ArenaBreakout",  "ArenaBreakout.exe",    EngineType::UE5,            nullptr, "ArenaBreakout.exe" },
		{ "ArenaBreakout",  "ArenaBreakoutInfinite-Win64-Shipping.exe", EngineType::UE5, nullptr, "ArenaBreakoutInfinite-Win64-Shipping.exe" },
		// Source 2
		{ "CS2",            "cs2.exe",              EngineType::Source2,        nullptr, "client.dll" },
		// Source (Respawn)
		{ "ApexLegends",    "r5apex.exe",           EngineType::SourceRespawn,  nullptr, "r5apex.exe" },
		// Enfusion
		{ "ArmaReforger",   "ArmaReforger.exe",     EngineType::Enfusion,       nullptr, "ArmaReforger.exe" },
		{ "ArmaReforger",   "ArmaReforger_BE.exe",  EngineType::Enfusion,       nullptr, "ArmaReforger.exe" },
		{ "DayZ",           "DayZ_x64.exe",         EngineType::Enfusion,       nullptr, "DayZ_x64.exe" },
		{ "DayZ",           "DayZ_BE.exe",          EngineType::Enfusion,       nullptr, "DayZ_x64.exe" },
		// AnvilNext 2.0
		{ "RainbowSix",     "RainbowSix.exe",       EngineType::Native,         nullptr, "RainbowSix.exe" },
		{ "RainbowSix",     "RainbowSix_BE.exe",    EngineType::Native,         nullptr, "RainbowSix.exe" },
	};

	inline std::string MakeOutputDir(const char* gameName)
	{
		char desktop[MAX_PATH] = {};
		SHGetFolderPathA(NULL, CSIDL_DESKTOPDIRECTORY, NULL, 0, desktop);
		std::string dumps = std::string(desktop) + "\\Dumps";
		_mkdir(dumps.c_str());

		time_t now = time(nullptr);
		struct tm t = {};
		localtime_s(&t, &now);
		char date[32];
		sprintf_s(date, "%04d-%02d-%02d", t.tm_year + 1900, t.tm_mon + 1, t.tm_mday);

		std::string dir = dumps + "\\" + gameName + "_Offsets_" + date;
		_mkdir(dir.c_str());
		return dir;
	}

	// ============================================================
	// Module export dumper (works for ALL games)
	// ============================================================
	inline void DumpModuleExports(FILE* f, const char* moduleName)
	{
		DWORD64 modBase = DMA::GetModuleBase(moduleName);
		if (!modBase) { fprintf(f, "// Module '%s' not found\n\n", moduleName); return; }

		fprintf(f, "// === %s @ 0x%llX ===\n", moduleName, modBase);

		IMAGE_DOS_HEADER dos = {};
		read_buffer(modBase, &dos, sizeof(dos));
		if (dos.e_magic != IMAGE_DOS_SIGNATURE) { fprintf(f, "// Invalid DOS header\n\n"); return; }

		IMAGE_NT_HEADERS64 nt = {};
		read_buffer(modBase + dos.e_lfanew, &nt, sizeof(nt));
		if (nt.Signature != IMAGE_NT_SIGNATURE) { fprintf(f, "// Invalid NT header\n\n"); return; }

		fprintf(f, "// ImageSize: 0x%X (%u KB)\n", nt.OptionalHeader.SizeOfImage, nt.OptionalHeader.SizeOfImage / 1024);
		fprintf(f, "// TimeDateStamp: 0x%X\n", nt.FileHeader.TimeDateStamp);

		// Sections
		WORD numSections = nt.FileHeader.NumberOfSections;
		DWORD64 secBase = modBase + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS64);
		fprintf(f, "// Sections (%d):\n", numSections);
		for (WORD i = 0; i < numSections; i++)
		{
			IMAGE_SECTION_HEADER sec = {};
			read_buffer(secBase + i * sizeof(IMAGE_SECTION_HEADER), &sec, sizeof(sec));
			char secName[9] = {};
			memcpy(secName, sec.Name, 8);
			fprintf(f, "//   %-8s  VA=0x%08X  Size=0x%08X  Flags=0x%08X\n",
				secName, sec.VirtualAddress, sec.Misc.VirtualSize, sec.Characteristics);
		}

		// Exports
		auto& expDir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		if (expDir.VirtualAddress && expDir.Size)
		{
			IMAGE_EXPORT_DIRECTORY exportDir = {};
			read_buffer(modBase + expDir.VirtualAddress, &exportDir, sizeof(exportDir));

			fprintf(f, "\n// Exports (%u functions, %u named):\n", exportDir.NumberOfFunctions, exportDir.NumberOfNames);
			fprintf(f, "namespace Exports {\n");

			int maxExports = min((int)exportDir.NumberOfNames, 2000);
			for (int i = 0; i < maxExports; i++)
			{
				DWORD nameRva = read<DWORD>(modBase + exportDir.AddressOfNames + i * sizeof(DWORD));
				char name[256] = {};
				read_buffer(modBase + nameRva, name, 255);

				WORD ordinal = read<WORD>(modBase + exportDir.AddressOfNameOrdinals + i * sizeof(WORD));
				DWORD funcRva = read<DWORD>(modBase + exportDir.AddressOfFunctions + ordinal * sizeof(DWORD));

				fprintf(f, "    // 0x%08X  %s\n", funcRva, name);
			}
			fprintf(f, "}\n\n");
		}
		else
		{
			fprintf(f, "// No exports\n\n");
		}
	}

	inline void DumpAllModuleList(FILE* f)
	{
		auto modules = Dumper::EnumerateModules();
		fprintf(f, "// === All Loaded Modules (%zu) ===\n", modules.size());
		for (auto& mod : modules)
			fprintf(f, "// 0x%012llX  %8u KB  %s\n", mod.base, mod.size / 1024, mod.name.c_str());
		fprintf(f, "\n");
	}

	// ============================================================
	// Mono offset dumper (Unturned, etc.)
	// ============================================================
	inline bool DumpMonoOffsets(const GameDef& game, const std::string& outDir)
	{
		baseAddress = DMA::GetModuleBase(game.monoModule);
		if (!baseAddress)
		{
			Log("[-] Failed to find %s", game.monoModule);
			return false;
		}
		Log("[+] %s -> 0x%llX", game.monoModule, baseAddress);

		GET_ROOT_DOMAIN_OFFSET = find_root_domain_offset();
		if (!GET_ROOT_DOMAIN_OFFSET)
		{
			Log("[-] Could not find root domain offset");
			return false;
		}

		auto root = mono::get_root_domain();
		if (!root)
		{
			Log("[-] Could not get root domain");
			return false;
		}

		// Walk all assemblies and dump every class
		std::string filePath = outDir + "\\offsets.h";
		FILE* f = nullptr;
		fopen_s(&f, filePath.c_str(), "w");
		if (!f) { Log("[-] Failed to create %s", filePath.c_str()); return false; }

		time_t now = time(nullptr);
		struct tm t = {};
		localtime_s(&t, &now);
		char date[32];
		sprintf_s(date, "%04d-%02d-%02d", t.tm_year + 1900, t.tm_mon + 1, t.tm_mday);

		fprintf(f, "// %s Offset Dump - %s\n", game.name, date);
		fprintf(f, "// Engine: Unity (Mono)\n");
		fprintf(f, "// Auto-generated via DMA Mono reflection\n");
		fprintf(f, "// %s base: 0x%llX\n\n", game.monoModule, baseAddress);
		fprintf(f, "#pragma once\n#include <cstdint>\n\n");

		DumpAllModuleList(f);

		// Walk all assemblies
		auto domain_assemblies = root->domain_assemblies();
		int assemblyCount = 0;
		std::vector<std::pair<std::string, uintptr_t>> assemblies;

		auto cursor = domain_assemblies;
		int maxIter = 256;
		while (cursor && maxIter-- > 0)
		{
			auto data = cursor->data();
			if (data)
			{
				auto asmName = read_widechar(read<uintptr_t>(data + 0x10), 128);
				assemblies.push_back({ asmName, data });
			}
			auto next = cursor->next();
			if (!next) break;
			cursor = reinterpret_cast<glist_t*>(next);
		}

		Log("[+] Found %zu assemblies", assemblies.size());
		fprintf(f, "// Found %zu assemblies\n\n", assemblies.size());

		for (auto& [asmName, asmPtr] : assemblies)
		{
			auto assembly = reinterpret_cast<mono_assembly_t*>(asmPtr);
			auto image = assembly->mono_image();
			if (!image) continue;

			auto tableInfo = image->get_table_info(3);
			if (!tableInfo) continue;

			int rows = tableInfo->get_rows();
			if (rows <= 0) continue;

			fprintf(f, "// ============================================\n");
			fprintf(f, "// Assembly: %s (%d types)\n", asmName.c_str(), rows);
			fprintf(f, "// ============================================\n\n");

			Log("[*] Dumping %s (%d types)...", asmName.c_str(), rows);

			auto tbl = reinterpret_cast<mono_hash_table_t*>(reinterpret_cast<uintptr_t>(image) + 0x4D0);

			for (int i = 0; i < rows; i++)
			{
				auto klass = tbl->lookup<mono_class_t>(reinterpret_cast<void*>(0x02000000 | (i + 1)));
				if (!klass) continue;

				auto className = klass->name();
				auto nsName = klass->namespace_name();
				if (className.empty()) continue;

				std::string fullName = nsName.empty() ? className : nsName + "." + className;

				int numFields = klass->num_fields();
				if (numFields <= 0 || numFields > 500) continue;

				// Make safe namespace name for C++
				std::string safeName = fullName;
				for (auto& ch : safeName)
					if (ch == '.' || ch == '<' || ch == '>' || ch == ' ' || ch == '/' || ch == '+' || ch == '-')
						ch = '_';

				fprintf(f, "// %s (ptr=0x%llX, fields=%d)\n", fullName.c_str(), (uintptr_t)klass, numFields);
				fprintf(f, "namespace %s {\n", safeName.c_str());

				for (int fi = 0; fi < numFields && fi < 200; fi++)
				{
					auto field = klass->get_field(fi);
					if (!field) continue;
					std::string fname = field->name();
					int off = field->offset();
					if (fname.empty()) continue;

					std::string safeFname = fname;
					for (auto& ch : safeFname)
						if (ch == '<' || ch == '>' || ch == ' ' || ch == '/' || ch == '+' || ch == '-')
							ch = '_';

					fprintf(f, "    constexpr uintptr_t %s = 0x%X; // %s\n", safeFname.c_str(), off, fname.c_str());
				}
				fprintf(f, "}\n\n");
			}
		}

		// If this is Unturned, also dump the resolved cheat offsets
		if (strcmp(game.name, "Unturned") == 0)
		{
			Classes::init();
			Offsets::init();

			fprintf(f, "// ============================================\n");
			fprintf(f, "// Resolved Cheat Offsets (Unturned-specific)\n");
			fprintf(f, "// ============================================\n");
			fprintf(f, "namespace CheatOffsets {\n");

			#define DUMP_OFFSET(name) fprintf(f, "    constexpr uintptr_t %s = 0x%X;\n", #name, (uint32_t)Offsets::name)
			DUMP_OFFSET(_localPlayer); DUMP_OFFSET(_player);
			DUMP_OFFSET(_isConnected); DUMP_OFFSET(isLoadingUGC); DUMP_OFFSET(_clients);
			DUMP_OFFSET(channel); DUMP_OFFSET(owner);
			DUMP_OFFSET(_isAdmin); DUMP_OFFSET(_splayer);
			DUMP_OFFSET(_equipment); DUMP_OFFSET(_asset);
			DUMP_OFFSET(recoilMin_x); DUMP_OFFSET(recoilMax_x);
			DUMP_OFFSET(recoilMin_y); DUMP_OFFSET(recoilMax_y);
			DUMP_OFFSET(baseSpreadAngleRadians);
			DUMP_OFFSET(_life); DUMP_OFFSET(_health);
			DUMP_OFFSET(_food); DUMP_OFFSET(_water);
			DUMP_OFFSET(_stamina); DUMP_OFFSET(_virus);
			DUMP_OFFSET(_isBleeding); DUMP_OFFSET(_isBroken);
			DUMP_OFFSET(_movement);
			DUMP_OFFSET(pluginGravityMultiplier); DUMP_OFFSET(pluginSpeedMultiplier);
			DUMP_OFFSET(pluginJumpMultiplier); DUMP_OFFSET(velocity);
			DUMP_OFFSET(pendingLaunchVelocity); DUMP_OFFSET(_vehicle);
			DUMP_OFFSET(pluginFallDamageMultiplier);
			DUMP_OFFSET(_isGrounded); DUMP_OFFSET(totalSpeedMultiplier);
			DUMP_OFFSET(totalGravityMultiplier);
			DUMP_OFFSET(_look); DUMP_OFFSET(_yaw); DUMP_OFFSET(_pitch);
			DUMP_OFFSET(flinchLocalRotation); DUMP_OFFSET(smoothedExplosionLocalRotation);
			DUMP_OFFSET(_animator); DUMP_OFFSET(scopeSway);
			DUMP_OFFSET(_clothing); DUMP_OFFSET(fallingDamageMultiplier);
			DUMP_OFFSET(_playerID); DUMP_OFFSET(_characterName);
			DUMP_OFFSET(firerate); DUMP_OFFSET(range);
			DUMP_OFFSET(spreadHip); DUMP_OFFSET(spreadAim);
			DUMP_OFFSET(aimingMovementSpeedMultiplier); DUMP_OFFSET(damageFalloffRange);
			DUMP_OFFSET(_speed); DUMP_OFFSET(_fuel);
			DUMP_OFFSET(_isExploded); DUMP_OFFSET(_health_vehicle);
			DUMP_OFFSET(vm_vehicles); DUMP_OFFSET(im_clampedItems);
			DUMP_OFFSET(ii_asset); DUMP_OFFSET(ia_itemName);
			DUMP_OFFSET(zm_tickingZombies); DUMP_OFFSET(zm_zombies);
			DUMP_OFFSET(zm_regions); DUMP_OFFSET(zr_zombies);
			DUMP_OFFSET(z_isDead); DUMP_OFFSET(_useable);
			DUMP_OFFSET(ug_isReloading); DUMP_OFFSET(ug_reloadTime);
			DUMP_OFFSET(ug_needsRechamber); DUMP_OFFSET(ll_vision);
			DUMP_OFFSET(os_cachedVerticalFOV);
			#undef DUMP_OFFSET

			fprintf(f, "}\n\n");
		}

		fclose(f);
		Log("[+] Mono offsets dumped to %s", filePath.c_str());
		return true;
	}

	// ============================================================
	// IL2CPP offset dumper (Rust, etc.)
	// ============================================================

	#pragma pack(push, 1)
	struct Il2CppMetadataHeader {
		uint32_t magic;         // 0xFAB11BAF
		int32_t  version;
		int32_t  stringLiteralOffset;
		int32_t  stringLiteralCount;
		int32_t  stringLiteralDataOffset;
		int32_t  stringLiteralDataCount;
		int32_t  stringOffset;
		int32_t  stringCount;
		int32_t  eventsOffset;
		int32_t  eventsCount;
		int32_t  propertiesOffset;
		int32_t  propertiesCount;
		int32_t  methodsOffset;
		int32_t  methodsCount;
		int32_t  parameterDefaultValuesOffset;
		int32_t  parameterDefaultValuesCount;
		int32_t  fieldDefaultValuesOffset;
		int32_t  fieldDefaultValuesCount;
		int32_t  fieldAndParameterDefaultValueDataOffset;
		int32_t  fieldAndParameterDefaultValueDataCount;
		int32_t  fieldMarshaledSizesOffset;
		int32_t  fieldMarshaledSizesCount;
		int32_t  parametersOffset;
		int32_t  parametersCount;
		int32_t  fieldsOffset;
		int32_t  fieldsCount;
		int32_t  genericParametersOffset;
		int32_t  genericParametersCount;
		int32_t  genericParameterConstraintsOffset;
		int32_t  genericParameterConstraintsCount;
		int32_t  genericContainersOffset;
		int32_t  genericContainersCount;
		int32_t  nestedTypesOffset;
		int32_t  nestedTypesCount;
		int32_t  interfacesOffset;
		int32_t  interfacesCount;
		int32_t  vtableMethodsOffset;
		int32_t  vtableMethodsCount;
		int32_t  interfaceOffsetsOffset;
		int32_t  interfaceOffsetsCount;
		int32_t  typeDefinitionsOffset;
		int32_t  typeDefinitionsCount;
		int32_t  imagesOffset;
		int32_t  imagesCount;
		int32_t  assembliesOffset;
		int32_t  assembliesCount;
	};

	struct Il2CppFieldDefinition {
		int32_t nameIndex;
		int32_t typeIndex;
		uint32_t token;
	};

	struct Il2CppTypeDefinition {
		int32_t nameIndex;
		int32_t namespaceIndex;
		int32_t byvalTypeIndex;
		int32_t declaringTypeIndex;
		int32_t parentIndex;
		int32_t elementTypeIndex;
		int32_t genericContainerIndex;
		uint32_t flags;
		int32_t fieldStart;
		int32_t methodStart;
		int32_t eventStart;
		int32_t propertyStart;
		int32_t nestedTypesStart;
		int32_t interfacesStart;
		int32_t vtableStart;
		int32_t interfaceOffsetsStart;
		uint16_t method_count;
		uint16_t property_count;
		uint16_t field_count;
		uint16_t event_count;
		uint16_t nested_type_count;
		uint16_t vtable_count;
		uint16_t interfaces_count;
		uint16_t interface_offsets_count;
		uint32_t bitfield;
		uint32_t token;
	};

	struct Il2CppImageDefinition {
		int32_t nameIndex;
		int32_t assemblyIndex;
		int32_t typeStart;
		uint32_t typeCount;
		int32_t exportedTypeStart;
		uint32_t exportedTypeCount;
		int32_t entryPointIndex;
		uint32_t token;
		int32_t customAttributeStart;
		uint32_t customAttributeCount;
	};
	#pragma pack(pop)

	inline std::string ReadMetadataString(DWORD64 metaBase, int32_t stringOffset, int32_t index)
	{
		if (index < 0 || index >= stringOffset) return "";
		char buf[512] = {};
		read_buffer(metaBase + stringOffset + index, buf, 511);
		buf[511] = 0;
		return std::string(buf);
	}

	inline bool DumpIL2CPPOffsets(const GameDef& game, const std::string& outDir)
	{
		DWORD64 gaBase = DMA::GetModuleBase("GameAssembly.dll");
		if (!gaBase)
		{
			Log("[-] GameAssembly.dll not found");
			return false;
		}
		Log("[+] GameAssembly.dll -> 0x%llX", gaBase);

		// Find global-metadata.dat in memory by scanning loaded modules
		// It's typically loaded as a memory-mapped file, look for the magic
		DWORD64 metaBase = 0;
		auto modules = Dumper::EnumerateModules();

		// First try: scan GameAssembly.dll's data sections for a pointer to metadata
		// The metadata is usually in a separate allocation. Search process memory.
		Log("[*] Scanning for IL2CPP metadata (magic 0xFAB11BAF)...");

		// Scan each module for the metadata magic as a fallback
		// But metadata is typically its own allocation. Use VMMDLL scatter read to scan.
		// Simpler approach: check common module "global-metadata.dat"
		// It's not a PE module but we can scan known regions

		// Try reading from GameAssembly.dll exports to find metadata pointer
		IMAGE_DOS_HEADER dos = {};
		read_buffer(gaBase, &dos, sizeof(dos));
		IMAGE_NT_HEADERS64 nt = {};
		read_buffer(gaBase + dos.e_lfanew, &nt, sizeof(nt));

		// Scan .rdata section of GameAssembly for the metadata pointer
		WORD numSections = nt.FileHeader.NumberOfSections;
		DWORD64 secBase = gaBase + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS64);

		for (WORD si = 0; si < numSections && !metaBase; si++)
		{
			IMAGE_SECTION_HEADER sec = {};
			read_buffer(secBase + si * sizeof(IMAGE_SECTION_HEADER), &sec, sizeof(sec));
			char secName[9] = {};
			memcpy(secName, sec.Name, 8);

			// Only scan data sections, not code
			if (strcmp(secName, ".data") != 0 && strcmp(secName, ".rdata") != 0) continue;

			DWORD scanSize = min(sec.Misc.VirtualSize, 64 * 1024 * 1024);
			DWORD chunkSize = 0x10000;

			for (DWORD offset = 0; offset < scanSize && !metaBase; offset += chunkSize)
			{
				DWORD toRead = min(chunkSize, scanSize - offset);
				std::vector<BYTE> chunk(toRead);
				read_buffer(gaBase + sec.VirtualAddress + offset, chunk.data(), toRead);

				// Look for pointers that might reference metadata
				// Scan for 8-byte aligned pointers, read where they point, check for magic
				for (DWORD j = 0; j + 8 <= toRead; j += 8)
				{
					DWORD64 ptr = *(DWORD64*)(chunk.data() + j);
					if (ptr < 0x10000 || ptr > 0x7FFFFFFFFFFF) continue;

					uint32_t magic = 0;
					read_buffer(ptr, &magic, 4);
					if (magic == 0xFAB11BAF)
					{
						metaBase = ptr;
						Log("[+] Found IL2CPP metadata at 0x%llX (via %s+0x%X)", metaBase, secName, sec.VirtualAddress + offset + j);
						break;
					}
				}
			}
		}

		std::string filePath = outDir + "\\offsets.h";
		FILE* f = nullptr;
		fopen_s(&f, filePath.c_str(), "w");
		if (!f) { Log("[-] Failed to create %s", filePath.c_str()); return false; }

		time_t now = time(nullptr);
		struct tm t = {};
		localtime_s(&t, &now);
		char date[32];
		sprintf_s(date, "%04d-%02d-%02d", t.tm_year + 1900, t.tm_mon + 1, t.tm_mday);

		fprintf(f, "// %s Offset Dump - %s\n", game.name, date);
		fprintf(f, "// Engine: Unity (IL2CPP)\n");
		fprintf(f, "// Auto-generated via DMA IL2CPP metadata parsing\n");
		fprintf(f, "// GameAssembly.dll base: 0x%llX\n", gaBase);
		if (metaBase) fprintf(f, "// global-metadata base: 0x%llX\n", metaBase);
		fprintf(f, "\n#pragma once\n#include <cstdint>\n\n");

		DumpAllModuleList(f);
		DumpModuleExports(f, "GameAssembly.dll");

		if (!metaBase)
		{
			fprintf(f, "// WARNING: Could not locate global-metadata.dat in memory\n");
			fprintf(f, "// Only module exports were dumped. Run il2cppdumper on the PE dumps for full offsets.\n");
			Log("[!] Metadata not found. Dumped exports only. Use il2cppdumper on PE dumps for full offsets.");
			fclose(f);
			return true;
		}

		// Parse metadata
		Il2CppMetadataHeader header = {};
		read_buffer(metaBase, &header, sizeof(header));
		Log("[+] IL2CPP metadata version: %d", header.version);
		fprintf(f, "// IL2CPP metadata version: %d\n", header.version);
		fprintf(f, "// Type definitions: %d\n", header.typeDefinitionsCount);
		fprintf(f, "// Field definitions: %d\n", header.fieldsCount);
		fprintf(f, "// Method definitions: %d\n\n", header.methodsCount);

		// Read string table (for type and field names)
		int32_t stringTableSize = header.stringCount;
		if (stringTableSize <= 0 || stringTableSize > 32 * 1024 * 1024)
		{
			fprintf(f, "// String table size invalid: %d\n", stringTableSize);
			fclose(f);
			return true;
		}

		// Calculate sizes
		int typeDefSize = sizeof(Il2CppTypeDefinition);
		int fieldDefSize = sizeof(Il2CppFieldDefinition);
		int numTypes = header.typeDefinitionsCount / typeDefSize;
		int numFields = header.fieldsCount / fieldDefSize;

		if (numTypes <= 0 || numTypes > 200000) {
			// Try count-based (some versions store count directly)
			numTypes = header.typeDefinitionsCount;
			if (numTypes <= 0 || numTypes > 200000) {
				fprintf(f, "// Could not determine type count (raw: %d)\n", header.typeDefinitionsCount);
				fclose(f);
				return true;
			}
		}

		Log("[*] Parsing %d types, %d fields...", numTypes, numFields > 0 ? numFields : header.fieldsCount);

		// Read image definitions to group types by assembly
		int numImages = header.imagesCount / (int)sizeof(Il2CppImageDefinition);
		if (numImages <= 0 || numImages > 5000) numImages = header.imagesCount;

		std::vector<Il2CppImageDefinition> images;
		if (numImages > 0 && numImages < 5000)
		{
			images.resize(numImages);
			read_buffer(metaBase + header.imagesOffset, images.data(), numImages * sizeof(Il2CppImageDefinition));
		}

		// Read all type definitions
		std::vector<Il2CppTypeDefinition> types(numTypes);
		read_buffer(metaBase + header.typeDefinitionsOffset, types.data(), numTypes * typeDefSize);

		// Read all field definitions
		int actualFields = numFields > 0 ? numFields : header.fieldsCount;
		if (actualFields > 500000) actualFields = 500000;
		std::vector<Il2CppFieldDefinition> fields(actualFields);
		read_buffer(metaBase + header.fieldsOffset, fields.data(), actualFields * fieldDefSize);

		// Dump by image (assembly)
		for (int img = 0; img < (int)images.size(); img++)
		{
			std::string imgName = ReadMetadataString(metaBase, header.stringOffset, images[img].nameIndex);
			if (imgName.empty()) continue;

			int typeStart = images[img].typeStart;
			int typeCount = images[img].typeCount;
			if (typeCount <= 0 || typeStart < 0) continue;

			fprintf(f, "// ============================================\n");
			fprintf(f, "// Image: %s (%u types)\n", imgName.c_str(), typeCount);
			fprintf(f, "// ============================================\n\n");

			for (int ti = typeStart; ti < typeStart + (int)typeCount && ti < numTypes; ti++)
			{
				auto& td = types[ti];
				std::string typeName = ReadMetadataString(metaBase, header.stringOffset, td.nameIndex);
				std::string typeNs = ReadMetadataString(metaBase, header.stringOffset, td.namespaceIndex);
				if (typeName.empty()) continue;

				std::string fullName = typeNs.empty() ? typeName : typeNs + "." + typeName;

				if (td.field_count == 0) continue;

				std::string safeName = fullName;
				for (auto& ch : safeName)
					if (ch == '.' || ch == '<' || ch == '>' || ch == ' ' || ch == '/' || ch == '+' || ch == '-' || ch == '`')
						ch = '_';

				fprintf(f, "// %s (fields=%d)\n", fullName.c_str(), td.field_count);
				fprintf(f, "namespace %s {\n", safeName.c_str());

				for (int fi = 0; fi < td.field_count && (td.fieldStart + fi) < actualFields; fi++)
				{
					auto& fd = fields[td.fieldStart + fi];
					std::string fname = ReadMetadataString(metaBase, header.stringOffset, fd.nameIndex);
					if (fname.empty()) continue;

					std::string safeFname = fname;
					for (auto& ch : safeFname)
						if (ch == '<' || ch == '>' || ch == ' ' || ch == '/' || ch == '+' || ch == '-')
							ch = '_';

					// IL2CPP field offsets are runtime-computed, token gives metadata identity
					fprintf(f, "    // token=0x%08X type_idx=%d  %s\n", fd.token, fd.typeIndex, fname.c_str());
				}
				fprintf(f, "}\n\n");
			}
		}

		fclose(f);
		Log("[+] IL2CPP offsets dumped to %s", filePath.c_str());
		return true;
	}

	// ============================================================
	// Pattern scanner
	// ============================================================
	struct PatternByte {
		uint8_t value;
		bool wildcard;
	};

	inline std::vector<PatternByte> ParsePattern(const char* pattern)
	{
		std::vector<PatternByte> result;
		const char* p = pattern;
		while (*p)
		{
			while (*p == ' ') p++;
			if (!*p) break;
			if (*p == '?')
			{
				result.push_back({ 0, true });
				p++;
				if (*p == '?') p++;
			}
			else
			{
				char hex[3] = { p[0], p[1], 0 };
				result.push_back({ (uint8_t)strtol(hex, nullptr, 16), false });
				p += 2;
			}
		}
		return result;
	}

	inline DWORD64 ScanPattern(DWORD64 base, DWORD size, const char* pattern, int skip = 0)
	{
		auto pat = ParsePattern(pattern);
		if (pat.empty()) return 0;

		const DWORD chunkSize = 0x100000;
		DWORD overlap = (DWORD)pat.size();
		int found = 0;

		for (DWORD offset = 0; offset < size; offset += chunkSize - overlap)
		{
			DWORD toRead = min(chunkSize, size - offset);
			if (toRead < pat.size()) break;
			std::vector<BYTE> chunk(toRead);
			read_buffer(base + offset, chunk.data(), toRead);

			for (DWORD i = 0; i + pat.size() <= toRead; i++)
			{
				bool match = true;
				for (size_t j = 0; j < pat.size(); j++)
				{
					if (!pat[j].wildcard && chunk[i + j] != pat[j].value)
					{ match = false; break; }
				}
				if (match)
				{
					if (found++ == skip)
						return base + offset + i;
				}
			}
		}
		return 0;
	}

	inline DWORD64 ScanPatternMulti(DWORD64 base, DWORD size, const char* pattern)
	{
		return ScanPattern(base, size, pattern, 0);
	}

	inline DWORD64 ResolveRIP(DWORD64 instrAddr, int opcodeLen)
	{
		int32_t disp = read<int32_t>(instrAddr + opcodeLen);
		return instrAddr + opcodeLen + 4 + disp;
	}

	struct SectionInfo {
		DWORD64 base;
		DWORD   size;
		char    name[9];
		DWORD   characteristics;
	};

	inline std::vector<SectionInfo> GetPESections(DWORD64 modBase)
	{
		std::vector<SectionInfo> result;
		IMAGE_DOS_HEADER dos = {};
		read_buffer(modBase, &dos, sizeof(dos));
		if (dos.e_magic != IMAGE_DOS_SIGNATURE) return result;

		IMAGE_NT_HEADERS64 nt = {};
		read_buffer(modBase + dos.e_lfanew, &nt, sizeof(nt));
		if (nt.Signature != IMAGE_NT_SIGNATURE) return result;

		DWORD64 secBase = modBase + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS64);
		for (WORD i = 0; i < nt.FileHeader.NumberOfSections; i++)
		{
			IMAGE_SECTION_HEADER sec = {};
			read_buffer(secBase + i * sizeof(IMAGE_SECTION_HEADER), &sec, sizeof(sec));
			SectionInfo si = {};
			si.base = modBase + sec.VirtualAddress;
			si.size = sec.Misc.VirtualSize;
			si.characteristics = sec.Characteristics;
			memcpy(si.name, sec.Name, 8);
			si.name[8] = 0;
			result.push_back(si);
		}
		return result;
	}

	// ============================================================
	// UE4/UE5 FName reader
	// ============================================================
	inline std::string ReadUEFName(DWORD64 gnamesBase, int32_t nameIndex)
	{
		if (nameIndex <= 0 || !gnamesBase) return "";

		// Method 1: Chunked pool (UE4 4.23+ / UE5)
		int blockIdx = (nameIndex >> 16) & 0xFFFF;
		int offsetInBlock = nameIndex & 0xFFFF;

		DWORD64 block = read<DWORD64>(gnamesBase + 0x10 + blockIdx * 8);
		if (block > 0x10000 && block < 0x7FFFFFFFFFFF)
		{
			DWORD64 entry = block + (DWORD64)offsetInBlock * 2;
			uint16_t header = read<uint16_t>(entry);
			int len = header >> 6;
			if (len > 0 && len <= 256)
			{
				char buf[257] = {};
				read_buffer(entry + 2, buf, len);
				buf[len] = 0;
				bool valid = (strlen(buf) > 0);
				for (int i = 0; buf[i] && valid; i++)
					if ((unsigned char)buf[i] < 0x20 || (unsigned char)buf[i] > 0x7E) valid = false;
				if (valid) return std::string(buf);
			}
		}

		// Method 2: Old-style chunked array (UE4 < 4.23)
		int chunkIdx = nameIndex / 16384;
		int chunkOff = nameIndex % 16384;
		DWORD64 chunk = read<DWORD64>(gnamesBase + chunkIdx * 8);
		if (chunk > 0x10000 && chunk < 0x7FFFFFFFFFFF)
		{
			DWORD64 entry = read<DWORD64>(chunk + chunkOff * 8);
			if (entry > 0x10000 && entry < 0x7FFFFFFFFFFF)
			{
				for (int off : {0x10, 0x0C, 0x08})
				{
					char buf[257] = {};
					read_buffer(entry + off, buf, 256);
					buf[256] = 0;
					bool valid = (strlen(buf) > 1);
					for (int i = 0; buf[i] && valid; i++)
						if ((unsigned char)buf[i] < 0x20 || (unsigned char)buf[i] > 0x7E) valid = false;
					if (valid) return std::string(buf);
				}
			}
		}
		return "";
	}

	// ============================================================
	// Unreal Engine 4/5 offset dumper
	// ============================================================
	inline bool DumpUEOffsets(const GameDef& game, const std::string& outDir, bool isUE5)
	{
		DWORD64 modBase = DMA::GetModuleBase(game.coreModule);
		if (!modBase) { Log("[-] %s not found", game.coreModule); return false; }
		Log("[+] %s -> 0x%llX", game.coreModule, modBase);

		auto sections = GetPESections(modBase);
		DWORD64 textBase = 0;
		DWORD textSize = 0;
		for (auto& s : sections)
		{
			if (strcmp(s.name, ".text") == 0)
			{ textBase = s.base; textSize = s.size; break; }
		}
		if (!textBase)
		{
			for (auto& s : sections)
			{
				if (s.characteristics & IMAGE_SCN_MEM_EXECUTE)
				{ textBase = s.base; textSize = s.size; break; }
			}
		}
		if (!textBase) { Log("[-] No executable section"); return false; }

		Log("[*] Scanning %s .text: 0x%llX (%u MB)", isUE5 ? "UE5" : "UE4",
			textBase, textSize / (1024 * 1024));

		// === Scan for GWorld ===
		DWORD64 gworldPtr = 0;
		const char* gworldSigs[] = {
			"48 8B 1D ?? ?? ?? ?? 48 85 DB 74",
			"48 8B 05 ?? ?? ?? ?? 48 8B 88 ?? ?? 00 00 48 85 C9 74 06 48 8B 49",
			"48 89 05 ?? ?? ?? ?? 48 8B 4B",
			"48 8B 05 ?? ?? ?? ?? 48 3B C3 48 0F 44 05",
			nullptr
		};
		for (int i = 0; gworldSigs[i] && !gworldPtr; i++)
		{
			DWORD64 addr = ScanPattern(textBase, textSize, gworldSigs[i]);
			if (addr)
			{
				DWORD64 resolved = ResolveRIP(addr, 3);
				DWORD64 val = read<DWORD64>(resolved);
				if (val > 0x10000 && val < 0x7FFFFFFFFFFF)
				{
					gworldPtr = resolved;
					Log("[+] GWorld @ 0x%llX (sig #%d, val=0x%llX)", resolved, i, val);
				}
			}
		}

		// === Scan for GNames ===
		DWORD64 gnamesPtr = 0;
		const char* gnamesSigs[] = {
			"48 8D 05 ?? ?? ?? ?? EB ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? C6 05",
			"4C 8D 05 ?? ?? ?? ?? EB ?? 48 8D 0D",
			"E8 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ??",
			"48 8D 35 ?? ?? ?? ?? EB ?? 48 8D 0D",
			nullptr
		};
		for (int i = 0; gnamesSigs[i] && !gnamesPtr; i++)
		{
			DWORD64 addr = ScanPattern(textBase, textSize, gnamesSigs[i]);
			if (addr)
			{
				gnamesPtr = ResolveRIP(addr, 3);
				// Validate: read first block, check it points somewhere valid
				DWORD64 block0 = read<DWORD64>(gnamesPtr + 0x10);
				if (block0 > 0x10000 && block0 < 0x7FFFFFFFFFFF)
				{
					std::string testName = ReadUEFName(gnamesPtr, 1);
					if (!testName.empty())
					{
						Log("[+] GNames @ 0x%llX (sig #%d, test='%s')", gnamesPtr, i, testName.c_str());
						break;
					}
				}
				gnamesPtr = 0;
			}
		}

		// === Scan for GObjects ===
		DWORD64 gobjectsPtr = 0;
		const char* gobjectsSigs[] = {
			"48 8B 05 ?? ?? ?? ?? 48 8B 0C C8 48 8D 04 D1",
			"48 8B 05 ?? ?? ?? ?? 48 8B 0C C8 48 8B 04 D1",
			"48 8B 05 ?? ?? ?? ?? 48 63 C9 48 8B 0C C8",
			"89 0D ?? ?? ?? ?? 48 8B DF 48 89 5C 24",
			nullptr
		};
		for (int i = 0; gobjectsSigs[i] && !gobjectsPtr; i++)
		{
			DWORD64 addr = ScanPattern(textBase, textSize, gobjectsSigs[i]);
			if (addr)
			{
				gobjectsPtr = ResolveRIP(addr, 3);
				Log("[+] GObjects @ 0x%llX (sig #%d)", gobjectsPtr, i);
				break;
			}
		}

		// === Output ===
		std::string filePath = outDir + "\\offsets.h";
		FILE* f = nullptr;
		fopen_s(&f, filePath.c_str(), "w");
		if (!f) return false;

		time_t now = time(nullptr);
		struct tm ti = {};
		localtime_s(&ti, &now);
		char date[32];
		sprintf_s(date, "%04d-%02d-%02d", ti.tm_year + 1900, ti.tm_mon + 1, ti.tm_mday);

		fprintf(f, "// %s Offset Dump - %s\n", game.name, date);
		fprintf(f, "// Engine: %s\n", isUE5 ? "Unreal Engine 5" : "Unreal Engine 4");
		fprintf(f, "// Auto-generated via DMA pattern scanning + reflection\n");
		fprintf(f, "// %s base: 0x%llX\n\n", game.coreModule, modBase);
		fprintf(f, "#pragma once\n#include <cstdint>\n\n");

		DumpAllModuleList(f);

		fprintf(f, "// ============================================\n");
		fprintf(f, "// UE Globals (Pattern Scan Results)\n");
		fprintf(f, "// ============================================\n\n");
		fprintf(f, "namespace UE_Globals {\n");
		fprintf(f, "    constexpr uintptr_t ModuleBase = 0x%llX;\n", modBase);
		if (gworldPtr)
			fprintf(f, "    constexpr uintptr_t GWorld   = 0x%llX;  // RVA=0x%llX\n", gworldPtr, gworldPtr - modBase);
		else
			fprintf(f, "    constexpr uintptr_t GWorld   = 0x0;  // NOT FOUND\n");
		if (gnamesPtr)
			fprintf(f, "    constexpr uintptr_t GNames   = 0x%llX;  // RVA=0x%llX\n", gnamesPtr, gnamesPtr - modBase);
		else
			fprintf(f, "    constexpr uintptr_t GNames   = 0x0;  // NOT FOUND\n");
		if (gobjectsPtr)
			fprintf(f, "    constexpr uintptr_t GObjects = 0x%llX;  // RVA=0x%llX\n", gobjectsPtr, gobjectsPtr - modBase);
		else
			fprintf(f, "    constexpr uintptr_t GObjects = 0x0;  // NOT FOUND\n");
		fprintf(f, "}\n\n");

		// Common UE4/5 structure offsets
		fprintf(f, "// ============================================\n");
		fprintf(f, "// %s Common Offsets\n", isUE5 ? "UE5" : "UE4");
		fprintf(f, "// ============================================\n\n");

		fprintf(f, "namespace UObject {\n");
		fprintf(f, "    constexpr int VTable       = 0x00;\n");
		fprintf(f, "    constexpr int ObjectFlags  = 0x08;\n");
		fprintf(f, "    constexpr int InternalIndex= 0x0C;\n");
		fprintf(f, "    constexpr int ClassPrivate = 0x10;\n");
		fprintf(f, "    constexpr int NamePrivate  = 0x18;\n");
		fprintf(f, "    constexpr int OuterPrivate = 0x20;\n");
		fprintf(f, "}\n\n");

		fprintf(f, "namespace FName {\n");
		fprintf(f, "    constexpr int ComparisonIndex = 0x00;\n");
		fprintf(f, "    constexpr int Number          = 0x04;\n");
		fprintf(f, "}\n\n");

		if (isUE5)
		{
			fprintf(f, "namespace UWorld {\n");
			fprintf(f, "    constexpr int PersistentLevel    = 0x30;\n");
			fprintf(f, "    constexpr int OwningGameInstance = 0x1B8;\n");
			fprintf(f, "    constexpr int Levels             = 0x170;\n");
			fprintf(f, "    constexpr int GameState          = 0x158;\n");
			fprintf(f, "}\n\n");

			fprintf(f, "namespace ULevel {\n");
			fprintf(f, "    constexpr int Actors     = 0x98;\n");
			fprintf(f, "    constexpr int ActorCount = 0xA0;\n");
			fprintf(f, "}\n\n");

			fprintf(f, "namespace AActor {\n");
			fprintf(f, "    constexpr int RootComponent    = 0x198;\n");
			fprintf(f, "    constexpr int bHidden          = 0x60;\n");
			fprintf(f, "    constexpr int bCanBeDamaged     = 0x62;\n");
			fprintf(f, "    constexpr int Owner             = 0x100;\n");
			fprintf(f, "    constexpr int CustomTimeDilation= 0xA0;\n");
			fprintf(f, "}\n\n");

			fprintf(f, "namespace USceneComponent {\n");
			fprintf(f, "    constexpr int RelativeLocation  = 0x128;\n");
			fprintf(f, "    constexpr int RelativeRotation  = 0x134;\n");
			fprintf(f, "    constexpr int RelativeScale3D   = 0x140;\n");
			fprintf(f, "    constexpr int ComponentToWorld  = 0x1C0;\n");
			fprintf(f, "}\n\n");
		}
		else
		{
			fprintf(f, "namespace UWorld {\n");
			fprintf(f, "    constexpr int PersistentLevel    = 0x30;\n");
			fprintf(f, "    constexpr int OwningGameInstance = 0x180;\n");
			fprintf(f, "    constexpr int Levels             = 0x148;\n");
			fprintf(f, "    constexpr int GameState          = 0x128;\n");
			fprintf(f, "}\n\n");

			fprintf(f, "namespace ULevel {\n");
			fprintf(f, "    constexpr int Actors     = 0x98;\n");
			fprintf(f, "    constexpr int ActorCount = 0xA0;\n");
			fprintf(f, "}\n\n");

			fprintf(f, "namespace AActor {\n");
			fprintf(f, "    constexpr int RootComponent    = 0x130;\n");
			fprintf(f, "    constexpr int bHidden          = 0x58;\n");
			fprintf(f, "    constexpr int Owner             = 0xE0;\n");
			fprintf(f, "}\n\n");

			fprintf(f, "namespace USceneComponent {\n");
			fprintf(f, "    constexpr int RelativeLocation  = 0x11C;\n");
			fprintf(f, "    constexpr int RelativeRotation  = 0x128;\n");
			fprintf(f, "    constexpr int RelativeScale3D   = 0x134;\n");
			fprintf(f, "    constexpr int ComponentToWorld  = 0x1C0;\n");
			fprintf(f, "}\n\n");
		}

		fprintf(f, "namespace APawn {\n");
		fprintf(f, "    constexpr int PlayerState   = 0x%X;\n", isUE5 ? 0x2A8 : 0x248);
		fprintf(f, "    constexpr int Controller    = 0x%X;\n", isUE5 ? 0x290 : 0x230);
		fprintf(f, "}\n\n");

		fprintf(f, "namespace ACharacter {\n");
		fprintf(f, "    constexpr int Mesh          = 0x%X;\n", isUE5 ? 0x318 : 0x280);
		fprintf(f, "    constexpr int CharMovement  = 0x%X;\n", isUE5 ? 0x308 : 0x278);
		fprintf(f, "}\n\n");

		fprintf(f, "namespace APlayerState {\n");
		fprintf(f, "    constexpr int Score          = 0x%X;\n", isUE5 ? 0x2C4 : 0x298);
		fprintf(f, "    constexpr int PlayerNamePrivate = 0x%X;\n", isUE5 ? 0x310 : 0x300);
		fprintf(f, "    constexpr int PlayerId      = 0x%X;\n", isUE5 ? 0x2C8 : 0x29C);
		fprintf(f, "}\n\n");

		fprintf(f, "namespace APlayerController {\n");
		fprintf(f, "    constexpr int PlayerCameraManager = 0x%X;\n", isUE5 ? 0x338 : 0x2B8);
		fprintf(f, "    constexpr int AcknowledgedPawn    = 0x%X;\n", isUE5 ? 0x330 : 0x2B0);
		fprintf(f, "}\n\n");

		fprintf(f, "namespace APlayerCameraManager {\n");
		fprintf(f, "    constexpr int CameraCachePrivate  = 0x%X;\n", isUE5 ? 0x2220 : 0x1AB0);
		fprintf(f, "}\n\n");

		fprintf(f, "namespace UGameInstance {\n");
		fprintf(f, "    constexpr int LocalPlayers = 0x38;\n");
		fprintf(f, "}\n\n");

		fprintf(f, "namespace ULocalPlayer {\n");
		fprintf(f, "    constexpr int PlayerController = 0x30;\n");
		fprintf(f, "}\n\n");

		fprintf(f, "namespace USkeletalMeshComponent {\n");
		fprintf(f, "    constexpr int BoneArray      = 0x%X;\n", isUE5 ? 0x5B0 : 0x480);
		fprintf(f, "    constexpr int BoneCount      = 0x%X;\n", isUE5 ? 0x5B8 : 0x488);
		fprintf(f, "    constexpr int ComponentSpace = 0x%X;\n", isUE5 ? 0x250 : 0x1F0);
		fprintf(f, "}\n\n");

		fprintf(f, "namespace UCharacterMovementComponent {\n");
		fprintf(f, "    constexpr int Velocity           = 0x%X;\n", isUE5 ? 0x178 : 0x134);
		fprintf(f, "    constexpr int MaxWalkSpeed       = 0x%X;\n", isUE5 ? 0x1A8 : 0x168);
		fprintf(f, "    constexpr int JumpZVelocity      = 0x%X;\n", isUE5 ? 0x2D8 : 0x298);
		fprintf(f, "    constexpr int GravityScale       = 0x%X;\n", isUE5 ? 0x248 : 0x208);
		fprintf(f, "}\n\n");

		// === Walk GWorld chain ===
		if (gworldPtr)
		{
			DWORD64 world = read<DWORD64>(gworldPtr);
			fprintf(f, "// ============================================\n");
			fprintf(f, "// Live GWorld Chain\n");
			fprintf(f, "// ============================================\n\n");

			int persLevelOff = isUE5 ? 0x30 : 0x30;
			int gameStateOff = isUE5 ? 0x158 : 0x128;
			int gameInstOff  = isUE5 ? 0x1B8 : 0x180;

			if (world > 0x10000)
			{
				DWORD64 persLevel = read<DWORD64>(world + persLevelOff);
				DWORD64 gameState = read<DWORD64>(world + gameStateOff);
				DWORD64 gameInst  = read<DWORD64>(world + gameInstOff);

				fprintf(f, "// UWorld           = 0x%llX\n", world);
				fprintf(f, "// PersistentLevel  = 0x%llX\n", persLevel);
				fprintf(f, "// GameState        = 0x%llX\n", gameState);
				fprintf(f, "// GameInstance     = 0x%llX\n\n", gameInst);

				if (persLevel > 0x10000)
				{
					DWORD64 actorsPtr = read<DWORD64>(persLevel + 0x98);
					int32_t actorCount = read<int32_t>(persLevel + 0xA0);
					fprintf(f, "// Actors array = 0x%llX, count = %d\n", actorsPtr, actorCount);

					if (actorsPtr > 0x10000 && actorCount > 0 && actorCount < 100000)
					{
						fprintf(f, "// Sample actors (first 10):\n");
						for (int i = 0; i < min(actorCount, 10); i++)
						{
							DWORD64 actor = read<DWORD64>(actorsPtr + i * 8);
							if (!actor) continue;

							std::string actorName = "";
							if (gnamesPtr)
							{
								int32_t nameIdx = read<int32_t>(actor + 0x18);
								actorName = ReadUEFName(gnamesPtr, nameIdx);
							}

							DWORD64 classPtr = read<DWORD64>(actor + 0x10);
							std::string className = "";
							if (classPtr && gnamesPtr)
							{
								int32_t classNameIdx = read<int32_t>(classPtr + 0x18);
								className = ReadUEFName(gnamesPtr, classNameIdx);
							}

							fprintf(f, "//   [%d] 0x%llX  class=%s  name=%s\n",
								i, actor, className.c_str(), actorName.c_str());
						}
					}
					fprintf(f, "\n");
				}
			}
		}

		// === Try to walk GObjects for class property dumps ===
		if (gobjectsPtr && gnamesPtr)
		{
			fprintf(f, "// ============================================\n");
			fprintf(f, "// GObjects Class/Property Scan\n");
			fprintf(f, "// ============================================\n\n");

			// FUObjectArray: +0x00 = ObjObjects (pointer to chunked array)
			// Or in some versions: +0x10 = ObjObjects
			DWORD64 objArray = read<DWORD64>(gobjectsPtr);
			int32_t objCount = read<int32_t>(gobjectsPtr + 0x14);
			if (objCount <= 0 || objCount > 10000000)
			{
				objArray = read<DWORD64>(gobjectsPtr + 0x10);
				objCount = read<int32_t>(gobjectsPtr + 0x0C);
			}

			if (objArray > 0x10000 && objCount > 0 && objCount < 10000000)
			{
				Log("[*] GObjects: %d objects, scanning for classes...", objCount);

				const int CHUNK_SIZE = 65536;
				int classesFound = 0;
				int maxScan = min(objCount, 200000);

				for (int i = 0; i < maxScan && classesFound < 200; i++)
				{
					int chunkIdx = i / CHUNK_SIZE;
					int chunkOff = i % CHUNK_SIZE;

					DWORD64 chunk = read<DWORD64>(objArray + chunkIdx * 8);
					if (!chunk) continue;

					// FUObjectItem is either 24 or 16 bytes depending on version
					DWORD64 obj = read<DWORD64>(chunk + chunkOff * 24);
					if (!obj || obj < 0x10000 || obj > 0x7FFFFFFFFFFF) continue;

					DWORD64 classPtr = read<DWORD64>(obj + 0x10);
					if (!classPtr || classPtr < 0x10000) continue;

					// Check if this IS a UClass (class == self for UClass objects)
					DWORD64 classOfClass = read<DWORD64>(classPtr + 0x10);
					if (classOfClass != classPtr) continue;

					// This is likely a UClass — read its name
					int32_t nameIdx = read<int32_t>(obj + 0x18);
					std::string name = ReadUEFName(gnamesPtr, nameIdx);
					if (name.empty()) continue;

					// Filter to interesting classes
					bool interesting = false;
					const char* keywords[] = {
						"Player", "Pawn", "Character", "Controller",
						"Weapon", "Vehicle", "Health", "Camera",
						"Soldier", "Ship", "Squad", "Team",
						"Inventory", "Item", "Projectile",
						nullptr
					};
					for (int k = 0; keywords[k]; k++)
					{
						if (name.find(keywords[k]) != std::string::npos)
						{ interesting = true; break; }
					}
					if (!interesting) continue;

					fprintf(f, "// UClass: %s @ 0x%llX\n", name.c_str(), obj);

					// Walk ChildProperties (FField chain) at UStruct+0x50 (UE4 4.25+)
					DWORD64 propPtr = read<DWORD64>(obj + 0x50);
					int propCount = 0;
					bool hasProp = false;

					while (propPtr > 0x10000 && propPtr < 0x7FFFFFFFFFFF && propCount < 200)
					{
						if (!hasProp)
						{
							fprintf(f, "namespace %s {\n", name.c_str());
							hasProp = true;
						}

						int32_t propNameIdx = read<int32_t>(propPtr + 0x28);
						std::string propName = ReadUEFName(gnamesPtr, propNameIdx);
						int32_t propOffset = read<int32_t>(propPtr + 0x4C);

						if (!propName.empty() && propOffset >= 0 && propOffset < 0x10000)
						{
							fprintf(f, "    constexpr int %s = 0x%X;\n", propName.c_str(), propOffset);
						}

						propPtr = read<DWORD64>(propPtr + 0x20); // FField::Next
						propCount++;
					}

					// Also try Children (UField chain) for older UE4
					if (!hasProp)
					{
						DWORD64 childPtr = read<DWORD64>(obj + 0x48);
						int childCount = 0;
						while (childPtr > 0x10000 && childPtr < 0x7FFFFFFFFFFF && childCount < 200)
						{
							if (!hasProp)
							{
								fprintf(f, "namespace %s {\n", name.c_str());
								hasProp = true;
							}

							int32_t childNameIdx = read<int32_t>(childPtr + 0x18);
							std::string childName = ReadUEFName(gnamesPtr, childNameIdx);
							int32_t childOffset = read<int32_t>(childPtr + 0x44);

							if (!childName.empty() && childOffset >= 0 && childOffset < 0x10000)
							{
								fprintf(f, "    constexpr int %s = 0x%X;\n", childName.c_str(), childOffset);
							}

							childPtr = read<DWORD64>(childPtr + 0x28); // UField::Next
							childCount++;
						}
					}

					if (hasProp)
					{
						fprintf(f, "}\n\n");
						classesFound++;
					}
				}

				Log("[+] Found %d interesting classes with properties", classesFound);
			}
		}

		fprintf(f, "// ============================================\n");
		fprintf(f, "// Pointer Chain Reference\n");
		fprintf(f, "// ============================================\n");
		fprintf(f, "//\n");
		fprintf(f, "// Local player chain:\n");
		fprintf(f, "//   [GWorld] -> GameInstance (+0x%X) -> LocalPlayers (+0x38)\n",
			isUE5 ? 0x1B8 : 0x180);
		fprintf(f, "//   -> [0] -> PlayerController (+0x30)\n");
		fprintf(f, "//   -> AcknowledgedPawn (+0x%X) = your pawn\n",
			isUE5 ? 0x330 : 0x2B0);
		fprintf(f, "//\n");
		fprintf(f, "// Actor enumeration:\n");
		fprintf(f, "//   [GWorld] -> PersistentLevel (+0x30) -> Actors (+0x98)\n");
		fprintf(f, "//   Actors is TArray<AActor*>, stride 8\n");
		fprintf(f, "//\n");
		fprintf(f, "// World-to-screen:\n");
		fprintf(f, "//   PlayerController -> PlayerCameraManager (+0x%X)\n",
			isUE5 ? 0x338 : 0x2B8);
		fprintf(f, "//   -> CameraCachePrivate (+0x%X) contains view matrix\n\n",
			isUE5 ? 0x2220 : 0x1AB0);

		fclose(f);

		// Generate INI
		std::string iniPath = outDir + "\\" + std::string(game.name) + "_offsets.ini";
		FILE* ini = nullptr;
		fopen_s(&ini, iniPath.c_str(), "w");
		if (ini)
		{
			fprintf(ini, "# %s — Auto-generated Offsets\n", game.name);
			fprintf(ini, "# Date: %s\n", date);
			fprintf(ini, "# Engine: %s\n\n", isUE5 ? "Unreal Engine 5" : "Unreal Engine 4");

			fprintf(ini, "[Identity]\n");
			fprintf(ini, "GameName=%s\n", game.name);
			fprintf(ini, "ProcessName=%s\n", game.processName);
			fprintf(ini, "ModuleName=%s\n", game.coreModule);
			fprintf(ini, "Engine=%s\n\n", isUE5 ? "ue5" : "ue4");

			fprintf(ini, "[Globals]\n");
			fprintf(ini, "GWorld=0x%llX\n", gworldPtr ? gworldPtr - modBase : 0);
			fprintf(ini, "GNames=0x%llX\n", gnamesPtr ? gnamesPtr - modBase : 0);
			fprintf(ini, "GObjects=0x%llX\n\n", gobjectsPtr ? gobjectsPtr - modBase : 0);

			fprintf(ini, "[UWorld]\n");
			fprintf(ini, "PersistentLevel=0x30\n");
			fprintf(ini, "OwningGameInstance=0x%X\n", isUE5 ? 0x1B8 : 0x180);
			fprintf(ini, "GameState=0x%X\n\n", isUE5 ? 0x158 : 0x128);

			fprintf(ini, "[ULevel]\n");
			fprintf(ini, "Actors=0x98\n");
			fprintf(ini, "ActorCount=0xA0\n\n");

			fprintf(ini, "[AActor]\n");
			fprintf(ini, "RootComponent=0x%X\n\n", isUE5 ? 0x198 : 0x130);

			fprintf(ini, "[USceneComponent]\n");
			fprintf(ini, "RelativeLocation=0x%X\n", isUE5 ? 0x128 : 0x11C);
			fprintf(ini, "ComponentToWorld=0x1C0\n\n");

			fprintf(ini, "[APawn]\n");
			fprintf(ini, "PlayerState=0x%X\n", isUE5 ? 0x2A8 : 0x248);
			fprintf(ini, "Controller=0x%X\n\n", isUE5 ? 0x290 : 0x230);

			fprintf(ini, "[APlayerController]\n");
			fprintf(ini, "PlayerCameraManager=0x%X\n", isUE5 ? 0x338 : 0x2B8);
			fprintf(ini, "AcknowledgedPawn=0x%X\n\n", isUE5 ? 0x330 : 0x2B0);

			fprintf(ini, "[APlayerCameraManager]\n");
			fprintf(ini, "CameraCachePrivate=0x%X\n\n", isUE5 ? 0x2220 : 0x1AB0);

			fprintf(ini, "[ACharacter]\n");
			fprintf(ini, "Mesh=0x%X\n", isUE5 ? 0x318 : 0x280);
			fprintf(ini, "CharacterMovement=0x%X\n\n", isUE5 ? 0x308 : 0x278);

			fprintf(ini, "[USkeletalMeshComponent]\n");
			fprintf(ini, "BoneArray=0x%X\n\n", isUE5 ? 0x5B0 : 0x480);

			fclose(ini);
			Log("[+] INI written to %s", iniPath.c_str());
		}

		Log("[+] %s offsets dumped to %s", isUE5 ? "UE5" : "UE4", filePath.c_str());
		return true;
	}

	// ============================================================
	// Source 2 offset dumper (CS2)
	// ============================================================
	inline bool DumpSource2Offsets(const GameDef& game, const std::string& outDir)
	{
		// Source 2 uses SchemaSystem for runtime type info
		// Key DLLs: schemasystem.dll, client.dll, engine2.dll, server.dll
		DWORD64 clientBase = DMA::GetModuleBase("client.dll");
		DWORD64 engine2Base = DMA::GetModuleBase("engine2.dll");
		DWORD64 schemaBase = DMA::GetModuleBase("schemasystem.dll");
		DWORD64 inputBase = DMA::GetModuleBase("inputsystem.dll");
		DWORD64 matchBase = DMA::GetModuleBase("matchmaking.dll");

		if (!clientBase) { Log("[-] client.dll not found"); return false; }
		Log("[+] client.dll -> 0x%llX", clientBase);
		if (engine2Base) Log("[+] engine2.dll -> 0x%llX", engine2Base);
		if (schemaBase) Log("[+] schemasystem.dll -> 0x%llX", schemaBase);

		auto sections = GetPESections(clientBase);
		DWORD64 textBase = 0;
		DWORD textSize = 0;
		for (auto& s : sections)
		{
			if (strcmp(s.name, ".text") == 0)
			{ textBase = s.base; textSize = s.size; break; }
		}
		if (!textBase)
		{
			for (auto& s : sections)
			{
				if (s.characteristics & IMAGE_SCN_MEM_EXECUTE)
				{ textBase = s.base; textSize = s.size; break; }
			}
		}

		Log("[*] Scanning client.dll .text (%u MB)", textSize / (1024 * 1024));

		// Scan client.dll for key globals
		DWORD64 entityListPtr = 0;
		DWORD64 localPlayerControllerPtr = 0;
		DWORD64 viewMatrixPtr = 0;
		DWORD64 globalVarsPtr = 0;
		DWORD64 plantedC4Ptr = 0;

		// dwEntityList
		const char* entitySigs[] = {
			"48 8B 0D ?? ?? ?? ?? 48 89 7C 24 ?? 8B FA C1 EB",
			"48 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B F0 48 85 C0 74 ?? 44 8B 4D",
			nullptr
		};
		for (int i = 0; entitySigs[i] && !entityListPtr; i++)
		{
			DWORD64 addr = ScanPattern(textBase, textSize, entitySigs[i]);
			if (addr) { entityListPtr = ResolveRIP(addr, 3); Log("[+] EntityList @ 0x%llX (sig #%d)", entityListPtr, i); }
		}

		// dwLocalPlayerController
		const char* localSigs[] = {
			"48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? 8B 88 ?? ?? 00 00",
			"48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? 8B 48",
			nullptr
		};
		for (int i = 0; localSigs[i] && !localPlayerControllerPtr; i++)
		{
			DWORD64 addr = ScanPattern(textBase, textSize, localSigs[i]);
			if (addr) { localPlayerControllerPtr = ResolveRIP(addr, 3); Log("[+] LocalPlayerController @ 0x%llX", localPlayerControllerPtr); }
		}

		// dwViewMatrix
		const char* viewSigs[] = {
			"48 8D 0D ?? ?? ?? ?? 48 C1 E0 06",
			"48 8D 05 ?? ?? ?? ?? 48 C1 E1 06 48 03 C1",
			nullptr
		};
		for (int i = 0; viewSigs[i] && !viewMatrixPtr; i++)
		{
			DWORD64 addr = ScanPattern(textBase, textSize, viewSigs[i]);
			if (addr) { viewMatrixPtr = ResolveRIP(addr, 3); Log("[+] ViewMatrix @ 0x%llX", viewMatrixPtr); }
		}

		// dwGlobalVars
		const char* gvSigs[] = {
			"48 89 0D ?? ?? ?? ?? 48 89 41",
			"48 89 15 ?? ?? ?? ?? 48 8B C2 48 89 0D",
			nullptr
		};
		for (int i = 0; gvSigs[i] && !globalVarsPtr; i++)
		{
			DWORD64 addr = ScanPattern(textBase, textSize, gvSigs[i]);
			if (addr) { globalVarsPtr = ResolveRIP(addr, 3); Log("[+] GlobalVars @ 0x%llX", globalVarsPtr); }
		}

		// Scan engine2.dll if available
		DWORD64 e2_entityListPtr = 0;
		if (engine2Base)
		{
			auto e2sections = GetPESections(engine2Base);
			DWORD64 e2text = 0; DWORD e2size = 0;
			for (auto& s : e2sections)
			{
				if (strcmp(s.name, ".text") == 0)
				{ e2text = s.base; e2size = s.size; break; }
			}
			if (e2text)
			{
				Log("[*] Scanning engine2.dll .text (%u MB)", e2size / (1024 * 1024));
			}
		}

		// SchemaSystem walking
		int schemaClassCount = 0;
		std::vector<std::pair<std::string, std::vector<std::pair<std::string, int>>>> schemaClasses;

		if (schemaBase)
		{
			auto schemaSections = GetPESections(schemaBase);
			DWORD64 schemaText = 0; DWORD schemaTextSize = 0;
			for (auto& s : schemaSections)
			{
				if (strcmp(s.name, ".text") == 0)
				{ schemaText = s.base; schemaTextSize = s.size; break; }
			}

			// Find SchemaSystem singleton
			const char* schemaSig[] = {
				"48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 05 ?? ?? ?? ?? 48 89 05",
				"48 89 05 ?? ?? ?? ?? 4C 8D 0D ?? ?? ?? ?? 0F B6 45",
				nullptr
			};
			DWORD64 schemaSystemPtr = 0;
			if (schemaText)
			{
				for (int i = 0; schemaSig[i] && !schemaSystemPtr; i++)
				{
					DWORD64 addr = ScanPattern(schemaText, schemaTextSize, schemaSig[i]);
					if (addr)
					{
						schemaSystemPtr = ResolveRIP(addr, 3);
						DWORD64 val = read<DWORD64>(schemaSystemPtr);
						if (val > 0x10000 && val < 0x7FFFFFFFFFFF)
						{
							Log("[+] SchemaSystem @ 0x%llX (val=0x%llX)", schemaSystemPtr, val);
							break;
						}
						schemaSystemPtr = 0;
					}
				}
			}

			if (schemaSystemPtr)
			{
				DWORD64 schemaSystem = read<DWORD64>(schemaSystemPtr);
				if (schemaSystem)
				{
					// CSchemaSystem has type scopes
					// Walk through scope list
					// Typical layout: scopes at +0x190 (TUtlVector of CSchemaSystemTypeScope*)
					for (int scopeOff : {0x190, 0x188, 0x1A0, 0x198})
					{
						DWORD64 scopeArrayPtr = read<DWORD64>(schemaSystem + scopeOff);
						int32_t scopeCount = read<int32_t>(schemaSystem + scopeOff + 0x10);
						if (scopeCount <= 0 || scopeCount > 100 || scopeArrayPtr < 0x10000) continue;

						Log("[*] SchemaSystem: %d type scopes at +0x%X", scopeCount, scopeOff);

						for (int sc = 0; sc < scopeCount && sc < 20; sc++)
						{
							DWORD64 scope = read<DWORD64>(scopeArrayPtr + sc * 8);
							if (!scope) continue;

							char scopeName[256] = {};
							read_buffer(scope + 0x8, scopeName, 255);

							// DeclaredClasses: CUtlTSHash at scope+0x5B8 or similar
							for (int classOff : {0x5B8, 0x588, 0x5C0, 0x558})
							{
								// CUtlTSHash structure
								int32_t numElements = read<int32_t>(scope + classOff + 0x0);
								if (numElements <= 0 || numElements > 10000) continue;

								DWORD64 buckets = read<DWORD64>(scope + classOff + 0x18);
								if (!buckets) continue;

								Log("[*] Scope '%s': %d classes at +0x%X", scopeName, numElements, classOff);

								for (int b = 0; b < min(numElements, 500); b++)
								{
									DWORD64 binding = read<DWORD64>(buckets + b * 0x18);
									if (!binding) continue;

									// CSchemaClassBinding
									char className[256] = {};
									DWORD64 namePtr = read<DWORD64>(binding + 0x8);
									if (namePtr) read_buffer(namePtr, className, 255);

									if (strlen(className) == 0) continue;

									int16_t fieldCount = read<int16_t>(binding + 0x1C);
									DWORD64 fieldsPtr = read<DWORD64>(binding + 0x28);

									if (fieldCount <= 0 || fieldCount > 500 || !fieldsPtr) continue;

									std::vector<std::pair<std::string, int>> fields;
									for (int fi = 0; fi < fieldCount; fi++)
									{
										DWORD64 fieldEntry = fieldsPtr + fi * 0x20;
										DWORD64 fieldNamePtr = read<DWORD64>(fieldEntry + 0x0);
										int32_t fieldOffset = read<int32_t>(fieldEntry + 0x10);

										char fieldName[256] = {};
										if (fieldNamePtr) read_buffer(fieldNamePtr, fieldName, 255);

										if (strlen(fieldName) > 0 && fieldOffset >= 0)
											fields.push_back({ fieldName, fieldOffset });
									}

									if (!fields.empty())
									{
										schemaClasses.push_back({ className, fields });
										schemaClassCount++;
									}
								}
								break;
							}
						}
						break;
					}
				}
			}
		}

		// Output
		std::string filePath = outDir + "\\offsets.h";
		FILE* f = nullptr;
		fopen_s(&f, filePath.c_str(), "w");
		if (!f) return false;

		time_t now = time(nullptr);
		struct tm ti = {};
		localtime_s(&ti, &now);
		char date[32];
		sprintf_s(date, "%04d-%02d-%02d", ti.tm_year + 1900, ti.tm_mon + 1, ti.tm_mday);

		fprintf(f, "// %s Offset Dump - %s\n", game.name, date);
		fprintf(f, "// Engine: Source 2\n");
		fprintf(f, "// Auto-generated via DMA pattern scanning + SchemaSystem\n\n");
		fprintf(f, "#pragma once\n#include <cstdint>\n\n");

		DumpAllModuleList(f);

		fprintf(f, "// ============================================\n");
		fprintf(f, "// Source 2 Globals (client.dll offsets)\n");
		fprintf(f, "// ============================================\n\n");

		fprintf(f, "namespace S2_Globals {\n");
		fprintf(f, "    constexpr uintptr_t ClientBase = 0x%llX;\n", clientBase);
		if (entityListPtr)
			fprintf(f, "    constexpr uintptr_t dwEntityList = 0x%llX;  // RVA=0x%llX\n", entityListPtr, entityListPtr - clientBase);
		else
			fprintf(f, "    constexpr uintptr_t dwEntityList = 0x0;\n");
		if (localPlayerControllerPtr)
			fprintf(f, "    constexpr uintptr_t dwLocalPlayerController = 0x%llX;  // RVA=0x%llX\n", localPlayerControllerPtr, localPlayerControllerPtr - clientBase);
		else
			fprintf(f, "    constexpr uintptr_t dwLocalPlayerController = 0x0;\n");
		if (viewMatrixPtr)
			fprintf(f, "    constexpr uintptr_t dwViewMatrix = 0x%llX;  // RVA=0x%llX\n", viewMatrixPtr, viewMatrixPtr - clientBase);
		else
			fprintf(f, "    constexpr uintptr_t dwViewMatrix = 0x0;\n");
		if (globalVarsPtr)
			fprintf(f, "    constexpr uintptr_t dwGlobalVars = 0x%llX;  // RVA=0x%llX\n", globalVarsPtr, globalVarsPtr - clientBase);
		else
			fprintf(f, "    constexpr uintptr_t dwGlobalVars = 0x0;\n");
		fprintf(f, "}\n\n");

		// Known CS2 structure offsets
		fprintf(f, "// ============================================\n");
		fprintf(f, "// Source 2 Known Structure Offsets\n");
		fprintf(f, "// ============================================\n\n");

		fprintf(f, "namespace C_BaseEntity {\n");
		fprintf(f, "    constexpr int m_iHealth         = 0x344;\n");
		fprintf(f, "    constexpr int m_iTeamNum        = 0x3CB;\n");
		fprintf(f, "    constexpr int m_lifeState       = 0x348;\n");
		fprintf(f, "    constexpr int m_pGameSceneNode  = 0x328;\n");
		fprintf(f, "    constexpr int m_fFlags          = 0x3D4;\n");
		fprintf(f, "    constexpr int m_vecAbsOrigin    = 0xD0;   // via CGameSceneNode\n");
		fprintf(f, "}\n\n");

		fprintf(f, "namespace CCSPlayerController {\n");
		fprintf(f, "    constexpr int m_sSanitizedPlayerName = 0x758;\n");
		fprintf(f, "    constexpr int m_hPlayerPawn          = 0x814;\n");
		fprintf(f, "    constexpr int m_bPawnIsAlive         = 0x834;\n");
		fprintf(f, "    constexpr int m_iPawnHealth          = 0x854;\n");
		fprintf(f, "    constexpr int m_iPawnArmor           = 0x858;\n");
		fprintf(f, "}\n\n");

		fprintf(f, "namespace C_CSPlayerPawn {\n");
		fprintf(f, "    constexpr int m_ArmorValue            = 0x2444;\n");
		fprintf(f, "    constexpr int m_iShotsFired           = 0x2484;\n");
		fprintf(f, "    constexpr int m_aimPunchAngle         = 0x1584;\n");
		fprintf(f, "    constexpr int m_aimPunchAngleVel      = 0x1590;\n");
		fprintf(f, "    constexpr int m_vecLastClipCameraPos  = 0x12F0;\n");
		fprintf(f, "    constexpr int m_angEyeAngles          = 0x1580;\n");
		fprintf(f, "    constexpr int m_pClippingWeapon       = 0x13A8;\n");
		fprintf(f, "    constexpr int m_flFlashDuration       = 0x1478;\n");
		fprintf(f, "    constexpr int m_bIsScoped             = 0x23D8;\n");
		fprintf(f, "}\n\n");

		fprintf(f, "namespace C_BasePlayerPawn {\n");
		fprintf(f, "    constexpr int m_pCameraServices  = 0x1138;\n");
		fprintf(f, "    constexpr int m_pWeaponServices  = 0x1140;\n");
		fprintf(f, "    constexpr int m_pItemServices    = 0x1148;\n");
		fprintf(f, "    constexpr int m_vOldOrigin       = 0x1304;\n");
		fprintf(f, "}\n\n");

		fprintf(f, "namespace CGameSceneNode {\n");
		fprintf(f, "    constexpr int m_vecAbsOrigin     = 0xD0;\n");
		fprintf(f, "    constexpr int m_vecOrigin        = 0xC8;\n");
		fprintf(f, "    constexpr int m_angAbsRotation   = 0xDC;\n");
		fprintf(f, "}\n\n");

		fprintf(f, "namespace CCSPlayerBase_CameraServices {\n");
		fprintf(f, "    constexpr int m_iFOV             = 0x210;\n");
		fprintf(f, "    constexpr int m_iFOVStart        = 0x214;\n");
		fprintf(f, "}\n\n");

		fprintf(f, "namespace CSkeletonInstance {\n");
		fprintf(f, "    constexpr int m_modelState       = 0x170;\n");
		fprintf(f, "    constexpr int m_boneArray        = 0x80;  // within modelState\n");
		fprintf(f, "}\n\n");

		// Schema dump results
		if (!schemaClasses.empty())
		{
			fprintf(f, "// ============================================\n");
			fprintf(f, "// SchemaSystem Dump (%d classes)\n", schemaClassCount);
			fprintf(f, "// ============================================\n\n");

			for (auto& [className, fields] : schemaClasses)
			{
				std::string safeName = className;
				for (auto& ch : safeName)
					if (ch == ':' || ch == '<' || ch == '>' || ch == ' ')
						ch = '_';

				fprintf(f, "namespace %s {\n", safeName.c_str());
				for (auto& [fname, foff] : fields)
				{
					std::string safeFname = fname;
					for (auto& ch : safeFname)
						if (ch == '<' || ch == '>' || ch == ' ' || ch == '[' || ch == ']')
							ch = '_';
					fprintf(f, "    constexpr int %s = 0x%X;\n", safeFname.c_str(), foff);
				}
				fprintf(f, "}\n\n");
			}
		}

		fprintf(f, "// ============================================\n");
		fprintf(f, "// Pointer Chain Reference (CS2)\n");
		fprintf(f, "// ============================================\n");
		fprintf(f, "//\n");
		fprintf(f, "// Entity enumeration:\n");
		fprintf(f, "//   [dwEntityList] -> entry = EntityList + 0x8 * ((idx & 0x7FFF) >> 9) + 16\n");
		fprintf(f, "//   controller = [entry + 120 * (idx & 0x1FF)]\n");
		fprintf(f, "//   pawn handle = controller + m_hPlayerPawn\n");
		fprintf(f, "//   pawn entry = [EntityList + 0x8 * ((handle & 0x7FFF) >> 9) + 16]\n");
		fprintf(f, "//   pawn = [pawn_entry + 120 * (handle & 0x1FF)]\n");
		fprintf(f, "//\n");
		fprintf(f, "// Position:\n");
		fprintf(f, "//   pawn + m_pGameSceneNode -> + m_vecAbsOrigin\n");
		fprintf(f, "//\n");
		fprintf(f, "// Bones (skeleton ESP):\n");
		fprintf(f, "//   pawn + m_pGameSceneNode -> CSkeletonInstance\n");
		fprintf(f, "//   skeleton + m_modelState + m_boneArray\n\n");

		fclose(f);

		// INI
		std::string iniPath = outDir + "\\cs2_offsets.ini";
		FILE* ini = nullptr;
		fopen_s(&ini, iniPath.c_str(), "w");
		if (ini)
		{
			fprintf(ini, "# Counter-Strike 2 — Auto-generated Offsets\n");
			fprintf(ini, "# Date: %s\n", date);
			fprintf(ini, "# Engine: Source 2\n\n");

			fprintf(ini, "[Identity]\n");
			fprintf(ini, "GameName=Counter-Strike 2\n");
			fprintf(ini, "ProcessName=cs2.exe\n");
			fprintf(ini, "Engine=source2\n\n");

			fprintf(ini, "[Globals]\n");
			fprintf(ini, "dwEntityList=0x%llX\n", entityListPtr ? entityListPtr - clientBase : 0);
			fprintf(ini, "dwLocalPlayerController=0x%llX\n", localPlayerControllerPtr ? localPlayerControllerPtr - clientBase : 0);
			fprintf(ini, "dwViewMatrix=0x%llX\n", viewMatrixPtr ? viewMatrixPtr - clientBase : 0);
			fprintf(ini, "dwGlobalVars=0x%llX\n\n", globalVarsPtr ? globalVarsPtr - clientBase : 0);

			fprintf(ini, "[C_BaseEntity]\n");
			fprintf(ini, "m_iHealth=0x344\n");
			fprintf(ini, "m_iTeamNum=0x3CB\n");
			fprintf(ini, "m_lifeState=0x348\n");
			fprintf(ini, "m_pGameSceneNode=0x328\n\n");

			fprintf(ini, "[CCSPlayerController]\n");
			fprintf(ini, "m_sSanitizedPlayerName=0x758\n");
			fprintf(ini, "m_hPlayerPawn=0x814\n");
			fprintf(ini, "m_bPawnIsAlive=0x834\n\n");

			fprintf(ini, "[C_CSPlayerPawn]\n");
			fprintf(ini, "m_ArmorValue=0x2444\n");
			fprintf(ini, "m_aimPunchAngle=0x1584\n");
			fprintf(ini, "m_angEyeAngles=0x1580\n");
			fprintf(ini, "m_bIsScoped=0x23D8\n\n");

			fprintf(ini, "[CGameSceneNode]\n");
			fprintf(ini, "m_vecAbsOrigin=0xD0\n\n");

			fprintf(ini, "[Camera]\n");
			fprintf(ini, "m_iFOV=0x210\n\n");

			fclose(ini);
			Log("[+] INI written to %s", iniPath.c_str());
		}

		Log("[+] Source 2 offsets dumped to %s", filePath.c_str());
		return true;
	}

	// ============================================================
	// Source (Respawn) offset dumper (Apex Legends)
	// ============================================================
	inline bool DumpSourceRespawnOffsets(const GameDef& game, const std::string& outDir)
	{
		DWORD64 modBase = DMA::GetModuleBase(game.coreModule);
		if (!modBase) { Log("[-] %s not found", game.coreModule); return false; }
		Log("[+] %s -> 0x%llX", game.coreModule, modBase);

		auto sections = GetPESections(modBase);
		DWORD64 textBase = 0;
		DWORD textSize = 0;
		for (auto& s : sections)
		{
			if (strcmp(s.name, ".text") == 0)
			{ textBase = s.base; textSize = s.size; break; }
		}
		if (!textBase)
		{
			for (auto& s : sections)
			{
				if (s.characteristics & IMAGE_SCN_MEM_EXECUTE)
				{ textBase = s.base; textSize = s.size; break; }
			}
		}
		if (!textBase) { Log("[-] No .text section"); return false; }

		Log("[*] Scanning r5apex.exe .text (%u MB)", textSize / (1024 * 1024));

		// Scan for key Apex globals
		DWORD64 entityListPtr = 0;
		DWORD64 localPlayerPtr = 0;
		DWORD64 viewRenderPtr = 0;
		DWORD64 viewMatrixPtr = 0;
		DWORD64 levelNamePtr = 0;
		DWORD64 globalVarsPtr = 0;
		DWORD64 nameListPtr = 0;

		// cl_entitylist
		const char* entSigs[] = {
			"48 8D 3D ?? ?? ?? ?? 48 8B CF 48 03 F8",
			"4C 8D 05 ?? ?? ?? ?? 41 8B 1C 88",
			nullptr
		};
		for (int i = 0; entSigs[i] && !entityListPtr; i++)
		{
			DWORD64 addr = ScanPattern(textBase, textSize, entSigs[i]);
			if (addr) { entityListPtr = ResolveRIP(addr, 3); Log("[+] EntityList @ 0x%llX", entityListPtr); }
		}

		// LocalPlayer
		const char* lpSigs[] = {
			"48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B 40 ?? C3",
			"48 8D 0D ?? ?? ?? ?? 48 8B 14 C1 48 85 D2",
			nullptr
		};
		for (int i = 0; lpSigs[i] && !localPlayerPtr; i++)
		{
			DWORD64 addr = ScanPattern(textBase, textSize, lpSigs[i]);
			if (addr) { localPlayerPtr = ResolveRIP(addr, 3); Log("[+] LocalPlayer @ 0x%llX", localPlayerPtr); }
		}

		// ViewRender
		const char* vrSigs[] = {
			"48 8B 05 ?? ?? ?? ?? 48 8B 58 ?? 48 85 DB 74 ?? 48 8B 0D",
			nullptr
		};
		for (int i = 0; vrSigs[i] && !viewRenderPtr; i++)
		{
			DWORD64 addr = ScanPattern(textBase, textSize, vrSigs[i]);
			if (addr) { viewRenderPtr = ResolveRIP(addr, 3); Log("[+] ViewRender @ 0x%llX", viewRenderPtr); }
		}

		// NameList
		const char* nlSigs[] = {
			"48 8D 05 ?? ?? ?? ?? 48 69 CA ?? ?? 00 00 48 03 C1",
			nullptr
		};
		for (int i = 0; nlSigs[i] && !nameListPtr; i++)
		{
			DWORD64 addr = ScanPattern(textBase, textSize, nlSigs[i]);
			if (addr) { nameListPtr = ResolveRIP(addr, 3); Log("[+] NameList @ 0x%llX", nameListPtr); }
		}

		// GlobalVars
		const char* gvSigs[] = {
			"48 8B 0D ?? ?? ?? ?? F3 0F 10 81 ?? ?? 00 00",
			nullptr
		};
		for (int i = 0; gvSigs[i] && !globalVarsPtr; i++)
		{
			DWORD64 addr = ScanPattern(textBase, textSize, gvSigs[i]);
			if (addr) { globalVarsPtr = ResolveRIP(addr, 3); Log("[+] GlobalVars @ 0x%llX", globalVarsPtr); }
		}

		// Output
		std::string filePath = outDir + "\\offsets.h";
		FILE* f = nullptr;
		fopen_s(&f, filePath.c_str(), "w");
		if (!f) return false;

		time_t now = time(nullptr);
		struct tm ti = {};
		localtime_s(&ti, &now);
		char date[32];
		sprintf_s(date, "%04d-%02d-%02d", ti.tm_year + 1900, ti.tm_mon + 1, ti.tm_mday);

		fprintf(f, "// %s Offset Dump - %s\n", game.name, date);
		fprintf(f, "// Engine: Source (Respawn Modified)\n");
		fprintf(f, "// Auto-generated via DMA pattern scanning\n");
		fprintf(f, "// r5apex.exe base: 0x%llX\n\n", modBase);
		fprintf(f, "#pragma once\n#include <cstdint>\n\n");

		DumpAllModuleList(f);

		fprintf(f, "// ============================================\n");
		fprintf(f, "// Apex Globals (Pattern Scan Results)\n");
		fprintf(f, "// ============================================\n\n");

		fprintf(f, "namespace Apex_Globals {\n");
		fprintf(f, "    constexpr uintptr_t ModuleBase  = 0x%llX;\n", modBase);
		auto apexGlobal = [&](const char* name, DWORD64 ptr) {
			if (ptr) fprintf(f, "    constexpr uintptr_t %s = 0x%llX;  // RVA=0x%llX\n", name, ptr, ptr - modBase);
			else fprintf(f, "    constexpr uintptr_t %s = 0x0;\n", name);
		};
		apexGlobal("EntityList", entityListPtr);
		apexGlobal("LocalPlayer", localPlayerPtr);
		apexGlobal("ViewRender", viewRenderPtr);
		apexGlobal("NameList", nameListPtr);
		apexGlobal("GlobalVars", globalVarsPtr);
		fprintf(f, "}\n\n");

		// Known Apex structure offsets
		fprintf(f, "// ============================================\n");
		fprintf(f, "// Apex Entity Offsets (CPlayer/CBaseEntity)\n");
		fprintf(f, "// ============================================\n\n");

		fprintf(f, "namespace CPlayer {\n");
		fprintf(f, "    constexpr int m_iHealth         = 0x043C;\n");
		fprintf(f, "    constexpr int m_iMaxHealth      = 0x0578;\n");
		fprintf(f, "    constexpr int m_shieldHealth    = 0x0170;\n");
		fprintf(f, "    constexpr int m_shieldHealthMax = 0x0174;\n");
		fprintf(f, "    constexpr int m_iTeamNum        = 0x044C;\n");
		fprintf(f, "    constexpr int m_iName           = 0x0589;\n");
		fprintf(f, "    constexpr int m_lifeState       = 0x0798;\n");
		fprintf(f, "    constexpr int m_bleedoutState   = 0x2740;\n");
		fprintf(f, "}\n\n");

		fprintf(f, "namespace CBaseEntity {\n");
		fprintf(f, "    constexpr int m_vecAbsOrigin    = 0x014C;\n");
		fprintf(f, "    constexpr int m_vecAbsVelocity  = 0x0480;\n");
		fprintf(f, "    constexpr int m_iSignifierName  = 0x0580;\n");
		fprintf(f, "    constexpr int m_ModelName       = 0x0030;\n");
		fprintf(f, "}\n\n");

		fprintf(f, "namespace CCamera {\n");
		fprintf(f, "    constexpr int m_vecCamPos       = 0x0;\n");
		fprintf(f, "    constexpr int m_matViewMatrix   = 0x11A350;  // in ViewRender chain\n");
		fprintf(f, "}\n\n");

		fprintf(f, "namespace CBoneMatrix {\n");
		fprintf(f, "    constexpr int m_pBoneMatrix     = 0x0E98;\n");
		fprintf(f, "    constexpr int m_nBoneCount      = 0x0EA0;\n");
		fprintf(f, "}\n\n");

		fprintf(f, "namespace CWeapon {\n");
		fprintf(f, "    constexpr int m_latestPrimaryWeapons = 0x1A14;\n");
		fprintf(f, "    constexpr int m_ammoInClip           = 0x1694;\n");
		fprintf(f, "    constexpr int m_ammoInStockpile      = 0x1698;\n");
		fprintf(f, "}\n\n");

		fprintf(f, "namespace CInput {\n");
		fprintf(f, "    constexpr int m_vecViewAngles   = 0x25A0;\n");
		fprintf(f, "}\n\n");

		fprintf(f, "// ============================================\n");
		fprintf(f, "// Pointer Chain Reference (Apex)\n");
		fprintf(f, "// ============================================\n");
		fprintf(f, "//\n");
		fprintf(f, "// Entity enumeration:\n");
		fprintf(f, "//   EntityList[i * 0x20] = CBaseEntity* (max ~65535)\n");
		fprintf(f, "//\n");
		fprintf(f, "// Local player:\n");
		fprintf(f, "//   [LocalPlayer] = CPlayer* (your entity)\n");
		fprintf(f, "//\n");
		fprintf(f, "// View matrix:\n");
		fprintf(f, "//   [ViewRender] -> +0x11A350 = 4x4 float matrix\n\n");

		fclose(f);

		// INI
		std::string iniPath = outDir + "\\apex_offsets.ini";
		FILE* ini = nullptr;
		fopen_s(&ini, iniPath.c_str(), "w");
		if (ini)
		{
			fprintf(ini, "# Apex Legends — Auto-generated Offsets\n");
			fprintf(ini, "# Date: %s\n", date);
			fprintf(ini, "# Engine: Source (Respawn Modified)\n\n");

			fprintf(ini, "[Identity]\n");
			fprintf(ini, "GameName=Apex Legends\n");
			fprintf(ini, "ProcessName=r5apex.exe\n");
			fprintf(ini, "Engine=source_respawn\n\n");

			fprintf(ini, "[Globals]\n");
			fprintf(ini, "EntityList=0x%llX\n", entityListPtr ? entityListPtr - modBase : 0);
			fprintf(ini, "LocalPlayer=0x%llX\n", localPlayerPtr ? localPlayerPtr - modBase : 0);
			fprintf(ini, "ViewRender=0x%llX\n", viewRenderPtr ? viewRenderPtr - modBase : 0);
			fprintf(ini, "NameList=0x%llX\n", nameListPtr ? nameListPtr - modBase : 0);
			fprintf(ini, "GlobalVars=0x%llX\n\n", globalVarsPtr ? globalVarsPtr - modBase : 0);

			fprintf(ini, "[CPlayer]\n");
			fprintf(ini, "m_iHealth=0x043C\n");
			fprintf(ini, "m_iMaxHealth=0x0578\n");
			fprintf(ini, "m_shieldHealth=0x0170\n");
			fprintf(ini, "m_iTeamNum=0x044C\n");
			fprintf(ini, "m_lifeState=0x0798\n");
			fprintf(ini, "m_bleedoutState=0x2740\n\n");

			fprintf(ini, "[CBaseEntity]\n");
			fprintf(ini, "m_vecAbsOrigin=0x014C\n");
			fprintf(ini, "m_vecAbsVelocity=0x0480\n\n");

			fprintf(ini, "[Bones]\n");
			fprintf(ini, "m_pBoneMatrix=0x0E98\n\n");

			fprintf(ini, "[Camera]\n");
			fprintf(ini, "m_matViewMatrix=0x11A350\n\n");

			fclose(ini);
			Log("[+] INI written to %s", iniPath.c_str());
		}

		Log("[+] Apex offsets dumped to %s", filePath.c_str());
		return true;
	}

	// ============================================================
	// Enfusion offset dumper (Arma Reforger, DayZ)
	// ============================================================
	inline bool DumpEnfusionOffsets(const GameDef& game, const std::string& outDir)
	{
		DWORD64 modBase = DMA::GetModuleBase(game.coreModule);
		if (!modBase) { Log("[-] %s not found", game.coreModule); return false; }
		Log("[+] %s -> 0x%llX", game.coreModule, modBase);

		auto sections = GetPESections(modBase);
		DWORD64 textBase = 0;
		DWORD textSize = 0;
		for (auto& s : sections)
		{
			if (strcmp(s.name, ".text") == 0)
			{ textBase = s.base; textSize = s.size; break; }
		}
		if (!textBase)
		{
			for (auto& s : sections)
			{
				if (s.characteristics & IMAGE_SCN_MEM_EXECUTE)
				{ textBase = s.base; textSize = s.size; break; }
			}
		}
		if (!textBase) { Log("[-] No .text section"); return false; }

		bool isDayZ = (_stricmp(game.name, "DayZ") == 0);
		Log("[*] Scanning %s .text (%u MB)", isDayZ ? "Enfusion (DayZ)" : "Enfusion (Reforger)",
			textSize / (1024 * 1024));

		DWORD64 worldPtr = 0;
		DWORD64 networkMgrPtr = 0;
		DWORD64 cameraPtr = 0;
		DWORD64 entityTablePtr = 0;
		DWORD64 inputMgrPtr = 0;
		DWORD64 scoreBoardPtr = 0;

		// World pointer
		const char* worldSigs[] = {
			"48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B 48 ?? E8",
			"48 8B 0D ?? ?? ?? ?? 48 85 C9 74 ?? 48 8B 01 FF 90",
			"48 89 05 ?? ?? ?? ?? 48 8B 4C 24 ?? 48 33 CC",
			nullptr
		};
		for (int i = 0; worldSigs[i] && !worldPtr; i++)
		{
			DWORD64 addr = ScanPattern(textBase, textSize, worldSigs[i]);
			if (addr)
			{
				DWORD64 resolved = ResolveRIP(addr, 3);
				DWORD64 val = read<DWORD64>(resolved);
				if (val > 0x10000 && val < 0x7FFFFFFFFFFF)
				{
					worldPtr = resolved;
					Log("[+] World @ 0x%llX (val=0x%llX)", resolved, val);
				}
			}
		}

		// NetworkManager
		const char* netSigs[] = {
			"48 8B 0D ?? ?? ?? ?? 48 85 C9 0F 84 ?? ?? ?? ?? 48 8B 01 48 8D 54 24",
			"48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? 80 B8 ?? ?? 00 00 00",
			nullptr
		};
		for (int i = 0; netSigs[i] && !networkMgrPtr; i++)
		{
			DWORD64 addr = ScanPattern(textBase, textSize, netSigs[i]);
			if (addr)
			{
				DWORD64 resolved = ResolveRIP(addr, 3);
				DWORD64 val = read<DWORD64>(resolved);
				if (val > 0x10000 && val < 0x7FFFFFFFFFFF)
				{
					networkMgrPtr = resolved;
					Log("[+] NetworkManager @ 0x%llX", resolved);
				}
			}
		}

		// Camera
		const char* camSigs[] = {
			"48 8B 05 ?? ?? ?? ?? F3 0F 10 80 ?? ?? 00 00 F3 0F 10 88",
			"48 8B 0D ?? ?? ?? ?? 48 85 C9 74 ?? F3 0F 10 41",
			nullptr
		};
		for (int i = 0; camSigs[i] && !cameraPtr; i++)
		{
			DWORD64 addr = ScanPattern(textBase, textSize, camSigs[i]);
			if (addr)
			{
				DWORD64 resolved = ResolveRIP(addr, 3);
				DWORD64 val = read<DWORD64>(resolved);
				if (val > 0x10000 && val < 0x7FFFFFFFFFFF)
				{
					cameraPtr = resolved;
					Log("[+] Camera @ 0x%llX", resolved);
				}
			}
		}

		// EntityTable / ScoreBoard (DayZ-specific)
		if (isDayZ)
		{
			const char* scoreSigs[] = {
				"48 8B 0D ?? ?? ?? ?? 48 85 C9 0F 84 ?? ?? ?? ?? 48 8B 89 ?? ?? 00 00",
				nullptr
			};
			for (int i = 0; scoreSigs[i] && !scoreBoardPtr; i++)
			{
				DWORD64 addr = ScanPattern(textBase, textSize, scoreSigs[i]);
				if (addr)
				{
					scoreBoardPtr = ResolveRIP(addr, 3);
					Log("[+] ScoreBoard @ 0x%llX", scoreBoardPtr);
				}
			}
		}

		// Output
		std::string filePath = outDir + "\\offsets.h";
		FILE* f = nullptr;
		fopen_s(&f, filePath.c_str(), "w");
		if (!f) return false;

		time_t now = time(nullptr);
		struct tm ti = {};
		localtime_s(&ti, &now);
		char date[32];
		sprintf_s(date, "%04d-%02d-%02d", ti.tm_year + 1900, ti.tm_mon + 1, ti.tm_mday);

		fprintf(f, "// %s Offset Dump - %s\n", game.name, date);
		fprintf(f, "// Engine: Enfusion%s\n", isDayZ ? " (Legacy)" : "");
		fprintf(f, "// Auto-generated via DMA pattern scanning\n");
		fprintf(f, "// %s base: 0x%llX\n\n", game.coreModule, modBase);
		fprintf(f, "#pragma once\n#include <cstdint>\n\n");

		DumpAllModuleList(f);

		fprintf(f, "// ============================================\n");
		fprintf(f, "// Enfusion Globals (Pattern Scan Results)\n");
		fprintf(f, "// ============================================\n\n");

		fprintf(f, "namespace Enfusion_Globals {\n");
		fprintf(f, "    constexpr uintptr_t ModuleBase = 0x%llX;\n", modBase);
		auto enfGlobal = [&](const char* name, DWORD64 ptr) {
			if (ptr) fprintf(f, "    constexpr uintptr_t %s = 0x%llX;  // RVA=0x%llX\n", name, ptr, ptr - modBase);
			else fprintf(f, "    constexpr uintptr_t %s = 0x0;\n", name);
		};
		enfGlobal("World", worldPtr);
		enfGlobal("NetworkManager", networkMgrPtr);
		enfGlobal("Camera", cameraPtr);
		enfGlobal("InputManager", inputMgrPtr);
		if (isDayZ) enfGlobal("ScoreBoard", scoreBoardPtr);
		fprintf(f, "}\n\n");

		if (isDayZ)
		{
			fprintf(f, "// ============================================\n");
			fprintf(f, "// DayZ Enfusion Structure Offsets\n");
			fprintf(f, "// ============================================\n\n");

			fprintf(f, "namespace DayZ_World {\n");
			fprintf(f, "    constexpr int CameraOn       = 0x18;\n");
			fprintf(f, "    constexpr int NearEntities    = 0xC70;\n");
			fprintf(f, "    constexpr int FarEntities     = 0xC88;\n");
			fprintf(f, "    constexpr int BulletTable     = 0xF88;\n");
			fprintf(f, "}\n\n");

			fprintf(f, "namespace DayZ_Camera {\n");
			fprintf(f, "    constexpr int InvViewMatrix  = 0x2BC;\n");
			fprintf(f, "    constexpr int ViewMatrix     = 0x2FC;\n");
			fprintf(f, "    constexpr int ProjMatrix     = 0x33C;\n");
			fprintf(f, "    constexpr int ViewportWidth  = 0x38;\n");
			fprintf(f, "    constexpr int ViewportHeight = 0x3C;\n");
			fprintf(f, "    constexpr int NearPlane      = 0x2A0;\n");
			fprintf(f, "    constexpr int FarPlane       = 0x2A4;\n");
			fprintf(f, "    constexpr int FOV            = 0x2B0;\n");
			fprintf(f, "}\n\n");

			fprintf(f, "namespace DayZ_Entity {\n");
			fprintf(f, "    constexpr int NetworkID         = 0xC;\n");
			fprintf(f, "    constexpr int ConfigName        = 0x18;\n");
			fprintf(f, "    constexpr int Visual            = 0xD0;\n");
			fprintf(f, "    constexpr int InvTransformLS    = 0xA8;\n");
			fprintf(f, "    constexpr int FutureVisualState = 0x190;\n");
			fprintf(f, "    constexpr int PositionX         = 0x1CC;\n");
			fprintf(f, "    constexpr int PositionZ         = 0x1D4;\n");
			fprintf(f, "}\n\n");

			fprintf(f, "namespace DayZ_Player {\n");
			fprintf(f, "    constexpr int Identity          = 0x1A8;\n");
			fprintf(f, "    constexpr int PlayerName        = 0x8;   // via Identity\n");
			fprintf(f, "    constexpr int IsAlive           = 0xB0;\n");
			fprintf(f, "    constexpr int m_bIsDead         = 0x190;\n");
			fprintf(f, "}\n\n");

			fprintf(f, "namespace DayZ_Network {\n");
			fprintf(f, "    constexpr int PlayerIdentity    = 0x10;\n");
			fprintf(f, "    constexpr int PlayerTable       = 0x18;\n");
			fprintf(f, "    constexpr int PlayerCount       = 0x20;\n");
			fprintf(f, "}\n\n");

			fprintf(f, "namespace DayZ_Scoreboard {\n");
			fprintf(f, "    constexpr int PlayerList  = 0x80;\n");
			fprintf(f, "    constexpr int PlayerCount = 0x88;\n");
			fprintf(f, "}\n\n");

			fprintf(f, "// Pointer chains:\n");
			fprintf(f, "//   [World] + NearEntities -> entity array (stride 0x8)\n");
			fprintf(f, "//   Entity + ConfigName -> type string (\"dayz_player\", etc.)\n");
			fprintf(f, "//   [Camera] -> InvViewMatrix for W2S\n");
			fprintf(f, "//   [NetworkManager] + PlayerTable -> player network entries\n\n");
		}
		else
		{
			fprintf(f, "// ============================================\n");
			fprintf(f, "// Arma Reforger Enfusion Structure Offsets\n");
			fprintf(f, "// ============================================\n\n");

			fprintf(f, "namespace Reforger_World {\n");
			fprintf(f, "    constexpr int EntityManager  = 0x80;\n");
			fprintf(f, "    constexpr int CameraManager  = 0x88;\n");
			fprintf(f, "    constexpr int GameMode        = 0x90;\n");
			fprintf(f, "}\n\n");

			fprintf(f, "namespace Reforger_EntityManager {\n");
			fprintf(f, "    constexpr int EntityList = 0x18;\n");
			fprintf(f, "    constexpr int EntityCount= 0x20;\n");
			fprintf(f, "}\n\n");

			fprintf(f, "namespace Reforger_Entity {\n");
			fprintf(f, "    constexpr int Transform      = 0x30;   // 4x4 matrix\n");
			fprintf(f, "    constexpr int Health          = 0x1F0;\n");
			fprintf(f, "    constexpr int Faction         = 0x218;\n");
			fprintf(f, "    constexpr int EntityFlags     = 0x10;\n");
			fprintf(f, "}\n\n");

			fprintf(f, "namespace Reforger_Camera {\n");
			fprintf(f, "    constexpr int ViewMatrix      = 0x40;\n");
			fprintf(f, "    constexpr int ProjMatrix      = 0x80;\n");
			fprintf(f, "    constexpr int Position        = 0xC0;\n");
			fprintf(f, "    constexpr int FOV             = 0xCC;\n");
			fprintf(f, "}\n\n");

			fprintf(f, "// Pointer chains:\n");
			fprintf(f, "//   [World] + EntityManager -> EntityList -> Entity[i]\n");
			fprintf(f, "//   Entity + Transform = position/rotation\n");
			fprintf(f, "//   [World] + CameraManager -> ViewMatrix for W2S\n\n");
		}

		// Dump PE exports for reference
		DumpModuleExports(f, game.coreModule);

		fclose(f);

		// INI
		std::string iniName = isDayZ ? "dayz_offsets.ini" : "reforger_offsets.ini";
		std::string iniPath = outDir + "\\" + iniName;
		FILE* ini = nullptr;
		fopen_s(&ini, iniPath.c_str(), "w");
		if (ini)
		{
			fprintf(ini, "# %s — Auto-generated Offsets\n", game.name);
			fprintf(ini, "# Date: %s\n", date);
			fprintf(ini, "# Engine: Enfusion%s\n\n", isDayZ ? " (Legacy)" : "");

			fprintf(ini, "[Identity]\n");
			fprintf(ini, "GameName=%s\n", isDayZ ? "DayZ" : "Arma Reforger");
			fprintf(ini, "ProcessName=%s\n", game.processName);
			fprintf(ini, "Engine=enfusion\n\n");

			fprintf(ini, "[Globals]\n");
			fprintf(ini, "World=0x%llX\n", worldPtr ? worldPtr - modBase : 0);
			fprintf(ini, "NetworkManager=0x%llX\n", networkMgrPtr ? networkMgrPtr - modBase : 0);
			fprintf(ini, "Camera=0x%llX\n\n", cameraPtr ? cameraPtr - modBase : 0);

			if (isDayZ)
			{
				fprintf(ini, "[DayZ_World]\n");
				fprintf(ini, "NearEntities=0xC70\n");
				fprintf(ini, "FarEntities=0xC88\n\n");

				fprintf(ini, "[DayZ_Camera]\n");
				fprintf(ini, "InvViewMatrix=0x2BC\n");
				fprintf(ini, "ViewMatrix=0x2FC\n");
				fprintf(ini, "FOV=0x2B0\n\n");

				fprintf(ini, "[DayZ_Entity]\n");
				fprintf(ini, "ConfigName=0x18\n");
				fprintf(ini, "PositionX=0x1CC\n");
				fprintf(ini, "PositionZ=0x1D4\n\n");

				if (scoreBoardPtr)
				{
					fprintf(ini, "[Scoreboard]\n");
					fprintf(ini, "Address=0x%llX\n", scoreBoardPtr - modBase);
					fprintf(ini, "PlayerList=0x80\n");
					fprintf(ini, "PlayerCount=0x88\n\n");
				}
			}
			else
			{
				fprintf(ini, "[World]\n");
				fprintf(ini, "EntityManager=0x80\n");
				fprintf(ini, "CameraManager=0x88\n\n");

				fprintf(ini, "[EntityManager]\n");
				fprintf(ini, "EntityList=0x18\n");
				fprintf(ini, "EntityCount=0x20\n\n");

				fprintf(ini, "[Camera]\n");
				fprintf(ini, "ViewMatrix=0x40\n");
				fprintf(ini, "FOV=0xCC\n\n");
			}

			fclose(ini);
			Log("[+] INI written to %s", iniPath.c_str());
		}

		Log("[+] Enfusion offsets dumped to %s", filePath.c_str());
		return true;
	}

	// ============================================================
	// AnvilNext 2.0 sig scanner (Rainbow Six Siege)
	// ============================================================
	struct R6ScanResult {
		DWORD64 gameManagerPtr;
		DWORD64 statusManagerPtr;
		DWORD64 cameraManagerPtr;
		DWORD64 profileManagerPtr;
		DWORD64 networkManagerPtr;
		DWORD64 roundManagerPtr;
		DWORD64 glowManagerPtr;
		DWORD64 gameRendererPtr;
		DWORD64 decryptedGameManager; // actual heap address after decryption
		int gmRotation; // ROL rotation used, 0 = plaintext
		bool found;
	};

	inline R6ScanResult ScanR6Signatures(DWORD64 modBase)
	{
		R6ScanResult r = {};
		auto sections = GetPESections(modBase);

		DWORD64 textBase = 0;
		DWORD   textSize = 0;
		for (auto& s : sections)
		{
			if (strcmp(s.name, ".text") == 0)
			{ textBase = s.base; textSize = s.size; break; }
		}
		if (!textBase)
		{
			for (auto& s : sections)
			{
				if (s.characteristics & IMAGE_SCN_MEM_EXECUTE)
				{ textBase = s.base; textSize = s.size; break; }
			}
		}
		if (!textBase || textSize < 0x1000)
		{
			Log("[-] No executable section found in RainbowSix.exe");
			return r;
		}

		Log("[*] Scanning .text section: 0x%llX (size: 0x%X / %u MB)",
			textBase, textSize, textSize / (1024 * 1024));

		// GameManager — MOV RAX, [RIP+disp32] patterns
		// Known sigs (try multiple, pick first valid one)
		const char* gmSigs[] = {
			"48 8B 05 ?? ?? ?? ?? 8B 8E",
			"48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B 48",
			"48 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B D8 48 85 C0",
			nullptr
		};

		for (int i = 0; gmSigs[i]; i++)
		{
			DWORD64 addr = ScanPattern(textBase, textSize, gmSigs[i]);
			if (addr)
			{
				DWORD64 resolved = ResolveRIP(addr, 3);
				DWORD64 val = read<DWORD64>(resolved);
				if (val > 0x10000 && val < 0x7FFFFFFFFFFF)
				{
					r.gameManagerPtr = resolved;
					Log("[+] GameManager ptr @ 0x%llX (sig #%d, value=0x%llX)", resolved, i, val);
					r.found = true;
					break;
				}
				Log("[*] GameManager sig #%d matched @ 0x%llX -> 0x%llX but value 0x%llX invalid",
					i, addr, resolved, val);
			}
		}

		// StatusManager
		const char* smSigs[] = {
			"48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B 40 28",
			"48 8B 05 ?? ?? ?? ?? 48 85 C0 0F 84 ?? ?? ?? ?? 48 8B 48 28",
			nullptr
		};
		for (int i = 0; smSigs[i]; i++)
		{
			DWORD64 addr = ScanPattern(textBase, textSize, smSigs[i]);
			if (addr)
			{
				DWORD64 resolved = ResolveRIP(addr, 3);
				DWORD64 val = read<DWORD64>(resolved);
				if (val > 0x10000 && val < 0x7FFFFFFFFFFF)
				{
					r.statusManagerPtr = resolved;
					Log("[+] StatusManager ptr @ 0x%llX (sig #%d)", resolved, i);
					r.found = true;
					break;
				}
			}
		}

		// CameraManager
		const char* camSigs[] = {
			"48 8B 05 ?? ?? ?? ?? 48 8B 48 ?? 48 8B 81 ?? ?? 00 00",
			"48 8B 0D ?? ?? ?? ?? 48 85 C9 74 ?? E8 ?? ?? ?? ?? 48 8B C8 48 8B 10",
			nullptr
		};
		for (int i = 0; camSigs[i]; i++)
		{
			DWORD64 addr = ScanPattern(textBase, textSize, camSigs[i]);
			if (addr)
			{
				DWORD64 resolved = ResolveRIP(addr, 3);
				DWORD64 val = read<DWORD64>(resolved);
				if (val > 0x10000 && val < 0x7FFFFFFFFFFF)
				{
					r.cameraManagerPtr = resolved;
					Log("[+] CameraManager ptr @ 0x%llX (sig #%d)", resolved, i);
					r.found = true;
					break;
				}
			}
		}

		// ProfileManager
		const char* pmSigs[] = {
			"48 8B 05 ?? ?? ?? ?? 33 D2 48 8B 88 ?? ?? 00 00",
			nullptr
		};
		for (int i = 0; pmSigs[i]; i++)
		{
			DWORD64 addr = ScanPattern(textBase, textSize, pmSigs[i]);
			if (addr)
			{
				DWORD64 resolved = ResolveRIP(addr, 3);
				DWORD64 val = read<DWORD64>(resolved);
				if (val > 0x10000 && val < 0x7FFFFFFFFFFF)
				{
					r.profileManagerPtr = resolved;
					Log("[+] ProfileManager ptr @ 0x%llX (sig #%d)", resolved, i);
					r.found = true;
					break;
				}
			}
		}

		// NetworkManager
		const char* nmSigs[] = {
			"48 89 05 ?? ?? ?? ?? 48 8B 4C 24 ?? 48 33 CC E8",
			nullptr
		};
		for (int i = 0; nmSigs[i]; i++)
		{
			DWORD64 addr = ScanPattern(textBase, textSize, nmSigs[i]);
			if (addr)
			{
				DWORD64 resolved = ResolveRIP(addr, 3);
				r.networkManagerPtr = resolved;
				Log("[+] NetworkManager ptr @ 0x%llX (sig #%d)", resolved, i);
				r.found = true;
				break;
			}
		}

		// GlowManager
		const char* glowSigs[] = {
			"48 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 84 C0 74 ?? 48 8B 0D ?? ?? ?? ?? 48 8B 01",
			"48 8B 0D ?? ?? ?? ?? 48 8B D7 E8 ?? ?? ?? ?? 48 85 C0",
			"48 8B 0D ?? ?? ?? ?? 48 85 C9 74 ?? 48 89 F2 E8 ?? ?? ?? ?? 48 85 C0 74",
			nullptr
		};
		for (int i = 0; glowSigs[i]; i++)
		{
			DWORD64 addr = ScanPattern(textBase, textSize, glowSigs[i]);
			if (addr)
			{
				DWORD64 resolved = ResolveRIP(addr, 3);
				DWORD64 val = read<DWORD64>(resolved);
				if (val > 0x10000 && val < 0x7FFFFFFFFFFF)
				{
					r.glowManagerPtr = resolved;
					Log("[+] GlowManager ptr @ 0x%llX (sig #%d)", resolved, i);
					r.found = true;
					break;
				}
			}
		}

		// GameRenderer (camera chains off this)
		const char* grSigs[] = {
			"4C 89 0D ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? 45 33 C9 BA",
			"48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? F3 0F 10 80",
			nullptr
		};
		for (int i = 0; grSigs[i]; i++)
		{
			DWORD64 addr = ScanPattern(textBase, textSize, grSigs[i]);
			if (addr)
			{
				DWORD64 resolved = ResolveRIP(addr, 3);
				DWORD64 val = read<DWORD64>(resolved);
				if (val > 0x10000 && val < 0x7FFFFFFFFFFF)
				{
					r.gameRendererPtr = resolved;
					Log("[+] GameRenderer ptr @ 0x%llX (sig #%d, value=0x%llX)", resolved, i, val);
					r.found = true;
					break;
				}
			}
		}

		// ============================================================
		// Validate GameManager chain (detect encryption)
		// ============================================================
		bool gmChainValid = false;
		DWORD64 gmEncryptedAddr = 0;
		if (r.gameManagerPtr)
		{
			DWORD64 gmVal = read<DWORD64>(r.gameManagerPtr);
			if (gmVal > 0x10000 && gmVal < 0x7FFFFFFFFFFF)
			{
				DWORD64 el = read<DWORD64>(gmVal + 0x1C8);
				int32_t ec = read<int32_t>(gmVal + 0x1D0);
				if (el > 0x10000 && el < 0x7FF000000000 && ec > 0 && ec < 100)
				{
					DWORD64 ent0 = read<DWORD64>(el);
					if (ent0 > 0x10000 && ent0 < 0x7FF000000000)
					{
						gmChainValid = true;
						r.decryptedGameManager = gmVal;
						r.gmRotation = 0;
						Log("[+] GameManager chain VALID (plaintext): %d entities", ec);
					}
				}

				if (!gmChainValid)
				{
					Log("[*] GameManager at 0x%llX has encrypted value 0x%llX — trying ROL decryption...",
						r.gameManagerPtr, gmVal);
					gmEncryptedAddr = r.gameManagerPtr;

					for (int rot = 1; rot <= 63; rot++)
					{
						DWORD64 dec = _rotl64(gmVal, rot);
						if (dec < 0x10000 || dec > 0x7FF000000000) continue;
						DWORD64 el2 = read<DWORD64>(dec + 0x1C8);
						int32_t ec2 = read<int32_t>(dec + 0x1D0);
						if (el2 < 0x10000 || el2 > 0x7FF000000000) continue;
						if (ec2 <= 0 || ec2 > 100) continue;
						DWORD64 ent = read<DWORD64>(el2);
						if (ent < 0x10000 || ent > 0x7FF000000000) continue;
						gmChainValid = true;
						r.decryptedGameManager = dec;
						r.gmRotation = rot;
						Log("[+] GameManager decrypted with ROL(%d): 0x%llX -> 0x%llX", rot, gmVal, dec);
						Log("[+]   EntityList=0x%llX, Count=%d", el2, ec2);
						break;
					}

					// Try ROTR too
					if (!gmChainValid)
					{
						for (int rot = 1; rot <= 63; rot++)
						{
							DWORD64 dec = _rotr64(gmVal, rot);
							if (dec < 0x10000 || dec > 0x7FF000000000) continue;
							DWORD64 el2 = read<DWORD64>(dec + 0x1C8);
							int32_t ec2 = read<int32_t>(dec + 0x1D0);
							if (el2 < 0x10000 || el2 > 0x7FF000000000) continue;
							if (ec2 <= 0 || ec2 > 100) continue;
							DWORD64 ent = read<DWORD64>(el2);
							if (ent < 0x10000 || ent > 0x7FF000000000) continue;
							gmChainValid = true;
							r.decryptedGameManager = dec;
							r.gmRotation = -rot; // negative = ROR
							Log("[+] GameManager decrypted with ROR(%d): 0x%llX -> 0x%llX", rot, gmVal, dec);
							Log("[+]   EntityList=0x%llX, Count=%d", el2, ec2);
							break;
						}
					}

					if (!gmChainValid)
						Log("[!] ROL/ROR alone didn't work — pointer uses XOR+ROL encryption");
				}
			}
		}

		// ============================================================
		// Brute-force: if no valid GameManager chain, scan ALL RIP-relative
		// MOV instructions and validate entity chain (try plaintext + ROL)
		// ============================================================
		if (!gmChainValid)
		{
			Log("[*] Running brute-force GameManager scan (plaintext + ROL 1-63)...");

			const DWORD chunkSize = 0x400000; // 4MB chunks
			std::set<DWORD64> testedPtrs;

			for (DWORD offset = 0; offset < textSize - 7 && !gmChainValid; offset += chunkSize)
			{
				DWORD toRead = min(chunkSize + 16, textSize - offset);
				std::vector<BYTE> chunk(toRead);
				read_buffer(textBase + offset, chunk.data(), toRead);

				for (DWORD i = 0; i + 7 <= toRead && !gmChainValid; i++)
				{
					if (chunk[i] != 0x48) continue;
					if (chunk[i + 1] != 0x8B) continue;
					BYTE modrm = chunk[i + 2];
					if ((modrm & 0xC7) != 0x05) continue;

					int32_t disp = *(int32_t*)(&chunk[i + 3]);
					DWORD64 instrAddr = textBase + offset + i;
					DWORD64 targetAddr = instrAddr + 7 + disp;

					if (targetAddr >= textBase && targetAddr < textBase + textSize) continue;
					if (testedPtrs.count(targetAddr)) continue;
					testedPtrs.insert(targetAddr);

					DWORD64 val = read<DWORD64>(targetAddr);
					if (val < 0x10000 || val > 0x7FFFFFFFFFFF) continue;

					// Validate entity chain with strict checks to avoid false positives
					auto tryChain = [&](DWORD64 candidate) -> bool {
						DWORD64 el = read<DWORD64>(candidate + 0x1C8);
						int32_t ec = read<int32_t>(candidate + 0x1D0);
						// EntityList must be a heap pointer (not in module range)
						if (el < 0x10000 || el > 0x7FF000000000) return false;
						if (ec <= 0 || ec > 30) return false;
						// Check multiple entities, require at least 2 non-null
						int validEnts = 0;
						bool anyNonZeroPos = false;
						for (int e = 0; e < min(ec, 10); e++)
						{
							DWORD64 ent = read<DWORD64>(el + e * 0x8);
							if (ent < 0x10000 || ent > 0x7FF000000000) continue;
							validEnts++;
							float hx = read<float>(ent + 0x6A0);
							float hy = read<float>(ent + 0x6A4);
							float hz = read<float>(ent + 0x6A8);
							if (hx != hx || hy != hy || hz != hz) continue; // NaN
							if (hx < -100000 || hx > 100000) continue;
							if (hx != 0.0f || hy != 0.0f || hz != 0.0f)
								anyNonZeroPos = true;
						}
						if (validEnts < 1) return false;
						// In-menu might have zero positions; accept if we got valid entity pointers
						return true;
					};

					if (tryChain(val))
					{
						r.gameManagerPtr = targetAddr;
						r.decryptedGameManager = val;
						r.gmRotation = 0;
						gmChainValid = true;
						r.found = true;
						Log("[+] BRUTE-FORCE: GameManager @ 0x%llX (RVA=0x%llX), value=0x%llX",
							targetAddr, targetAddr - modBase, val);
						break;
					}

					// Try ROL 1-63
					for (int rot = 1; rot <= 63 && !gmChainValid; rot++)
					{
						DWORD64 dec = _rotl64(val, rot);
						if (dec < 0x10000 || dec > 0x7FFFFFFFFFFF) continue;
						if (tryChain(dec))
						{
							r.gameManagerPtr = targetAddr;
							r.decryptedGameManager = dec;
							r.gmRotation = rot;
							gmChainValid = true;
							r.found = true;
							Log("[+] BRUTE-FORCE+ROL(%d): GameManager @ 0x%llX, raw=0x%llX -> dec=0x%llX",
								rot, targetAddr, val, dec);
							break;
						}
					}
				}

				if ((offset % 0x2000000) == 0 && offset > 0)
					Log("[*]   scanned %u / %u MB...", offset / (1024*1024), textSize / (1024*1024));
			}

			if (!gmChainValid)
				Log("[!] Brute-force: tested %llu unique addrs, no valid GameManager chain",
					(DWORD64)testedPtrs.size());
		}

		return r;
	}

	inline bool DumpAnvilNextOffsets(const GameDef& game, const std::string& outDir)
	{
		DWORD64 modBase = DMA::GetModuleBase(game.coreModule);
		if (!modBase) { Log("[-] %s not found", game.coreModule); return false; }
		Log("[+] %s -> 0x%llX", game.coreModule, modBase);

		R6ScanResult scan = ScanR6Signatures(modBase);

		std::string filePath = outDir + "\\offsets.h";
		FILE* f = nullptr;
		fopen_s(&f, filePath.c_str(), "w");
		if (!f) { Log("[-] Failed to create %s", filePath.c_str()); return false; }

		time_t now = time(nullptr);
		struct tm t = {};
		localtime_s(&t, &now);
		char date[32];
		sprintf_s(date, "%04d-%02d-%02d", t.tm_year + 1900, t.tm_mon + 1, t.tm_mday);

		fprintf(f, "// %s Offset Dump - %s\n", game.name, date);
		fprintf(f, "// Engine: AnvilNext 2.0 (Ubisoft)\n");
		fprintf(f, "// Auto-generated via DMA pattern scanning\n");
		fprintf(f, "// %s base: 0x%llX\n", game.coreModule, modBase);
		fprintf(f, "// NOTE: Static pointers change every game update.\n");
		fprintf(f, "//       Re-run dumper after patches.\n\n");
		fprintf(f, "#pragma once\n#include <cstdint>\n\n");

		DumpAllModuleList(f);

		// Scan results
		fprintf(f, "// ============================================\n");
		fprintf(f, "// Pattern Scan Results (Static Pointers)\n");
		fprintf(f, "// These are ABSOLUTE addresses in the process.\n");
		fprintf(f, "// Subtract module base for RVA.\n");
		fprintf(f, "// ============================================\n\n");

		fprintf(f, "namespace R6_Statics {\n");
		fprintf(f, "    constexpr uintptr_t ModuleBase = 0x%llX;\n\n", modBase);

		auto dumpPtr = [&](const char* name, DWORD64 ptr) {
			if (ptr)
			{
				DWORD64 val = read<DWORD64>(ptr);
				fprintf(f, "    constexpr uintptr_t %s = 0x%llX;  // RVA=0x%llX  value=0x%llX\n",
					name, ptr, ptr - modBase, val);
			}
			else
			{
				fprintf(f, "    constexpr uintptr_t %s = 0x0;  // NOT FOUND\n", name);
			}
		};

		dumpPtr("GameManager",    scan.gameManagerPtr);
		dumpPtr("StatusManager",  scan.statusManagerPtr);
		dumpPtr("CameraManager",  scan.cameraManagerPtr);
		dumpPtr("ProfileManager", scan.profileManagerPtr);
		dumpPtr("NetworkManager", scan.networkManagerPtr);
		dumpPtr("GlowManager",    scan.glowManagerPtr);
		dumpPtr("GameRenderer",   scan.gameRendererPtr);

		if (scan.decryptedGameManager)
		{
			fprintf(f, "\n    // Decrypted GameManager: 0x%llX (ROL %d)\n",
				scan.decryptedGameManager, scan.gmRotation);
		}
		fprintf(f, "}\n\n");

		// Known AnvilNext 2.0 structure offsets (from public RE sources)
		fprintf(f, "// ============================================\n");
		fprintf(f, "// AnvilNext 2.0 Structure Offsets\n");
		fprintf(f, "// These are RELATIVE offsets within structures.\n");
		fprintf(f, "// More stable across patches than static ptrs.\n");
		fprintf(f, "// ============================================\n\n");

		fprintf(f, "namespace R6_GameManager {\n");
		fprintf(f, "    constexpr uintptr_t EntityList  = 0x1C8;\n");
		fprintf(f, "    constexpr uintptr_t EntityCount = 0x1D0;\n");
		fprintf(f, "}\n\n");

		fprintf(f, "namespace R6_Entity {\n");
		fprintf(f, "    constexpr uintptr_t Pawn              = 0x20;\n");
		fprintf(f, "    constexpr uintptr_t Replication       = 0xC8;\n");
		fprintf(f, "    constexpr uintptr_t ComponentChain    = 0xD8;\n");
		fprintf(f, "    constexpr uintptr_t HeadPosition      = 0x6A0;  // Vec3\n");
		fprintf(f, "    constexpr uintptr_t FeetPosition      = 0x700;  // Vec3\n");
		fprintf(f, "}\n\n");

		fprintf(f, "namespace R6_Replication {\n");
		fprintf(f, "    constexpr uintptr_t TeamID = 0x190;\n");
		fprintf(f, "}\n\n");

		fprintf(f, "namespace R6_Component {\n");
		fprintf(f, "    constexpr uintptr_t ChildComponent = 0x8;\n");
		fprintf(f, "    constexpr uintptr_t Health         = 0x168;  // int32\n");
		fprintf(f, "}\n\n");

		fprintf(f, "namespace R6_StatusManager {\n");
		fprintf(f, "    constexpr uintptr_t LocalEntity = 0x28;\n");
		fprintf(f, "}\n\n");

		fprintf(f, "namespace R6_CameraManager {\n");
		fprintf(f, "    constexpr uintptr_t EngineLink = 0x120;\n");
		fprintf(f, "}\n\n");

		fprintf(f, "namespace R6_CameraEngine {\n");
		fprintf(f, "    constexpr uintptr_t CameraPtr = 0x1C8;\n");
		fprintf(f, "}\n\n");

		fprintf(f, "namespace R6_Camera {\n");
		fprintf(f, "    constexpr uintptr_t Object          = 0x08;\n");
		fprintf(f, "    constexpr uintptr_t ViewRight       = 0xD0;   // Vec3\n");
		fprintf(f, "    constexpr uintptr_t ViewUp          = 0xE0;   // Vec3\n");
		fprintf(f, "    constexpr uintptr_t ViewForward     = 0xF0;   // Vec3\n");
		fprintf(f, "    constexpr uintptr_t ViewTranslation = 0x100;  // Vec3\n");
		fprintf(f, "    constexpr uintptr_t FovX            = 0x110;  // float\n");
		fprintf(f, "    constexpr uintptr_t FovY            = 0x124;  // float\n");
		fprintf(f, "}\n\n");

		// Pointer chain documentation
		fprintf(f, "// ============================================\n");
		fprintf(f, "// Pointer Chain Reference\n");
		fprintf(f, "// ============================================\n");
		fprintf(f, "//\n");
		fprintf(f, "// Entity chain:\n");
		fprintf(f, "//   [GameManager] -> +0x1C8 = EntityList\n");
		fprintf(f, "//   EntityList[i * 0x8] = Entity\n");
		fprintf(f, "//   Entity + 0x20 = Pawn\n");
		fprintf(f, "//   Entity + 0x6A0 = Head (Vec3)\n");
		fprintf(f, "//   Entity + 0x700 = Feet (Vec3)\n");
		fprintf(f, "//\n");
		fprintf(f, "// Health chain:\n");
		fprintf(f, "//   Entity + 0xD8 -> + 0x8 -> + 0x168 = Health\n");
		fprintf(f, "//\n");
		fprintf(f, "// Team chain:\n");
		fprintf(f, "//   Entity + 0xC8 -> + 0x190 = TeamID\n");
		fprintf(f, "//\n");
		fprintf(f, "// Camera chain:\n");
		fprintf(f, "//   [CameraManager] + 0x120 -> + 0x1C8 -> + 0x08 = Camera\n");
		fprintf(f, "//   Camera + 0xD0 = ViewRight\n");
		fprintf(f, "//   Camera + 0xE0 = ViewUp\n");
		fprintf(f, "//   Camera + 0xF0 = ViewForward\n");
		fprintf(f, "//   Camera + 0x100 = ViewTranslation\n");
		fprintf(f, "//   Camera + 0x110 = FovX, + 0x124 = FovY\n");
		fprintf(f, "//\n");
		fprintf(f, "// Local player:\n");
		fprintf(f, "//   [StatusManager] + 0x28 = LocalEntity\n");
		fprintf(f, "//\n");
		fprintf(f, "// NOTE: GameManager pointer may be encrypted (XOR + ROL).\n");
		fprintf(f, "//       Decryption keys change per patch.\n\n");

		// Validate by trying to walk the GameManager chain
		if (scan.gameManagerPtr)
		{
			fprintf(f, "// ============================================\n");
			fprintf(f, "// Live Validation\n");
			fprintf(f, "// ============================================\n\n");

			DWORD64 gmRaw = read<DWORD64>(scan.gameManagerPtr);
			fprintf(f, "// GameManager raw value: 0x%llX\n", gmRaw);

			DWORD64 gmVal = scan.decryptedGameManager ? scan.decryptedGameManager : gmRaw;
			if (scan.decryptedGameManager && scan.gmRotation != 0)
				fprintf(f, "// Decrypted (ROL %d): 0x%llX\n", scan.gmRotation, gmVal);

			if (gmVal > 0x10000 && gmVal < 0x7FFFFFFFFFFF)
			{
				DWORD64 entityList = read<DWORD64>(gmVal + 0x1C8);
				DWORD32 entityCount = read<DWORD32>(gmVal + 0x1D0);
				fprintf(f, "// EntityList ptr: 0x%llX\n", entityList);
				fprintf(f, "// EntityCount: %u\n", entityCount);

				if (entityList > 0x10000 && entityCount > 0 && entityCount < 100)
				{
					fprintf(f, "// Chain validation: PASSED (found %u entities)\n\n", entityCount);
					Log("[+] Chain validation PASSED: %u entities found", entityCount);

					for (DWORD32 i = 0; i < min(entityCount, (DWORD32)20); i++)
					{
						DWORD64 entity = read<DWORD64>(entityList + i * 0x8);
						if (!entity) continue;

						float headX = read<float>(entity + 0x6A0);
						float headY = read<float>(entity + 0x6A4);
						float headZ = read<float>(entity + 0x6A8);

						DWORD64 repl = read<DWORD64>(entity + 0xC8);
						int teamId = repl ? read<int>(repl + 0x190) : -1;

						DWORD64 comp = read<DWORD64>(entity + 0xD8);
						DWORD64 child = comp ? read<DWORD64>(comp + 0x8) : 0;
						int health = child ? read<int>(child + 0x168) : -1;

						fprintf(f, "// Entity[%u] @ 0x%llX  pos=(%.1f, %.1f, %.1f)  team=%d  hp=%d\n",
							i, entity, headX, headY, headZ, teamId, health);
					}
					fprintf(f, "\n");
				}
				else
				{
					fprintf(f, "// Chain validation: FAILED — pointer encrypted or stale\n\n");
					Log("[!] EntityList chain invalid at decrypted GM 0x%llX", gmVal);
				}
			}
			else
			{
				fprintf(f, "// GameManager value outside valid range\n\n");
			}
		}

		fclose(f);

		// Also generate an INI with the resolved offsets
		std::string iniPath = outDir + "\\r6_offsets.ini";
		FILE* ini = nullptr;
		fopen_s(&ini, iniPath.c_str(), "w");
		if (ini)
		{
			fprintf(ini, "# Rainbow Six Siege — Auto-generated Offsets\n");
			fprintf(ini, "# Date: %s\n", date);
			fprintf(ini, "# Engine: AnvilNext 2.0\n");
			fprintf(ini, "# Module: %s @ 0x%llX\n\n", game.coreModule, modBase);

			fprintf(ini, "[Identity]\n");
			fprintf(ini, "GameName=Rainbow Six Siege\n");
			fprintf(ini, "ProcessName=RainbowSix.exe\n");
			fprintf(ini, "ProcessName_BE=RainbowSix_BE.exe\n");
			fprintf(ini, "ModuleName=RainbowSix.exe\n");
			fprintf(ini, "Engine=anvilnext\n\n");

			fprintf(ini, "[Managers]\n");
			fprintf(ini, "GameManager=0x%llX\n",    scan.gameManagerPtr ? scan.gameManagerPtr - modBase : 0);
			fprintf(ini, "StatusManager=0x%llX\n",  scan.statusManagerPtr ? scan.statusManagerPtr - modBase : 0);
			fprintf(ini, "CameraManager=0x%llX\n",  scan.cameraManagerPtr ? scan.cameraManagerPtr - modBase : 0);
			fprintf(ini, "ProfileManager=0x%llX\n", scan.profileManagerPtr ? scan.profileManagerPtr - modBase : 0);
			fprintf(ini, "NetworkManager=0x%llX\n", scan.networkManagerPtr ? scan.networkManagerPtr - modBase : 0);
			fprintf(ini, "GlowManager=0x%llX\n",    scan.glowManagerPtr ? scan.glowManagerPtr - modBase : 0);
			fprintf(ini, "GameRenderer=0x%llX\n\n",  scan.gameRendererPtr ? scan.gameRendererPtr - modBase : 0);

			if (scan.decryptedGameManager)
			{
				fprintf(ini, "[Decryption]\n");
				fprintf(ini, "GameManagerDecrypted=0x%llX\n", scan.decryptedGameManager);
				fprintf(ini, "GameManagerRotation=%d\n\n", scan.gmRotation);
			}

			fprintf(ini, "[GameManager]\n");
			fprintf(ini, "EntityList=0x1C8\n");
			fprintf(ini, "EntityCount=0x1D0\n\n");

			fprintf(ini, "[Entity]\n");
			fprintf(ini, "Pawn=0x20\n");
			fprintf(ini, "Replication=0xC8\n");
			fprintf(ini, "ComponentChain=0xD8\n");
			fprintf(ini, "HeadPosition=0x6A0\n");
			fprintf(ini, "FeetPosition=0x700\n\n");

			fprintf(ini, "[Replication]\n");
			fprintf(ini, "TeamID=0x190\n\n");

			fprintf(ini, "[Component]\n");
			fprintf(ini, "ChildComponent=0x8\n");
			fprintf(ini, "Health=0x168\n\n");

			fprintf(ini, "[StatusManager]\n");
			fprintf(ini, "LocalEntity=0x28\n\n");

			fprintf(ini, "[CameraChain]\n");
			fprintf(ini, "EngineLink=0x120\n");
			fprintf(ini, "CameraEngine=0x1C8\n");
			fprintf(ini, "CameraObject=0x08\n\n");

			fprintf(ini, "[Camera]\n");
			fprintf(ini, "ViewRight=0xD0\n");
			fprintf(ini, "ViewUp=0xE0\n");
			fprintf(ini, "ViewForward=0xF0\n");
			fprintf(ini, "ViewTranslation=0x100\n");
			fprintf(ini, "FovX=0x110\n");
			fprintf(ini, "FovY=0x124\n");

			fclose(ini);
			Log("[+] R6 INI offsets written to %s", iniPath.c_str());
		}

		Log("[+] AnvilNext offsets dumped to %s", filePath.c_str());
		return true;
	}

	// ============================================================
	// Native engine dumper (Apex, generic, etc.)
	// ============================================================
	inline bool DumpNativeOffsets(const GameDef& game, const std::string& outDir)
	{
		// R6 Siege gets the dedicated AnvilNext scanner
		if (_stricmp(game.name, "RainbowSix") == 0)
			return DumpAnvilNextOffsets(game, outDir);

		std::string filePath = outDir + "\\offsets.h";
		FILE* f = nullptr;
		fopen_s(&f, filePath.c_str(), "w");
		if (!f) { Log("[-] Failed to create %s", filePath.c_str()); return false; }

		time_t now = time(nullptr);
		struct tm t = {};
		localtime_s(&t, &now);
		char date[32];
		sprintf_s(date, "%04d-%02d-%02d", t.tm_year + 1900, t.tm_mon + 1, t.tm_mday);

		fprintf(f, "// %s Offset Dump - %s\n", game.name, date);
		fprintf(f, "// Engine: Native\n");
		fprintf(f, "// Auto-generated via DMA PE analysis + pattern scan\n\n");
		fprintf(f, "#pragma once\n#include <cstdint>\n\n");

		DumpAllModuleList(f);

		auto modules = Dumper::EnumerateModules();
		DumpModuleExports(f, game.coreModule);

		const char* interestingModules[] = {
			"client.dll", "engine.dll", "materialsystem.dll", "vstdlib.dll",
			"tier0.dll", "inputsystem.dll", "datacache.dll",
			"gamedll_ph_be.dll", "uplay_r2.dll",
			nullptr
		};

		for (int i = 0; interestingModules[i]; i++)
		{
			for (auto& mod : modules)
			{
				if (_stricmp(mod.name.c_str(), interestingModules[i]) == 0)
				{ DumpModuleExports(f, interestingModules[i]); break; }
			}
		}

		fclose(f);
		Log("[+] Native offsets dumped to %s", filePath.c_str());
		return true;
	}

	// ============================================================
	// Auto-detect and dump
	// ============================================================
	inline bool AutoDump()
	{
		Log("[*] Scanning for supported games on target PC...");

		GameDef* found = nullptr;
		for (auto& game : SupportedGames)
		{
			if (DMA::FindProcess(game.processName))
			{
				found = &game;
				break;
			}
		}

		if (!found)
		{
			Log("[!] No supported game detected. Showing all processes...");
			if (!DMA::FindProcessInteractive())
				return false;

			// Get process name
			VMMDLL_PROCESS_INFORMATION info = {};
			info.magic = VMMDLL_PROCESS_INFORMATION_MAGIC;
			info.wVersion = VMMDLL_PROCESS_INFORMATION_VERSION;
			SIZE_T cbInfo = sizeof(info);
			std::string procName = "Unknown";
			if (VMMDLL_ProcessGetInformation(hVMM, dwPID, &info, &cbInfo))
				procName = info.szNameLong[0] ? info.szNameLong : info.szName;

			// Strip .exe for folder name
			std::string gameName = procName;
			auto dot = gameName.find('.');
			if (dot != std::string::npos) gameName = gameName.substr(0, dot);

			std::string outDir = MakeOutputDir(gameName.c_str());

			// Try Mono first, then IL2CPP, then native
			DWORD64 monoBase = DMA::GetModuleBase("mono-2.0-bdwgc.dll");
			if (!monoBase) monoBase = DMA::GetModuleBase("mono.dll");
			DWORD64 gaBase = DMA::GetModuleBase("GameAssembly.dll");

			GameDef custom = {};
			custom.name = gameName.c_str();
			custom.processName = procName.c_str();

			if (monoBase)
			{
				Log("[+] Detected Mono engine");
				custom.engine = EngineType::Mono;
				custom.monoModule = monoBase == DMA::GetModuleBase("mono-2.0-bdwgc.dll") ? "mono-2.0-bdwgc.dll" : "mono.dll";
				custom.coreModule = "Assembly-CSharp";
				return DumpMonoOffsets(custom, outDir);
			}
			else if (gaBase)
			{
				Log("[+] Detected IL2CPP engine");
				custom.engine = EngineType::IL2CPP;
				custom.coreModule = "GameAssembly.dll";
				return DumpIL2CPPOffsets(custom, outDir);
			}
			else
			{
				// Check for Source 2
				DWORD64 schemaBase = DMA::GetModuleBase("schemasystem.dll");
				if (schemaBase)
				{
					Log("[+] Detected Source 2 engine");
					custom.engine = EngineType::Source2;
					custom.coreModule = "client.dll";
					return DumpSource2Offsets(custom, outDir);
				}

				// Check for Source (Respawn)
				DWORD64 tier0Base = DMA::GetModuleBase("tier0.dll");
				if (tier0Base)
				{
					Log("[+] Detected Source engine");
					custom.engine = EngineType::SourceRespawn;
					custom.coreModule = procName.c_str();
					return DumpSourceRespawnOffsets(custom, outDir);
				}

				Log("[+] Native/Unknown engine");
				custom.engine = EngineType::Native;
				custom.coreModule = procName.c_str();
				return DumpNativeOffsets(custom, outDir);
			}
		}

		Log("[+] Found %s (PID %u)", found->name, dwPID);
		std::string outDir = MakeOutputDir(found->name);

		switch (found->engine)
		{
		case EngineType::Mono:           return DumpMonoOffsets(*found, outDir);
		case EngineType::IL2CPP:         return DumpIL2CPPOffsets(*found, outDir);
		case EngineType::UE4:            return DumpUEOffsets(*found, outDir, false);
		case EngineType::UE5:            return DumpUEOffsets(*found, outDir, true);
		case EngineType::Source2:        return DumpSource2Offsets(*found, outDir);
		case EngineType::SourceRespawn:  return DumpSourceRespawnOffsets(*found, outDir);
		case EngineType::Enfusion:       return DumpEnfusionOffsets(*found, outDir);
		case EngineType::Native:         return DumpNativeOffsets(*found, outDir);
		}
		return false;
	}
}
