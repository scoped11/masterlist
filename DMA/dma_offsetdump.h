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

namespace OffsetDump
{
	enum class EngineType { Mono, IL2CPP, Native };

	struct GameDef {
		const char* name;
		const char* processName;
		EngineType engine;
		const char* monoModule;     // for Mono games
		const char* coreModule;     // main game DLL to focus on
	};

	inline GameDef SupportedGames[] = {
		{ "Unturned",      "Unturned.exe",    EngineType::Mono,   "mono-2.0-bdwgc.dll", "Assembly-CSharp" },
		{ "Rust",          "RustClient.exe",  EngineType::IL2CPP, nullptr,               "GameAssembly.dll" },
		{ "RainbowSix",    "RainbowSix.exe",  EngineType::Native, nullptr,               "RainbowSix.exe" },
		{ "RainbowSix",    "RainbowSix_BE.exe", EngineType::Native, nullptr,             "RainbowSix.exe" },
		{ "ApexLegends",   "r5apex.exe",      EngineType::Native, nullptr,               "r5apex.exe" },
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
	// Native engine dumper (R6, Apex, etc.)
	// ============================================================
	inline bool DumpNativeOffsets(const GameDef& game, const std::string& outDir)
	{
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
		fprintf(f, "// Auto-generated via DMA PE analysis\n\n");
		fprintf(f, "#pragma once\n#include <cstdint>\n\n");

		DumpAllModuleList(f);

		// Dump exports from key modules
		auto modules = Dumper::EnumerateModules();

		// Always dump the main exe
		DumpModuleExports(f, game.coreModule);

		// Dump exports from interesting DLLs
		const char* interestingModules[] = {
			// R6
			"gamedll_ph_be.dll", "uplay_r2.dll",
			// Apex
			"client.dll", "engine.dll", "materialsystem.dll", "vstdlib.dll",
			"tier0.dll", "inputsystem.dll", "datacache.dll",
			// Common
			"d3d11.dll", "dxgi.dll",
			nullptr
		};

		for (int i = 0; interestingModules[i]; i++)
		{
			bool found = false;
			for (auto& mod : modules)
			{
				if (_stricmp(mod.name.c_str(), interestingModules[i]) == 0)
				{
					found = true;
					break;
				}
			}
			if (found)
				DumpModuleExports(f, interestingModules[i]);
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
				Log("[+] Native engine (no Mono/IL2CPP)");
				custom.engine = EngineType::Native;
				custom.coreModule = procName.c_str();
				return DumpNativeOffsets(custom, outDir);
			}
		}

		Log("[+] Found %s (PID %u)", found->name, dwPID);
		std::string outDir = MakeOutputDir(found->name);

		switch (found->engine)
		{
		case EngineType::Mono:   return DumpMonoOffsets(*found, outDir);
		case EngineType::IL2CPP: return DumpIL2CPPOffsets(*found, outDir);
		case EngineType::Native: return DumpNativeOffsets(*found, outDir);
		}
		return false;
	}
}
