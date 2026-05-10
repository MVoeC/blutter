#include "pch.h"
#include "ElfHelper.h"
PRAGMA_WARNING(push, 0)
#include <platform/elf.h>
PRAGMA_WARNING(pop)
#include <algorithm>
#include <stdexcept>
#if defined(_WIN32) || defined(WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
//#include <dlfcn.h>
#include <sys/mman.h>
#endif // #if defined(_WIN32) || defined(WIN32)

struct ElfIdent {
	uint8_t ei_magic[4];
	uint8_t ei_class;
	uint8_t ei_data;
	uint8_t ei_version;
	uint8_t ei_osabi;
	uint8_t ei_abiversion;
	uint8_t pad1[7];
};

namespace mach_o {
constexpr uint32_t MH_MAGIC_64 = 0xfeedfacf;
constexpr uint32_t LC_SEGMENT_64 = 0x19;
constexpr uint32_t LC_SYMTAB = 0x2;
constexpr uint32_t N_STAB = 0xe0;
constexpr uint32_t N_TYPE = 0x0e;
constexpr uint32_t N_SECT = 0x0e;
constexpr uint32_t MAX_SEGMENTS = 64;

struct mach_header_64 {
	uint32_t magic;
	int32_t cputype;
	int32_t cpusubtype;
	uint32_t filetype;
	uint32_t ncmds;
	uint32_t sizeofcmds;
	uint32_t flags;
	uint32_t reserved;
};

struct load_command {
	uint32_t cmd;
	uint32_t cmdsize;
};

struct segment_command_64 {
	uint32_t cmd;
	uint32_t cmdsize;
	char segname[16];
	uint64_t vmaddr;
	uint64_t vmsize;
	uint64_t fileoff;
	uint64_t filesize;
	int32_t maxprot;
	int32_t initprot;
	uint32_t nsects;
	uint32_t flags;
};

struct section_64 {
	char sectname[16];
	char segname[16];
	uint64_t addr;
	uint64_t size;
	uint32_t offset;
	uint32_t align;
	uint32_t reloff;
	uint32_t nreloc;
	uint32_t flags;
	uint32_t reserved1;
	uint32_t reserved2;
	uint32_t reserved3;
};

struct symtab_command {
	uint32_t cmd;
	uint32_t cmdsize;
	uint32_t symoff;
	uint32_t nsyms;
	uint32_t stroff;
	uint32_t strsize;
};

struct nlist_64 {
	uint32_t n_strx;
	uint8_t n_type;
	uint8_t n_sect;
	uint16_t n_desc;
	uint64_t n_value;
};
} // namespace mach_o

using namespace dart::elf;

#ifdef _WIN32
static void* load_map_file(const char* path)
{
	HANDLE hFile = CreateFileA(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("\nCannot find %s\n", path);
		return NULL;
	}

	// because Dart API requires only snapshot buffer addresses (no relative access across snapshot),
	//   so we can just mapping a whole file and find address of snapshots
	HANDLE hMapFile = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (hMapFile == INVALID_HANDLE_VALUE)
		return NULL;

	// need RW because dart initialization need writing data in BSS
	void* mem = MapViewOfFile(hMapFile, FILE_MAP_COPY, 0, 0, 0);
	CloseHandle(hMapFile);

	CloseHandle(hFile);
	return mem;
}
#else
static void* load_map_file(const char* path)
{
	// need RW because dart initialization need writing data in BSS
	int fd = open(path, O_RDONLY);
	struct stat st;

	fstat(fd, &st);
	void* mem = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

	close(fd);
	return mem;
}
#endif

LibAppInfo ElfHelper::findSnapshots(const uint8_t* elf)
{
	const auto* hdr = (const ElfHeader*)elf;
	if (hdr->section_table_entry_size != sizeof(SectionHeader))
		throw std::invalid_argument("ELF: Invalid section entry size");

	const auto* section = (SectionHeader*)(elf + hdr->section_table_offset);
	const auto sh_num = hdr->num_section_headers;

	// find .dynstr and .dynsym sections, so we can map the section names
	const char* dynstr = nullptr;
	const Symbol* dynsym = nullptr;
	const Symbol* dynsym_end = nullptr;
	for (uint16_t i = 0; i < sh_num; i++, section++) {
		if (section->type == SectionHeaderType::SHT_STRTAB && dynstr == nullptr) {
			// we want only .dynstr for .dynsym
			const char* strtab = (const char*)elf + section->file_offset;
			const char* last = strtab + section->file_size;
			const char* s_first = kVmSnapshotDataAsmSymbol;
			const char* s_last = s_first + strlen(kVmSnapshotDataAsmSymbol) + 1;
			//if (memmem(strtab, section->s_size, kVmSnapshotDataAsmSymbol, strlen(kVmSnapshotDataAsmSymbol))) {
			if (std::search(strtab, last, s_first, s_last) != last) {
				// found it
				dynstr = strtab;
			}
		}
		if (section->type == SectionHeaderType::SHT_DYNSYM) {
			if (section->entry_size != sizeof(Symbol))
				throw std::invalid_argument("ELF: Invalid DYNSYM entry size");
			dynsym = (Symbol*)(elf + section->file_offset);
			dynsym_end = (Symbol*)(elf + section->file_offset + section->file_size);
		}
		if (dynsym != nullptr && dynstr != nullptr)
			break;
	}

	// find the required symbol addresses
	const uint8_t* vm_snapshot_data = nullptr;
	const uint8_t* vm_snapshot_instructions = nullptr;
	const uint8_t* isolate_snapshot_data = nullptr;
	const uint8_t* isolate_snapshot_instructions = nullptr;
	for (; dynsym < dynsym_end; dynsym++) {
		if (dynsym->info == 0)
			continue;

		const char* name = dynstr + dynsym->name;
		// Note: sym_size is no needed for dart VM (its blob contains size)
		if (strcmp(name, kVmSnapshotDataAsmSymbol) == 0) {
			vm_snapshot_data = elf + dynsym->value;
		}
		else if (strcmp(name, kVmSnapshotInstructionsAsmSymbol) == 0) {
			vm_snapshot_instructions = elf + dynsym->value;
		}
		else if (strcmp(name, kIsolateSnapshotDataAsmSymbol) == 0) {
			isolate_snapshot_data = elf + dynsym->value;
		}
		else if (strcmp(name, kIsolateSnapshotInstructionsAsmSymbol) == 0) {
			isolate_snapshot_instructions = elf + dynsym->value;
		}
	}

	if (vm_snapshot_data == nullptr)
		throw std::invalid_argument("ELF: Cannot find Dart VM Snapshot Data");
	if (vm_snapshot_instructions == nullptr)
		throw std::invalid_argument("ELF: Cannot find Dart VM Snapshot Instructions");
	if (isolate_snapshot_data == nullptr)
		throw std::invalid_argument("ELF: Cannot find Dart Isolate Snapshot Data");
	if (isolate_snapshot_instructions == nullptr)
		throw std::invalid_argument("ELF: Cannot find Dart Isolate Snapshot Instructions");

	return LibAppInfo{
		.lib = elf,
		.vm_snapshot_data = vm_snapshot_data,
		.vm_snapshot_instructions = vm_snapshot_instructions,
		.isolate_snapshot_data = isolate_snapshot_data,
		.isolate_snapshot_instructions = isolate_snapshot_instructions,
	};
}

static const uint8_t* macho_addr_to_ptr(const uint8_t* lib, const mach_o::segment_command_64* segments[64], uint32_t segment_count, uint64_t addr)
{
	for (uint32_t i = 0; i < segment_count; i++) {
		const auto* seg = segments[i];
		if (addr >= seg->vmaddr && addr < seg->vmaddr + seg->vmsize) {
			return lib + seg->fileoff + (addr - seg->vmaddr);
		}
	}
	return nullptr;
}

static LibAppInfo findSnapshotsMachO(const uint8_t* lib)
{
	const auto* header = (const mach_o::mach_header_64*)lib;
	if (header->magic != mach_o::MH_MAGIC_64)
		throw std::invalid_argument("Mach-O: Invalid magic header");

	const mach_o::symtab_command* symtab = nullptr;
	const mach_o::segment_command_64* segments[mach_o::MAX_SEGMENTS]{};
	uint32_t segment_count = 0;
	const uint8_t* lc_ptr = lib + sizeof(mach_o::mach_header_64);
	for (uint32_t i = 0; i < header->ncmds; i++) {
		const auto* lc = (const mach_o::load_command*)lc_ptr;
		if (lc->cmd == mach_o::LC_SYMTAB) {
			symtab = (const mach_o::symtab_command*)lc_ptr;
		}
		else if (lc->cmd == mach_o::LC_SEGMENT_64 && segment_count < mach_o::MAX_SEGMENTS) {
			segments[segment_count++] = (const mach_o::segment_command_64*)lc_ptr;
		}
		lc_ptr += lc->cmdsize;
	}

	if (symtab == nullptr)
		throw std::invalid_argument("Mach-O: Cannot find symbol table");

	const auto* symbols = (const mach_o::nlist_64*)(lib + symtab->symoff);
	const char* strings = (const char*)lib + symtab->stroff;
	const uint8_t* vm_snapshot_data = nullptr;
	const uint8_t* vm_snapshot_instructions = nullptr;
	const uint8_t* isolate_snapshot_data = nullptr;
	const uint8_t* isolate_snapshot_instructions = nullptr;

	for (uint32_t i = 0; i < symtab->nsyms; i++) {
		const auto& sym = symbols[i];
		if ((sym.n_type & mach_o::N_STAB) != 0 || (sym.n_type & mach_o::N_TYPE) != mach_o::N_SECT || sym.n_strx == 0 || sym.n_strx >= symtab->strsize)
			continue;

		const char* name = strings + sym.n_strx;
		const uint8_t* ptr = macho_addr_to_ptr(lib, segments, segment_count, sym.n_value);
		if (ptr == nullptr)
			continue;

		if (strcmp(name, kVmSnapshotDataAsmSymbol) == 0) {
			vm_snapshot_data = ptr;
		}
		else if (strcmp(name, kVmSnapshotInstructionsAsmSymbol) == 0) {
			vm_snapshot_instructions = ptr;
		}
		else if (strcmp(name, kIsolateSnapshotDataAsmSymbol) == 0) {
			isolate_snapshot_data = ptr;
		}
		else if (strcmp(name, kIsolateSnapshotInstructionsAsmSymbol) == 0) {
			isolate_snapshot_instructions = ptr;
		}
	}

	if (vm_snapshot_data == nullptr)
		throw std::invalid_argument("Mach-O: Cannot find Dart VM Snapshot Data");
	if (vm_snapshot_instructions == nullptr)
		throw std::invalid_argument("Mach-O: Cannot find Dart VM Snapshot Instructions");
	if (isolate_snapshot_data == nullptr)
		throw std::invalid_argument("Mach-O: Cannot find Dart Isolate Snapshot Data");
	if (isolate_snapshot_instructions == nullptr)
		throw std::invalid_argument("Mach-O: Cannot find Dart Isolate Snapshot Instructions");

	return LibAppInfo{
		.lib = lib,
		.vm_snapshot_data = vm_snapshot_data,
		.vm_snapshot_instructions = vm_snapshot_instructions,
		.isolate_snapshot_data = isolate_snapshot_data,
		.isolate_snapshot_instructions = isolate_snapshot_instructions,
	};
}

LibAppInfo ElfHelper::MapLibAppSo(const char* path)
{
	void* lib = load_map_file(path);
	uint8_t* elf = (uint8_t*)(lib);
	const auto* hdr = (ElfHeader*)elf;
	const auto* ident = (ElfIdent*)hdr->ident;
	if (memcmp(ident->ei_magic, "\x7f" "ELF", 4) == 0) {
		if (ident->ei_data != 1)
			throw std::invalid_argument("ELF: Support only little endian"); // expect little-endian

		if (ident->ei_class != ELFCLASS64) { // 1 is 32 bits, 2 is 64 bits
			throw std::invalid_argument("ELF: Support only 64 bits"); // support only 64 bits
		}
		return findSnapshots(elf);
	}

	const auto* macho_header = (const mach_o::mach_header_64*)lib;
	if (macho_header->magic == mach_o::MH_MAGIC_64) {
		return findSnapshotsMachO((const uint8_t*)lib);
	}

	throw std::invalid_argument("Unsupported file format: expected ELF or 64-bit little-endian Mach-O");
}
