#include "module.h"
#include <vector>
#include "binreader.h"

struct elf_header
{
	uint16_t type;
	uint16_t machine;
	uint32_t version;
	uint64_t entry;
	uint64_t phoff;
	uint64_t shoff;
	uint32_t flags;
	uint16_t ehsize;
	uint16_t phentsize;
	uint16_t phnum;
	uint16_t shentsize;
	uint16_t shnum;
	uint16_t shstrndx;
};

struct elf_section_header
{
	std::string name;
	uint32_t nameidx;
	uint32_t type;
	uint64_t flags;
	uint64_t addr;
	uint64_t offset;
	uint64_t size;
	uint32_t link;
	uint32_t info;
	uint64_t addralign;
	uint64_t entsize;
};

struct elf_sym
{
	std::string name;
	uint32_t nameidx;
	uint8_t info;
	uint8_t other;
	uint16_t shndx;
	uint64_t value;
	uint64_t size;
};

struct elf_reader
	: bin_reader
{
	elf_reader(file & f, file::offset_t offset, bool be, bool elf64)
		: bin_reader(f, offset, be), m_elf64(elf64)
	{
	}

	void readx(uint64_t & addr)
	{
		if (m_elf64)
			addr = this->read<uint64_t>();
		else
			addr = this->read<uint32_t>();
	}

private:
	bool m_elf64;
};

struct elf_loader
	: file
{
	explicit elf_loader(file & f)
		: m_file(f)
	{
	}

	void add_section(offset_t va, offset_t offset, size_t size)
	{
		m_sections[va] = std::make_pair(offset, size);
	}

	void read(offset_t va, uint8_t * buf, size_t size) override
	{
		auto it = m_sections.upper_bound(va);
		if (it == m_sections.begin())
			throw std::runtime_error("invalid va");
		--it;
		if (va - it->first + size > it->first + it->second.second)
			throw std::runtime_error("requested chunk is not contained in a section");
		m_file.read((va - it->first) + it->second.first, buf, size);
	}

	file & m_file;
	std::map<offset_t, std::pair<offset_t, size_t>> m_sections; 
};

module load_elf(file & fin)
{
	module r;

	uint8_t ident[4];
	fin.read(4, ident, sizeof ident);

	if (ident[0] != 1 && ident[0] != 2)
		throw std::runtime_error("unsupported ELF class");
	if (ident[1] != 1 && ident[1] != 2)
		throw std::runtime_error("unknown ELF data encoding");
	if (ident[1] != 1)
		throw std::runtime_error("unsupported ELF version");

	bool elf64 = ident[0] == 2;
	elf_reader br(fin, 16, /*be=*/ident[1] == 2, elf64);

	elf_header h;
	br.read(h.type);
	br.read(h.machine);
	br.read(h.version);
	br.readx(h.entry);
	br.readx(h.phoff);
	br.readx(h.shoff);
	br.read(h.flags);
	br.read(h.ehsize);
	br.read(h.phentsize);
	br.read(h.phnum);
	br.read(h.shentsize);
	br.read(h.shnum);
	br.read(h.shstrndx);

	switch (h.machine)
	{
	case 3: // EM_386
		r.arch = module::arch_t::x86;
		break;
	case 62: // EM_X86_64
		r.arch = module::arch_t::x86_64;
		break;
	default:
		throw std::runtime_error("unsupported architecture");
	}

	auto loader = std::make_shared<elf_loader>(fin);
	std::vector<elf_section_header> sections(h.shnum);
	for (size_t i = 0; i < sections.size(); ++i)
	{
		elf_section_header & sh = sections[i];
		br.seek(h.shoff + i*h.shentsize);

		br.read(sh.nameidx);
		br.read(sh.type);
		br.readx(sh.flags);
		br.readx(sh.addr);
		br.readx(sh.offset);
		br.readx(sh.size);
		br.read(sh.link);
		br.read(sh.info);
		br.readx(sh.addralign);
		br.readx(sh.entsize);

		if (sh.flags & 0x2 /*SHF_ALLOC*/)
			loader->add_section(sh.addr, sh.offset, sh.size);
	}
	r.loader = loader;

	if (h.shstrndx > sections.size())
		throw std::runtime_error("invalid string table index");

	auto load_string_table = [&](size_t sec, std::vector<char> & strtab) {
		if (sec == 0)
		{
			strtab.push_back(0);
			return;
		}

		if (sec >= sections.size())
			throw std::runtime_error("invalid string table index");
		if (sections[sec].type != 3 /*SHT_STRTAB*/)
			throw std::runtime_error("invalid string table section type");

		strtab.resize(sections[sec].size);
		fin.read(sections[sec].offset, (uint8_t *)strtab.data(), strtab.size());
		if (strtab[0] != 0 || strtab.back() != 0)
			throw std::runtime_error("corrupted string table section");
	};

	std::map<size_t, std::vector<char>> strtabs;
	auto get_string_table = [&](size_t sec) -> std::vector<char> const & {
		auto it = strtabs.find(sec);
		if (it == strtabs.end())
		{
			std::vector<char> strtab;
			load_string_table(sec, strtab);
			it = strtabs.insert(std::make_pair(sec, std::move(strtab))).first;
		}

		return it->second;
	};

	std::vector<char> const & string_table = get_string_table(h.shstrndx);
	for (auto && sec: sections)
	{
		if (sec.nameidx >= string_table.size())
			throw std::runtime_error("invalid section name");
		sec.name = string_table.data() + sec.nameidx;
	}


	std::vector<elf_sym> syms;
	for (auto && sec: sections)
	{
		if (sec.type != 2 /*SHT_SYMTAB*/)
			continue;

		if (elf64)
		{
			if (sec.entsize < 24)
				throw std::runtime_error("invalid symbol entry size");

			std::vector<char> const & strtab = get_string_table(sec.link);
			size_t entry_count = sec.size / sec.entsize;

			for (size_t i = 0; i < entry_count; ++i)
			{
				br.seek(sec.offset + i*sec.entsize);

				elf_sym sym;
				br.read(sym.nameidx);
				if (sym.nameidx >= strtab.size())
					throw std::runtime_error("invalid string table index");
				sym.name = strtab.data() + sym.nameidx;
				br.read(sym.info);
				br.read(sym.other);
				br.read(sym.shndx);
				br.readx(sym.value);
				br.readx(sym.size);

				if ((sym.info & 0xf) == 2 /*STT_FUNC*/)
				{
					module::sym s;
					s.name = sym.name;
					s.addr = sym.value;
					s.size = sym.size;
					r.syms[s.addr] = std::move(s);
				}

				syms.push_back(std::move(sym));
			}
		}
	}

	return r;
}
