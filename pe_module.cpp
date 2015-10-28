#include "module.h"
#include <vector>
#include <sstream>
#include <iomanip>
#include <windows.h>
#include <dia2.h>
#include <atlbase.h>
#include <set>
#include "hrchk.h"
#include "utf.h"
#include "binreader.h"

struct pe_file
	: file
{
	typedef uint64_t va_t;

	pe_file()
		: m_arch(module::arch_t::unknown)
	{
	}

	uint64_t base() const { return m_image_base; }

	void load(file & fin)
	{
		m_fin = &fin;

		bin_reader br(fin, 0, /*be=*/false);

		if (br.read_at<uint16_t>(0) != IMAGE_DOS_SIGNATURE)
			throw std::runtime_error("not a PE file");

		auto peoffs = br.read_at<uint32_t>(60);

		if (br.read_at<uint32_t>(peoffs) != IMAGE_NT_SIGNATURE)
			throw std::runtime_error("not a PE file");

		IMAGE_FILE_HEADER fh;
		br % fh.Machine % fh.NumberOfSections % fh.TimeDateStamp
			% fh.PointerToSymbolTable % fh.NumberOfSymbols % fh.SizeOfOptionalHeader
			% fh.Characteristics;

		switch (fh.Machine)
		{
		case 0x014c:
			m_arch = module::arch_t::x86;
			break;
		case 0x8664:
			m_arch = module::arch_t::x86_64;
			break;
		default:
			throw std::runtime_error("unsupported architecture");
		}

		switch (br.read<uint16_t>())
		{
		case 0x10b:
			br.skip(26);
			m_image_base = br.read<uint32_t>();
			break;
		case 0x20b:
			br.skip(26);
			m_image_base = br.read<uint64_t>();
			break;
		default:
			throw std::runtime_error("unsupported PE type");
		}

		file::offset_t section_table_offs = peoffs + 4 + sizeof(IMAGE_FILE_HEADER) + fh.SizeOfOptionalHeader;
		br.seek(section_table_offs);

		m_raw_sections.resize(fh.NumberOfSections);
		for (auto && sec: m_raw_sections)
		{
			br % sec.Name % sec.Misc.VirtualSize % sec.VirtualAddress % sec.SizeOfRawData
				% sec.PointerToRawData % sec.PointerToRelocations % sec.PointerToLinenumbers
				% sec.NumberOfRelocations % sec.NumberOfLinenumbers % sec.Characteristics;
		}

		for (size_t i = 0; i < m_raw_sections.size(); ++i)
			m_section_map[m_image_base + m_raw_sections[i].VirtualAddress] = i;
	}

	void read(offset_t addr, uint8_t * buf, size_t size) override
	{
		auto secit = m_section_map.upper_bound(addr);
		if (secit == m_section_map.begin())
			throw std::runtime_error("access violation");
		--secit;
		size_t sec_offset = addr - m_raw_sections[secit->second].VirtualAddress - m_image_base;
		m_fin->read(m_raw_sections[secit->second].PointerToRawData + sec_offset, buf, size);
	}

	file * m_fin;
	uint64_t m_image_base;
	std::map<va_t, size_t> m_section_map;
	std::vector<IMAGE_SECTION_HEADER> m_raw_sections;
	module::arch_t m_arch;
};

module load_pe(std::string const & fname, file & fin)
{
	auto loader = std::make_shared<pe_file>();
	loader->load(fin);

	hrchk CoInitialize(0);

	CComPtr<IDiaDataSource> source;
	{
		HRESULT hr = CoCreateInstance(CLSID_DiaSource, NULL, CLSCTX_INPROC_SERVER, __uuidof(IDiaDataSource), (void **)&source);
		if (hr == REGDB_E_CLASSNOTREG)
			throw std::runtime_error("DIA SDK is not installed");
		hrchk hr;
	}

	{
		HRESULT hr = source->loadDataForExe(to_utf16(fname).c_str(), 0, 0);
		if (hr == E_PDB_NOT_FOUND)
			throw std::runtime_error("failed to open file or its associated PDB");
		hrchk hr;
	}

	CComPtr<IDiaSession> session;
	hrchk source->openSession(&session);
	hrchk session->put_loadAddress(loader->base());

	CComPtr<IDiaSymbol> global_scope;
	hrchk session->get_globalScope(&global_scope);

	CComPtr<IDiaEnumSymbols> sym_enum;
	hrchk global_scope->findChildrenEx(SymTagFunction, NULL, nsNone, &sym_enum);

	module m;
	for (;;)
	{
		CComPtr<IDiaSymbol> child;
		ULONG cnt;
		if (!(hrchk sym_enum->Next(1, &child, &cnt)))
			break;

		CComBSTR name;
		hrchk child->get_name(&name);

		module::sym sym;
		sym.name = to_utf8(name);
		hrchk child->get_virtualAddress(&sym.addr);
		hrchk child->get_length(&sym.size);

		m.syms[sym.addr] = std::move(sym);
	}

	m.arch = module::arch_t::x86;
	m.loader = loader;
	return m;
}
