#include <atlbase.h>
#include <dia2.h>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <vector>
#include <deque>
#include <string>
#include <map>
#include <set>
#include <assert.h>
#include <algorithm>

#include "distorm/include/distorm.h"

struct file
{
	typedef uint64_t offset_t;
	virtual void read(offset_t offset, uint8_t * buf, size_t size) = 0;

	template <typename T>
	void read(offset_t offset, T & buf)
	{
		this->read(offset, (uint8_t *)&buf, sizeof buf);
	}

	template <typename T>
	void read_multi(offset_t offset, T * buf, size_t count)
	{
		this->read(offset, (uint8_t *)buf, count * sizeof(T));
	}

protected:
	~file() = default;
};

struct istream_file
	: file
{
	explicit istream_file(std::istream & fin)
		: m_fin(&fin)
	{
	}

	void read(offset_t offset, uint8_t * buf, size_t size) override
	{
		m_fin->seekg(offset);
		m_fin->read((char *)buf, size);
	}

	std::istream * m_fin;
};

struct pe_file
{
	typedef uint64_t va_t;

	va_t entry() const { return m_entry_point; }
	va_t base() const { return m_image_base; }

	void load(file & fin)
	{
		m_fin = &fin;

		IMAGE_DOS_HEADER dos_header;
		fin.read(0, dos_header);

		if (dos_header.e_magic != IMAGE_DOS_SIGNATURE)
			throw std::runtime_error("not a PE file");

		IMAGE_NT_HEADERS32 header;
		fin.read(dos_header.e_lfanew, header);

		if (header.Signature != IMAGE_NT_SIGNATURE)
			throw std::runtime_error("not a PE file");

		m_image_base = header.OptionalHeader.ImageBase;
		m_entry_point = header.OptionalHeader.AddressOfEntryPoint + m_image_base;

		m_raw_sections.resize(header.FileHeader.NumberOfSections);
		file::offset_t section_table_offs = dos_header.e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + header.FileHeader.SizeOfOptionalHeader;
		fin.read_multi(section_table_offs, m_raw_sections.data(), m_raw_sections.size());

		for (size_t i = 0; i < m_raw_sections.size(); ++i)
			m_section_map[m_image_base + m_raw_sections[i].VirtualAddress] = i;
	}

	void load(va_t addr, uint8_t * buf, size_t size)
	{
		auto secit = m_section_map.upper_bound(addr);
		if (secit == m_section_map.begin())
			throw std::runtime_error("access violation");
		--secit;
		size_t sec_offset = addr - m_raw_sections[secit->second].VirtualAddress - m_image_base;
		m_fin->read(m_raw_sections[secit->second].PointerToRawData + sec_offset, buf, size);
	}

	file * m_fin;
	va_t m_image_base;
	va_t m_entry_point;
	std::map<va_t, size_t> m_section_map;
	std::vector<IMAGE_SECTION_HEADER> m_raw_sections;
};

struct hrchecker
{
	hrchecker(char const * file, int line, bool sok, bool invert)
		: file(file), line(line), sok(sok), invert(invert)
	{
	}

	hrchecker operator!() const
	{
		return hrchecker(file, line, sok, !invert);
	}

	bool operator%(HRESULT hr) const
	{
		if ((sok && hr != S_OK) || FAILED(hr))
		{
			std::ostringstream oss;
			oss << file << "(" << line << "): error: hresult 0x" << std::hex << std::setprecision(8) << hr;
			throw std::runtime_error(oss.str());
		}

		return (hr == S_OK) != invert;
	}

	char const * file;
	int line;
	bool sok;
	bool invert;
};

#define hrchk hrchecker(__FILE__, __LINE__, false, false) %
#define hrsok hrchecker(__FILE__, __LINE__, true, false) %

static std::string to_utf8(wchar_t const * src)
{
	char tmp[16 * 1024];
	size_t len;
	wcstombs_s(&len, tmp, src, sizeof tmp);
	return std::string(tmp);
}

static std::wstring to_utf16(std::string const & s)
{
	int len = MultiByteToWideChar(CP_ACP, 0, s.data(), s.size(), 0, 0);

	std::vector<wchar_t> res;
	res.resize(len);
	len = MultiByteToWideChar(CP_ACP, 0, s.data(), s.size(), res.data(), res.size());

	return std::wstring(res.data(), len);
}

struct print_symbol_ctx_t
{
	std::set<uint32_t> visited;
};

std::string get_loc(IDiaSymbol * sym)
{
	static char const * const loc_names[] = {
		"Null",
		"Static",
		"TLS",
		"RegRel",
		"ThisRel",
		"Enregistered",
		"BitField",
		"Slot",
		"IlRel",
		"InMetaData",
		"Constant",
	};

	std::stringstream ss;

	DWORD loctype;
	hrchk sym->get_locationType(&loctype);
	ss << loc_names[loctype] << ":";

	DWORD sec, offs;
	if (hrchk sym->get_addressSection(&sec) && hrchk sym->get_addressOffset(&offs))
		ss << std::hex << sec << ":" << offs << ":";

	uint64_t len;
	hrchk sym->get_length(&len);
	ss << std::hex << len;

	return ss.str();
}

std::string format_type(IDiaSymbol * type)
{
	static char const * const basic_names[] = {
		"NoType",
		"Void",
		"Char",
		"WChar",
		"(unk:4)",
		"(unk:5)",
		"Int",
		"UInt",
		"Float",
		"BCD",
		"Bool",
		"(unk:11)",
		"(unk:12)",
		"Long",
		"ULong",
		"(unk:15)",
		"(unk:16)",
		"(unk:17)",
		"(unk:18)",
		"(unk:19)",
		"(unk:20)",
		"(unk:21)",
		"(unk:22)",
		"(unk:23)",
		"(unk:24)",
		"Currency",
		"Date",
		"Variant",
		"Complex",
		"Bit",
		"BSTR",
		"Hresult",
		"Char16",
		"Char32",
	};

	DWORD typetag;
	hrchk type->get_symTag(&typetag);

	switch (typetag)
	{
	case SymTagFunctionType:
		{
			CComPtr<IDiaSymbol> result_type;
			hrsok type->get_type(&result_type);
			std::string res = format_type(result_type);
			res.append("(");

			CComPtr<IDiaEnumSymbols> args;
			hrchk type->findChildren(SymTagNull, 0, 0, &args);

			bool first = true;

			CComPtr<IDiaSymbol> class_parent;
			if (type->get_classParent(&class_parent) == S_OK)
			{
				res.append(format_type(class_parent));
				res.append("*");
				first = false;
			}

			ULONG celt;
			CComPtr<IDiaSymbol> arg;
			while (SUCCEEDED(args->Next(1, &arg, &celt)) && celt == 1)
			{
				CComPtr<IDiaSymbol> arg_type;
				hrsok arg->get_type(&arg_type);

				if (!first)
					res.append(",");
				first = false;

				res.append(format_type(arg_type));
				arg.Release();
			}

			res.append(")");

			return res;
		}

	case SymTagPointerType:
		{
			CComPtr<IDiaSymbol> nested_type;
			hrsok type->get_type(&nested_type);
			return format_type(nested_type) + "*";
		}
		break;

	case SymTagTypedef:
		{
			CComPtr<IDiaSymbol> nested_type;
			hrsok type->get_type(&nested_type);
			return format_type(nested_type);
		}
		break;

	case SymTagEnum:
		{
			CComBSTR name;
			hrsok type->get_name(&name);
			std::string res = "enum(";
			res.append(to_utf8(name.m_str));
			res.append(")");
			return res;
		}
		break;

	case SymTagUDT:
		{
			CComBSTR name;
			hrsok type->get_name(&name);
			return "struct(" + to_utf8(name.m_str) + ")";
		}
		break;

	case SymTagArrayType:
		{
			DWORD len;
			hrsok type->get_count(&len);

			CComPtr<IDiaSymbol> nested_type;
			hrsok type->get_type(&nested_type);

			std::string nested = format_type(nested_type);
			char tmp[32];
			sprintf_s(tmp, "[%d]", len);

			return nested + tmp;
		}
		break;

	case SymTagBaseType:
	{
		DWORD baseType;
		hrsok type->get_baseType(&baseType);
		return baseType < std::size(basic_names)? basic_names[baseType]: "(unktype)";
	}
	default:
		return "(unktype)";
	}
}

std::string get_type(IDiaSymbol * sym)
{
	CComPtr<IDiaSymbol> type;
	hrchk sym->get_type(&type);

	if (!type)
		return "(notype)";

	return format_type(type);
}

void print_symbol_impl(print_symbol_ctx_t & ctx, IDiaSymbol * sym, size_t indent)
{
	static char const * const tag_names[] = {
		"Null",
		"Exe",
		"Compiland",
		"CompilandDetails",
		"CompilandEnv",
		"Function",
		"Block",
		"Data",
		"Annotation",
		"Label",
		"PublicSymbol",
		"UDT",
		"Enum",
		"FunctionType",
		"PointerType",
		"ArrayType",
		"BaseType",
		"Typedef",
		"BaseClass",
		"Friend",
		"FunctionArgType",
		"FuncDebugStart",
		"FuncDebugEnd",
		"UsingNamespace",
		"VTableShape",
		"VTable",
		"Custom",
		"Thunk",
		"CustomType",
		"ManagedType",
		"Dimension",
		"CallSite",
		"InlineSite",
		"BaseInterface",
		"VectorType",
		"MatrixType",
		"HLSLType",
		"Caller",
		"Callee",
		"Export",
		"HeapAllocationSite",
		"CoffGroup",
		"Max",
	};

	DWORD tag;
	hrchk sym->get_symTag(&tag);

	CComBSTR name;
	sym->get_name(&name);

	uint64_t addr, size;
	hrchk sym->get_virtualAddress(&addr);
	hrchk sym->get_length(&size);

	DWORD id, parent_id;
	hrchk sym->get_symIndexId(&id);

	bool seen = (ctx.visited.find(id) != ctx.visited.end());

	for (size_t i = 0; i < indent; ++i)
		std::cout << "    ";

	std::cout << (seen? "&": "") << tag_names[tag] << "(" << id << ") " << get_loc(sym) << " " << get_type(sym) << " " << (name? to_utf8(name): "(null)");

	uint64_t excHandler;
	if (hrchk sym->get_exceptionHandlerVirtualAddress(&excHandler))
		std::cout << "exc:" << std::hex << excHandler;

	std::cout << '\n';

	if (!seen)
	{
		ctx.visited.insert(id);

		CComPtr<IDiaEnumSymbols> sym_enum;
		hrchk sym->findChildrenEx(SymTagNull, NULL, nsNone, &sym_enum);
		if (!sym_enum)
			return;

		for (;;)
		{
			CComPtr<IDiaSymbol> child;
			ULONG cnt;
			if (!(hrchk sym_enum->Next(1, &child, &cnt)))
				break;

			print_symbol_impl(ctx, child, indent + 1);
		}
	}
}

void print_symbol(IDiaSymbol * sym)
{
	print_symbol_ctx_t ctx;
	print_symbol_impl(ctx, sym, 0);
}

void print_help(char const * argv0)
{
	std::cout <<
		"usage: " << argv0 << " <filename>\n";
}

int _main(int argc, char *argv[])
{
	std::string input_fname;
	bool help = false;
	for (int i = 1; i < argc; ++i)
	{
		std::string arg = argv[i];
		if (arg == "-h" || arg == "--help")
		{
			help = true;
		}
		else
		{
			if (!input_fname.empty())
			{
				std::cerr << "error: multiple input files\n";
				return 2;
			}

			input_fname = std::move(arg);
		}
	}

	if (help)
	{
		print_help(argv[0]);
		return 0;
	}

	if (input_fname.empty())
	{
		std::cerr << "error: no input files\n";
		return 2;
	}

	std::ifstream fin(argv[1], std::ios::binary);
	istream_file fin_file(fin);

	pe_file pe;
	pe.load(fin_file);

	hrchk CoInitialize(0);

	CComPtr<IDiaDataSource> source;
	{
		HRESULT hr = CoCreateInstance(CLSID_DiaSource, NULL, CLSCTX_INPROC_SERVER, __uuidof(IDiaDataSource), (void **)&source);
		if (hr == REGDB_E_CLASSNOTREG)
		{
			std::cerr << "error: DIA SDK is not installed\n";
			return 1;
		}

		hrchk hr;
	}

	{
		HRESULT hr = source->loadDataForExe(to_utf16(argv[1]).c_str(), 0, 0);
		if (hr == E_PDB_NOT_FOUND)
		{
			std::cerr << "error: failed to open file or its associated PDB: " << argv[1]<< std::endl;
			return 3;
		}
		hrchk hr;
	}

	CComPtr<IDiaSession> session;
	hrchk source->openSession(&session);

	hrchk session->put_loadAddress(pe.base());

	CComPtr<IDiaSymbol> global_scope;
	hrchk session->get_globalScope(&global_scope);

	//print_symbol(global_scope);

	CComPtr<IDiaEnumSymbols> sym_enum;
	hrchk global_scope->findChildrenEx(SymTagFunction, NULL, nsNone, &sym_enum);

	struct func_node_t
	{
		uint64_t start_addr;
		uint64_t end_addr;
		std::string name;
		uint64_t reachable_size;
		std::set<func_node_t *> callees;
	};

	std::map<uint64_t, func_node_t> funcs;

	for (;;)
	{
		CComPtr<IDiaSymbol> child;
		ULONG cnt;
		if (!(hrchk sym_enum->Next(1, &child, &cnt)))
			break;

		CComBSTR name;
		hrchk child->get_name(&name);

		func_node_t fn;
		hrchk child->get_virtualAddress(&fn.start_addr);
		hrchk child->get_length(&fn.end_addr);
		fn.end_addr += fn.start_addr;
		fn.name = to_utf8(name);

		funcs[fn.start_addr] = fn;
	}

	std::vector<uint8_t> buf;
	for (auto && kv: funcs)
	{
		func_node_t & fn = kv.second;
		auto reference = [&](uint64_t addr) {
			auto it = funcs.upper_bound(addr);
			if (it == funcs.begin())
				return;
			--it;
			func_node_t & callee = it->second;
			if (callee.start_addr > addr || addr >= callee.end_addr)
				return;
			if (&callee != &fn)
				fn.callees.insert(&callee);
		};

		buf.resize(fn.end_addr - fn.start_addr);
		pe.load(fn.start_addr, buf.data(), fn.end_addr - fn.start_addr);

		_CodeInfo ci = {};
		ci.code = buf.data();
		ci.nextOffset = ci.codeOffset = fn.start_addr;
		ci.codeLen = buf.size();
		ci.dt = Decode32Bits;

		while (ci.codeLen)
		{
			_DInst insts[16];
			unsigned int used_insts;
			distorm_decompose(&ci, insts, 16, &used_insts);

			ci.codeLen -= ci.nextOffset - ci.codeOffset;
			ci.code += ci.nextOffset - ci.codeOffset;
			ci.codeOffset = ci.nextOffset;

			for (size_t i = 0; i < used_insts; ++i)
			{
				_DInst const & inst = insts[i];
				for (auto && op: inst.ops)
				{
					switch (op.type)
					{
					case O_IMM:
						reference(inst.imm.sqword);
						break;
					case O_PC:
						reference(inst.imm.addr + inst.addr + inst.size);
						break;
					case O_PTR:
						reference(inst.imm.ptr.off);
						break;
					}
				}
			}
		}
	}

	for (auto && kv: funcs)
	{
		std::set<func_node_t *> visited = { &kv.second };
		std::deque<func_node_t *> q = { &kv.second };
		while (!q.empty())
		{
			auto cur = q.front();
			q.pop_front();

			for (auto callee: cur->callees)
			{
				if (visited.find(callee) != visited.end())
					continue;
				visited.insert(callee);
				q.push_back(callee);
			}
		}

		uint64_t total_size = 0;
		for (auto fn: visited)
			total_size += (fn->end_addr - fn->start_addr);
		kv.second.reachable_size = total_size;
	}

	std::vector<func_node_t *> sorted_funcs;
	for (auto && kv: funcs)
		sorted_funcs.push_back(&kv.second);
	std::sort(sorted_funcs.begin(), sorted_funcs.end(), [](auto lhs, auto rhs) {
		return lhs->reachable_size > rhs->reachable_size;
	});

	for (auto && func: sorted_funcs)
	{
		std::cout << std::hex << func->start_addr << " " << func->name << " " << std::dec << (func->end_addr - func->start_addr) << " " << func->reachable_size << "\n";

		std::vector<func_node_t *> callees;
		callees.assign(func->callees.begin(), func->callees.end());
		std::sort(callees.begin(), callees.end(), [](auto lhs, auto rhs) {
			return lhs->reachable_size > rhs->reachable_size;
		});

		for (auto && callee: callees)
			std::cout << "    " << std::hex << callee->start_addr << " " <<  std::dec << (callee->end_addr - callee->start_addr) << " " << callee->reachable_size << " " << callee->name << "\n";
	}

	return 0;
}

int main(int argc, char *argv[])
{
	try
	{
		return _main(argc, argv);
	}
	catch (std::exception const & e)
	{
		std::cerr << e.what() << std::endl;
		return 2;
	}
}
