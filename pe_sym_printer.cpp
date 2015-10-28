#include <atlbase.h>
#include <dia2.h>
#include <set>
#include <string>
#include "hrchk.h"
#include "utf.h"

struct print_symbol_ctx_t
{
	std::ostream & out;
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

	DWORD id;
	hrchk sym->get_symIndexId(&id);

	bool seen = (ctx.visited.find(id) != ctx.visited.end());

	for (size_t i = 0; i < indent; ++i)
		ctx.out << "    ";

	ctx.out << (seen? "&": "") << tag_names[tag] << "(" << id << ") " << get_loc(sym) << " " << get_type(sym) << " " << (name? to_utf8(name): "(null)");

	uint64_t excHandler;
	if (hrchk sym->get_exceptionHandlerVirtualAddress(&excHandler))
		ctx.out << "exc:" << std::hex << excHandler;

	ctx.out << '\n';

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

void pe_print_symbols(std::ostream & out, IDiaSymbol * sym)
{
	print_symbol_ctx_t ctx = { out };
	print_symbol_impl(ctx, sym, 0);
}
