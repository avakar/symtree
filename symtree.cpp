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
#include <array>
#include <memory>

#include "distorm/include/distorm.h"

#include "module.h"
#include "binreader.h"

void print_help(char const * argv0)
{
	std::cout <<
		"usage: " << argv0 << " <filename>\n";
}

int _main(int argc, char *argv[])
{
	std::string input_fname;
	bool print_syms = false;
	bool help = false;
	for (int i = 1; i < argc; ++i)
	{
		std::string arg = argv[i];
		if (arg == "-h" || arg == "--help")
		{
			help = true;
		}
		else if (arg == "--print-syms")
		{
			print_syms = true;
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

	std::ifstream fin(input_fname, std::ios::binary);
	istream_file fin_file(fin);

	std::array<uint8_t, 4> magic;
	fin_file.read(0, magic.data(), magic.size());

	module mod;
	if (magic == std::array<uint8_t, 4>{ 0x7f, 'E', 'L', 'F' })
	{
		mod = load_elf(fin_file);
	}
	else
	{
		mod = load_pe(input_fname, fin_file);
	}

	if (print_syms)
	{
		mod.sym_printer(std::cout);
		return 0;
	}

	struct sym_node_t
	{
		sym_node_t()
			: sym(nullptr), reachable_size(0)
		{
		}

		module::sym * sym;
		uint64_t reachable_size;
		std::set<sym_node_t *> callees;
	};

	std::map<uint64_t, sym_node_t> syms;
	for (auto && sym: mod.syms)
	{
		if (sym.second.size != 0)
			syms[sym.first].sym = &sym.second;
	}

	std::vector<uint8_t> buf;
	for (auto && kv: syms)
	{
		sym_node_t & sym = kv.second;
		auto reference = [&](uint64_t addr) {
			auto it = syms.upper_bound(addr);
			if (it == syms.begin())
				return;
			--it;
			sym_node_t & callee = it->second;
			if (callee.sym->addr > addr || addr >= callee.sym->addr + callee.sym->size)
				return;
			if (&callee != &sym)
				sym.callees.insert(&callee);
		};

		buf.resize(sym.sym->size);
		mod.loader->read(sym.sym->addr, buf.data(), sym.sym->size);

		if (sym.sym->type == module::type_t::data)
		{
			switch (mod.arch)
			{
			case module::arch_t::x86:
				if (sym.sym->addr % 4 == 0 && sym.sym->size % 4 == 0)
				{
					size_t cnt = buf.size() / 4;
					uint8_t const * p = buf.data();
					for (size_t i = 0; i < cnt; ++i)
					{
						reference(bin_reader::load_le<uint32_t>(p));
						p += 4;
					}
				}
				break;
			case module::arch_t::x86_64:
				if (sym.sym->addr % 8 == 0 && sym.sym->size % 8 == 0)
				{
					size_t cnt = buf.size() / 8;
					uint8_t const * p = buf.data();
					for (size_t i = 0; i < cnt; ++i)
					{
						reference(bin_reader::load_le<uint64_t>(p));
						p += 8;
					}
				}
				break;
			}
			continue;
		}

		_CodeInfo ci = {};
		ci.code = buf.data();
		ci.nextOffset = ci.codeOffset = sym.sym->addr;
		ci.codeLen = buf.size();
		switch (mod.arch)
		{
		case module::arch_t::x86:
			ci.dt = Decode32Bits;
			break;
		case module::arch_t::x86_64:
			ci.dt = Decode64Bits;
			break;
		default:
			throw std::runtime_error("unsupported architecture");
		}

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

	for (auto && kv: syms)
	{
		std::set<sym_node_t *> visited = { &kv.second };
		std::deque<sym_node_t *> q = { &kv.second };
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
			total_size += fn->sym->size;
		kv.second.reachable_size = total_size;
	}

	std::vector<sym_node_t *> sorted_syms;
	for (auto && kv: syms)
		sorted_syms.push_back(&kv.second);
	std::sort(sorted_syms.begin(), sorted_syms.end(), [](auto lhs, auto rhs) {
		return lhs->reachable_size > rhs->reachable_size;
	});

	for (auto && func: sorted_syms)
	{
		std::cout << std::hex << func->sym->addr << " " << func->sym->name << " " << std::dec << func->sym->size << " " << func->reachable_size << "\n";

		std::vector<sym_node_t *> callees;
		callees.assign(func->callees.begin(), func->callees.end());
		std::sort(callees.begin(), callees.end(), [](auto lhs, auto rhs) {
			return lhs->reachable_size > rhs->reachable_size;
		});

		for (auto && callee: callees)
			std::cout << "    " << std::hex << callee->sym->addr << " " <<  std::dec << callee->sym->size << " " << callee->reachable_size << " " << callee->sym->name << "\n";
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
