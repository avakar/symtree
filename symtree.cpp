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

	struct func_node_t
	{
		func_node_t()
			: sym(nullptr), reachable_size(0)
		{
		}

		module::sym * sym;
		uint64_t reachable_size;
		std::set<func_node_t *> callees;
	};

	std::map<uint64_t, func_node_t> funcs;
	for (auto && sym: mod.syms)
	{
		if (sym.second.size != 0)
			funcs[sym.first].sym = &sym.second;
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
			if (callee.sym->addr > addr || addr >= callee.sym->addr + callee.sym->size)
				return;
			if (&callee != &fn)
				fn.callees.insert(&callee);
		};

		buf.resize(fn.sym->size);
		mod.loader->read(fn.sym->addr, buf.data(), fn.sym->size);

		_CodeInfo ci = {};
		ci.code = buf.data();
		ci.nextOffset = ci.codeOffset = fn.sym->addr;
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
			total_size += fn->sym->size;
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
		std::cout << std::hex << func->sym->addr << " " << func->sym->name << " " << std::dec << func->sym->size << " " << func->reachable_size << "\n";

		std::vector<func_node_t *> callees;
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
