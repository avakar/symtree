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

#include "find_refs.h"
#include "module.h"
#include "binreader.h"

void print_help(char const * argv0)
{
	std::cout <<
		"usage: " << argv0 << " [--sort {total|savings}] [--expand-saved] <filename>\n";
}

int _main(int argc, char *argv[])
{
	std::string input_fname;
	bool print_syms = false;
	bool help = false;
	enum class sort_kind { by_total, by_savings } sort = sort_kind::by_total;
	bool expand_saved = false;
	bool compute_savings = false;
	for (int i = 1; i < argc; ++i)
	{
		std::string arg = argv[i];
		if (arg == "-h" || arg == "--help")
		{
			help = true;
		}
		else if (arg == "--sort")
		{
			if (i + 1 == argc || (strcmp(argv[i+1], "total") != 0 && strcmp(argv[i+1], "savings") != 0))
			{
				std::cerr << "error: --sort expects one of 'total' or 'savings'\n";
				return 2;
			}

			if (strcmp(argv[++i], "savings") == 0)
				sort = sort_kind::by_savings;
		}
		else if (arg == "--expand-saved")
		{
			expand_saved = true;
		}
		else if (arg == "--compute-savings")
		{
			compute_savings = true;
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

	if (help || input_fname.empty())
	{
		print_help(argv[0]);
		return 0;
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
		uint64_t size_savings;
		std::set<sym_node_t *> callees;
		std::set<sym_node_t *> callers;
		std::set<sym_node_t *> saved;
	};

	size_t total_size = 0;
	std::map<uint64_t, sym_node_t> syms;
	std::set<sym_node_t *> all_syms;
	for (auto && sym: mod.syms)
	{
		if (sym.second.size != 0)
		{
			auto & new_sym = syms[sym.first];
			new_sym.sym = &sym.second;
			new_sym.size_savings = 0;
			total_size += sym.second.size;
			all_syms.insert(&new_sym);
		}
	}

	std::cerr << "total symbol size: " << total_size << "\n";

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
			{
				sym.callees.insert(&callee);
				callee.callers.insert(&sym);
			}
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

		switch (mod.arch)
		{
		case module::arch_t::x86:
			find_refs_x86(sym.sym->addr, /*x64=*/false, buf, reference);
			break;
		case module::arch_t::x86_64:
			find_refs_x86(sym.sym->addr, /*x64=*/true, buf, reference);
			break;
		case module::arch_t::arm32:
			find_refs_arm32(sym.sym->addr, buf, reference);
			break;
		default:
			throw std::runtime_error("unsupported architecture");
		}

	}

	std::set<sym_node_t *> roots;
	for (auto && kv: syms)
	{
		if (kv.second.callers.empty())
			roots.insert(&kv.second);
	}

	if (compute_savings)
	{
		for (auto && kv: syms)
		{
			sym_node_t & blacklist = kv.second;

			std::set<sym_node_t *> visited = roots;
			visited.erase(&blacklist);

			std::deque<sym_node_t *> q(visited.begin(), visited.end());
			while (!q.empty())
			{
				auto cur = q.front();
				q.pop_front();

				for (auto callee: cur->callees)
				{
					if (callee == &blacklist)
						continue;

					if (visited.find(callee) != visited.end())
						continue;
					visited.insert(callee);
					q.push_back(callee);
				}
			}

			std::set_difference(all_syms.begin(), all_syms.end(), visited.begin(), visited.end(), std::inserter(blacklist.saved, blacklist.saved.begin()));

			blacklist.size_savings = 0;
			for (auto && sym: blacklist.saved)
				blacklist.size_savings += sym->sym->size;
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

	auto sort_syms = [&](std::vector<sym_node_t *> & syms) {
		switch (sort)
		{
		case sort_kind::by_savings:
			std::sort(syms.begin(), syms.end(), [](auto lhs, auto rhs) {
				return lhs->size_savings > rhs->size_savings;
			});
			break;
		case sort_kind::by_total:
			std::sort(syms.begin(), syms.end(), [](auto lhs, auto rhs) {
				return lhs->reachable_size > rhs->reachable_size;
			});
			break;
		}
	};

	std::vector<sym_node_t *> sorted_syms;
	for (auto && kv: syms)
		sorted_syms.push_back(&kv.second);
	sort_syms(sorted_syms);

	for (auto && func: sorted_syms)
	{
		std::cout << std::hex << std::setw(8) << std::setfill('0') << func->sym->addr << " " << std::dec << func->sym->size << " " << func->reachable_size << " " << func->size_savings;
		if (func->callers.empty())
			std::cout << " %root";
		std::cout << " " << func->sym->name;
		if (!func->sym->fname.empty())
			std::cout << " " << func->sym->fname << ":" << func->sym->lineno;
		std::cout << "\n";

		if (expand_saved)
		{
			std::vector<sym_node_t *> sorted_saved(func->saved.begin(), func->saved.end());
			std::sort(sorted_saved.begin(), sorted_saved.end(), [](auto lhs, auto rhs) {
				return lhs->sym->size > rhs->sym->size;
			});

			for (auto && saved: sorted_saved)
				std::cout << "    " << std::hex << std::setw(8) << std::setfill('0') << saved->sym->addr << " " <<  std::dec << saved->sym->size << " " << saved->reachable_size << " " << saved->size_savings << " %saved " << saved->sym->name << "\n";
		}

		std::vector<sym_node_t *> callees;
		callees.assign(func->callees.begin(), func->callees.end());
		sort_syms(callees);

		for (auto && callee: callees)
			std::cout << "    " << std::hex << std::setw(8) << std::setfill('0') << callee->sym->addr << " " <<  std::dec << callee->sym->size << " " << callee->reachable_size << " " << callee->size_savings << " " << callee->sym->name << "\n";
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
