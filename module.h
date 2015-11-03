#ifndef SYMTREE_MODULE_H
#define SYMTREE_MODULE_H

#include "file.h"
#include <stdint.h>
#include <map>
#include <memory>
#include <functional>

struct module
{
	enum class type_t
	{
		data,
		function,
	};

	struct sym
	{
		std::string name;
		uint64_t addr;
		uint64_t size;
		type_t type;

		std::string fname;
		int32_t lineno;
	};

	enum class arch_t
	{
		unknown,
		x86,
		x86_64,
		arm32,
	};

	arch_t arch;
	std::shared_ptr<file> loader;
	std::map<uint64_t, sym> syms;
	std::function<void (std::ostream &)> sym_printer;
};

module load_elf(file & fin);
module load_pe(std::string const & fname, file & fin);

module load_autodetect(file & fin);

#endif // SYMTREE_MODULE_H
