#ifndef SYMTREE_HRCHK_H
#define SYMTREE_HRCHK_H

#include <Windows.h>
#include <sstream>
#include <iomanip>

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

#endif
