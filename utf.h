#ifndef SYMTREE_UTF_H
#define SYMTREE_UTF_H

#include <string>
#include <vector>
#include <Windows.h>

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

#endif // SYMTREE_UTF_H
