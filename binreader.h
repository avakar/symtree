#ifndef SYMTREE_BINREADER_H
#define SYMTREE_BINREADER_H

#include "file.h"

struct bin_reader
{
	bin_reader(file & f, file::offset_t offset, bool be)
		: m_f(f), m_offset(offset), m_be(be)
	{
	}

	template <typename T>
	T read()
	{
		T res;
		this->read(res);
		return res;
	}

	template <typename T>
	void read(T & value)
	{
		uint8_t * first = reinterpret_cast<uint8_t *>(&value);
		uint8_t * last = first + sizeof(T);
		m_f.read(m_offset, first, last - first);
		m_offset += last - first;
		if (m_be)
			std::reverse(first, last);
	}

	template <typename T, size_t N>
	void read(T(&value)[N])
	{
		for (size_t i = 0; i < N; ++i)
			this->read(value[i]);
	}

	template <typename T>
	T read_at(file::offset_t offset)
	{
		this->seek(offset);
		return this->read<T>();
	}

	template <typename T>
	void read_at(file::offset_t offset, T & value)
	{
		this->seek(offset);
		this->read(value);
	}

	void seek(file::offset_t offset)
	{
		m_offset = offset;
	}

	void skip(file::offset_t dist)
	{
		m_offset += dist;
	}

	template <typename T>
	bin_reader & operator%(T & value)
	{
		this->read(value);
		return *this;
	}

private:
	file & m_f;
	file::offset_t m_offset;
	bool m_be;
};

#endif // SYMTREE_BINREADER_H
