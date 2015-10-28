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
	static T load_le(uint8_t const * p)
	{
		T res;
		memcpy(&res, p, sizeof(T));
		return res;
	}

	template <typename T>
	static T load_be(uint8_t const * p)
	{
		T res;
		auto q = reinterpret_cast<uint8_t *>(&res) + sizeof(T);
		for (size_t i = 0; i < sizeof(T); ++i)
			*--q = *p++;
		return res;
	}

	template <typename T>
	static T load(uint8_t const * p, bool be)
	{
		if (be)
			return load_be<T>(p);
		else
			return load_le<T>(p);
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
		uint8_t buf[sizeof(T)];
		m_f.read(m_offset, buf, sizeof(T));
		m_offset += sizeof(T);
		value = load<T>(buf, m_be);
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
