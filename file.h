#ifndef SYMTREE_FILE_H
#define SYMTREE_FILE_H

#include <stdint.h>
#include <istream>

struct file
{
	typedef uint64_t offset_t;
	virtual void read(offset_t offset, uint8_t * buf, size_t size) = 0;

	template <typename T>
	void read_le(offset_t offset, T & buf)
	{
		this->read(offset, (uint8_t *)&buf, sizeof buf);
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

#endif // SYMTREE_FILE_H
