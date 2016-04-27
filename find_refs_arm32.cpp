#include "find_refs.h"
#include "binreader.h"

void find_refs_arm32(uint64_t addr, std::vector<uint8_t> const & buf, std::function<void(uint64_t addr)> const & cb)
{
	if (addr % 4 != 0 || buf.size() % 4 != 0)
		return;

	size_t cnt = buf.size() / 4;
	for (size_t i = 0; i < cnt; ++i)
		cb(bin_reader::load_le<uint32_t>(buf.data() + i*4));
}
