#include "find_refs.h"
#include "distorm/include/distorm.h"

void find_refs_x86(size_t addr, bool x64, std::vector<uint8_t> const & buf, std::function<void(size_t addr)> const & cb)
{
	_CodeInfo ci = {};
	ci.code = buf.data();
	ci.nextOffset = ci.codeOffset = addr;
	ci.codeLen = buf.size();
	ci.dt = x64? Decode64Bits: Decode32Bits;

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
					cb(inst.imm.sqword);
					break;
				case O_PC:
					cb(inst.imm.addr + inst.addr + inst.size);
					break;
				case O_PTR:
					cb(inst.imm.ptr.off);
					break;
				case O_SMEM:
					if (inst.flags & FLAG_RIP_RELATIVE)
						cb(INSTRUCTION_GET_RIP_TARGET(&inst));
				}
			}
		}
	}
}
