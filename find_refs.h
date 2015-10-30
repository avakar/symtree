#ifndef SYMTREE_FIND_REFS_H
#define SYMTREE_FIND_REFS_H

#include <functional>
#include <vector>

void find_refs_x86(size_t addr, bool x64, std::vector<uint8_t> const & buf, std::function<void (size_t addr)> const & cb);
void find_refs_arm32(size_t addr, std::vector<uint8_t> const & buf, std::function<void (size_t addr)> const & cb);

#endif // SYMTREE_FIND_REFS_H
