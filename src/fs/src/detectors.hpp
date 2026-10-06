// SPDX-License-Identifier: MIT
// Internal: one detector per family. Each returns NotFound when the bytes are
// not its format, and a populated SimpleFileSystem otherwise.
#pragma once

#include "stein/fs/detail/simple_fs.hpp"

namespace stein::fs::detail {

using Result = Expected<std::unique_ptr<FileSystem>>;
using Dev = std::shared_ptr<BlockDevice>;

inline Result notMine(const char* why) { return fail(ErrorCategory::NotFound, why); }

Result detectExt(Dev);
Result detectFat(Dev);
Result detectExFat(Dev);
Result detectNtfs(Dev);
Result detectReFs(Dev);
Result detectHfsPlus(Dev);
Result detectHfs(Dev);
Result detectApfs(Dev);
Result detectXfs(Dev);
Result detectBtrfs(Dev);
Result detectF2fs(Dev);
Result detectJfs(Dev);
Result detectReiserFs(Dev);
Result detectReiser4(Dev);
Result detectNilfs2(Dev);
Result detectBcachefs(Dev);
Result detectOcfs2(Dev);
Result detectMinix(Dev);
Result detectErofs(Dev);
Result detectSquashFs(Dev);
Result detectUdf(Dev);
Result detectIso9660(Dev);
Result detectSwap(Dev);
Result detectZfs(Dev);
Result detectUfs(Dev);
Result detectLuks(Dev);
Result detectLvm(Dev);
Result detectMd(Dev);
Result detectBitLocker(Dev);

} // namespace stein::fs::detail
