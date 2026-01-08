/*
 * GCC libstdc++ std::basic_string layout
 * 用于 Ghidra 逆向分析
 */

// 简化版本(推荐用于 Ghidra):
struct std_basic_string_simple {
    char*  _M_dataplus;        // +0x0: 指向数据(SSO或堆)
    size_t _M_length;          // +0x8: 当前长度
    char   _M_local_buf[16];   // +0x10: SSO缓冲区或容量字段
};
// 总大小: 0x20 (32字节)

// 完整版本(更精确但复杂):
struct std_basic_string_full {
    char*  _M_dataplus;        // +0x0: 数据指针
    size_t _M_length;          // +0x8: 当前长度

    union {
        char   _M_local_buf[16];  // SSO模式:本地缓冲区
        struct {
            size_t _M_capacity;   // 堆模式:容量
            char   _unused[8];    // 未使用
        } _M_allocated;
    };
};
// 总大小: 0x20 (32字节)

/*
 * 使用建议:
 *
 * 1. 如果只是为了可读性,用 std_basic_string_simple
 *    - 简单直观
 *    - Ghidra 更容易处理
 *    - 缺点:访问 offset 0x10 时不知道是数据还是容量
 *
 * 2. 如果需要区分 SSO/堆模式,用 std_basic_string_full
 *    - 更精确
 *    - 但 Ghidra 对 union 支持不完美
 *    - 需要手动判断当前模式
 *
 * 判断 SSO vs 堆模式:
 *   if (_M_dataplus >= (char*)&this &&
 *       _M_dataplus < (char*)&this + sizeof(*this)) {
 *       // SSO 模式:数据在 _M_local_buf 中
 *   } else {
 *       // 堆模式:数据在外部,_M_capacity 有效
 *   }
 */

 // 定义 vector 结构
struct std_vector_char {
    char* _M_start;          // +0x0: 数据开始
    char* _M_finish;         // +0x8: 数据结尾
    char* _M_end_of_storage; // +0x10: 容量结尾
};