/*
 * self-sign.c — OpenHarmony 二进制自签名参考实现 (C99, 无第三方依赖)
 *
 * 用法:
 *     cc self-sign.c -o self-sign
 *     ./self-sign <input_elf> [output_elf]
 *         缺省 output 时, inplace 改写 input.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ─────────────────────────── SHA-256 ─────────────────────────── */
/* 按 FIPS 180-4 (Secure Hash Standard, 公开规范) 自实现 */
typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t  buf[64];
    size_t   buflen;
} SHA256_CTX;

/* FIPS 180-4 §4.2.2: SHA-256 的 64 个轮常量 K (κ = floor(2^32 * sin(i)) 的前32位) */
static const uint32_t SHA256_K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

/* FIPS 180-4 §3.1.1: 32 位字上的轮函数 (ROTRr / SHRr) 及压缩函数 Σ/Ch/Maj */
#define ROTR32(x,n) (((x) >> (n)) | ((x) << (32 - (n))))
#define SHA_BIG_S0(x) (ROTR32(x,2)  ^ ROTR32(x,13) ^ ROTR32(x,22))   /* Σ0 */
#define SHA_BIG_S1(x) (ROTR32(x,6)  ^ ROTR32(x,11) ^ ROTR32(x,25))   /* Σ1 */
#define SHA_SMALL_S0(x) (ROTR32(x,7) ^ ROTR32(x,18) ^ ((x) >> 3))    /* σ0 */
#define SHA_SMALL_S1(x) (ROTR32(x,17) ^ ROTR32(x,19) ^ ((x) >> 10))  /* σ1 */
#define SHA_CH(e,f,g)  (((e) & (f)) ^ ((~(e)) & (g)))                /* Ch */
#define SHA_MAJ(a,b,c) (((a) & (b)) ^ ((a) & (c)) ^ ((b) & (c)))    /* Maj */

/* FIPS 180-4 §5.3.3: SHA-256 的 8 个初始哈希值 H (κ = floor(2^32 * sin(i)) 的前32位) */
static void sha256_init(SHA256_CTX *c) {
    c->bitlen = 0; c->buflen = 0;
    c->state[0]=0x6a09e667; c->state[1]=0xbb67ae85; c->state[2]=0x3c6ef372; c->state[3]=0xa54ff53a;
    c->state[4]=0x510e527f; c->state[5]=0x9b05688c; c->state[6]=0x1f83d9ab; c->state[7]=0x5be0cd19;
}

/* FIPS 180-4 §5.1.1 + §6.2.2: 对一个 512-bit (64B) 块做压缩, 更新 state */
static void sha256_block(SHA256_CTX *c, const uint8_t *p) {
    uint32_t w[64];
    uint32_t a, b, cc, d, e, f, g, h, t1, t2;
    int i;
    /* §5.1.1: 把 16 个字做大端解析为 W0..W15; §6.2.2 步骤1: W16..W63 = σ1(W[i-2]) + W[i-7] + σ0(W[i-15]) + W[i-16] */
    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t)p[i*4]) << 24 | ((uint32_t)p[i*4+1]) << 16
             | ((uint32_t)p[i*4+2]) << 8 | ((uint32_t)p[i*4+3]);
    }
    for (; i < 64; i++) {
        w[i] = SHA_SMALL_S1(w[i-2]) + w[i-7] + SHA_SMALL_S0(w[i-15]) + w[i-16];
    }
    /* §6.2.2 步骤2: 初始化工作变量为当前 state */
    a = c->state[0]; b = c->state[1]; cc = c->state[2]; d = c->state[3];
    e = c->state[4]; f = c->state[5]; g = c->state[6]; h = c->state[7];
    /* 步骤3: 64 轮压缩; T1 = h + Σ1(e) + Ch(e,f,g) + K[i] + W[i]; T2 = Σ0(a) + Maj(a,b,c) */
    for (i = 0; i < 64; i++) {
        t1 = h + SHA_BIG_S1(e) + SHA_CH(e, f, g) + SHA256_K[i] + w[i];
        t2 = SHA_BIG_S0(a) + SHA_MAJ(a, b, cc);
        h = g; g = f; f = e; e = d + t1; d = cc; cc = b; b = a; a = t1 + t2;
    }
    /* 步骤4: 把工作变量回加进 state */
    c->state[0] += a; c->state[1] += b; c->state[2] += cc; c->state[3] += d;
    c->state[4] += e; c->state[5] += f; c->state[6] += g; c->state[7] += h;
}

/* FIPS 180-4 §5.2: 把字节流按 64B 一块喂给 sha256_block, 维护 bitlen */
static void sha256_update(SHA256_CTX *c, const uint8_t *data, size_t len) {
    c->bitlen += (uint64_t)len * 8;
    while (len--) {
        c->buf[c->buflen++] = *data++;
        if (c->buflen == 64) { sha256_block(c, c->buf); c->buflen = 0; }
    }
}

/* FIPS 180-4 §5.1.1: padding — 末块补 1bit 0x80 + 0.. 直到剩 8 字节, 末 8 字节填 bitlen 大端 */
static void sha256_final(SHA256_CTX *c, uint8_t out[32]) {
    uint64_t bits = c->bitlen;
    size_t i = c->buflen;
    c->buf[i++] = 0x80;
    if (i > 56) { while (i < 64) c->buf[i++] = 0; sha256_block(c, c->buf); i = 0; }
    while (i < 56) c->buf[i++] = 0;
    for (i = 0; i < 8; i++) c->buf[56 + i] = (uint8_t)(bits >> (56 - 8*i));
    sha256_block(c, c->buf);
    /* 输出: 8 个 state 字大端 */
    for (i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)(c->state[i] >> 24);
        out[i*4+1] = (uint8_t)(c->state[i] >> 16);
        out[i*4+2] = (uint8_t)(c->state[i] >> 8);
        out[i*4+3] = (uint8_t)(c->state[i]);
    }
}

static void sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    SHA256_CTX c; sha256_init(&c); sha256_update(&c, data, len); sha256_final(&c, out);
}

/* ─────────────────────────── 工具 ─────────────────────────── */
static int read_file(const char *path, uint8_t **out, size_t *outlen) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return -1; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0) { fclose(f); return -1; }
    uint8_t *buf = malloc(sz > 0 ? sz : 1);
    if (!buf) { fclose(f); return -1; }
    if (sz > 0 && fread(buf, 1, sz, f) != (size_t)sz) { free(buf); fclose(f); return -1; }
    fclose(f);
    *out = buf; *outlen = (size_t)sz; return 0;
}
static int write_file(const char *path, const uint8_t *data, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) { perror(path); return -1; }
    if (len && fwrite(data, 1, len, f) != len) { fclose(f); return -1; }
    fclose(f); return 0;
}

/* 小端多字节写入 */
static void put_u32le(uint8_t *p, uint32_t v) { p[0]=v&0xff; p[1]=(v>>8)&0xff; p[2]=(v>>16)&0xff; p[3]=(v>>24)&0xff; }
static void put_u64le(uint8_t *p, uint64_t v) { for (int i=0;i<8;i++) p[i]=(v>>(8*i))&0xff; }

/* ─────────────────────── merkle 树根哈希 ─────────────────────── */
/*
 * 与上游 merkle_tree_builder.cpp::RunHashTask 精确等价:
 *   - 对含段产物按原偏移分页, 每页 4096B, 末页补0
 *   - 段所在页(csOff/4096 .. (csOff+csLen)/4096)的叶哈希全填0, 不做SHA256
 *   - 上推: 当前哈希层每 4096B(=128个哈希)一页再 SHA-256, 末页补0
 *   - 单页即根; 顶层(packed<=4096)整页补0再哈希即根
 * 内存: cur 始终指向"当前哈希层", owns 标记是否需 free.
 */
static void merkle_root_hash(const uint8_t *data, size_t len,
                             uint64_t cs_off, uint64_t cs_len,
                             uint8_t root[32]) {
    const size_t PAGE = 4096, H = 32;
    uint8_t page[PAGE];
    if (len == 0) {
        memset(page, 0, PAGE); sha256(page, PAGE, root); return;
    }
    /* 叶层: 含段产物按原偏移分页, 段所在页哈希置0 */
    size_t npages = (len + PAGE - 1) / PAGE;
    uint8_t *cur = malloc(npages * H);
    /* 段占用的页范围 [cs_off/PAGE, ceil((cs_off+cs_len)/PAGE)) */
    size_t cs_page_begin = (size_t)(cs_off / PAGE);
    size_t cs_page_end   = (size_t)((cs_off + cs_len + PAGE - 1) / PAGE);
    for (size_t i = 0; i < npages; i++) {
        if (cs_len > 0 && i >= cs_page_begin && i < cs_page_end) {
            /* 段所在页: 叶哈希全填0 */
            memset(cur + i * H, 0, H);
            continue;
        }
        memset(page, 0, PAGE);
        size_t off = i * PAGE;
        size_t n = (off + PAGE <= len) ? PAGE : (len - off);
        memcpy(page, data + off, n);
        sha256(page, PAGE, cur + i * H);
    }
    if (npages == 1) { memcpy(root, cur, H); free(cur); return; }
    size_t ncur = npages; int owns = 1;
    for (;;) {
        size_t packed = ncur * H;
        if (packed <= PAGE) {
            memset(page, 0, PAGE);
            memcpy(page, cur, packed);
            sha256(page, PAGE, root);
            if (owns) free(cur);
            return;
        }
        size_t next_pages = (packed + PAGE - 1) / PAGE;
        uint8_t *next = malloc(next_pages * H);
        for (size_t i = 0; i < next_pages; i++) {
            memset(page, 0, PAGE);
            size_t off = i * PAGE;
            size_t n = (off + PAGE <= packed) ? PAGE : (packed - off);
            memcpy(page, cur + off, n);
            sha256(page, PAGE, next + i * H);
        }
        if (owns) free(cur);
        cur = next; ncur = next_pages; owns = 1;
    }
}

/* ─────────────────────── descriptor 与 ElfSignInfo ─────────────────────── */
/*
 * descriptor 256 字节布局, 全小端.
 *   off  size  field
 *   0    1     version = 1
 *   1    1     hashAlgorithm = 1
 *   2    1     log2BlockSize = 12
 *   3    1     saltSize = 0
 *   4    4     signSize (摘要时=0, 落盘时=signature长)
 *   8    8     fileSize
 *   16   64    rootHash (左对齐, 余0)
 *   80   32    salt (全0)
 *   112  4     flags (自签名=0x10)
 *   116  4     reserved1 = 0
 *   120  8     merkleTreeOffset = 0
 *   128  127   reserved2 = 0
 *   255  1     csVersion = 3
 */
static void build_descriptor(uint8_t *out /*256*/,
                             uint32_t sign_size, uint64_t file_size,
                             const uint8_t root[32], uint32_t flags) {
    memset(out, 0, 256);
    out[0] = 1;            /* version */
    out[1] = 1;            /* hashAlgorithm SHA-256 */
    out[2] = 12;           /* log2BlockSize */
    out[3] = 0;            /* saltSize */
    put_u32le(out + 4, sign_size);
    put_u64le(out + 8, file_size);
    memcpy(out + 16, root, 32);           /* rootHash 左对齐填64B后32B保持0 */
    /* out+80 salt 全0 */
    put_u32le(out + 112, flags);
    /* out+116 reserved1=0; out+120 merkleTreeOffset=0; out+128 reserved2=0 */
    out[255] = 3;          /* csVersion */
}

static const size_t DESC_SIZE = 256;
static const size_t PAGE_SIZE = 4096;
static const uint32_t FLAG_SELF_SIGN = 0x10;
static const uint32_t FS_VERITY_DESCRIPTOR_TYPE = 1;

/* ─────────────────────── ELF64 section 注入器 ─────────────────────── */
/*
 * 自注入 .codesign 段到 ELF64 末尾, 段文件偏移 4KB 对齐, 段内容 4KB (全0占位),
 * 并更新 section header table + shstrtab. 与上游 binary-sign-tool 产物在段级等价.
 *
 * 流程 (复刻上游 sign_elf.cpp::WriteCodeSignBlock):
 *   1. 解 ELF64 header 拿 e_shoff / e_shnum / e_shstrndx
 *   2. 定位 shstrtab 段, 在末尾追加 ".codesign\0"
 *   3. 算 .codesign 段文件偏移: 现有所有段末尾 max(段末) + 4KB 对齐
 *   4. 新 shstrtab 落到段后; 新 section header table 落到 shstrtab 后 (8B 对齐)
 *   5. 追加 .codesign entry: sh_type=SHT_PROGBITS, sh_addralign=4096, sh_size=4096
 *   6. 重写文件: 原内容[0..旧末尾] + .codesign段(4KB全0) + 新shstrtab + 新SHT
 *   7. 改 ELF header: e_shoff/e_shnum/e_shstrndx
 * 返回: .codesign 段在产物中的文件偏移 (4KB对齐), 通过 *cs_off_out.
 */
static uint64_t align_up(uint64_t v, uint64_t a) { return ((v + a - 1) / a) * a; }

static int64_t inject_codesign_section(uint8_t *raw, size_t raw_len,
                                        uint8_t **out, size_t *out_len,
                                        uint64_t *cs_off_out) {
    /* ELF64 header 字段偏移 */
    const size_t E_SHOFF = 0x28, E_SHENTSIZE = 0x3a, E_SHNUM = 0x3c, E_SHSTRNDX = 0x3e;
    if (raw_len < 64 || memcmp(raw, "\x7f""ELF", 4) != 0 || raw[4] != 2) {
        fprintf(stderr, "not ELF64\n"); return -1;
    }
    uint64_t e_shoff   = *(uint64_t*)(raw + E_SHOFF);
    uint16_t e_shnum   = *(uint16_t*)(raw + E_SHNUM);
    uint16_t e_shstrndx= *(uint16_t*)(raw + E_SHSTRNDX);
    if (e_shoff == 0 || e_shnum == 0 || e_shstrndx >= e_shnum) {
        fprintf(stderr, "no section header table (e_shoff=0?) — stripped ELF unsupported\n");
        return -1;
    }
    /* shstrtab entry */
    uint8_t *shstr_e = raw + e_shoff + (size_t)e_shstrndx * 64;
    uint64_t shstr_off = *(uint64_t*)(shstr_e + 24);
    uint64_t shstr_sz  = *(uint64_t*)(shstr_e + 32);
    if (shstr_off + shstr_sz > raw_len) { fprintf(stderr, "shstrtab OOB\n"); return -1; }

    /* 算 .codesign 段文件偏移: 所有段末尾 max(e_shoff + e_shnum*64, 各段 off+size) + 4KB 对齐 */
    uint64_t cur_end = e_shoff + (uint64_t)e_shnum * 64;
    for (uint16_t i = 0; i < e_shnum; i++) {
        uint8_t *e = raw + e_shoff + (size_t)i * 64;
        uint64_t off = *(uint64_t*)(e + 24), sz = *(uint64_t*)(e + 32);
        if (e[4] == 8 /* SHT_NOBITS */) sz = 0;     /* .bss 等不占文件 */
        if (off + sz > cur_end) cur_end = off + sz;
    }
    uint64_t cs_off = align_up(cur_end, PAGE_SIZE);

    /* 新 shstrtab = 旧 shstrtab + ".codesign\0" */
    static const char CS_NAME[] = ".codesign";
    size_t name_len = strlen(CS_NAME) + 1;
    uint64_t new_shstr_sz = shstr_sz + name_len;
    uint8_t *new_shstr = malloc(new_shstr_sz);
    memcpy(new_shstr, raw + shstr_off, shstr_sz);
    memcpy(new_shstr + shstr_sz, CS_NAME, name_len);
    uint32_t cs_shname = (uint32_t)shstr_sz;       /* .codesign 名字在新 shstrtab 内偏移 */

    /* 新 shstrtab 落到段后 */
    uint64_t new_shstr_off = cs_off + PAGE_SIZE;
    /* 新 SHT 落到新 shstrtab 后, 8B 对齐 */
    uint64_t new_sht_off = align_up(new_shstr_off + new_shstr_sz, 8);
    uint16_t new_shnum = e_shnum + 1;
    /* 新文件总长 */
    size_t new_total = new_sht_off + (size_t)new_shnum * 64;

    uint8_t *buf = calloc(1, new_total);
    /* 1) 原内容 (含旧 SHT 在原位置; 旧 shstrtab 在原位置; ELF header 后面会被改) */
    memcpy(buf, raw, raw_len);
    /* 2) .codesign 段内容 (4KB 全0, 已 calloc) */
    /* 3) 新 shstrtab (覆盖旧位置若重叠则无妨, 我们写到新位置) */
    memcpy(buf + new_shstr_off, new_shstr, new_shstr_sz);
    free(new_shstr);
    /* 4) 旧 SHT 复制到新位置 */
    memcpy(buf + new_sht_off, raw + e_shoff, (size_t)e_shnum * 64);
    /* 5) 追加 .codesign entry (64B) */
    uint8_t *cs_e = buf + new_sht_off + (size_t)e_shnum * 64;
    memset(cs_e, 0, 64);
    *(uint32_t*)(cs_e + 0)  = cs_shname;     /* sh_name */
    *(uint32_t*)(cs_e + 4)  = 1;            /* sh_type SHT_PROGBITS */
    *(uint64_t*)(cs_e + 8)  = 0;            /* sh_flags */
    *(uint64_t*)(cs_e + 16) = 0;            /* sh_addr */
    *(uint64_t*)(cs_e + 24) = cs_off;       /* sh_offset */
    *(uint64_t*)(cs_e + 32) = PAGE_SIZE;    /* sh_size */
    *(uint32_t*)(cs_e + 40) = 0;            /* sh_link */
    *(uint32_t*)(cs_e + 44) = 0;            /* sh_info */
    *(uint64_t*)(cs_e + 48) = PAGE_SIZE;    /* sh_addralign */
    *(uint64_t*)(cs_e + 56) = 0;            /* sh_entsize */
    /* 6) 改 shstrtab entry: 新 off + 新 size */
    uint8_t *shstr_e_new = buf + new_sht_off + (size_t)e_shstrndx * 64;
    *(uint64_t*)(shstr_e_new + 24) = new_shstr_off;
    *(uint64_t*)(shstr_e_new + 32) = new_shstr_sz;
    /* 7) 改 ELF header: e_shoff / e_shnum / e_shstrndx */
    *(uint64_t*)(buf + E_SHOFF) = new_sht_off;
    *(uint16_t*)(buf + E_SHNUM) = new_shnum;
    /* e_shstrndx 不变 */

    *out = buf; *out_len = new_total; *cs_off_out = cs_off;
    return 0;
}

/* ─────────────────────────── 主流程 ─────────────────────────── */
/*
 * 上游 sign_elf.cpp::Sign 流程复刻:
 *   1. 先剥旧 .codesign/.profile/.permission 段 (本实现假定输入未签, 跳过)
 *   2. 注入 4KB 占位 .codesign 段 → 含段产物 tmp
 *   3. fileSize = tmp 大小; csOffset = 段在 tmp 中的偏移
 *   4. 对 tmp 跳过段区间建 merkle 根哈希
 *   5. descriptor(signSize=0, fileSize=tmp大小) → SHA256 → signature
 *   6. 落盘 descriptor(signSize=32) + signature, 原地改写段内字节
 * 验签端按 section header 找 .codesign 段, 校验段偏移4KB对齐 + flags第4位.
 */
static int self_sign(const char *inPath, const char *outPath) {
    uint8_t *raw = NULL; size_t rawLen = 0;
    if (read_file(inPath, &raw, &rawLen) < 0) return -1;

    /* 0. 前置校验: 已含 .codesign 段则拒签 (本工具只加签, 不剥旧段).
     *    反复签会累积段畸形, 验签侧按段名找到旧的不完整段会拒.
     *    需重签时请先 llvm-objcopy --remove-section .codesign <elf> 剥旧段. */
    {
        uint64_t e_shoff = *(uint64_t*)(raw + 0x28);
        uint16_t e_shnum = *(uint16_t*)(raw + 0x3c);
        uint16_t e_shstrndx = *(uint16_t*)(raw + 0x3e);
        if (e_shoff != 0 && e_shnum != 0 && e_shstrndx < e_shnum) {
            uint8_t *shstr_e = raw + e_shoff + (size_t)e_shstrndx * 64;
            uint64_t shstr_off = *(uint64_t*)(shstr_e + 24);
            uint64_t shstr_sz  = *(uint64_t*)(shstr_e + 32);
            if (shstr_off + shstr_sz <= rawLen) {
                for (uint16_t i = 0; i < e_shnum; i++) {
                    uint8_t *e = raw + e_shoff + (size_t)i * 64;
                    uint32_t name_off = *(uint32_t*)(e + 0);
                    if (name_off < shstr_sz &&
                        strcmp((const char*)(raw + shstr_off + name_off), ".codesign") == 0) {
                        fprintf(stderr,
                            "error: %s already has a .codesign section.\n"
            "  This tool only adds a signature, it does not strip old ones.\n"
            "  To re-sign, first strip the old section with:\n"
            "    llvm-objcopy --remove-section .codesign %s\n"
            "  then run self-sign again.\n", inPath, inPath);
                        free(raw); return -1;
                    }
                }
            }
        }
    }

    /* 1. 注入 4KB 占位 .codesign 段 → tmp */
    uint8_t *tmp = NULL; size_t tmpLen = 0; uint64_t csOff = 0;
    if (inject_codesign_section(raw, rawLen, &tmp, &tmpLen, &csOff) < 0) {
        free(raw); return -1;
    }
    free(raw);
    /* tmp 此时已含 4KB 占位段, 段内全0 */

    /* 2. merkle 根哈希: 对 tmp 跳过 [csOff, csOff+4096) 区间建树 */
    uint8_t root[32];
    merkle_root_hash(tmp, tmpLen, csOff, PAGE_SIZE, root);

    /* 3/4. descriptor with signSize=0 用于摘要; fileSize = tmpLen */
    uint8_t desc_for_digest[256];
    build_descriptor(desc_for_digest, 0, (uint64_t)tmpLen, root, FLAG_SELF_SIGN);

    /* 5. signature = SHA256(descriptor) */
    uint8_t signature[32];
    sha256(desc_for_digest, DESC_SIZE, signature);

    /* 6. descriptor with signSize=32 用于落盘 */
    uint8_t desc_on_disk[256];
    build_descriptor(desc_on_disk, 32, (uint64_t)tmpLen, root, FLAG_SELF_SIGN);

    /* 7. 拼 ElfSignInfo 头部 8B + descriptor 256B + signature 32B = 296B */
    uint8_t payload[8 + DESC_SIZE + 32];
    put_u32le(payload + 0, FS_VERITY_DESCRIPTOR_TYPE);            /* type = 1 */
    put_u32le(payload + 4, (uint32_t)(DESC_SIZE + 32));           /* length = 288 */
    memcpy(payload + 8, desc_on_disk, DESC_SIZE);
    memcpy(payload + 8 + DESC_SIZE, signature, 32);

    /* 8. 原地改写段内字节 (段从 csOff 开始, 段内放 payload) */
    if (csOff + sizeof(payload) > tmpLen) {
        free(tmp); return -1;
    }
    memcpy(tmp + csOff, payload, sizeof(payload));

    /* 9. 落盘 */
    if (write_file(outPath, tmp, tmpLen) < 0) { free(tmp); return -1; }

    printf("self-sign ok: %s → %s (tmp=%zu, cs_off=0x%llx, payload=%zu)\n",
           inPath, outPath, tmpLen, (unsigned long long)csOff, sizeof(payload));
    free(tmp);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "usage: %s <input_elf> [output_elf]\n  (output defaults to input, in-place)\n", argv[0]);
        return 1;
    }
    const char *inPath = argv[1];
    const char *outPath = argc == 3 ? argv[2] : inPath;
    return self_sign(inPath, outPath) == 0 ? 0 : 2;
}
