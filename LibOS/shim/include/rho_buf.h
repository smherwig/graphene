#ifndef _RHO_BUF_H_
#define _RHO_BUF_H_

#include <shim_internal.h>
#include <shim_types.h>

#include <rho_decls.h>

RHO_DECLS_BEGIN

struct rho_buf {
    uint8_t *data;
    off_t pos;
    size_t len;
    size_t cap;
    bool bounded;
    bool fixed;
};

struct rho_buf * rho_buf_create(void);
struct rho_buf * rho_buf_bounded_create(size_t maxsize);
struct rho_buf * rho_buf_fixed_create(void *data, size_t size);

void rho_buf_destroy(struct rho_buf *buf);

off_t rho_buf_tell(const struct rho_buf *buf);
void rho_buf_rewind(struct rho_buf *buf);
off_t rho_buf_seek(struct rho_buf *buf, off_t offset, int whence);

void rho_buf_ensure(struct rho_buf *buf, size_t len);
void rho_buf_truncate(struct rho_buf *buf, off_t off);
void rho_buf_clear(struct rho_buf *buf);

void * rho_buf_raw(const struct rho_buf *buf, off_t offset, int whence);

size_t rho_buf_length(const struct rho_buf *buf);
size_t rho_buf_left(const struct rho_buf *buf);
void rho_buf_setlength(struct rho_buf *buf, size_t len);

int rho_buf_preadu8_at(struct rho_buf *buf, uint8_t *v, off_t offset);
int rho_buf_preadu8(struct rho_buf *buf, uint8_t *v);
int rho_buf_readu8(struct rho_buf *buf, uint8_t *v);

void rho_buf_pwriteu8_at(struct rho_buf *buf, uint8_t v, off_t offset);
void rho_buf_pwriteu8(struct rho_buf *buf, uint8_t v);
void rho_buf_writeu8(struct rho_buf *buf, uint8_t v);

#define rho_buf_pread8_at(buf, v, offset) rho_buf_preadu8_at(buf, (uint8_t *)(v), offset)
#define rho_buf_pread8(buf, v) rho_buf_preadu8(buf, (uint8_t *)(v))
#define rho_buf_read8(buf, v) rho_buf_readu8(buf, (uint8_t *)(v))

#define rho_buf_pwrite8_at(buf, v, offset) rho_buf_pwriteu8_at(buf, (uint8_t)(v), offset)
#define rho_buf_pwrite8(buf, v) rho_buf_pwriteu8(buf, (uint8_t)(v))
#define rho_buf_write8(buf, v) rho_buf_writeu8(buf, (uint8_t)(v))

int rho_buf_preadu16be_at(struct rho_buf *buf, uint16_t *v, off_t offset);
int rho_buf_preadu16be(struct rho_buf *buf, uint16_t *v);
int rho_buf_readu16be(struct rho_buf *buf, uint16_t *v);

void rho_buf_pwriteu16be_at(struct rho_buf *buf, uint16_t v, off_t offset);
void rho_buf_pwriteu16be(struct rho_buf *buf, uint16_t v);
void rho_buf_writeu16be(struct rho_buf *buf, uint16_t v);

#define rho_buf_pread16be_at(buf, v, offset) rho_buf_preadu16be_at(buf, (uint16_t *)(v), offset)
#define rho_buf_pread16be(buf, v) rho_buf_preadu16be(buf, (uint16_t *)(v))
#define rho_buf_read16be(buf, v) rho_buf_readu16be(buf, (uint16_t *)(v))

#define rho_buf_pwrite16be_at(buf, v, offset) rho_buf_pwriteu16be_at(buf, (uint16_t)(v), offset)
#define rho_buf_pwrite16be(buf, v) rho_buf_pwriteu16be(buf, (uint16_t)(v))
#define rho_buf_write16be(buf, v) rho_buf_writeu16be(buf, (uint16_t)(v))

int rho_buf_preadu16le_at(struct rho_buf *buf, uint16_t *v, off_t offset);
int rho_buf_preadu16le(struct rho_buf *buf, uint16_t *v);
int rho_buf_readu16le(struct rho_buf *buf, uint16_t *v);

void rho_buf_pwriteu16le_at(struct rho_buf *buf, uint16_t v, off_t offset);
void rho_buf_pwriteu16le(struct rho_buf *buf, uint16_t v);
void rho_buf_writeu16le(struct rho_buf *buf, uint16_t v);

#define rho_buf_pread16le_at(buf, v, offset) rho_buf_preadu16le_at(buf, (uint16_t *)(v), offset)
#define rho_buf_pread16le(buf, v) rho_buf_preadu16le(buf, (uint16_t *)(v))
#define rho_buf_read16le(buf, v) rho_buf_readu16le(buf, (uint16_t *)(v))

#define rho_buf_pwrite16le_at(buf, v, offset) rho_buf_pwriteu16le_at(buf, (uint16_t)(v), offset)
#define rho_buf_pwrite16le(buf, v) rho_buf_pwriteu16le(buf, (uint16_t)(v))
#define rho_buf_write16le(buf, v) rho_buf_writeu16le(buf, (uint16_t)(v))

int rho_buf_preadu32be_at(struct rho_buf *buf, uint32_t *v, off_t offset);
int rho_buf_preadu32be(struct rho_buf *buf, uint32_t *v);
int rho_buf_readu32be(struct rho_buf *buf, uint32_t *v);

void rho_buf_pwriteu32be_at(struct rho_buf *buf, uint32_t v, off_t offset);
void rho_buf_pwriteu32be(struct rho_buf *buf, uint32_t v);
void rho_buf_writeu32be(struct rho_buf *buf, uint32_t v);

#define rho_buf_pread32be_at(buf, v, offset) rho_buf_preadu32be_at(buf, (uint32_t *)(v), offset)
#define rho_buf_pread32be(buf, v) rho_buf_preadu32be(buf, (uint32_t *)(v))
#define rho_buf_read32be(buf, v) rho_buf_readu32be(buf, (uint32_t *)(v))

#define rho_buf_pwrite32be_at(buf, v, offset) rho_buf_pwriteu32be_at(buf, (uint32_t)(v), offset)
#define rho_buf_pwrite32be(buf, v) rho_buf_pwriteu32be(buf, (uint32_t)(v))
#define rho_buf_write32be(buf, v) rho_buf_writeu32be(buf, (uint32_t)(v))

int rho_buf_preadu32le_at(struct rho_buf *buf, uint32_t *v, off_t offset);
int rho_buf_preadu32le(struct rho_buf *buf, uint32_t *v);
int rho_buf_readu32le(struct rho_buf *buf, uint32_t *v);

void rho_buf_pwriteu32le_at(struct rho_buf *buf, uint32_t v, off_t offset);
void rho_buf_pwriteu32le(struct rho_buf *buf, uint32_t v);
void rho_buf_writeu32le(struct rho_buf *buf, uint32_t v);

#define rho_buf_pread32le_at(buf, v, offset) rho_buf_preadu32le_at(buf, (uint32_t *)(v), offset)
#define rho_buf_pread32le(buf, v) rho_buf_preadu32le(buf, (uint32_t *)(v))
#define rho_buf_read32le(buf, v) rho_buf_readu32le(buf, (uint32_t *)(v))

#define rho_buf_pwrite32le_at(buf, v, offset) rho_buf_pwriteu32le_at(buf, (uint32_t)(v), offset)
#define rho_buf_pwrite32le(buf, v) rho_buf_pwriteu32le(buf, (uint32_t)(v))
#define rho_buf_write32le(buf, v) rho_buf_writeu32le(buf, (uint32_t)(v))

int rho_buf_preadu64be_at(struct rho_buf *buf, uint64_t *v, off_t offset);
int rho_buf_preadu64be(struct rho_buf *buf, uint64_t *v);
int rho_buf_readu64be(struct rho_buf *buf, uint64_t *v);

void rho_buf_pwriteu64be_at(struct rho_buf *buf, uint64_t v, off_t offset);
void rho_buf_pwriteu64be(struct rho_buf *buf, uint64_t v);
void rho_buf_writeu64be(struct rho_buf *buf, uint64_t v);

#define rho_buf_pread64be_at(buf, v, offset) rho_buf_preadu64be_at(buf, (uint64_t *)(v), offset)
#define rho_buf_pread64be(buf, v) rho_buf_preadu64be(buf, (uint64_t *)(v))
#define rho_buf_read64be(buf, v) rho_buf_readu64be(buf, (uint64_t *)(v))

#define rho_buf_pwrite64be_at(buf, v, offset) rho_buf_pwriteu64be_at(buf, (uint64_t)(v), offset)
#define rho_buf_pwrite64be(buf, v) rho_buf_pwriteu64be(buf, (uint64_t)(v))
#define rho_buf_write64be(buf, v) rho_buf_writeu64be(buf, (uint64_t)(v))

int rho_buf_preadu64le_at(struct rho_buf *buf, uint64_t *v, off_t offset);
int rho_buf_preadu64le(struct rho_buf *buf, uint64_t *v);
int rho_buf_readu64le(struct rho_buf *buf, uint64_t *v);

void rho_buf_pwriteu64le_at(struct rho_buf *buf, uint64_t v, off_t offset);
void rho_buf_pwriteu64le(struct rho_buf *buf, uint64_t v);
void rho_buf_writeu64le(struct rho_buf *buf, uint64_t v);

#define rho_buf_pread64le_at(buf, v, offset) rho_buf_preadu64le_at(buf, (uint64_t *)(v), offset)
#define rho_buf_pread64le(buf, v) rho_buf_preadu64le(buf, (uint64_t *)(v))
#define rho_buf_read64le(buf, v) rho_buf_readu64le(buf, (uint64_t *)(v))

#define rho_buf_pwrite64le_at(buf, v, offset) rho_buf_pwriteu64le_at(buf, (uint64_t)(v), offset)
#define rho_buf_pwrite64le(buf, v) rho_buf_pwriteu64le(buf, (uint64_t)(v))
#define rho_buf_write64le(buf, v) rho_buf_writeu64le(buf, (uint64_t)(v))

size_t rho_buf_read(struct rho_buf *buf, void *b, size_t len);
void rho_buf_write(struct rho_buf *buf, const void *b, size_t len);

int rho_buf_read_u32size_blob(struct rho_buf *buf, void *b, size_t len,
        size_t *ngot);

void rho_buf_write_u32size_blob(struct rho_buf *buf, const void *b,
        size_t len);

void rho_buf_puts(struct rho_buf *buf, const char *s);
void rho_buf_puts_nul(struct rho_buf *buf, const char *s);

int rho_buf_read_u32size_str(struct rho_buf *buf, char *s, size_t len);
void rho_buf_write_u32size_str(struct rho_buf *buf, const char *s);

void rho_buf_append(struct rho_buf *buf, const struct rho_buf *a);

RHO_DECLS_END

#endif /* ! _RHO_BUF_H_ */

