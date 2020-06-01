#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <shim_internal.h>
#include <shim_types.h>

#include <rho_buf.h>
#include <rho_endian.h>
#include <rho_log.h>
#include <rho_mem.h>

/*
 * XXX: assumes size_t larger than off_t
 */

#define RHO_BUF_STRIDE 128

/* off_t is usually a long int */
#define RHO_OFF_MIN (~((off_t)1 << (sizeof(off_t) * 8 - 1)))
#define RHO_OFF_MAX ((off_t)1 << (sizeof(off_t) * 8 - 1))

static void rho_buf_grow(struct rho_buf *buf, size_t newsize);

static void
rho_buf_grow(struct rho_buf *buf, size_t newsize)
{
    size_t d = 0;
    size_t r = 0;
    size_t extra = 0;
    size_t newcap = 0;

    RHO_ASSERT(buf != NULL);
    RHO_ASSERT(newsize > 0);

    if (buf->bounded)
        rho_die("attempt to resize a bounded buffer");

    /* e.g., if d is RHO_BUF_STRIDE, we want d to end up as 1 */
    d = newsize / RHO_BUF_STRIDE;
    r = newsize % RHO_BUF_STRIDE;
    if (r != 0)
        d += 1;

    /* TODO: check for overflow: do the same thing you do for mallocarray */
    newcap = d * RHO_BUF_STRIDE;
    extra = newcap - buf->cap;
    //debug("rho_buf_grow before realloc: buf->data=%p\n", buf->data);
    buf->data = rhoL_realloc(buf->data, buf->cap, newcap);
    //debug("rho_buf_grow after realloc: buf->data=%p\n", buf->data);
    memset(buf->data + buf->cap, 0x00, extra);
    buf->cap = newcap;
}

struct rho_buf *
rho_buf_create(void)
{
    struct rho_buf *buf = NULL;

    buf = rhoL_zalloc(sizeof(*buf));
    buf->data = rhoL_zalloc(RHO_BUF_STRIDE);
    buf->cap = RHO_BUF_STRIDE;
    buf->pos = 0;
    buf->bounded = false;

    return (buf);
}

struct rho_buf *
rho_buf_bounded_create(size_t maxsize)
{
    struct rho_buf *buf = NULL;

    /* XXX: consider expanding to maxsize lazily (as needed)
     * rather than allocate all bytes upfront.
     */
    buf = rhoL_zalloc(sizeof(*buf));
    buf->data = rhoL_zalloc(maxsize);
    buf->cap = maxsize;
    buf->pos = 0;
    buf->bounded = true;

    return (buf);
}

/* a fixed buffer is a bounded buffer, but, instead of allocating
 * the underlying bytearray, operates on a user-provided bytearray
 */
struct rho_buf *
rho_buf_fixed_create(void *data, size_t size)
{
    struct rho_buf *buf = NULL;

    /* XXX: consider expanding to maxsize lazily (as needed)
     * rather than allocate all bytes upfront.
     */
    buf = rhoL_zalloc(sizeof(*buf));
    buf->data = data;
    buf->cap = size;
    buf->pos = 0;
    buf->bounded = true;
    buf->fixed = true;

    return (buf);
}

void
rho_buf_destroy(struct rho_buf *buf)
{
    RHO_ASSERT(buf != NULL);
    if (!buf->fixed)
        rhoL_free(buf->data);
    rhoL_free(buf);
}

off_t
rho_buf_tell(const struct rho_buf *buf)
{
    RHO_ASSERT(buf != NULL);
    return (buf->pos);
}

void
rho_buf_rewind(struct rho_buf *buf)
{
    RHO_ASSERT(buf != NULL);
    buf->pos = 0;
}

off_t
rho_buf_seek(struct rho_buf *buf, off_t offset, int whence)
{
    off_t newpos = 0;

    RHO_ASSERT(buf != NULL);
    RHO_ASSERT(whence == SEEK_SET || whence == SEEK_CUR || whence == SEEK_END);

    /* TODO: check for overflows */
    switch (whence) {
    case SEEK_SET:
        newpos = offset;
        break;
    case SEEK_CUR:
        newpos = buf->pos + offset;
        break;
    case SEEK_END:
        newpos = buf->len + offset;
        break;
    default:
        rho_warn("invalid value (%d) for whence\n", whence);
        newpos = -1; 
        goto done;
    }
   
    if (newpos < 0) {
        rho_warn("tried to seek to negative index\n");
        newpos = -1; 
        goto done; 
    } 

    if ((size_t)newpos > buf->len)
        buf->len = newpos;

    if (((size_t)newpos) > buf->cap)
        rho_buf_grow(buf, newpos);

    buf->pos = newpos;

done:
    return (newpos);
}

/* 
 * ensure there is enough space to write len bytes
 */
void
rho_buf_ensure(struct rho_buf *buf, size_t len)
{
    off_t newpos = 0;

    RHO_ASSERT(buf != NULL);

    if (((size_t)(RHO_OFF_MAX - buf->pos)) < len)
        rho_die("signed integer overflow");

    newpos = buf->pos + len;
    if (((size_t)newpos) > buf->cap)
        rho_buf_grow(buf, newpos);
}

/* 
 * like truncate(2); note that we don't implement sparse bufs,
 * so, the call is responsible for updating pos appropriately.
 */
void
rho_buf_truncate(struct rho_buf *buf, off_t off)
{
    RHO_ASSERT(off > 0);

    if (((size_t)off) < buf->len) {
        buf->len = off;
        return;
    }

    if (((size_t)off) == buf->len)
        return;

    if ( (((size_t)off) > buf->len) && (((size_t)off) <= buf->cap) ) {
        memset(buf->data + buf->len, 0x00, ((size_t)off) - buf->len);
        buf->len = off;
    }

    if (((size_t)off) < buf->cap) {
        rho_buf_grow(buf, off);
        memset(buf->data + buf->len, 0x00, buf->cap - buf->len);
        buf->len = off;
    }
    
    if (((size_t)buf->pos) > buf->len)
        rho_warn("after truncation, pos > len");
}

/* TODO: we should have a high water mark whereby, if the buffer
 * exceeds this mark, we realloc the buffer to a smaller size;
 * this prevents long-lived, monotonically increasing buffers.
 * This goes for rho_buf_truncate as well.
 *
 * This is a conveninence function and is the same as:
 *  rho_truncate(buf, 0)
 *  rho_seek(buf, 0, SEEK_SET);
 */
void
rho_buf_clear(struct rho_buf *buf)
{
    RHO_ASSERT(buf != NULL);
    memset(buf->data, 0x00, buf->cap);  /* XXX: necessary? */
    buf->len = 0;
    buf->pos = 0;
}

/* 
 * This is unsafe, so make sure you know what you're doing 
 * If the offset is past the buffer (in either direction),
 * return NULL.
 */
void *
rho_buf_raw(const struct rho_buf *buf, off_t offset, int whence)
{
    off_t curoff = 0;

    /* TODO: check for overflows */
    switch (whence) {
    case SEEK_SET:
        curoff = offset;
        break;
    case SEEK_CUR:
        curoff = buf->pos + offset;
        break;
    case SEEK_END:
        curoff = buf->len + offset;
        break;
    default:
        rho_warn("invalid value (%d) for whence", whence);
        goto fail;
    }
   
    if (curoff < 0) {
        rho_warn("tried to seek to negative index");
        goto fail; 
    } 

    /* OK for curoff == len */
    if (((size_t)curoff) > buf->len) {
        rho_warn("offset (%jd) would be past buf length (%zu)",
                (intmax_t)curoff, buf->len);
        goto fail;
    }

    return (buf->data + curoff);

fail:
    return (NULL);
}

size_t
rho_buf_length(const struct rho_buf *buf)
{
    RHO_ASSERT(buf != NULL);
    return (buf->len);
}

size_t
rho_buf_left(const struct rho_buf *buf)
{
    return (buf->len - buf->pos);
}

/* XXX: unsafe -- needed by rho_sock_precvn_buf */
void
rho_buf_setlength(struct rho_buf *buf, size_t len)
{
    buf->len = len;
}

/*
 * 8-bit unsigned
 */

int
rho_buf_preadu8_at(struct rho_buf *buf, uint8_t *v, off_t offset)
{
    int error = 0;
    uint8_t x = 0;

    RHO_ASSERT(buf != NULL);
    RHO_ASSERT(v != NULL);

    if (((size_t)(RHO_OFF_MAX - offset)) < sizeof(x))
        rho_die("signed integer overflow");

    if ((offset + sizeof(x)) > buf->len) {
        error = -1;
        rho_warn("attempted read past end of buf");
        goto out;
    }

    x = *((uint8_t *)(buf->data + offset));
    *v = x;

out:
    return (error);
}

int
rho_buf_preadu8(struct rho_buf *buf, uint8_t *v)
{
    return (rho_buf_preadu8_at(buf, v, buf->pos));
}

int
rho_buf_readu8(struct rho_buf *buf, uint8_t *v)
{
    int error = rho_buf_preadu8_at(buf, v, buf->pos);
    if (error != -1)
        buf->pos += sizeof(*v);
    return (error);
}

void
rho_buf_pwriteu8_at(struct rho_buf *buf, uint8_t v, off_t offset)
{
    off_t newpos = 0;

    RHO_ASSERT(buf != NULL);

    if (((size_t)(RHO_OFF_MAX - offset)) < sizeof(v))
        rho_die("signed integer overflow");
        
    newpos = offset + sizeof(v);
    if (((size_t)newpos) > buf->cap) {
        if (buf->bounded) {
            rho_die("attempt to write past a bounded buffer");
        } else {
            rho_buf_grow(buf, newpos);
        }
    }

    buf->data[offset] = v;

    if (((size_t)newpos) > buf->len)
        buf->len = newpos;
}

void
rho_buf_pwriteu8(struct rho_buf *buf, uint8_t v)
{
    return (rho_buf_pwriteu8_at(buf, v, buf->pos));
}

void
rho_buf_writeu8(struct rho_buf *buf, uint8_t v)
{
    rho_buf_pwriteu8_at(buf, v, buf->pos);
    buf->pos += sizeof(v);
}

/*
 * 16-bit unsigned big-endian
 */
int
rho_buf_preadu16be_at(struct rho_buf *buf, uint16_t *v, off_t offset)
{
    int error = 0;
    uint16_t x = 0;

    RHO_ASSERT(buf != NULL);
    RHO_ASSERT(v != NULL);

    if (((size_t)(RHO_OFF_MAX - offset)) < sizeof(x))
        rho_die("signed integer overflow");
    
    if ((offset + sizeof(x)) > buf->len) {
        error = -1;
        rho_warn("attempts read past end of buf");
        goto out;
    }

    x = *((uint16_t *)(buf->data + offset));
    x = rho_be16toh(x);
    *v = x;

out:
    return (error);
}

int
rho_buf_preadu16be(struct rho_buf *buf, uint16_t *v)
{
    return (rho_buf_preadu16be_at(buf, v, buf->pos));
}

int
rho_buf_readu16be(struct rho_buf *buf, uint16_t *v)
{
    int error = rho_buf_preadu16be_at(buf, v, buf->pos);
    if (error != -1)
        buf->pos += sizeof(*v);
    return (error);
}

void
rho_buf_pwriteu16be_at(struct rho_buf *buf, uint16_t v, off_t offset)
{
    off_t newpos = 0;

    RHO_ASSERT(buf != NULL);

    if (((size_t)(RHO_OFF_MAX - offset)) < sizeof(v))
        rho_die("signed integer overflow");
        
    newpos = offset + sizeof(v);
    if (((size_t)newpos) > buf->cap) {
        if (buf->bounded) {
            rho_die("attempt to write past a bounded buffer");
        } else {
            rho_buf_grow(buf, newpos);
        }
    }

    v = rho_htobe16(v);
    memcpy(buf->data + offset, &v, sizeof(v));

    if (((size_t)newpos) > buf->len)
        buf->len = newpos;
}

void
rho_buf_pwriteu16be(struct rho_buf *buf, uint16_t v)
{
    return (rho_buf_pwriteu16be_at(buf, v, buf->pos));
}

void
rho_buf_writeu16be(struct rho_buf *buf, uint16_t v)
{
    rho_buf_pwriteu16be_at(buf, v, buf->pos);
    buf->pos += sizeof(v);
}

/*
 * 16-bit unsigned little-endian
 */
int
rho_buf_preadu16le_at(struct rho_buf *buf, uint16_t *v, off_t offset)
{
    int error = 0;
    uint16_t x = 0;

    RHO_ASSERT(buf != NULL);
    RHO_ASSERT(v != NULL);
    
    if (((size_t)(RHO_OFF_MAX - offset)) < sizeof(x))
        rho_die("signed integer overflow");

    if ((offset + sizeof(x)) > buf->len) {
        error = -1;
        rho_warn("attempts read past end of buf");
        goto out;
    }

    x = *((uint16_t *)(buf->data + offset));
    x = rho_le16toh(x);
    *v = x;

out:
    return (error);
}

int
rho_buf_preadu16le(struct rho_buf *buf, uint16_t *v)
{
    return (rho_buf_preadu16le_at(buf, v, buf->pos));
}

int
rho_buf_readu16le(struct rho_buf *buf, uint16_t *v)
{
    int error = rho_buf_preadu16le_at(buf, v, buf->pos);
    if (error != -1)
        buf->pos += sizeof(*v);
    return (error);
}

void
rho_buf_pwriteu16le_at(struct rho_buf *buf, uint16_t v, off_t offset)
{
    off_t newpos = 0;

    RHO_ASSERT(buf != NULL);

    if (((size_t)(RHO_OFF_MAX - offset)) < sizeof(v))
        rho_die("signed integer overflow");

    newpos = offset + sizeof(v);
    if (((size_t)newpos) > buf->cap) {
        if (buf->bounded) {
            rho_die("attempt to write past a bounded buffer");
        } else {
            rho_buf_grow(buf, newpos);
        }
    }

    v = rho_htole16(v);
    memcpy(buf->data + offset, &v, sizeof(v));
    buf->pos = newpos;

    if (((size_t)newpos) > buf->len)
        buf->len = newpos;
}

void
rho_buf_pwriteu16le(struct rho_buf *buf, uint16_t v)
{
    return (rho_buf_pwriteu16le_at(buf, v, buf->pos));
}

void
rho_buf_writeu16le(struct rho_buf *buf, uint16_t v)
{
    rho_buf_pwriteu16le_at(buf, v, buf->pos);
    buf->pos += sizeof(v);
}

/*
 * 32-bit unsigned big-endian
 */

int
rho_buf_preadu32be_at(struct rho_buf *buf, uint32_t *v, off_t offset)
{
    int error = 0;
    uint32_t x = 0;

    RHO_ASSERT(buf != NULL);
    RHO_ASSERT(v != NULL);

    if (((size_t)(RHO_OFF_MAX - offset)) < sizeof(x))
        rho_die("signed integer overflow");
    
    if ((offset + sizeof(x)) > buf->len) {
        error = -1;
        rho_warn("attempted read past end of buf (offset=%lld, len=%lu)",
                (long long)offset, buf->len);
        goto out;
    }

    x = *((uint32_t *)(buf->data + offset));
    x = rho_be32toh(x);
    *v = x;

out:
    return (error);
}

int
rho_buf_preadu32be(struct rho_buf *buf, uint32_t *v)
{
    return (rho_buf_preadu32be_at(buf, v, buf->pos));
}

int
rho_buf_readu32be(struct rho_buf *buf, uint32_t *v)
{
    int error = rho_buf_preadu32be_at(buf, v, buf->pos);
    if (error != -1)
        buf->pos += sizeof(*v);
    return (error);
}

void
rho_buf_pwriteu32be_at(struct rho_buf *buf, uint32_t v, off_t offset)
{
    off_t newpos = 0;

    RHO_ASSERT(buf != NULL);

    if (((size_t)(RHO_OFF_MAX - offset)) < sizeof(v))
        rho_die("signed integer overflow");

    newpos = offset + sizeof(v);
    if (((size_t)newpos) > buf->cap) {
        if (buf->bounded) {
            rho_die("attempt to write past a bounded buffer");
        } else {
            rho_buf_grow(buf, newpos);
        }
    }

    v = rho_htobe32(v);
    memcpy(buf->data + offset, &v, sizeof(v));

    if (((size_t)newpos) > buf->len)
        buf->len = newpos;
}

void
rho_buf_pwriteu32be(struct rho_buf *buf, uint32_t v)
{
    return (rho_buf_pwriteu32be_at(buf, v, buf->pos));
}

void
rho_buf_writeu32be(struct rho_buf *buf, uint32_t v)
{
    rho_buf_pwriteu32be_at(buf, v, buf->pos);
    buf->pos += sizeof(v);
}

/*
 * 32-bit unsigned little-endian
 */
int
rho_buf_preadu32le_at(struct rho_buf *buf, uint32_t *v, off_t offset)
{
    int error = 0;
    uint32_t x = 0;

    RHO_ASSERT(buf != NULL);
    RHO_ASSERT(v != NULL);

    if (((size_t)(RHO_OFF_MAX - offset)) < sizeof(x))
        rho_die("signed integer overflow");
    
    if ((offset + sizeof(x)) > buf->len) {
        error = -1;
        rho_warn("attempted read past end of buf");
        goto out;
    }

    x = *((uint32_t *)(buf->data + offset));
    x = rho_le32toh(x);
    *v = x;

out:
    return (error);
}

int
rho_buf_preadu32le(struct rho_buf *buf, uint32_t *v)
{
    return (rho_buf_preadu32le_at(buf, v, buf->pos));
}

int
rho_buf_readu32le(struct rho_buf *buf, uint32_t *v)
{
    int error = rho_buf_preadu32le_at(buf, v, buf->pos);
    if (error != -1)
        buf->pos += sizeof(*v);
    return (error);
}

void
rho_buf_pwriteu32le_at(struct rho_buf *buf, uint32_t v, off_t offset)
{
    off_t newpos = 0;

    RHO_ASSERT(buf != NULL);

    if (((size_t)(RHO_OFF_MAX - offset)) < sizeof(v))
        rho_die("signed integer overflow");

    newpos = offset + sizeof(v);
    if (((size_t)newpos) > buf->cap) {
        if (buf->bounded) {
            rho_die("attempt to write past a bounded buffer");
        } else {
            rho_buf_grow(buf, newpos);
        }
    }

    v = rho_htole32(v);
    memcpy(buf->data + offset, &v, sizeof(v));

    if (((size_t)newpos) > buf->len)
        buf->len = newpos;
}

void
rho_buf_pwriteu32le(struct rho_buf *buf, uint32_t v)
{
    return (rho_buf_pwriteu32le_at(buf, v, buf->pos));
}

void
rho_buf_writeu32le(struct rho_buf *buf, uint32_t v)
{
    rho_buf_pwriteu32le_at(buf, v, buf->pos);
    buf->pos += sizeof(v);
}

/*
 * 64-bit unsigned big-endian
 */
int
rho_buf_preadu64be_at(struct rho_buf *buf, uint64_t *v, off_t offset)
{
    int error = 0;
    uint64_t x = 0;

    RHO_ASSERT(buf != NULL);
    RHO_ASSERT(v != NULL);

    if (((size_t)(RHO_OFF_MAX - offset)) < sizeof(x))
        rho_die("signed integer overflow");
    
    if ((offset + sizeof(x)) > buf->len) {
        error = -1;
        rho_warn("attempted read past end of buf");
        goto out;
    }

    x = *((uint64_t *)(buf->data + offset));
    x = rho_be64toh(x);
    *v = x;

out:
    return (error);
}

int
rho_buf_preadu64be(struct rho_buf *buf, uint64_t *v)
{
    return (rho_buf_preadu64be_at(buf, v, buf->pos));
}

int
rho_buf_readu64be(struct rho_buf *buf, uint64_t *v)
{
    int error = rho_buf_preadu64be_at(buf, v, buf->pos);
    if (error != -1)
        buf->pos += sizeof(*v);
    return (error);
}

void
rho_buf_pwriteu64be_at(struct rho_buf *buf, uint64_t v, off_t offset)
{
    off_t newpos = 0;

    RHO_ASSERT(buf != NULL);

    if (((size_t)(RHO_OFF_MAX - offset)) < sizeof(v))
        rho_die("signed integer overflow");

    newpos = offset + sizeof(v);
    if (((size_t)newpos) > buf->cap) {
        if (buf->bounded) {
            rho_die("attempt to write past a bounded buffer");
        } else {
            rho_buf_grow(buf, newpos);
        }
    }

    v = rho_htobe64(v);
    memcpy(buf->data + offset, &v, sizeof(v));

    if (((size_t)newpos) > buf->len)
        buf->len = newpos;
}

void
rho_buf_pwriteu64be(struct rho_buf *buf, uint64_t v)
{
    return (rho_buf_pwriteu64be_at(buf, v, buf->pos));
}

void
rho_buf_writeu64be(struct rho_buf *buf, uint64_t v)
{
    rho_buf_pwriteu64be_at(buf, v, buf->pos);
    buf->pos += sizeof(v);
}

/*
 * 64-bit unsigned little-endian
 */

int
rho_buf_preadu64le_at(struct rho_buf *buf, uint64_t *v, off_t offset)
{
    int error = 0;
    uint64_t x = 0;

    RHO_ASSERT(buf != NULL);
    RHO_ASSERT(v != NULL);

    if (((size_t)(RHO_OFF_MAX - offset)) < sizeof(x))
        rho_die("signed integer overflow");
    
    if ((offset + sizeof(x)) > buf->len) {
        error = -1;
        rho_warn("attempted read past end of buf");
        goto out;
    }

    x = *((uint64_t *)(buf->data + offset));
    x = rho_le64toh(x);
    *v = x;

out:
    return (error);
}

int
rho_buf_preadu64le(struct rho_buf *buf, uint64_t *v)
{
    return (rho_buf_preadu64le_at(buf, v, buf->pos));
}

int
rho_buf_readu64le(struct rho_buf *buf, uint64_t *v)
{
    int error = rho_buf_preadu64le_at(buf, v, buf->pos);
    if (error != -1)
        buf->pos += sizeof(*v);
    return (error);
}

void
rho_buf_pwriteu64le_at(struct rho_buf *buf, uint64_t v, off_t offset)
{
    off_t newpos = 0;

    RHO_ASSERT(buf != NULL);
    
    if (((size_t)(RHO_OFF_MAX - offset)) < sizeof(v))
        rho_die("signed integer overflow");

    newpos = offset + sizeof(v);
    if (((size_t)newpos) > buf->cap) {
        if (buf->bounded) {
            rho_die("attempt to write past a bounded buffer");
        } else {
            rho_buf_grow(buf, newpos);
        }
    }

    v = rho_htole64(v);
    memcpy(buf->data + offset, &v, sizeof(v));

    if (((size_t)newpos) > buf->len)
        buf->len = newpos;
}

void
rho_buf_pwriteu64le(struct rho_buf *buf, uint64_t v)
{
    return (rho_buf_pwriteu64le_at(buf, v, buf->pos));
}

void
rho_buf_writeu64le(struct rho_buf *buf, uint64_t v)
{
    rho_buf_pwriteu64le_at(buf, v, buf->pos);
    buf->pos += sizeof(v);
}

/*
 * VECTOR
 */

size_t
rho_buf_read(struct rho_buf *buf, void *b, size_t len)
{
    size_t avail = 0;
    size_t n = 0;

    RHO_ASSERT(buf != NULL);
    RHO_ASSERT(b != NULL);
    RHO_ASSERT(len > 0);

    avail = buf->len - buf->pos;
    n = avail >= len ? len : avail;

    memcpy(b, buf->data + buf->pos, n);
    buf->pos += n;

    return (n);
}

void
rho_buf_write(struct rho_buf *buf, const void *b, size_t len)
{
    off_t newpos = 0;

    RHO_ASSERT(buf != NULL);
    RHO_ASSERT(b != NULL);

    if (((size_t)(RHO_OFF_MAX - buf->pos)) < len)
        rho_die("signed integer overflow");

    newpos = buf->pos + len;
    if (((size_t)newpos) > buf->cap) {
        if (buf->bounded) {
            rho_die("attempt to write past a bounded buffer");
        } else {
            rho_buf_grow(buf, newpos);
        }
    }

    memcpy(buf->data + buf->pos, b, len); 
    buf->pos = newpos;

    if (((size_t)buf->pos) > buf->len)
        buf->len = buf->pos;
}

/**********************************************************
 * BYTE ARRAY WITH A U32 SIZE PREFIX
 **********************************************************/

int
rho_buf_read_u32size_blob(struct rho_buf *buf, void *b, size_t len, size_t *ngot)
{
    int error = 0;
    uint32_t n = 0;
    size_t left = 0;

    rho_buf_readu32be(buf, &n);

    /* malformed */
    left = rho_buf_left(buf);
    if (left < n) {
        rho_warn("want %lu bytes, but only have %lu",
                (unsigned long)n, (unsigned long)left);
        error = -1;
        goto done;
    }

    /* too big to fit in s */
    if (n > len) {
        rho_warn("blob is %lu bytes, but buffer can only hold %lu",
                (unsigned long)n, (unsigned long)len);
        error = -1;
        goto done;
    }

    rho_buf_read(buf, b, n);
    if (ngot != NULL)
        *ngot = (size_t)n;

done:
    return (error);
}

void
rho_buf_write_u32size_blob(struct rho_buf *buf, const void *b, size_t len)
{
    rho_buf_writeu32be(buf, len);
    rho_buf_write(buf, b, len);
}

/**********************************************************
 * STRINGS
 **********************************************************/

static void
rho_buf_doputs(struct rho_buf *buf, bool nulterm, const char *s)
{
    off_t newpos = 0;
    size_t len = 0;

    RHO_ASSERT(buf != NULL);
    RHO_ASSERT(s != NULL);

    len = strlen(s);
    if (nulterm)
        len += 1;

    if (((size_t)(RHO_OFF_MAX - buf->pos)) < len)
        rho_die("signed integer overflow");

    newpos = buf->pos + len;
    if (((size_t)newpos) > buf->cap) {
        if (buf->bounded) {
            rho_die("attempt to write past a bounded buffer");
        } else {
            rho_buf_grow(buf, newpos);
        }
    }

    memcpy(buf->data + buf->pos, s, len); 
    buf->pos = newpos;

    if (((size_t)buf->pos) > buf->len)
        buf->len = buf->pos;
}

void
rho_buf_puts(struct rho_buf *buf, const char *s)
{
    rho_buf_doputs(buf, false, s);
}

void
rho_buf_puts_nul(struct rho_buf *buf, const char *s)
{
    rho_buf_doputs(buf, true, s);
}

/**********************************************************
 * STRINGS WITH A U32 SIZE PREFIX (aka, PASCAL STRINGS)
 **********************************************************/

/*
 * len is the number of bytes s can hold, including the nul.
 */
int
rho_buf_read_u32size_str(struct rho_buf *buf, char *s, size_t len)
{
    int error = 0;
    uint32_t n = 0;
    size_t left = 0;

    rho_buf_readu32be(buf, &n);

    /* malformed */
    left = rho_buf_left(buf);
    if (left < n) {
        rho_warn("want %lu bytes, but only have %lu",
                (unsigned long)n, (unsigned long)left);
        error = -1;
        goto done;
    }

    /* too big to fit in s */
    if ((n+1) > len) {
        rho_warn("string+nul is %lu bytes, but buffer can only hold %lu",
                (unsigned long)(n+1), (unsigned long)len);
        error = -1;
        goto done;
    }

    rho_buf_read(buf, s, n);

    /* nul terminate */
    s[n] = '\0';

done:
    return (error);
}

void
rho_buf_write_u32size_str(struct rho_buf *buf, const char *s)
{
    size_t len = strlen(s);
    rho_buf_writeu32be(buf, len);
    rho_buf_puts(buf, s);
}

/**********************************************************
 * OPERTAIONS WITH TWO RHO_BUFS
 **********************************************************/

void
rho_buf_append(struct rho_buf *buf, const struct rho_buf *a)
{
    off_t newpos = 0;

    RHO_ASSERT(buf != NULL);
    RHO_ASSERT(a != NULL);

    if (((size_t)(RHO_OFF_MAX - buf->pos)) < buf->len)
        rho_die("signed integer overflow");

    newpos = buf->pos + buf->len;
    if (((size_t)newpos) > buf->cap) {
        if (buf->bounded) {
            rho_die("attempt to write past a bounded buffer");
        } else {
            rho_buf_grow(buf, newpos);
        }
    }

    memcpy(buf->data + buf->pos, a->data, a->len); 
    buf->pos = newpos;
    
    if (((size_t)buf->pos) > buf->len)
        buf->len = buf->pos;
}
