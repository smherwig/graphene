#ifndef _RHO_STR_H_
#define _RHO_STR_H_

#include <stdbool.h>
#include <stdint.h>

#include <rho_decls.h>

RHO_DECLS_BEGIN

#define RHO_STR_WHITESPACE " \t\n\v\f\r"

short rho_str_toshort(const char *s, int base);
unsigned short rho_str_toushort(const char *s, int base);
int rho_str_toint(const char *s, int base);
unsigned int rho_str_touint(const char *s, int base);

uint8_t rho_str_touint8(const char *s, int base);
int8_t rho_str_toint8(const char *s, int base);
uint16_t rho_str_touint16(const char *s, int base);
int16_t rho_str_toint16(const char *s, int base);
uint32_t rho_str_touint32(const char *s, int base);
int32_t rho_str_toint32(const char *s, int base);


bool rho_str_equal(const char *s1, const char *s2);
bool rho_str_equal_ignore(const char *s1, const char *s2, const char *ignore);
bool rho_str_equal_ci(const char *s1, const char *s2);
bool rho_str_equal_ci_ignore(const char *s1, const char *s2, 
        const char *ignore);
bool rho_str_startswith(const char *s, const char *prefix);
bool rho_str_startswith_ci(const char *s, const char *prefix);
bool rho_str_endswith(const char *s, const char *suffix);
bool rho_str_endswith_ci(const char *s, const char *suffix);

void rho_str_array_destroy(char **array);
char ** rho_str_splitc(const char *s, char c, size_t *n);

char * rho_str_lstrip_alloc(const char *s, const char *removeset);
char * rho_str_lstrip(char *s, const char *removeset);
char * rho_str_rstrip_alloc(const char *s, const char *removeset);
char * rho_str_rstrip(char *s, const char *removeset);

/* TODO:
 * rho_str_splits s
 * rho_str_join
 */

RHO_DECLS_END

#endif /* ! _RHO_STR_H_ */
