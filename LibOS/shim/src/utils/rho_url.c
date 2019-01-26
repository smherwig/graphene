#include <stdbool.h>
#include <string.h>

#include <shim_internal.h>
#include <shim_utils.h>

#include <rho_buf.h>
#include <rho_mem.h>
#include <rho_url.h>

/* RFC 2396 
 *
 * <url> ::= <scheme>://<authority>/<path>;<params>?<query>#<fragment>
 * <authority> :== <userinfo>@<host>:<port>
 * <userinfo> :== <user[:<password>]
 * <path> :: = {<segment>/}<segment>
 *
 *
 * The leading / is parth of path.
 */

struct rho_url *
rho_url_parse(const char *s)
{
    struct rho_url *url = NULL;
    char *copy = NULL;
    char *cur = NULL;
    char *mark = NULL;;

    debug("> rho_url_parse(s=%s)\n", s);

    if (s == NULL || strlen(s) == 0) {
        /* error */
        goto done;
    }

    copy = rhoL_strdup(s);
    cur = copy;

    url = rhoL_zalloc(sizeof(*url));

    /*
     * fragment
     */
    mark = strrchr(cur, '#');
    if (mark != NULL) {
        url->fragment = strdup(mark + 1);
        *mark = '\0';
    }

    /* 
     * scheme 
     *
     * TODO: check valid chars
     */
    mark = strchr(cur, ':');
    if (mark != NULL) {
        url->scheme = rhoL_strndup(s, mark - cur);
        cur = mark + 1;
    }

    if (strncmp(cur, "//", 2) == 0)
        cur += 2;

    /* 
     * authority 
     */
    mark = strchr(cur, '/');
    if (mark != NULL) {
        url->authority = rhoL_strndup(cur, mark - cur);
        cur = mark + 1;
    } else {
        url->authority = rhoL_strdup(cur);
        goto  authority;
    }
    
    /*
     * query 
     */
    mark = strchr(cur, '?');
    if (mark != NULL) {
        url->query = rhoL_strdup(mark + 1);
        *mark = '\0';
    }

    /*
     * params
     */
    mark = strchr(cur, ';');
    if (mark != NULL) {
        url->params = rhoL_strdup(mark + 1);
        *mark = '\0';
    }

    /* 
     * path 
     * 
     * whatever is left; backup to get leading '/'
     */
    cur -= 1;
    url->path = rhoL_strdup(cur);

    if (url->authority == NULL)
        goto done;

authority:
    /*
     * userinfo
     */
    cur = url->authority;
    mark = strchr(cur, '@');
    if (mark != NULL) {
        url->userinfo = rhoL_strndup(cur, mark - cur);
        cur = mark + 1;
    }

    /*
     * port,host
     */
    mark = strchr(cur, ':');
    if (mark != NULL) {
        url->port = rhoL_strdup(mark + 1);
        url->host = rhoL_strndup(cur, mark - cur);
    } else {
        url->host = rhoL_strdup(cur);
    }

    /* 
     * TODO: IPv6 host 
     * I think this is just removeing the brackets in [ipv6addr].
     */
     
    /* 
     * user, password 
     */
    if (url->userinfo == NULL)
        goto done;

    cur = url->userinfo;
    mark = strchr(cur, ':');
    if (mark != NULL) {
        url->user = rhoL_strndup(cur, mark - cur);
        url->password = rhoL_strdup(mark + 1);
    } else {
        url->user = rhoL_strdup(url->userinfo);
    }

done:
    if (copy != NULL)
        rhoL_free(copy);

    debug("< rho_url_parse => scheme=%s, path=%s\n",
            url->scheme, url->path);
    return (url);
}

void
rho_url_destroy(struct rho_url *url)
{
    if (url->scheme != NULL)    rhoL_free(url->scheme);
    if (url->authority != NULL) rhoL_free(url->authority);
    if (url->userinfo != NULL)  rhoL_free(url->userinfo);
    if (url->user != NULL)      rhoL_free(url->user);
    if (url->password != NULL)  rhoL_free(url->password);
    if (url->host != NULL)      rhoL_free(url->host);
    if (url->port != NULL)      rhoL_free(url->port);
    if (url->path != NULL)      rhoL_free(url->path);
    if (url->params != NULL)    rhoL_free(url->params);
    if (url->query != NULL)     rhoL_free(url->query);
    if (url->fragment != NULL)  rhoL_free(url->fragment);
}
