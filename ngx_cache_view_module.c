#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#if (NGX_HTTP_CACHE)

typedef struct {
    ngx_flag_t                    enable;
    ngx_str_t                     method;
    ngx_array_t                  *access;   /* array of ngx_in_cidr_t */
    ngx_array_t                  *access6;  /* array of ngx_in6_cidr_t */
} ngx_http_cache_view_conf_t;

typedef struct {
    ngx_http_cache_view_conf_t    proxy;

    ngx_http_cache_view_conf_t   *conf;
    ngx_http_handler_pt           handler;
    ngx_http_handler_pt           original_handler;
} ngx_http_cache_view_loc_conf_t;

char       *ngx_http_proxy_cache_view_conf(ngx_conf_t *cf,
                ngx_command_t *cmd, void *conf);
ngx_int_t   ngx_http_proxy_cache_view_handler(ngx_http_request_t *r);

ngx_int_t   ngx_http_cache_view_access_handler(ngx_http_request_t *r);
ngx_int_t   ngx_http_cache_view_access(ngx_array_t *a, ngx_array_t *a6,
    struct sockaddr *s);

ngx_int_t   ngx_http_cache_view_send_response(ngx_http_request_t *r);
ngx_int_t   ngx_http_cache_view_init(ngx_http_request_t *r,
    ngx_http_file_cache_t *cache, ngx_http_complex_value_t *cache_key);
void        ngx_http_cache_view_handler(ngx_http_request_t *r);

ngx_int_t   ngx_http_file_cache_view(ngx_http_request_t *r);

char       *ngx_http_cache_view_conf(ngx_conf_t *cf,
    ngx_http_cache_view_conf_t *cpcf);

void       *ngx_http_cache_view_create_loc_conf(ngx_conf_t *cf);
char       *ngx_http_cache_view_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);

static ngx_command_t  ngx_http_cache_view_module_commands[] = {

    { ngx_string("proxy_cache_view"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_proxy_cache_view_conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};

static ngx_http_module_t  ngx_http_cache_view_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_cache_view_create_loc_conf,  /* create location configuration */
    ngx_http_cache_view_merge_loc_conf    /* merge location configuration */
};

ngx_module_t  ngx_http_cache_view_module = {
    NGX_MODULE_V1,
    &ngx_http_cache_view_module_ctx,      /* module context */
    ngx_http_cache_view_module_commands,  /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

//static char ngx_http_cache_view_success_page_top[] =
//"<html>" CRLF
//"<head><title>Successful view</title></head>" CRLF
//"<body bgcolor=\"white\">" CRLF
//"<center><h1>Successful view</h1>" CRLF
//;

//static char ngx_http_cache_view_success_page_tail[] =
//CRLF "</center>" CRLF
//"<hr><center>" NGINX_VER "</center>" CRLF
//"</body>" CRLF
//"</html>" CRLF
//;

extern ngx_module_t  ngx_http_proxy_module;

typedef struct {
    ngx_str_t                      key_start;
    ngx_str_t                      schema;
    ngx_str_t                      host_header;
    ngx_str_t                      port;
    ngx_str_t                      uri;
} ngx_http_proxy_vars_t;

typedef struct {
    ngx_http_upstream_conf_t       upstream;

    ngx_array_t                   *flushes;
    ngx_array_t                   *body_set_len;
    ngx_array_t                   *body_set;
    ngx_array_t                   *headers_set_len;
    ngx_array_t                   *headers_set;
    ngx_hash_t                     headers_set_hash;

    ngx_array_t                   *headers_source;
#  if defined(nginx_version) && (nginx_version < 8040)
    ngx_array_t                   *headers_names;
#  endif /* nginx_version < 8040 */

    ngx_array_t                   *proxy_lengths;
    ngx_array_t                   *proxy_values;

    ngx_array_t                   *redirects;
#  if defined(nginx_version) && (nginx_version >= 1001015)
    ngx_array_t                   *cookie_domains;
    ngx_array_t                   *cookie_paths;
#  endif /* nginx_version >= 1001015 */

    ngx_str_t                      body_source;

    ngx_str_t                      method;
    ngx_str_t                      location;
    ngx_str_t                      url;

    ngx_http_complex_value_t       cache_key;

    ngx_http_proxy_vars_t          vars;

    ngx_flag_t                     redirect;

#  if defined(nginx_version) && (nginx_version >= 1001004)
    ngx_uint_t                     http_version;
#  endif /* nginx_version >= 1001004 */

    ngx_uint_t                     headers_hash_max_size;
    ngx_uint_t                     headers_hash_bucket_size;
} ngx_http_proxy_loc_conf_t;

char *
ngx_http_proxy_cache_view_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_compile_complex_value_t   ccv;
    ngx_http_cache_view_loc_conf_t   *cplcf;
    ngx_http_core_loc_conf_t          *clcf;
    ngx_http_proxy_loc_conf_t         *plcf;
    ngx_str_t                         *value;

    cplcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_cache_view_module);

    /* check for duplicates / collisions */
    if (cplcf->proxy.enable != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    if (cf->args->nelts != 3) {
        return ngx_http_cache_view_conf(cf, &cplcf->proxy);
    }

    if (cf->cmd_type & (NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF)) {
        return "(separate location syntax) is not allowed here";
    }

    plcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_proxy_module);

    if (plcf->upstream.cache != NGX_CONF_UNSET_PTR
        && plcf->upstream.cache != NULL)
    {
        return "is incompatible with \"proxy_cache\"";
    }

    if (plcf->upstream.upstream || plcf->proxy_lengths) {
        return "is incompatible with \"proxy_pass\"";
    }

    if (plcf->upstream.store > 0 || plcf->upstream.store_lengths) {
        return "is incompatible with \"proxy_store\"";
    }

    value = cf->args->elts;

    /* set proxy_cache part */
    plcf->upstream.cache = ngx_shared_memory_add(cf, &value[1], 0,
                                                 &ngx_http_proxy_module);
    if (plcf->upstream.cache == NULL) {
        return NGX_CONF_ERROR;
    }

    /* set proxy_cache_key part */
    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = &plcf->cache_key;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    /* set handler */
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    cplcf->proxy.enable = 0;
    clcf->handler = ngx_http_proxy_cache_view_handler;

    return NGX_CONF_OK;
}

ngx_int_t
ngx_http_proxy_cache_view_handler(ngx_http_request_t *r)
{
    ngx_http_proxy_loc_conf_t  *plcf;

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);

    if (ngx_http_cache_view_init(r, plcf->upstream.cache->data,
                                  &plcf->cache_key)
        != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

#  if defined(nginx_version) && (nginx_version >= 8011)
    r->main->count++;
#  endif

    ngx_http_cache_view_handler(r);

    return NGX_DONE;
}

ngx_int_t
ngx_http_cache_view_access_handler(ngx_http_request_t *r)
{
    ngx_http_cache_view_loc_conf_t   *cplcf;

    cplcf = ngx_http_get_module_loc_conf(r, ngx_http_cache_view_module);

    if (r->method_name.len != cplcf->conf->method.len
        || (ngx_strncmp(r->method_name.data, cplcf->conf->method.data,
                        r->method_name.len)))
    {
        return cplcf->original_handler(r);
    }

    if ((cplcf->conf->access || cplcf->conf->access6)
         && ngx_http_cache_view_access(cplcf->conf->access,
                                        cplcf->conf->access6,
                                        r->connection->sockaddr) != NGX_OK)
    {
        return NGX_HTTP_FORBIDDEN;
    }

    if (cplcf->handler == NULL) {
        return NGX_HTTP_NOT_FOUND;
    }

    return cplcf->handler(r);
}

ngx_int_t
ngx_http_cache_view_access(ngx_array_t *access, ngx_array_t *access6,
    struct sockaddr *s)
{
    in_addr_t         inaddr;
    ngx_in_cidr_t    *a;
    ngx_uint_t        i;
# if (NGX_HAVE_INET6)
    struct in6_addr  *inaddr6;
    ngx_in6_cidr_t   *a6;
    u_char           *p;
    ngx_uint_t        n;
# endif /* NGX_HAVE_INET6 */

    switch (s->sa_family) {
    case AF_INET:
        if (access == NULL) {
            return NGX_DECLINED;
        }

        inaddr = ((struct sockaddr_in *) s)->sin_addr.s_addr;

# if (NGX_HAVE_INET6)
    ipv4:
# endif /* NGX_HAVE_INET6 */

        a = access->elts;
        for (i = 0; i < access->nelts; i++) {
            if ((inaddr & a[i].mask) == a[i].addr) {
                return NGX_OK;
            }
        }

        return NGX_DECLINED;

# if (NGX_HAVE_INET6)
    case AF_INET6:
        inaddr6 = &((struct sockaddr_in6 *) s)->sin6_addr;
        p = inaddr6->s6_addr;

        if (access && IN6_IS_ADDR_V4MAPPED(inaddr6)) {
            inaddr = p[12] << 24;
            inaddr += p[13] << 16;
            inaddr += p[14] << 8;
            inaddr += p[15];
            inaddr = htonl(inaddr);

            goto ipv4;
        }

        if (access6 == NULL) {
            return NGX_DECLINED;
        }

        a6 = access6->elts;
        for (i = 0; i < access6->nelts; i++) {
            for (n = 0; n < 16; n++) {
                if ((p[n] & a6[i].mask.s6_addr[n]) != a6[i].addr.s6_addr[n]) {
                    goto next;
                }
            }

            return NGX_OK;

        next:
            continue;
        }

        return NGX_DECLINED;
# endif /* NGX_HAVE_INET6 */
    }

    return NGX_DECLINED;
}

ngx_int_t
ngx_http_cache_view_send_response(ngx_http_request_t *r)
{
    ngx_chain_t   out;
    ngx_buf_t    *b;
    ngx_buf_t    *header;
    ngx_str_t    *key;
    ngx_int_t     rc;
	
	ngx_http_cache_t       *c;

    size_t        len;
	size_t        cache_valid_len;
	size_t        cache_header_len;

	time_t        now;
	time_t        valid;
	u_char        valid_buffer[1024];

	ngx_uint_t    match_cr;
	ngx_uint_t    match_lf;
	size_t        headers_count;

	u_char        ch;
	u_char       *p;

	headers_count = 0;
	match_cr = 0;
	match_lf = 0;

	c = r->cache;
	cache_header_len = c->body_start - c->header_start;

	header = c->buf;
	header->pos += c->header_start;
	header->last = header->pos + c->body_start - c->header_start;

	now = ngx_time();
	valid = r->cache->valid_sec - now;

	ngx_memzero(valid_buffer, 1024);

	//calc cache valid content length
	cache_valid_len = ngx_sprintf(valid_buffer, "</br>Valid: of-file: %T now: %T diff: %T%s%s%Z",
			r->cache->valid_sec, now, valid, CRLF, "</br>") - valid_buffer - 1;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			"cache file cache valid: %T %T %T",
	        r->cache->valid_sec, now, valid);

    key = r->cache->keys.elts;

	//calc headers count
	for(p = header->pos; p < header->last; p++) {
		ch = *p;
		if (ch == CR) {
			match_cr = 1;
		}

		if (ch == LF) {
			match_lf = 1;
		}

		if (match_cr && match_lf) {
			headers_count++;
			match_cr = 0;
			match_lf = 0;
		}
	}

    len = sizeof("Key: ") -1 + key[0].len + sizeof(CRLF)
		  + sizeof("</br>Path: ") -1 + r->cache->file.name.len + sizeof(CRLF)
		  + cache_valid_len
		  + cache_header_len
		  + (sizeof("</br>") -1) * headers_count;

    r->headers_out.content_type.len = sizeof("text/html") - 1;
    r->headers_out.content_type.data = (u_char *) "text/html";
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = len;

    if (r->method == NGX_HTTP_HEAD) {
        rc = ngx_http_send_header(r);
        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }
    }

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    out.buf = b;
    out.next = NULL;

    b->last = ngx_cpymem(b->last, "Key: ", sizeof("Key: ") - 1);
    b->last = ngx_cpymem(b->last, key[0].data, key[0].len);
	b->last = ngx_cpymem(b->last, CRLF, sizeof(CRLF));
    
	b->last = ngx_cpymem(b->last, "</br>Path: ", sizeof("</br>Path: ") - 1);
    b->last = ngx_cpymem(b->last, r->cache->file.name.data,
                         r->cache->file.name.len);
	b->last = ngx_cpymem(b->last, CRLF, sizeof(CRLF));

	//valid buffer contains CRLF and double </br>
	b->last = ngx_cpymem(b->last, valid_buffer, cache_valid_len);

	len = 0;
	for(p = header->pos; p < header->last; p++) {
		len++;
		ch = *p;
		if (ch == CR) {
			match_cr = 1;
		}

		if (ch == LF) {
			match_lf = 1;
		}

		if (match_cr && match_lf) {
			b->last = ngx_cpymem(b->last, "</br>", sizeof("</br>") - 1);
			b->last = ngx_cpymem(b->last, header->pos, len);
			header->pos += len;
			len = 0;

			match_cr = 0;
			match_lf = 0;
		}
	}

    b->last_buf = 1;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
       return rc;
    }

    return ngx_http_output_filter(r, &out);
}

ngx_int_t
ngx_http_cache_view_init(ngx_http_request_t *r, ngx_http_file_cache_t *cache,
    ngx_http_complex_value_t *cache_key)
{
    ngx_http_cache_t  *c;
    ngx_str_t         *key;
    ngx_int_t          rc;

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    c = ngx_pcalloc(r->pool, sizeof(ngx_http_cache_t));
    if (c == NULL) {
        return NGX_ERROR;
    }

    rc = ngx_array_init(&c->keys, r->pool, 1, sizeof(ngx_str_t));
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    key = ngx_array_push(&c->keys);
    if (key == NULL) {
        return NGX_ERROR;
    }

    rc = ngx_http_complex_value(r, cache_key, key);
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    r->cache = c;
    c->body_start = ngx_pagesize;
    c->file_cache = cache;
    c->file.log = r->connection->log;

    ngx_http_file_cache_create_key(r);

    return NGX_OK;
}

void
ngx_http_cache_view_handler(ngx_http_request_t *r)
{
    ngx_int_t  rc;

#  if (NGX_HAVE_FILE_AIO)
    if (r->aio) {
        return;
    }
#  endif

    rc = ngx_http_file_cache_view(r);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http file cache view: %i, \"%s\"",
                   rc, r->cache->file.name.data);

    switch (rc) {
    case NGX_OK:
        r->write_event_handler = ngx_http_request_empty_handler;
        ngx_http_finalize_request(r, ngx_http_cache_view_send_response(r));
        return;
    case NGX_DECLINED:
        ngx_http_finalize_request(r, NGX_HTTP_NOT_FOUND);
        return;
#  if (NGX_HAVE_FILE_AIO)
    case NGX_AGAIN:
        r->write_event_handler = ngx_http_cache_view_handler;
        return;
#  endif
    default:
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
    }
}

ngx_int_t
ngx_http_file_cache_view(ngx_http_request_t *r)
{
	ngx_http_file_cache_t  *cache;
    ngx_http_cache_t       *c;

    switch (ngx_http_file_cache_open(r)) {
    case NGX_OK:
    case NGX_HTTP_CACHE_STALE:
#  if defined(nginx_version) \
      && ((nginx_version >= 8001) \
          || ((nginx_version < 8000) && (nginx_version >= 7060)))
    case NGX_HTTP_CACHE_UPDATING:
#  endif
        break;
    case NGX_DECLINED:
        return NGX_DECLINED;
#  if (NGX_HAVE_FILE_AIO)
    case NGX_AGAIN:
        return NGX_AGAIN;
#  endif
    default:
        return NGX_ERROR;
    }

    c = r->cache;
	cache = c->file_cache;
    /*
     * delete file from disk but *keep* in-memory node,
     * because other requests might still point to it.
     */

    ngx_shmtx_lock(&cache->shpool->mutex);

#  if defined(nginx_version) \
      && ((nginx_version >= 8001) \
          || ((nginx_version < 8000) && (nginx_version >= 7060)))
    c->node->updating = 0;
#  endif

	c->updating = 0;
    ngx_shmtx_unlock(&cache->shpool->mutex);

    /* file deleted from cache */
    return NGX_OK;
}

char *
ngx_http_cache_view_conf(ngx_conf_t *cf, ngx_http_cache_view_conf_t *cpcf)
{
    ngx_cidr_t       cidr;
    ngx_in_cidr_t   *access;
# if (NGX_HAVE_INET6)
    ngx_in6_cidr_t  *access6;
# endif /* NGX_HAVE_INET6 */
    ngx_str_t       *value;
    ngx_int_t        rc;
    ngx_uint_t       i;

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, (u_char *) "off") == 0) {
        cpcf->enable = 0;
        return NGX_CONF_OK;

    } else if (ngx_strcmp(value[1].data, (u_char *) "on") == 0) {
        ngx_str_set(&cpcf->method, "VIEW");

    } else {
        cpcf->method = value[1];
    }

    if (cf->args->nelts < 4) {
        cpcf->enable = 1;
        return NGX_CONF_OK;
    }

    /* sanity check */
    if (ngx_strcmp(value[2].data, (u_char *) "from") != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\", expected"
                           " \"from\" keyword", &value[2]);
        return NGX_CONF_ERROR;
    }

    if (ngx_strcmp(value[3].data, (u_char *) "all") == 0) {
        cpcf->enable = 1;
        return NGX_CONF_OK;
    }

    for (i = 3; i < cf->args->nelts; i++) {
        rc = ngx_ptocidr(&value[i], &cidr);

        if (rc == NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid parameter \"%V\"", &value[i]);
            return NGX_CONF_ERROR;
        }

        if (rc == NGX_DONE) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                               "low address bits of %V are meaningless",
                               &value[i]);
        }

        switch (cidr.family) {
        case AF_INET:
            if (cpcf->access == NULL) {
                cpcf->access = ngx_array_create(cf->pool, cf->args->nelts - 3,
                                                sizeof(ngx_in_cidr_t));
                if (cpcf->access == NULL) {
                    return NGX_CONF_ERROR;
                }
            }

            access = ngx_array_push(cpcf->access);
            if (access == NULL) {
                return NGX_CONF_ERROR;
            }

            access->mask = cidr.u.in.mask;
            access->addr = cidr.u.in.addr;

            break;

# if (NGX_HAVE_INET6)
        case AF_INET6:
            if (cpcf->access6 == NULL) {
                cpcf->access6 = ngx_array_create(cf->pool, cf->args->nelts - 3,
                                                 sizeof(ngx_in6_cidr_t));
                if (cpcf->access6 == NULL) {
                    return NGX_CONF_ERROR;
                }
            }

            access6 = ngx_array_push(cpcf->access6);
            if (access6 == NULL) {
                return NGX_CONF_ERROR;
            }

            access6->mask = cidr.u.in6.mask;
            access6->addr = cidr.u.in6.addr;

            break;
# endif /* NGX_HAVE_INET6 */
        }
    }

    cpcf->enable = 1;

    return NGX_CONF_OK;
}

void
ngx_http_cache_view_merge_conf(ngx_http_cache_view_conf_t *conf,
    ngx_http_cache_view_conf_t *prev)
{
    if (conf->enable == NGX_CONF_UNSET) {
        if (prev->enable == 1) {
            conf->enable = prev->enable;
            conf->method = prev->method;
            conf->access = prev->access;
            conf->access6 = prev->access6;

        } else {
            conf->enable = 0;
        }
    }
}

void *
ngx_http_cache_view_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_cache_view_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_cache_view_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->*.method = { 0, NULL }
     *     conf->*.access = NULL
     *     conf->*.access6 = NULL
     */

    conf->proxy.enable = NGX_CONF_UNSET;

    conf->conf = NGX_CONF_UNSET_PTR;
    conf->handler = NGX_CONF_UNSET_PTR;
    conf->original_handler = NGX_CONF_UNSET_PTR;

    return conf;
}

char *
ngx_http_cache_view_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_cache_view_loc_conf_t  *prev = parent;
    ngx_http_cache_view_loc_conf_t  *conf = child;
    ngx_http_core_loc_conf_t         *clcf;
    ngx_http_proxy_loc_conf_t        *plcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    ngx_http_cache_view_merge_conf(&conf->proxy, &prev->proxy);

    if (conf->proxy.enable && clcf->handler != NULL) {
        plcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_proxy_module);

        if (plcf->upstream.upstream || plcf->proxy_lengths) {
            conf->conf = &conf->proxy;
            conf->handler = plcf->upstream.cache
                          ? ngx_http_proxy_cache_view_handler : NULL;
            conf->original_handler = clcf->handler;

            clcf->handler = ngx_http_cache_view_access_handler;

            return NGX_CONF_OK;
        }
    }

    ngx_conf_merge_ptr_value(conf->conf, prev->conf, NULL);
    ngx_conf_merge_ptr_value(conf->handler, prev->handler, NULL);
    ngx_conf_merge_ptr_value(conf->original_handler, prev->original_handler,
                             NULL);

    return NGX_CONF_OK;
}

#else /* !NGX_HTTP_CACHE */

static ngx_http_module_t  ngx_http_cache_view_module_ctx = {
    NULL,  /* preconfiguration */
    NULL,  /* postconfiguration */

    NULL,  /* create main configuration */
    NULL,  /* init main configuration */

    NULL,  /* create server configuration */
    NULL,  /* merge server configuration */

    NULL,  /* create location configuration */
    NULL,  /* merge location configuration */
};

ngx_module_t  ngx_http_cache_view_module = {
    NGX_MODULE_V1,
    &ngx_http_cache_view_module_ctx,  /* module context */
    NULL,                              /* module directives */
    NGX_HTTP_MODULE,                   /* module type */
    NULL,                              /* init master */
    NULL,                              /* init module */
    NULL,                              /* init process */
    NULL,                              /* init thread */
    NULL,                              /* exit thread */
    NULL,                              /* exit process */
    NULL,                              /* exit master */
    NGX_MODULE_V1_PADDING
};

#endif /* NGX_HTTP_CACHE */
