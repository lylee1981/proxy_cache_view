关于
================

查看 nginx proxy cache 缓存文件有效期，文件路径，缓存Key，缓存文件响应头  
整个模块的实现，参照 ngx_cache_purge 来实现的。  

示例配置  
===============================================  
    http {
        proxy_cache_path        /var/proxy_cache levels=1:2 keys_zone=tmpcache:1    024m inactive=15d max_size=1g;

        server {
            location / {
                proxy_pass         http://127.0.0.1:8000;
                proxy_cache        tmpcache;
                proxy_cache_key    $uri$is_args$args;
            }

            location ~ /cacheview(/.*) {
                allow              127.0.0.1;
                deny               all;
                proxy_cache_view  tmpcache $1$is_args$args;
            }
        }
    }


指令说明
-----------------
* **syntax**: `proxy_cache_view zone_name key`
* **default**: `none`
* **context**: `location`

Sets area and key used for purging selected pages from `proxy`'s cache.

调用和输出  
-----------------
curl "http://www.che168.com/cacheview/exists.html" -x 192.168.193.1:80  

Key: /exists.html  
Path: /var/proxy_cache/1/c7/ce0bd73c10ff87305234ef84f5943c71  
`Valid: of-file: 1416929775 now: 1416929788 diff: -13  

HTTP/1.1 200 OK  
Server: nginx/1.4.2  
Date: Tue, 25 Nov 2014 15:36:10 GMT  
Content-Type: text/html  
Content-Length: 19  
Last-Modified: Fri, 14 Mar 2014 05:29:08 GMT  
Connection: close  
ETag: "532293a4-13"  
Cache-Control: max-age=5  
Accept-Ranges: bytes  

输出说明  
-----------------
Key：   缓存Key  
Path：  缓存文件路径  
Valid： 缓存有效期信息。 
        of-file：缓存文件中的绝对时间（UTC）     
        now：查询时的系统当前时间（UTC）  
        diff: 二者的差值，负数代表缓存已经过期的秒数。正数代表缓存还剩余的有效期时间（秒）  

最后一部分是缓存文件完整相应头信息  

