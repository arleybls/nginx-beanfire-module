nginx-beanfire-module
=====================

Non-blocking fire-and-forget logging to beanstalk with asynchronous socket control:

- Support JSON and Nginx logging format; 
- One dedicated socket per worker process; 
- Conservative use o file-descriptors; 
- Asynchronous evloop to handle POLLHUP/POLLERR events;
- Multi-location support; 

Configuration example:
```
http {
    beanfire_server     a.b.c.d;
    beanfire_port       11300;
    beanfire_retries    60;
    beanfire_polling    60;             # 1 minute polling
    ...
    server {
      ...
      beanfire_enable on;
      beanfire_json   on;
      beanfire_tube   site_log;
      beanfire_pri    0;
      beanfire_delay  10;
      beanfire_ttr    120;
      ...
      location /foo {
        ...
        beanfire_json   off;
        beanfire_tube   location_log;
```       

JSON Format example:
```
{
     "remote_addr": "a.b.c.d"
     "remote_user": "-",
     "time_local": "09/Jan/2014:21:56:03 +0000",
     "method": "GET",
     "request": "/index.php",
     "protocol": "HTTP/1.1",
     "status": "200",
     "bytes_sent": "7607",
     "http_referer": "-",
     "http_user_agent": "Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.9.2.10) Gecko/20100914 Firefox/3.6.10"	
} 
```
