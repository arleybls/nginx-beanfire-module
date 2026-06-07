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

## Updates

### v1.1.0 — Mutex-protected socket descriptor

**Why:** The original global `gmsofd` was accessed without synchronization by
two concurrent threads: the keepalive thread (which replaces the descriptor on
reconnect) and the nginx worker event loop (which calls `send()` on every
logged request). This was a data race.

**What changed:** `gmsofd` is now initialized to `-1` and guarded by a static
`pthread_mutex_t` (initialized with `PTHREAD_MUTEX_INITIALIZER`). The
keepalive thread holds the lock only for `close(fd)` + `gmsofd = -1` or
`gmsofd = sock` assignments. The handler acquires the lock, sends if
`gmsofd != -1`, and releases immediately.

**Fire-and-forget preserved:** The handler runs in nginx's `NGX_HTTP_LOG_PHASE`,
which executes after the response has already been sent to the client. The
client is unaffected regardless of what the handler does.

**Non-blocking in the normal case:** During steady-state operation the keepalive
thread is parked inside `epoll_wait(..., -1)` and holds no lock. The handler
acquires an uncontested mutex, calls `send(MSG_DONTWAIT)` (returns immediately
whether or not the kernel buffer has room), and releases — two atomic
operations with no I/O blocking.

**Sole contention window:** During a socket reconnect the keepalive thread holds
the mutex only for the duration of `close(fd)` + `gmsofd = -1`, measured in
microseconds. The `sleep()` and `connect()` retry loop run entirely outside the
lock, so the nginx event loop is never stalled meaningfully.

**Tradeoff accepted:** Every request pays two kernel-mode transitions
(lock/unlock) even when uncontested. A lock-free approach using `ngx_atomic_t`
would eliminate this overhead but adds significant complexity for a path that
only handles logging. The mutex is the correct choice here.
