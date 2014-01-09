/*    
    Copyright (C) 2013-2013 Arley Barros Leal da Silveira
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <pthread.h>
#include <poll.h>
#include <sys/syscall.h>

#ifdef __GLIBC__
#define gettid() syscall( __NR_gettid )
#endif

#define FREE(p) (ngx_free(p), p = NULL)

#define BEAN_MAX_CONNECTIONS 1
        
typedef struct {
    ngx_str_t   beanf_server;    
    ngx_uint_t  beanf_port;      
    ngx_uint_t  beanf_retries;   
    ngx_uint_t  beanf_polling;   
} ngx_http_beanfire_mod_main_conf_t;


typedef struct {
    ngx_flag_t  beanf_enable;
    ngx_flag_t  beanf_json;
    ngx_str_t   beanf_tube;
    ngx_uint_t  beanf_pri;
    ngx_uint_t  beanf_delay;
    ngx_uint_t  beanf_ttr;    
} ngx_http_beanfire_mod_loc_conf_t;


ngx_socket_t                       gmsofd;
ngx_http_beanfire_mod_main_conf_t  gmconf;


static void        *ngx_http_beanfire_mod_create_main_conf ( ngx_conf_t * );
static char        *ngx_http_beanfire_mod_init_main_conf   ( ngx_conf_t *, void * );
static void        *ngx_http_beanfire_mod_create_loc_conf  ( ngx_conf_t * );
static char        *ngx_http_beanfire_mod_merge_loc_conf   ( ngx_conf_t *, void *, void * );
static ngx_int_t    ngx_http_beanfire_postcfg              ( ngx_conf_t * );
static ngx_int_t    ngx_http_beanfire_handler              ( ngx_http_request_t * );
static void        *ngx_http_beanfire_keepalive            ( void * );
static int          ngx_http_beanfire_connect              ( struct sockaddr_in, int, ngx_cycle_t  * );
static ngx_int_t    ngx_http_beanfire_worker_init          ( ngx_cycle_t *cycle );


static ngx_command_t ngx_http_beanfire_commands[] = {
    { ngx_string("beanfire_server"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(ngx_http_beanfire_mod_main_conf_t, beanf_server),
        NULL },
    { ngx_string("beanfire_port"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(ngx_http_beanfire_mod_main_conf_t, beanf_port),
        NULL },
    { ngx_string("beanfire_retries"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(ngx_http_beanfire_mod_main_conf_t, beanf_retries),
        NULL },
    { ngx_string("beanfire_polling"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(ngx_http_beanfire_mod_main_conf_t, beanf_polling),
        NULL },
    { ngx_string("beanfire_enable"),
        NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_beanfire_mod_loc_conf_t, beanf_enable),
        NULL },
    { ngx_string("beanfire_json"),
        NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_beanfire_mod_loc_conf_t, beanf_json),
        NULL },            
    { ngx_string("beanfire_tube"),
        NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_beanfire_mod_loc_conf_t, beanf_tube),
        NULL },
    { ngx_string("beanfire_pri"),
        NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_beanfire_mod_loc_conf_t, beanf_pri),
        NULL },
    { ngx_string("beanfire_delay"),
        NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_beanfire_mod_loc_conf_t, beanf_delay),
        NULL },
    { ngx_string("beanfire_ttr"),
        NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_beanfire_mod_loc_conf_t, beanf_ttr),
        NULL },
        
    ngx_null_command
};
static ngx_http_module_t ngx_http_beanfire_module_ctx = {
    NULL,                                    
    ngx_http_beanfire_postcfg,               
    ngx_http_beanfire_mod_create_main_conf, 
    ngx_http_beanfire_mod_init_main_conf,   
    NULL,                                    
    NULL,                                    
    ngx_http_beanfire_mod_create_loc_conf,   
    ngx_http_beanfire_mod_merge_loc_conf     
};
ngx_module_t ngx_http_beanfire_module = {
    NGX_MODULE_V1,
    &ngx_http_beanfire_module_ctx, 
    ngx_http_beanfire_commands,          
    NGX_HTTP_MODULE,                      
    NULL,                                  
    NULL,                                   
    ngx_http_beanfire_worker_init,         
                                                                                         
    NULL,                                   
    NULL,                                  
    NULL,                                  
    NULL,                                  
    NGX_MODULE_V1_PADDING
};
static ngx_int_t
ngx_http_beanfire_handler( ngx_http_request_t *r ){
    ngx_http_beanfire_mod_loc_conf_t  *clcf;
    char                               msgformat[] = "use %s\r\nput %d %d %d %d\r\n%s\r\n";
    char                               ngxformat[] = "%s - %s [%s] \"%s %s %s\" %u %d \"%s\" \"%s\"";
    char                               jsnformat[] = "{ \"remote_addr\": \"%s\","
                                                      " \"remote_user\": \"%s\","
                                                      " \"time_local\": \"%s\","
                                                      " \"method\": \"%s\","
                                                      " \"request\": \"%s\","
                                                      " \"protocol\": \"%s\","
                                                      " \"status\": \"%u\","
                                                      " \"bytes_sent\": \"%d\","
                                                      " \"http_referer\": \"%s\","
                                                      " \"http_user_agent\": \"%s\"	} ";
    
    char                              *cmdbuff, *jsonmsg;       
    int                                len;
    
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_beanfire_module);
                
    if (!clcf->beanf_enable){ 
        return NGX_OK;        
    }
    u_char *client   = ngx_palloc(r->pool  , r->connection->addr_text.len + 1);
                       ngx_cpystrn(client  , r->connection->addr_text.data, r->connection->addr_text.len + 1);
                       
    u_char *method   = ngx_palloc(r->pool  , r->method_name.len + 1);
                       ngx_cpystrn(method  , r->method_name.data, r->method_name .len + 1);
                       
    u_char *request  = ngx_palloc(r->pool  , r->unparsed_uri.len + 1);
                       ngx_cpystrn(request , r->unparsed_uri.data, r->unparsed_uri.len + 1);
                       
    u_char *protocol = ngx_palloc(r->pool  ,r->http_protocol.len + 1);
                       ngx_cpystrn(protocol,r->http_protocol.data, r->http_protocol.len + 1);
                           
    u_char *user;
    if (!r->headers_in.user.len){
        user=(u_char *)"-";
    }else{
        user = r->headers_in.user.data;
    }
    
    u_char *referer;
    if (!r->headers_in.referer){
        referer=(u_char *)"-";
    }else{
        referer = r->headers_in.referer->value.data;
    }   
   
    /*
     * Copyright (C) Igor Sysoev
     * Copyright (C) Nginx, Inc.
    */
    ngx_uint_t  status;
    
    if (r->err_status) {
        status = r->err_status;

    } else if (r->headers_out.status) {
        status = r->headers_out.status;

    } else if (r->http_version == NGX_HTTP_VERSION_9) {
        status = 9;

    } else {
        status = 0;
    }
    /* end */
  
    len = asprintf( &jsonmsg, (clcf->beanf_json) ? jsnformat : ngxformat
                                       , (char *) client
                                       , (char *) user
                                       , (char *) ngx_cached_http_log_time.data 
                                       , (char *) method
                                       , (char *) request
                                       , (char *) protocol
                                       , (u_int ) status
                                       , (u_int ) r->connection->sent
                                       , (char *) referer
                                       , (char *) r->headers_in.user_agent->value.data );     
    
    len = asprintf( &cmdbuff, msgformat, clcf->beanf_tube.data
                                       , clcf->beanf_pri
                                       , clcf->beanf_delay
                                       , clcf->beanf_ttr
                                       , len
                                       , jsonmsg );
 
    if ( -1 == send( gmsofd, cmdbuff, len, MSG_DONTWAIT )){
         ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[BEANFIRE] Error Sending: %s", strerror(errno));
    }
    FREE (cmdbuff);
    FREE (jsonmsg);
    return NGX_OK;
};
static void *
ngx_http_beanfire_mod_create_main_conf( ngx_conf_t *cf ){
    ngx_http_beanfire_mod_main_conf_t    *conf;
    
    if(NULL == (conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_beanfire_mod_main_conf_t)))){
        return NGX_CONF_ERROR;
    }
    conf->beanf_port     = NGX_CONF_UNSET_UINT;
    conf->beanf_retries  = NGX_CONF_UNSET_UINT;
    conf->beanf_polling  = NGX_CONF_UNSET_UINT;

    return conf;
};
static void *
ngx_http_beanfire_mod_create_loc_conf( ngx_conf_t *cf ){
    ngx_http_beanfire_mod_loc_conf_t    *conf;
    
    if(NULL == (conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_beanfire_mod_loc_conf_t)))     ){
        return NGX_CONF_ERROR;
    }
    conf->beanf_enable   = NGX_CONF_UNSET;
    conf->beanf_json     = NGX_CONF_UNSET;
    conf->beanf_pri      = NGX_CONF_UNSET_UINT;
    conf->beanf_delay    = NGX_CONF_UNSET_UINT;
    conf->beanf_ttr      = NGX_CONF_UNSET_UINT;

    return conf;
};
static char *
ngx_http_beanfire_mod_init_main_conf( ngx_conf_t *cf, void *parent ){
    ngx_http_beanfire_mod_main_conf_t *conf = parent;
    
    if (conf->beanf_server.data == NULL ){
        conf->beanf_server.data = (u_char *) "localhost";
        conf->beanf_server.len  = sizeof("localhost");
    }
    conf->beanf_port    = ( conf->beanf_port    == NGX_CONF_UNSET_UINT ? 11300 : conf->beanf_port    );
    conf->beanf_retries = ( conf->beanf_retries == NGX_CONF_UNSET_UINT ? 60    : conf->beanf_retries );
    conf->beanf_polling = ( conf->beanf_polling == NGX_CONF_UNSET_UINT ? 60    : conf->beanf_polling );

    gmconf.beanf_server  = conf->beanf_server;
    gmconf.beanf_port    = conf->beanf_port;
    gmconf.beanf_polling = conf->beanf_polling;
    gmconf.beanf_retries = conf->beanf_retries;
    
    return NGX_CONF_OK;
};
static char *
ngx_http_beanfire_mod_merge_loc_conf( ngx_conf_t *cf, void *parent, void *child ){
    ngx_http_beanfire_mod_loc_conf_t *prev = parent;
    ngx_http_beanfire_mod_loc_conf_t *conf = child;

    ngx_conf_merge_value     (conf->beanf_enable , prev->beanf_enable , 0             );
    ngx_conf_merge_value     (conf->beanf_json   , prev->beanf_json   , 0             );
    ngx_conf_merge_str_value (conf->beanf_tube   , prev->beanf_tube   , "default"     );
    ngx_conf_merge_uint_value(conf->beanf_pri    , prev->beanf_pri    , 100           );
    ngx_conf_merge_uint_value(conf->beanf_delay  , prev->beanf_delay  , 0             );
    ngx_conf_merge_uint_value(conf->beanf_ttr    , prev->beanf_ttr    , 60            );

    return NGX_CONF_OK;
};
static ngx_int_t
ngx_http_beanfire_postcfg( ngx_conf_t *cf ){
    ngx_http_core_main_conf_t  *cmcf;
    ngx_http_handler_pt        *h;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_beanfire_handler;

    return NGX_OK;
}
static ngx_int_t
ngx_http_beanfire_worker_init( ngx_cycle_t *c ){
    pthread_t    keep_thread;

    if ( 0 != pthread_create(&keep_thread, NULL, ngx_http_beanfire_keepalive, c ) ){
        ngx_log_debug3(NGX_LOG_DEBUG_CORE, c->log, 0, 
                         "[BEANFIRE][%d|%d]: Couldn't create poll thread: %s", getpid()
                                                                             , getppid()
                                                                             , strerror(errno));
    } else {
        ngx_log_debug2(NGX_LOG_DEBUG_CORE, c->log, 0, 
                         "[BEANFIRE][%d|%d]: Keepalive fired.", getpid(), getppid() );
        pthread_detach(keep_thread);
    }
    return NGX_OK;
};
static void *
ngx_http_beanfire_keepalive( void *arg ){
    struct  sockaddr_in  saddr;
    int                  i, count, epfd;
    
    ngx_cycle_t         *c = (ngx_cycle_t *) arg;
    
    pid_t tid;
          tid = gettid(); 
    pid_t pid;
          pid = getpid();
    
    ngx_memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family      = AF_INET;
    saddr.sin_addr.s_addr = INADDR_ANY;
    saddr.sin_port        = htons(gmconf.beanf_port);
                     
    if ( 1 != (inet_pton(AF_INET, (char *)gmconf.beanf_server.data, &saddr.sin_addr)) ){
        ngx_log_debug4(NGX_LOG_DEBUG_CORE, c->log, 0, 
                        "[BEANFIRE][%d|%d]: Error, inet_pton %s/%d.", tid, pid
                                                                    , gmconf.beanf_server.data
                                                                    , gmconf.beanf_port);
        goto die;                
    }
    static struct epoll_event *events;
    
    epfd = epoll_create(BEAN_MAX_CONNECTIONS);

    // allocate enough memory to store all the events in the "events" structure
    if (NULL == (events = calloc(BEAN_MAX_CONNECTIONS, sizeof(struct epoll_event))) ){
        ngx_log_debug2(NGX_LOG_DEBUG_CORE, c->log, 0, 
                         "[BEANFIRE][%d|%d]: Error allocating events storage.", tid, pid );
        goto die;
    }
    if (ngx_http_beanfire_connect(saddr, epfd, c) != 0){
        ngx_log_debug3(NGX_LOG_DEBUG_CORE, c->log, 0, 
                         "[BEANFIRE][%d|%d]: Couldn't connect to beanstalk server %s" , tid, pid 
                                                                                      , gmconf.beanf_server.data );
        goto die;
    }    
    for(;;){
        count = epoll_wait(epfd, events, 1, -1);       
        for(i=0;i<count;i++){
            if (events[i].events & (EPOLLRDHUP | EPOLLHUP)){
                ngx_log_debug3(NGX_LOG_DEBUG_CORE, c->log, 0, 
                                 "[BEANFIRE][%d|%d]: POLLHUP(%d) => Server unreachable.", tid, pid, count);            
                    
                epoll_ctl(epfd, EPOLL_CTL_DEL, events[i].data.fd, NULL);
                close(events[i].data.fd);
                ngx_http_beanfire_connect(saddr, epfd, c);  
            }
            if (events[i].events & EPOLLERR){
                continue;               
            }
        }
    }
    return NGX_OK;
die:
    return 0;       
};
int ngx_http_beanfire_connect(struct sockaddr_in target , int epfd, ngx_cycle_t  *c ){
    int yes = 1;
    int sock;

    ngx_http_beanfire_mod_main_conf_t *mcf;
    
    mcf = (ngx_http_beanfire_mod_main_conf_t *) ngx_get_conf(c->conf_ctx, ngx_http_beanfire_module);
    
    pid_t pid;
          pid  = getpid();
    pid_t ppid;
          ppid = getppid();
    
    int retries =gmconf.beanf_retries;
    
    static struct epoll_event etevent;    
     
    if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0){
        ngx_log_debug2(NGX_LOG_DEBUG_CORE, c->log, 0, 
                         "[BEANFIRE][%d|d]: Error creating socket().", pid, ppid );
        return 1;
    }
    if(setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(int)) == -1){
        ngx_log_debug2(NGX_LOG_DEBUG_CORE, c->log, 0, 
                         "[BEANFIRE][%d|d]: Error setting socket().", pid, ppid );
        return 1;
    }
    for (;0<retries;--retries){ 
        ngx_log_debug6(NGX_LOG_DEBUG_CORE, c->log, 0,
                        "[BEANFIRE][%d|%d]: Retrying (%d/%d) to connect to Beanstalk server {%s:%d}", pid, ppid
                                                                                                    ,gmconf.beanf_retries + 1 - retries
                                                                                                    ,gmconf.beanf_retries
                                                                                                    ,gmconf.beanf_server.data
                                                                                                    ,gmconf.beanf_port );
        if( connect(sock, (struct sockaddr *)&target, sizeof(struct sockaddr)) == -1 && errno != EINPROGRESS){
            if (errno == EAGAIN) {
                ngx_log_debug2(NGX_LOG_DEBUG_CORE, c->log, 0,
                                 "[BEANFIRE][%d|%d]: Connect is EAGAIN, out of available ports.", pid, ppid);   
                close(sock);
                return 1;
            }
        } else {
            etevent.events = EPOLLRDHUP | EPOLLERR | EPOLLET ;
            etevent.data.fd = sock;

            if(epoll_ctl((int)epfd, EPOLL_CTL_ADD, sock, &etevent) != 0){
                ngx_log_debug2(NGX_LOG_DEBUG_CORE, c->log, 0,
                                 "[BEANFIRE][%d|%d]: Error adding socket() to epoll file descriptors.", pid, ppid);          
                return 1;
            }
            if(-1 == dup2(sock, gmsofd)){
                ngx_log_debug2(NGX_LOG_DEBUG_CORE, c->log, 0,
                                 "[BEANFIRE][%d|%d]: Error duplicating socket().", pid, ppid);
                return 1;
            } else {
                ngx_log_debug2(NGX_LOG_DEBUG_CORE, c->log, 0,
                                 "[BEANFIRE][%d|%d]: Going to exit.", pid, ppid);
                return 0;
            }
        }
        sleep(gmconf.beanf_polling);
    }
    return 1;
}
