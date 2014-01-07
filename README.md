nginx-beanfire-module
=====================

Non-blocking fire-and-forget logging to beanstalk with asynchronous socket control:

- Support JSON and Nginx logging format; 
- One dedicated socket per worker process; 
- Conservative use o file-descriptors; 
- Asynchronous evloop to handle POLLHUP/POLLERR events;
- Multi-location support; 
