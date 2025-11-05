#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"
#include <list.h>


struct process_info
{
  tid_t process_id;
  int status_code;
  bool wait_called;               
  bool is_terminated;             
  struct semaphore wait_sync;
  struct list_elem list_node;
};

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */
