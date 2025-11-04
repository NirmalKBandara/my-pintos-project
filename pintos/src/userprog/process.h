#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"
#include <list.h>

/* Child process status structure. */
struct process_info
{
  tid_t process_id;               /* Thread ID of child. */
  int status_code;                /* Exit status. */
  bool wait_called;               /* Has parent waited? */
  bool is_terminated;             /* Has child exited? */
  struct semaphore wait_sync;     /* Semaphore for wait. */
  struct list_elem list_node;     /* List element. */
};

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */
