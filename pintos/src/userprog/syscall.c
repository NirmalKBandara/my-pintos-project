#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <string.h>
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/malloc.h"

static void syscall_handler (struct intr_frame *);
static struct lock file_system_lock;

/* Helper functions. */
static void check_user_ptr (const void *ptr);
static void check_user_buffer (const void *buffer, unsigned size);
static void check_user_string (const char *str);
static int get_user (const uint8_t *uaddr);
static void terminate_process (int status);

/* System call implementations. */
static void halt_system (void);
static tid_t execute_program (const char *cmd_line);
static int wait_for_process (tid_t pid);
static bool create_file (const char *file, unsigned initial_size);
static bool delete_file (const char *file);
static int open_file (const char *file);
static int get_file_size (int fd);
static int read_from_file (int fd, void *buffer, unsigned size);
static int write_to_file (int fd, const void *buffer, unsigned size);
static void set_file_position (int fd, unsigned position);
static unsigned get_file_position (int fd);
static void close_file (int fd);

void
syscall_init (void) 
{
  lock_init (&file_system_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  uint32_t *stack_ptr = (uint32_t *) f->esp;
  check_user_ptr (stack_ptr);
  
  int call_num = *stack_ptr;
  
  switch (call_num)
    {
    case SYS_HALT:
      halt_system ();
      break;
      
    case SYS_EXIT:
      check_user_ptr (stack_ptr + 1);
      terminate_process (*(stack_ptr + 1));
      break;
      
    case SYS_EXEC:
      check_user_ptr (stack_ptr + 1);
      check_user_string ((char *) *(stack_ptr + 1));
      f->eax = execute_program ((char *) *(stack_ptr + 1));
      break;
      
    case SYS_WAIT:
      check_user_ptr (stack_ptr + 1);
      f->eax = wait_for_process (*(stack_ptr + 1));
      break;
      
    case SYS_CREATE:
      check_user_ptr (stack_ptr + 1);
      check_user_ptr (stack_ptr + 2);
      check_user_string ((char *) *(stack_ptr + 1));
      f->eax = create_file ((char *) *(stack_ptr + 1), *(stack_ptr + 2));
      break;
      
    case SYS_REMOVE:
      check_user_ptr (stack_ptr + 1);
      check_user_string ((char *) *(stack_ptr + 1));
      f->eax = delete_file ((char *) *(stack_ptr + 1));
      break;
      
    case SYS_OPEN:
      check_user_ptr (stack_ptr + 1);
      check_user_string ((char *) *(stack_ptr + 1));
      f->eax = open_file ((char *) *(stack_ptr + 1));
      break;
      
    case SYS_FILESIZE:
      check_user_ptr (stack_ptr + 1);
      f->eax = get_file_size (*(stack_ptr + 1));
      break;
      
    case SYS_READ:
      check_user_ptr (stack_ptr + 1);
      check_user_ptr (stack_ptr + 2);
      check_user_ptr (stack_ptr + 3);
      check_user_buffer ((void *) *(stack_ptr + 2), *(stack_ptr + 3));
      f->eax = read_from_file (*(stack_ptr + 1), (void *) *(stack_ptr + 2), *(stack_ptr + 3));
      break;
      
    case SYS_WRITE:
      check_user_ptr (stack_ptr + 1);
      check_user_ptr (stack_ptr + 2);
      check_user_ptr (stack_ptr + 3);
      check_user_buffer ((void *) *(stack_ptr + 2), *(stack_ptr + 3));
      f->eax = write_to_file (*(stack_ptr + 1), (void *) *(stack_ptr + 2), *(stack_ptr + 3));
      break;
      
    case SYS_SEEK:
      check_user_ptr (stack_ptr + 1);
      check_user_ptr (stack_ptr + 2);
      set_file_position (*(stack_ptr + 1), *(stack_ptr + 2));
      break;
      
    case SYS_TELL:
      check_user_ptr (stack_ptr + 1);
      f->eax = get_file_position (*(stack_ptr + 1));
      break;
      
    case SYS_CLOSE:
      check_user_ptr (stack_ptr + 1);
      close_file (*(stack_ptr + 1));
      break;
      
    default:
      terminate_process (-1);
      break;
    }
}

/* Validates that PTR is a valid user pointer. */
static void
check_user_ptr (const void *ptr)
{
  if (ptr == NULL || !is_user_vaddr (ptr) || 
      pagedir_get_page (thread_current ()->pagedir, ptr) == NULL)
    terminate_process (-1);
}

/* Validates that a buffer is entirely in valid user memory. */
static void
check_user_buffer (const void *buffer, unsigned size)
{
  unsigned i;
  char *buf = (char *) buffer;
  for (i = 0; i < size; i++)
    check_user_ptr (buf + i);
}

/* Validates that a string is entirely in valid user memory. */
static void
check_user_string (const char *str)
{
  check_user_ptr (str);
  while (*str != '\0')
    {
      str++;
      check_user_ptr (str);
    }
}

/* Terminates Pintos. */
static void
halt_system (void)
{
  shutdown_power_off ();
}

/* Terminates the current user program, returning STATUS to the kernel. */
static void
terminate_process (int status)
{
  struct thread *current = thread_current ();
  current->status_code = status;
  printf ("%s: exit(%d)\n", current->name, status);
  thread_exit ();
}

/* Runs the executable whose name is given in CMD_LINE. */
static tid_t
execute_program (const char *cmd_line)
{
  return process_execute (cmd_line);
}

/* Waits for a child process PID and returns its exit status. */
static int
wait_for_process (tid_t pid)
{
  return process_wait (pid);
}

/* Creates a new file called FILE with the given INITIAL_SIZE. */
static bool
create_file (const char *file, unsigned initial_size)
{
  if (file == NULL)
    terminate_process (-1);
    
  lock_acquire (&file_system_lock);
  bool success = filesys_create (file, initial_size);
  lock_release (&file_system_lock);
  return success;
}

/* Deletes the file called FILE. */
static bool
delete_file (const char *file)
{
  if (file == NULL)
    terminate_process (-1);
    
  lock_acquire (&file_system_lock);
  bool success = filesys_remove (file);
  lock_release (&file_system_lock);
  return success;
}

/* Opens the file called FILE. */
static int
open_file (const char *file)
{
  if (file == NULL)
    terminate_process (-1);
    
  lock_acquire (&file_system_lock);
  struct file *f = filesys_open (file);
  lock_release (&file_system_lock);
  
  if (f == NULL)
    return -1;
    
  struct thread *current = thread_current ();
  int fd = current->next_file_desc;
  
  if (fd >= 128)
    {
      file_close (f);
      return -1;
    }
    
  current->file_desc_table[fd] = f;
  current->next_file_desc++;
  return fd;
}

/* Returns the size of the file open as FD. */
static int
get_file_size (int fd)
{
  if (fd < 2 || fd >= 128)
    return -1;
    
  struct thread *current = thread_current ();
  struct file *f = current->file_desc_table[fd];
  
  if (f == NULL)
    return -1;
    
  lock_acquire (&file_system_lock);
  int size = file_length (f);
  lock_release (&file_system_lock);
  return size;
}

/* Reads SIZE bytes from the file open as FD into BUFFER. */
static int
read_from_file (int fd, void *buffer, unsigned size)
{
  if (fd == 1)  /* Cannot read from stdout. */
    return -1;
    
  if (fd == 0)  /* Read from stdin. */
    {
      unsigned i;
      uint8_t *buf = (uint8_t *) buffer;
      for (i = 0; i < size; i++)
        buf[i] = input_getc ();
      return size;
    }
    
  if (fd < 2 || fd >= 128)
    return -1;
    
  struct thread *current = thread_current ();
  struct file *f = current->file_desc_table[fd];
  
  if (f == NULL)
    return -1;
    
  lock_acquire (&file_system_lock);
  int bytes_read = file_read (f, buffer, size);
  lock_release (&file_system_lock);
  return bytes_read;
}

/* Writes SIZE bytes from BUFFER to the file open as FD. */
static int
write_to_file (int fd, const void *buffer, unsigned size)
{
  if (fd == 0)  /* Cannot write to stdin. */
    return -1;
    
  if (fd == 1)  /* Write to stdout. */
    {
      putbuf (buffer, size);
      return size;
    }
    
  if (fd < 2 || fd >= 128)
    return -1;
    
  struct thread *current = thread_current ();
  struct file *f = current->file_desc_table[fd];
  
  if (f == NULL)
    return -1;
    
  lock_acquire (&file_system_lock);
  int bytes_written = file_write (f, buffer, size);
  lock_release (&file_system_lock);
  return bytes_written;
}

/* Changes the next byte to be read or written in FD to POSITION. */
static void
set_file_position (int fd, unsigned position)
{
  if (fd < 2 || fd >= 128)
    return;
    
  struct thread *current = thread_current ();
  struct file *f = current->file_desc_table[fd];
  
  if (f == NULL)
    return;
    
  lock_acquire (&file_system_lock);
  file_seek (f, position);
  lock_release (&file_system_lock);
}

/* Returns the position of the next byte to be read or written in FD. */
static unsigned
get_file_position (int fd)
{
  if (fd < 2 || fd >= 128)
    return -1;
    
  struct thread *current = thread_current ();
  struct file *f = current->file_desc_table[fd];
  
  if (f == NULL)
    return -1;
    
  lock_acquire (&file_system_lock);
  unsigned position = file_tell (f);
  lock_release (&file_system_lock);
  return position;
}

/* Closes file descriptor FD. */
static void
close_file (int fd)
{
  if (fd < 2 || fd >= 128)
    return;
    
  struct thread *current = thread_current ();
  struct file *f = current->file_desc_table[fd];
  
  if (f == NULL)
    return;
    
  lock_acquire (&file_system_lock);
  file_close (f);
  lock_release (&file_system_lock);
  current->file_desc_table[fd] = NULL;
}
