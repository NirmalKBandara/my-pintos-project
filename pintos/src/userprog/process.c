#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
struct startup_args
{
  const char *command_str;
  struct semaphore startup_sync;
  bool startup_success;
  struct thread *parent_thread;
};

tid_t
process_execute (const char *file_name) 
{
  char *cmd_copy;
  char *token_ptr;
  tid_t child_tid;
  struct startup_args *args;

  args = palloc_get_page (0);
  if (args == NULL)
    return TID_ERROR;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  cmd_copy = palloc_get_page (0);
  if (cmd_copy == NULL)
    {
      palloc_free_page (args);
      return TID_ERROR;
    }
  strlcpy (cmd_copy, file_name, PGSIZE);

  args->command_str = cmd_copy;
  sema_init (&args->startup_sync, 0);
  args->startup_success = false;
  args->parent_thread = thread_current ();

  char *program_name = palloc_get_page (0);
  if (program_name == NULL) 
    {
      palloc_free_page (cmd_copy);
      palloc_free_page (args);
      return TID_ERROR;
    }
  strlcpy (program_name, file_name, PGSIZE);
  program_name = strtok_r (program_name, " ", &token_ptr);

  child_tid = thread_create (program_name, PRI_DEFAULT, start_process, args);
  palloc_free_page (program_name);
  
  if (child_tid == TID_ERROR)
    {
      palloc_free_page (cmd_copy);
      palloc_free_page (args);
      return child_tid;
    }

  sema_down (&args->startup_sync);
  bool success = args->startup_success;
  palloc_free_page (args);
  
  if (!success)
    return TID_ERROR;
  
  return child_tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *args_)
{
  struct startup_args *args = args_;
  char *cmd_line = (char *) args->command_str;
  char *parse_copy;
  struct intr_frame if_;
  bool success;
  struct thread *current = thread_current ();

  struct process_info *pinfo = malloc (sizeof (struct process_info));
  if (pinfo == NULL)
    {
      args->startup_success = false;
      sema_up (&args->startup_sync);
      palloc_free_page ((void *) cmd_line);
      thread_exit ();
    }
  
  pinfo->process_id = current->tid;
  pinfo->status_code = -1;
  pinfo->wait_called = false;
  pinfo->is_terminated = false;
  sema_init (&pinfo->wait_sync, 0);
  current->proc_info = pinfo;
  
  if (args->parent_thread != NULL)
    list_push_back (&args->parent_thread->child_list, &pinfo->list_node);

  parse_copy = palloc_get_page (0);
  if (parse_copy == NULL)
    {
      args->startup_success = false;
      sema_up (&args->startup_sync);
      palloc_free_page ((void *) cmd_line);
      thread_exit ();
    }
  strlcpy (parse_copy, cmd_line, PGSIZE);

  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (cmd_line, &if_.eip, &if_.esp);

  if (success)
    {
      char *arg_token, *token_state;
      char *arg_vector[128];
      int arg_count = 0;
      
      for (arg_token = strtok_r (parse_copy, " ", &token_state); arg_token != NULL;
           arg_token = strtok_r (NULL, " ", &token_state))
        {
          if (arg_count < 128)
            arg_vector[arg_count++] = arg_token;
        }
      
      int idx;
      uintptr_t *arg_addresses[128];
      
      for (idx = arg_count - 1; idx >= 0; idx--)
        {
          int str_len = strlen (arg_vector[idx]) + 1;
          if_.esp -= str_len;
          memcpy (if_.esp, arg_vector[idx], str_len);
          arg_addresses[idx] = (uintptr_t *) if_.esp;
        }
      
      while ((uintptr_t) if_.esp % 4 != 0)
        {
          if_.esp--;
          *(uint8_t *) if_.esp = 0;
        }
      
      if_.esp -= 4;
      *(uint32_t *) if_.esp = 0;
      
      for (idx = arg_count - 1; idx >= 0; idx--)
        {
          if_.esp -= 4;
          *(uintptr_t **) if_.esp = arg_addresses[idx];
        }
      
      uintptr_t arg_ptr = (uintptr_t) if_.esp;
      if_.esp -= 4;
      *(uintptr_t *) if_.esp = arg_ptr;
      
      if_.esp -= 4;
      *(int *) if_.esp = arg_count;
      
      if_.esp -= 4;
      *(uint32_t *) if_.esp = 0;
    }

  args->startup_success = success;
  sema_up (&args->startup_sync);
  palloc_free_page ((void *) cmd_line);
  palloc_free_page (parse_copy);
  
  if (!success) 
    thread_exit ();

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting. */
int
process_wait (tid_t child_tid) 
{
  struct thread *current = thread_current ();
  struct process_info *pinfo = NULL;
  struct list_elem *iter;
  
  for (iter = list_begin (&current->child_list); iter != list_end (&current->child_list); iter = list_next (iter))
    {
      struct process_info *proc = list_entry (iter, struct process_info, list_node);
      if (proc->process_id == child_tid)
        {
          pinfo = proc;
          break;
        }
    }
  
  if (pinfo == NULL || pinfo->wait_called)
    return -1;
  
  pinfo->wait_called = true;
  
  if (!pinfo->is_terminated)
    sema_down (&pinfo->wait_sync);
  
  int ret_status = pinfo->status_code;
  list_remove (&pinfo->list_node);
  free (pinfo);
  
  return ret_status;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *current = thread_current ();
  uint32_t *pd;

  int fd_idx;
  for (fd_idx = 2; fd_idx < 128; fd_idx++)
    {
      if (current->file_desc_table[fd_idx] != NULL)
        {
          file_close (current->file_desc_table[fd_idx]);
          current->file_desc_table[fd_idx] = NULL;
        }
    }
  
  if (current->exec_file != NULL)
    {
      file_allow_write (current->exec_file);
      file_close (current->exec_file);
      current->exec_file = NULL;
    }
  
  if (current->proc_info != NULL)
    {
      current->proc_info->status_code = current->status_code;
      current->proc_info->is_terminated = true;
      sema_up (&current->proc_info->wait_sync);
    }
  
  while (!list_empty (&current->child_list))
    {
      struct list_elem *node = list_pop_front (&current->child_list);
      struct process_info *pinfo = list_entry (node, struct process_info, list_node);
      free (pinfo);
    }

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = current->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         current->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      current->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *current = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *exec_file = NULL;
  off_t file_offset;
  bool success = false;
  int idx;
  char *program_name, *token_state;

  /* Allocate and activate page directory. */
  current->pagedir = pagedir_create ();
  if (current->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Extract program name (first token before space). */
  program_name = palloc_get_page (0);
  if (program_name == NULL)
    goto done;
  strlcpy (program_name, file_name, PGSIZE);
  program_name = strtok_r (program_name, " ", &token_state);

  /* Open executable file. */
  exec_file = filesys_open (program_name);
  palloc_free_page (program_name);
  if (exec_file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  /* Deny writes to executable. */
  current->exec_file = exec_file;
  file_deny_write (exec_file);

  /* Read and verify executable header. */
  if (file_read (exec_file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_offset = ehdr.e_phoff;
  for (idx = 0; idx < ehdr.e_phnum; idx++) 
    {
      struct Elf32_Phdr phdr;

      if (file_offset < 0 || file_offset > file_length (exec_file))
        goto done;
      file_seek (exec_file, file_offset);

      if (file_read (exec_file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_offset += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, exec_file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (exec_file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  /* Don't close file on success - it will be closed in process_exit. */
  if (!success && exec_file != NULL)
    {
      file_close (exec_file);
      current->exec_file = NULL;
    }
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        palloc_free_page (kpage);
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
