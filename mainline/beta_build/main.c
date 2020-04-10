//                              - Neccessary header files -
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


//                             - Module Signing -

//Assists with kernel taint warnings etc
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Broadcom");
MODULE_DESCRIPTION("NIC Device Driver");
MODULE_VERSION("1.0");

