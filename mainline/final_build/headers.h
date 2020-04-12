//                      -- KERNEL HEADER FILES (MODULE DENDENCIES) --

//Primary headers
#include <linux/init.h> //macros
#include <linux/module.h> 
#include <linux/kernel.h> //Kernel functions
#include <linux/stat.h>

//System call table headers and functions (& Others)

#include <linux/syscalls.h> //system calls functions
#include <linux/kallsyms.h> //access to call system functions
#include <linux/slab.h>
#include <linux/kern_levels.h>
#include <linux/gfp.h>
#include <asm/unistd.h>
#include <asm/paravirt.h>


#include <linux/kernel.h> //Kernel 

//Network Headers: 
#include <linux/in.h> //Networking functions header (internet header)
#include <linux/net.h>
#include <linux/in.h>
#include <linux/uaccess.h>

//-----------------------------------------------