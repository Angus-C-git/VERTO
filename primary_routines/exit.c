#include "headers.h"

static void hello_exit(void){

    printk(KERN_INFO "KIT_DEBUGGER: EXITING.. \n");
}

module_exit(hello_exit);
