#include <linux/module.h>
#include <linux/kernel.h> //Debugging messages
#include <linux/init.h> //Macros
#include <linux/moduleparam.h>
#include <linux/stat.h>


//-- Required to reduce warnings on injection --
#define DRIVER_AUTHOR "Broadcom Corporation"
#define DRIVER_DESCRIPTION "Linux STA NIC driver"

MODULE_LICENSE("GPL");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESCRIPTION);

MODULE_SUPPORTED_DEVICE("NIC_Device");

//-----------------------------------------------

static char *Argument = "";
module_param(Argument, charp, 0000);
MODULE_PARM_DESC(Argument, "Passed String.");


static int hello_init(void){

    printk(KERN_INFO "KIT_DEBUGGER: %s \n", Argument);

    return 0;
}

static void hello_exit(void){

    printk(KERN_INFO "KIT_DEBUGGER: EXITING.. \n");
}

module_init(hello_init);
module_exit(hello_exit);
