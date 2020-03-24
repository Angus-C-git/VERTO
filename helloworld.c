#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

static int hello_init(void){

    printk(KERN_INFO "KIT_DEBUG: HELLO WORLD! \n");

    return 0;
}

static void hello_exit(void){

    printk(KERN_INFO "KIT_DEBUG: EXITING.. \n");
}

module_init(hello_init);
module_exit(hello_exit);

MODULE_LICENSE("GPL");