#include "headers.h"


//-- Required to reduce warnings on injection --
#define DRIVER_AUTHOR "Broadcom Corporation"
#define DRIVER_DESCRIPTION "Linux STA NIC driver"

MODULE_LICENSE("GPL");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESCRIPTION);

MODULE_SUPPORTED_DEVICE("NIC_Device");

//-----------------------------------------------


int Major; //Defines module 'proccess number'
static int Device_Open = 0;
static char msg[BUFFER_LEN];
static char *msg_Ptr;


static struct file_ops fops = {
    .read = device_read,
    .write = device_write,
    .open = device_open,
    .release = device_release
}

//Entry ~>

init init_module(void){

    Major = register_chrdev(0, DEVICE_NAME, &fops)

    if (Major < 0){
        printk(KERN_ALERT "Couldn't assign major number, load failed... \n");
    }
    
    printk(KERN_ALERT "Loaded with major number: %d", Major);
    printk(KERN_ALERT "Create a device with name \n mknod /dev/%s c %d 0", DEVICE_NAME, Major);
    
    return 0;
}


int device_open(struct inode * inode, struct file *file){

    

}