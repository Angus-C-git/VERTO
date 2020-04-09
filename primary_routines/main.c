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


static struct file_operations fops = {
    .read = device_read,
    .write = device_write,
    .open = device_open,
    .release = device_release
};

//Entry ~>

int init_module(void){

    Major = register_chrdev(0, DEVICE_NAME, &fops);

    if (Major < 0){
        printk(KERN_ALERT "Couldn't assign major number, load failed... \n");
        return Major;
    }
    
    printk(KERN_ALERT "Loaded with major number: %d", Major);
    printk(KERN_ALERT "Create a device with name \n mknod /dev/%s c %d 0\n", DEVICE_NAME, Major);
    
    return 0;
}

//When sys call open is called run 
int device_open(struct inode * inode, struct file *file){

    static int counter = 0;

    if (Device_Open){

        return -EBUSY;
    }

    //To invoke write delete this 
    sprintf(msg, "Device Busy %d times", counter++); //When device is interacted with run this command
    msg_Ptr = msg;
    try_module_get(THIS_MODULE);

    return 0;
}


int device_release(struct inode * inode, struct file * file){

    Device_Open--;

    module_put(THIS_MODULE);
    
    return 0;

}


//On sys call read 
ssize_t device_read(struct file *file, char * buffer, size_t length, loff_t *offset){

    int bytes_read = 0;

    if(*msg_Ptr == 0){ // If msg is nothing
        return 0;
    }

    while(length && *msg_Ptr){

        put_user(* (msg_Ptr++), buffer++);
        length--;
        bytes_read++;

    }

    return bytes_read;

}

//Dangerous function because if we try to write to it, it will keep trying to write until bytes returned
ssize_t device_write(struct file * file, const char * buffer, size_t length, loff_t * offset){

    //NOTE -> Writing has changed significantly on newer kernels

    int count = 0;
    memset(msg, 0, BUF_LEN)

    printk(KERN_ALERT "Device Read \n"); 

    //care buffer
    while (length > 0){
        copy_from_user(msg, buffer, BUF_LEN-1);
        count++;
        length--;
        msg[BUF_LEN-1] = 0x00;
    }
    
    return count; //Must return >0
}