//-- KERNEL HEADER FILES --

#include <linux/module.h>
#include <linux/kernel.h> //Debugging messages
#include <linux/init.h> //Macros
#include <linux/moduleparam.h>
#include <linux/stat.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

//-----------------------------------------------

int init_module(void);
int device_open(struct inode * , struct file *);
int device_release(struct inode * , struct file *);

ssize_t device_read(struct file *file, char * buffer, size_t length, loff_t *offset);
ssize_t device_write(struct file *file, const char * buffer, size_t length, loff_t *offset);

#define SUCCESS 0
#define DEVICE_NAME "NIC_Driver"
#define BUFFER_LEN 80
extern int Major;