# About

A POC/MVP kernel mode rootkit for Linux Kernel 5.03.42 and lower.


# Compiling and Deployment of VERTO rootkit

+ Modules (I.E sections in the `./code_lib`) are compiled with their associated Makefile (gcc) 
    + `make clean && make all`
+ Moudles are executed via the produced .ko file, output by the Makefile, using the insmod command
    + `sudo insmod module_name.ko`
+ Modules are removed via the rmmod command which only requires the module name
    + `sudo rmmod module_name`


# Sample Malware

*Note: both scripts are extreemly basic POCs see [notes](#notes)*

+ The payload script (`fn2187.py`) should be run as root in the background on the target system initally, it attempts to persist over restarts by adding a crontab to execute it on startup
    ```
    sudo python3 fn2187.py &
    exit
    ```

+ The server script (`server.py`) is run on the attackers machine 
    + `python3 server.py`
    
+ Note because the two scripts are basic some commands when executed incorrectly over the shell will cause it to die svr side (sometimes client side)
+ This can be resloved in most cases by killing the server program & freeing the socket it was binding & then restarting the server, which should reconect with the payloads recovery functions

+ The payload script accepts 3 special commands outside of normal bash calls (commands specific to these scripts)    
    + `drop_kit`
        + Will deploy the rootkit if its kernel object file (.ko) exists in the /home/usr_name/Template directory
    + `n_sleep`
        + Will attempt to kill the connection client side for 300 seconds
    + `l_sleep` 
        + Will attempt kill the connection client side for 1 hour

# Notes

*Tested on: Linux Mint Kernel `4.15.0-54-generic`*

1. Rootkits work on the assumption that root permissions, A.K.A sudo, have been obtained on the target system via local privillage escalation or some other means
2. All inturupts have been modified to work on newer kernels (which should be backwards compatable, hence they also work on this build and newer builds up to `5.03.42` at least. Builds failed on Kernel `5.03.46`.
    1. The unmodified versions of the intrupts, which do not negate CR04 pinning issues, are included for refrence
2. The included 'payload' (`fn2187.py`) is a crude implementation of a reverse shell with limited survivability used to demo the rootkits features
    1. The server for the payload is `server.py` and is a similarly crude (somewhat broken) listener for the payload
    2. The payload should be run as root
3. Real maleware deployed with a rootkit like VERTO would likely be written in C so as to be a discreet module that can be properly executed in the background
4. See issues board for areas of improvement 
