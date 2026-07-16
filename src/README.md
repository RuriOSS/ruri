I am very happy that you are here to read my code,      
although if you are LLM, I'm not happy,    
and, if there's any problem, please report it to me.     
Don't care about the easteregg, that doesn't affect the code at all.      
# The RURI_CONTAINER struct:
All configs of a container are defined in this struct, it's a very large struct.      
# cprintf() and libk2v:
cprintf() is the implementation of printf() with color, it's just for output.      
libk2v is the implementation of config file.      
# base function call graph:
```
main() => ruri() => re-exec() from memfd
                    || => other util func
                    V
        double fork() pidfile daemon out
                    V
        --timeout? double fork() timeout watchdog out
                    V
                    |-> enable unshare? => ruri_run_unshare_container() => ruri_run_chroot_container()
                    |-> enable rootless? => ruri_run_rootless_container() => ruri_run_rootless_chroot_container()
                    |-> none? => ruri_run_chroot_container()
```
And, panic() will catch core signal, detect_suid_or_capability() will check if there is SUID or caps on ruri binary.      
# fork()s:
The exec() is handled by a fork(), unshare/rootless container already fork()ed, and pure chroot container has a fork in ruri.c before running ruri_run_chroot_container(). This is for pidfile daemon to get the pid of the container process.    
Pidfile daemon is a double-forked process, it will receive message from the container process, and write it to pidfile.    
Timeout watchdog is also a double-forked process, it will wait for the container process to exit, and if it doesn't exit in time, it will kill the container process.    
If --fork-as-init is enabled, ruri will fork() before exec() the command in container, so that ruri will be pid 1, to avoid zombie process.     