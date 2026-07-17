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
main()
 v
ruri()
 v
memfd re-exec()
 v
parse args => other util functions like ruri_umount_container()
 v
read .rurienv for ns_pid, so --unshare is auto synced
 v
 +--> pidfile daemon(double fork()ed)
 v
 +--> --timeout? => timeout watchdog (double fork()ed) => get RURI_PID_XXXX and watch => timeout? kill container : just exit
 v
 +--> container setup
        |
        |
        +--> geteuid()!=0?
        |       v
        |   ruri_run_rootless_container()
        |       v
        |   store/load .rurienv
        |       v
        |   ruri_run_rootless_chroot_container()
        |       v
        |   exec target
        |
        |
        +--> unshare?
        |       v
        |   ruri_run_unshare_container()
        |       v
        |   store/load .rurienv
        |       v
        |   ruri_run_chroot_container()
        |       v
        |    exec target
        |
        |
        +--> none?
                v
            ruri_run_chroot_container()
                v
            store/load .rurienv
                v
             exec target
```
```
ruri()
 v
pidfile daemon(double fork()ed) => write RURI_INIT_XXXX => write RURI_PID_FILE_XXXX => auto_umount? umount : just exit
 v
chroot/unshare/rootless fork(), to #1: parent, #2: child
 v
#2 wait_before_exec? write RURI_PID_FILE_WAIT_EXEC
 v
#2 write RURI_PID_FILE_PID_XXXX to daemon
 v
#2 exec() target
 v
#1 waitpid() end
 v
#1 write RURI_EXITED_XXXX stat to daemon
 v
#1 exit() as same stat of #2
```
And, panic() will catch core signal, detect_suid_or_capability() will check if there is SUID or caps on ruri binary.      
# fork()s:
The exec() is handled by a fork(), unshare/rootless container already fork()ed, and pure chroot container has a fork in ruri.c before running ruri_run_chroot_container(). This is for pidfile daemon to get the pid of the container process.    
Pidfile daemon is a double-forked process, it will receive message from the container process, and write it to pidfile.    
Timeout watchdog is also a double-forked process, it will wait for the container process to exit, and if it doesn't exit in time, it will kill the container process.    
If --fork-as-init is enabled, ruri will fork() before exec() the command in container, so that ruri will be pid 1, to avoid zombie process.     