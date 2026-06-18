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
main() => ruri() =>|| => other util func
                   |- enable unshare? => ruri_run_unshare_container() => ruri_run_chroot_container()
                   |- enable rootless? => ruri_run_rootless_container() => ruri_run_rootless_chroot_container()
                   |- none? => ruri_run_chroot_container()
```
And, panic() will catch core signal, detect_suid_or_capability() will check if there is SUID or caps on ruri binary.      