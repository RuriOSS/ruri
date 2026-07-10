# Network issue:
You might have `temporary failure resolving xxxxx` or `bad address xxxxx`.      
Try:       
```
rm /etc/resolv.conf
echo nameserver 1.1.1.1 > /etc/resolv.conf
```
Or, for Android, run https://github.com/rurioss/daijin/raw/refs/heads/main/src/share/fixup.sh in container.      
# About systemd:
Systemd needs pid namespace, make sure that your kernel has full support for namespaces.       
You can now use `ruri --systemd --even-unstable /path/to/container /sbin/init` to try booting it up.      
Some services like `systemd-resolved` might not work, you should disable or mask them.      
*WARNING*: systemd is not fully supported, and it might cause your Android device crash, please use it with caution.    
# About container environment:      
For safety, like default docker container, ruri will mask some directory in /sys and /proc, drop unnecessary capabilities, and you are not able to run command like `mknod` or `mount` by default.      
# About capability:      
Ruri drops unnecessary capabilities by default, you can use `-k [cap]` or `-d [cap]` to change the capability settings.      
For example, use `-d cap_sys_admin` to drop CAP_SYS_ADMIN.      
In fulture, maybe new caps will be added to the kernel, and their name might cannot be recognized if you are using old builds. You can use the value of cap (use `capsh  --explain=[cap]` to get the value) to drop it, for example, use `-d 114` to drop the cap 114 (I don't know what the cap should be, mabe can make superuser to be a homo).
# About config:
Since v3.0, ruri can use [k2v](https://github.com/rurioss/libk2v), a new simple config format, to store the config of a container.          
# About rurienv:
Since v3.0, ruri removed the daemon, it use a new way to store the info of a running container.         
ruri will creat `/.rurienv` file into the container, to store runtime info of container.          
The rurienv file is automatically controled by ruri, please do not edit it.      
# About tty:      
The command `tty` in ruri might say that "not a tty".      
If you need to run some program like `gpg`, please use `script -q -O /dev/null` in container.      
# About runtime dirs:
ruri will create /dev/, /sys/ and /proc/ after chroot(2) into container for better security. You can use `-S` option to force it to bind-mount system runtime dirs. But note that, this is very dangerous.      
# About multi-arch container:
Yes, you can run multi-arch containers via ruri if your device support.      
It needs CONFIG_BINFMT_MISC enabled in your kernel config.      
You need to copy qemu-*-static to your container first.      
The path of qemu is the absolute path of qemu binary in the chroot container, for example, you have a qemu binary at `/path/to/container/qemu-amd64-static`, use `-a x86_64 -q /qemu-amd64-static` arguments to start the container.
# About rootless container:
You need user namespaces enabled in your kernel config, and your user should have permission to use it.         
If you get error like `Couldn't create temporary file /tmp/apt.conf.sIKx3J for passing config to apt-key` in container, please `chmod 777 /tmp`.      
You need uidmap installed in your host.      
You might need /etc/subuid and /etc/subgid configured in your host.       