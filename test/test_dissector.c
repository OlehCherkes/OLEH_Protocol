#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#define TEST_PORT    7777
#define BUFFER_SIZE  210

struct _message {
   unsigned char pck_version;
   unsigned char pck_type;
   unsigned char pck_flags;
   unsigned char pck_boolean;
   unsigned int  pck_data_len;
};

int main() {
   struct sockaddr_in cli_addr;  // to specify the network address
   int s, cli_len = sizeof(cli_addr);
   char buf[BUFFER_SIZE];
   struct _message msg;
   char *value = "Hello Oleh";
   
   msg.pck_version = 1;
   msg.pck_data_len = 0;

   /* random value for flags, boolean  */
   unsigned int randomData = open("/dev/urandom", O_RDONLY);
   unsigned int myRandomInteger;
   read(randomData, &myRandomInteger, sizeof(myRandomInteger));
   msg.pck_flags  |= myRandomInteger%8;
   read(randomData, &myRandomInteger, sizeof(myRandomInteger));
   msg.pck_boolean = myRandomInteger%2;
   close(randomData);

   if ( (s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1 ) { // creating a socket, IPv4, Datagram socket, UDP
      perror("socket");
      exit(1);
   }

   memset((char*)&cli_addr, 0, sizeof(cli_addr));
   cli_addr.sin_family      = AF_INET;                     // IPv4
   cli_addr.sin_port        = htons(TEST_PORT);            // port 7777
   cli_addr.sin_addr.s_addr = inet_addr("192.168.0.100");  // IP
   
   memset(buf, 0, BUFFER_SIZE);

   msg.pck_type = 1;
   msg.pck_data_len = 10;

   strncpy(buf+sizeof(struct _message), value, (strlen(value)<200)?strlen(value):199);
   
   memcpy(buf, (char*)&msg, sizeof(struct _message));
   
   /* sending a data packet   */
   if ( sendto(s, buf, sizeof(struct _message) + msg.pck_data_len,
               0, (struct sockaddr*)&cli_addr, cli_len) == -1 ) {
      perror("sendto");
      exit(1);
   }
   
   exit(0);
}