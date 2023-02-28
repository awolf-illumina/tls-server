#include "tcp_echoserver.h"
#include "string.h"
#include "lwip/opt.h"
#include "lwip/init.h"
#include "netif/etharp.h"
#include "lwip/netif.h"
#include "lwip/timeouts.h"
#include "lwip/opt.h"
#include "lwip/api.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"


/* Definitions for tcpTask */
osThreadId_t tcpTaskHandle;
const osThreadAttr_t tcpTask_attributes = {
  .name = "tcpTask",
  .stack_size = 8096 * 4,
  .priority = 1,
};


/**
 *
 */
static void _run(void *argument)
{
  int sock, size, newconn;
  struct sockaddr_in address, remotehost;
  int ret;

  /* create a TCP socket */
  if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
  {
    return;
  }
  
  /* bind to port 7 at any interface */
  address.sin_family = AF_INET;
  address.sin_port = htons(7);
  address.sin_addr.s_addr = INADDR_ANY;

  if (bind(sock, (struct sockaddr *)&address, sizeof (address)) < 0)
  {
    return;
  }
  
  /* listen for incoming connections (TCP listen backlog = 5) */
  listen(sock, 5);
  
  size = sizeof(remotehost);
  
  while (1) 
  {
    uint8_t recv_buffer[100];
    memset(recv_buffer, 0, sizeof(recv_buffer));

    newconn = accept(sock, (struct sockaddr *)&remotehost, (socklen_t *) &size);

    /* Read in the request */
    ret = read(newconn, recv_buffer, sizeof(recv_buffer)); 

    write(newconn, recv_buffer, ret);

    /* Close connection socket */
    close(newconn);
  }
}

/**
 *
*/
void tcp_echoserver_create(void)
{
  /* creation of tcp task */
  tcpTaskHandle = osThreadNew(_run, NULL, &tcpTask_attributes);
}