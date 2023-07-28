#include <sys/types.h>

int pppoe2_create_discovery_socket(const char *ifname, unsigned char *hwaddr);
int pppoe2_create_if_and_session_socket(const char *ifname, const unsigned char hwaddr[6], int sid, int *ctlfd, int *pppdevfd);
