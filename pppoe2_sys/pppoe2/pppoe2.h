#include <sys/types.h>

int pppoe2_create_discovery_socket(const char *ifname, char *hwaddr);
int pppoe2_create_if_and_session_socket(const char *ifname, const char hwaddr[6], int sid, int *ctlfd, int *pppdevfd);
