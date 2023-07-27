#include <arpa/inet.h>
#include <bsd/string.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "pppoe2.h"

int pppoe2_create_discovery_socket(const char *ifname, char *hwaddr)
{
	struct ifreq ifr;
	struct sockaddr_ll sa;

	int sock;
	if ((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_PPP_DISC))) < 0) {
		if (EPERM == errno) {
			fprintf(stderr, "[pppoe2] can only create discovery socket as root\n");
		}

		perror("socket");
		return -1;
	}

	int broadcast = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof broadcast) < 0) {
		perror("setsockopt");

		close(sock);
		return -1;
	}

	if (hwaddr) {
		strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);
		if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
			perror("ioctl");

			close(sock);
			return -1;
		}

		memcpy(hwaddr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	}

	sa.sll_family = AF_PACKET;
	sa.sll_protocol = htons(ETH_P_PPP_DISC);

	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);
	if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
		perror("ioctl");

		close(sock);
		return -1;
	}

	sa.sll_ifindex = ifr.ifr_ifindex;

	if (bind(sock, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
		perror("bind");

		close(sock);
		return -1;
	}

	return sock;
}
