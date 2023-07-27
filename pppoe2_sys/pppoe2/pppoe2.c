#include <arpa/inet.h>
#include <bsd/string.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if_ppp.h>
#include <linux/if_pppox.h>
#include <netpacket/packet.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "pppoe2.h"

int pppoe2_create_discovery_socket(const char *ifname, char *hwaddr)
{
	struct ifreq ifr;
	struct sockaddr_ll sa;

	int sock;
	if ((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_PPP_DISC))) < 0) {
		return -1;
	}

	int broadcast = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof broadcast) < 0) {
		close(sock);
		return -1;
	}

	if (hwaddr) {
		strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);
		if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
			close(sock);
			return -1;
		}

		memcpy(hwaddr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	}

	sa.sll_family = AF_PACKET;
	sa.sll_protocol = htons(ETH_P_PPP_DISC);

	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);
	if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
		close(sock);
		return -1;
	}

	sa.sll_ifindex = ifr.ifr_ifindex;

	if (bind(sock, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
		close(sock);
		return -1;
	}

	return sock;
}

int pppoe2_create_if_and_session_socket(const char *ifname, const char hwaddr[6], int sid, int *ctlfd, int *pppdevfd)
{
	struct sockaddr_pppox sp;

	sp.sa_family = AF_PPPOX;
	sp.sa_protocol = PX_PROTO_OE;
	sp.sa_addr.pppoe.sid = htons(sid);
	memcpy(sp.sa_addr.pppoe.dev, ifname, strlen(ifname) + 1);
	memcpy(sp.sa_addr.pppoe.remote, hwaddr, 6);

	int sock;
	if ((sock = socket(AF_PPPOX, SOCK_STREAM, PX_PROTO_OE)) < 0) {
		return -1;
	}

	if (connect(sock, (const struct sockaddr *) &sp, sizeof sp) < 0) {
		close(sock);
		return -1;
	}

	int chindex;
	if (ioctl(sock, PPPIOCGCHAN, &chindex) < 0) {
		close(sock);
		return -1;
	}

	if ((*ctlfd = open("/dev/ppp", O_RDWR)) < 0) {
		close(sock);
		return -1;
	}

	// TODO: FD_CLOEXEC

	if (ioctl(*ctlfd, PPPIOCATTCHAN, &chindex) < 0) {
		close(*ctlfd);
		close(sock);

		return -1;
	}

	// nonblock shouldn't be needed here

	if ((*pppdevfd = open("/dev/ppp", O_RDWR)) < 0) {
		close(*ctlfd);
		close(sock);

		return -1;
	}

	int ifunit = -1;
	if (ioctl(*pppdevfd, PPPIOCNEWUNIT, &ifunit) < 0) {
		close(*pppdevfd);
		close(*ctlfd);
		close(sock);

		return -1;
	}

	if (ioctl(*ctlfd, PPPIOCCONNECT, &ifunit) < 0) {
		close(*pppdevfd);
		close(*ctlfd);
		close(sock);

		return -1;
	}

	return sock;
}
