#ifndef IFADDRS_H
#define IFADDRS_H

#ifdef __cplusplus
extern "C" {
#endif

struct ifaddrs {
    struct ifaddrs *ifa_next;     /* Next item in list */
    char *ifa_name;               /* Name of interface */
    unsigned int ifa_flags;       /* Flags from SIOCGIFFLAGS */
    struct sockaddr *ifa_addr;    /* Network address of interface */
    struct sockaddr *ifa_netmask; /* Netmask of interface */
#ifndef IFADDRS_USE_UNION
    struct sockaddr *ifa_broadaddr; /* Broadcast address */
    struct sockaddr *ifa_dstaddr;   /* P2P Destination address */
#else
    struct sockaddr *ifa_ifu; /* Broadcast or P2P Destination address */
#define ifa_broadaddr ifa_ifu
#define ifa_dstaddr ifa_ifu
#endif
    void *ifa_data; /* Address-specific data */
};

int getifaddrs(struct ifaddrs **ifap);
void freeifaddrs(struct ifaddrs *ifa);

#ifdef __cplusplus
}
#endif

#endif
