#ifndef IFADDRS_INTERNAL_H
#define IFADDRS_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "macros.h"
#include "ifaddrs.h"

struct ifaddrs_internal {
    struct ifaddrs inner;
    int index;
};

#define TO_INTERNAL(ifa) CONTAINER_OF_UNCHECKED(ifa, struct ifaddrs_internal, inner)

static struct ifaddrs_internal *alloc_ifaddr(size_t socklen, bool addr_only);
static void free_ifaddr(struct ifaddrs_internal *ifa);
static struct ifaddrs *getifaddrs_ioctl(struct ifaddrs **ifap, bool get_hwaddr);
#ifndef IFADDRS_USE_IOCTL
static struct ifaddrs *getifaddrs_getlink(struct ifaddrs **ifap);
static struct ifaddrs *getifaddrs_getaddr(struct ifaddrs **ifap, bool use_getlink_result);
static void match_getaddr_with_getlink(struct ifaddrs *links, struct ifaddrs *addrs);
#endif

#endif