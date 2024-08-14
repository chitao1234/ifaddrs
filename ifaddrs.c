#include <errno.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#define ifaddr __libc_ifaddr
#include <net/if.h>
#undef ifaddr
#ifdef ifa_broadaddr
#undef ifa_broadaddr
#endif
#ifdef ifa_dstaddr
#undef ifa_dstaddr
#endif

#include "ifaddrs.h"
#include "ifaddrs_internal.h"
#include "macros.h"

static bool is_zero(char *ptr, size_t size) {
    for (size_t i = 0; i < size; i++) {
        if (ptr[i] != 0) {
            return false;
        }
    }
    return true;
}

int getifaddrs(struct ifaddrs **ifap) {
#ifndef IFADDRS_USE_IOCTL
    struct ifaddrs *l3addr;
    struct ifaddrs *l2end;
    while (!(l2end = getifaddrs_getlink(ifap))) {
        if (errno != EINTR) {
            break;
        } else {
            continue;
        }
    }
    // struct ifaddrs *l2end = NULL;
    struct ifaddrs *l3end;
    while (!(l3end = getifaddrs_getaddr(&l3addr, (bool)l2end))) {
        if (errno != EINTR) {
            break;
        } else {
            continue;
        }
    }
    if (!l3end) {
        l3end = getifaddrs_ioctl(&l3addr, !l2end);
    }
    if (l2end) {
        ERR_0(l3end)
            // system configuration is not sane...
            freeifaddrs(*ifap);
            *ifap = NULL;
        ERR_END
        match_getaddr_with_getlink(*ifap, l3addr);
        l2end->ifa_next = l3addr;
    } else {
        // looks like an android device
        ERR_0(l3end)
            freeifaddrs(l3addr);
        ERR_END
        *ifap = l3addr;
    }
    return 0;
#else
    return getifaddrs_ioctl(ifap, true) ? 0 : -1;
#endif
}

void freeifaddrs(struct ifaddrs *ifa) {
    while (ifa) {
        struct ifaddrs *next = ifa->ifa_next;
        free_ifaddr(TO_INTERNAL(ifa));
        ifa = next;
    }
}

static void free_ifaddr(struct ifaddrs_internal *ifa) {
    if (!ifa) {
        return;
    }
    struct ifaddrs *ifp = &ifa->inner;
    free(ifp->ifa_name);
    free(ifp->ifa_addr);
    free(ifp->ifa_netmask);
    free(ifp->ifa_broadaddr);
#ifndef IFADDRS_USE_UNION
    free(ifp->ifa_dstaddr);
#endif
    free(ifp->ifa_data);

    free(ifa);
}

static void free_dstaddr(struct ifaddrs *ifa) {
    if (!ifa) {
        return;
    }
    free(ifa->ifa_dstaddr);
    ifa->ifa_dstaddr = NULL;
}

static void free_broadaddr(struct ifaddrs *ifa) {
    if (!ifa) {
        return;
    }
    free(ifa->ifa_broadaddr);
    ifa->ifa_broadaddr = NULL;
}

static struct ifaddrs_internal *
alloc_ifaddr(size_t socklen, bool hardware_address) {
    struct ifaddrs_internal *ifa;
    if (!(ifa = calloc(1, sizeof(struct ifaddrs_internal)))) {
        return NULL;
    }
    struct ifaddrs *ifp = &ifa->inner;

    if (!(ifp->ifa_name = calloc(1, IFNAMSIZ)) ||
        !(ifp->ifa_addr = calloc(1, socklen)) ||
        !(ifp->ifa_broadaddr = calloc(1, socklen))) {
        free_ifaddr(ifa);
        return NULL;
    }

    if (!hardware_address) {
        if (!(ifp->ifa_netmask = calloc(1, socklen))) {
            free_ifaddr(ifa);
            return NULL;
        }
    }

#ifndef IFADDRS_USE_UNION
    if (!hardware_address) {
        if (!(ifp->ifa_dstaddr = calloc(1, socklen))) {
            free_ifaddr(ifa);
            return NULL;
        }
    }
#endif

    return ifa;
}

#ifndef IFADDRS_USE_IOCTL
#define DUMP_BUF_SIZE 8192
// for AF_PACKET
static struct ifaddrs *getifaddrs_getlink(struct ifaddrs **ifap) {
    if (ifap == NULL) {
        errno = EFAULT;
        return NULL;
    }

    *ifap = NULL;

    int sockfd;
    ERR_NEG(sockfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE))
    NULL_END

    struct getlink_msg {
        struct nlmsghdr hdr;
        struct ifinfomsg ifi __attribute__((aligned(NLMSG_ALIGNTO)));
    } request = {0};
    request.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    request.hdr.nlmsg_type = RTM_GETLINK;
    request.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    request.hdr.nlmsg_seq = 1;
    request.ifi.ifi_family = AF_UNSPEC;
    request.ifi.ifi_change = 0xFFFFFFFF;

    struct sockaddr_nl sa = {AF_NETLINK};
    socklen_t salen = sizeof(sa);

    ERR_WITH_RETRY(
        sendto(
            sockfd, &request, sizeof(request), 0, (struct sockaddr *)&sa, salen
        ) < (ssize_t)sizeof(request)
    )
        close(sockfd);
    NULL_END

    // kernel recommend 32k for dump
    struct nlmsghdr *buf;
    ERR_0(buf = calloc(1, DUMP_BUF_SIZE))
        close(sockfd);
    NULL_END

    struct iovec iov = {buf, DUMP_BUF_SIZE};
    struct msghdr msg = {&sa, salen, &iov, 1, NULL, 0, 0};

    struct ifaddrs *ifp = *ifap;

    int finish = 0;
    while (!finish) {
        ssize_t len;
        ERR_NEG_WITH_RETRY(len = recvmsg(sockfd, &msg, 0))
            freeifaddrs(*ifap);
            *ifap = NULL;
            free(buf);
            close(sockfd);
        NULL_END

        ERR(msg.msg_flags & MSG_TRUNC)
            freeifaddrs(*ifap);
            *ifap = NULL;
            free(buf);
            close(sockfd);
        NULL_END

        for (struct nlmsghdr *nlh = buf; NLMSG_OK(nlh, len);
             nlh = NLMSG_NEXT(nlh, len)) {
            if (nlh->nlmsg_type == NLMSG_DONE) {
                finish = 1;
                break;
            }
            ERR(nlh->nlmsg_type == NLMSG_ERROR)
                freeifaddrs(*ifap);
                *ifap = NULL;
                free(buf);
                close(sockfd);
            NULL_END

            if (nlh->nlmsg_flags & NLM_F_DUMP_INTR) {
                errno = EINTR;
                freeifaddrs(*ifap);
                *ifap = NULL;
                free(buf);
                close(sockfd);
                return NULL;
            }

            if (nlh->nlmsg_type != RTM_NEWLINK) {
                fprintf(stderr, "Unknown message type %d\n", nlh->nlmsg_type);
                continue;
            }

            struct ifinfomsg *ifi = NLMSG_DATA(nlh);

            struct ifaddrs_internal *outer;
            if (ifi->ifi_family == AF_UNSPEC) {
                ERR_0(outer = alloc_ifaddr(sizeof(struct sockaddr_ll), true))
                    freeifaddrs(*ifap);
                    *ifap = NULL;
                    free(buf);
                    close(sockfd);
                NULL_END
            } else {
                fprintf(
                    stderr, "Unknown address family: %d\n", ifi->ifi_family
                );
                continue;
            }
            struct ifaddrs *ifaddr = &outer->inner;

            ifaddr->ifa_flags = ifi->ifi_flags;
            outer->index = ifi->ifi_index;

            ERR_0(ifaddr->ifa_data = malloc(sizeof(struct rtnl_link_stats)))
                free_ifaddr(outer);
                freeifaddrs(*ifap);
                *ifap = NULL;
                free(buf);
                close(sockfd);
            NULL_END

            bool has_broadaddr = false, has_addr = false;
            ssize_t rtl = IFLA_PAYLOAD(nlh);
            for (struct rtattr *rta = IFLA_RTA(ifi); RTA_OK(rta, rtl);
                 rta = RTA_NEXT(rta, rtl)) {
                size_t payload = RTA_PAYLOAD(rta);
                void *data = RTA_DATA(rta);
                if (rta->rta_type == IFLA_IFNAME) {
                    strncpy(ifaddr->ifa_name, data, IFNAMSIZ);
                    ifaddr->ifa_name[IFNAMSIZ - 1] = '\0';
                } else if (rta->rta_type == IFLA_STATS) {
                    memcpy(
                        ifaddr->ifa_data, data, sizeof(struct rtnl_link_stats)
                    );
                } else if (rta->rta_type == IFLA_ADDRESS) {
                    has_addr = true;
                    struct sockaddr_ll *sll =
                        (struct sockaddr_ll *)ifaddr->ifa_addr;
                    sll->sll_family = AF_PACKET;
                    if (payload > sizeof(sll->sll_addr)) {
                        free(ifaddr->ifa_addr);
                        continue;
                    }
                    memcpy(&sll->sll_addr, data, sizeof(sll->sll_addr));
                    sll->sll_halen = payload;
                    sll->sll_hatype = ifi->ifi_type;
                    sll->sll_ifindex = ifi->ifi_index;
                } else if (rta->rta_type == IFLA_BROADCAST) {
                    has_broadaddr = true;
                    struct sockaddr_ll *sll =
                        (struct sockaddr_ll *)ifaddr->ifa_broadaddr;
                    sll->sll_family = AF_PACKET;
                    if (payload > sizeof(sll->sll_addr)) {
                        free(ifaddr->ifa_broadaddr);
                        continue;
                    }
                    memcpy(&sll->sll_addr, data, sizeof(sll->sll_addr));
                    sll->sll_halen = payload;
                    sll->sll_hatype = ifi->ifi_type;
                    sll->sll_ifindex = ifi->ifi_index;
                }
            }

            if (!has_addr) {
                free(ifaddr->ifa_addr);
                ifaddr->ifa_addr = NULL;
            }
            if (!has_broadaddr) {
                free_broadaddr(ifaddr);
            }

            if (!ifp) {
                *ifap = ifaddr;
                ifp = ifaddr;
            } else {
                ifp->ifa_next = ifaddr;
                ifp = ifaddr;
            }
        }
    }

    free(buf);
    close(sockfd);
    return ifp;
}

static struct ifaddrs *
getifaddrs_getaddr(struct ifaddrs **ifap, bool use_getlink_result) {
    if (ifap == NULL) {
        errno = EFAULT;
        return NULL;
    }

    *ifap = NULL;

    int sockfd, ioctl_sockfd;
    ERR_NEG(sockfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE))
    NULL_END

    ERR_NEG(ioctl_sockfd = socket(AF_INET, SOCK_DGRAM, 0))
        close(sockfd);
    NULL_END

    struct getaddr_msg {
        struct nlmsghdr hdr;
        struct ifaddrmsg ifa __attribute__((aligned(NLMSG_ALIGNTO)));
    } request = {0};
    request.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    request.hdr.nlmsg_type = RTM_GETADDR;
    request.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    request.hdr.nlmsg_seq = 2;
    request.ifa.ifa_family = AF_UNSPEC;

    struct sockaddr_nl sa = {AF_NETLINK};
    socklen_t salen = sizeof(sa);

    ERR_WITH_RETRY(
        sendto(
            sockfd, &request, sizeof(request), 0, (struct sockaddr *)&sa, salen
        ) < (ssize_t)sizeof(request)
    )
        close(ioctl_sockfd);
        close(sockfd);
    NULL_END

    // kernel recommend 32k for dump
    struct nlmsghdr *buf;
    ERR_0(buf = calloc(1, DUMP_BUF_SIZE))
        close(ioctl_sockfd);
        close(sockfd);
    NULL_END

    struct iovec iov = {buf, DUMP_BUF_SIZE};
    struct msghdr msg = {&sa, salen, &iov, 1, NULL, 0, 0};

    struct ifaddrs *ifp = *ifap;

    int finish = 0;
    while (!finish) {
        ssize_t len;

        ERR_NEG_WITH_RETRY(len = recvmsg(sockfd, &msg, 0))
            freeifaddrs(*ifap);
            *ifap = NULL;
            free(buf);
            close(ioctl_sockfd);
            close(sockfd);
        NULL_END

        ERR(msg.msg_flags & MSG_TRUNC)
            freeifaddrs(*ifap);
            *ifap = NULL;
            free(buf);
            close(ioctl_sockfd);
            close(sockfd);
        NULL_END

        for (struct nlmsghdr *nlh = buf; NLMSG_OK(nlh, len);
             nlh = NLMSG_NEXT(nlh, len)) {
            if (nlh->nlmsg_type == NLMSG_DONE) {
                finish = 1;
                break;
            }
            ERR(nlh->nlmsg_type == NLMSG_ERROR)
                freeifaddrs(*ifap);
                *ifap = NULL;
                free(buf);
                close(ioctl_sockfd);
                close(sockfd);
            NULL_END

            if (nlh->nlmsg_flags & NLM_F_DUMP_INTR) {
                errno = EINTR;
                freeifaddrs(*ifap);
                *ifap = NULL;
                free(buf);
                close(ioctl_sockfd);
                close(sockfd);
                return NULL;
            }

            if (nlh->nlmsg_type != RTM_NEWADDR) {
                fprintf(stderr, "Unknown message type %d\n", nlh->nlmsg_type);
                continue;
            }

            struct ifaddrmsg *ifa = NLMSG_DATA(nlh);

            struct ifaddrs_internal *outer;
            if (ifa->ifa_family == AF_INET) {
                ERR_0(outer = alloc_ifaddr(sizeof(struct sockaddr_in), false))
                    freeifaddrs(*ifap);
                    *ifap = NULL;
                    free(buf);
                    close(ioctl_sockfd);
                    close(sockfd);
                NULL_END
            } else if (ifa->ifa_family == AF_INET6) {
                ERR_0(outer = alloc_ifaddr(sizeof(struct sockaddr_in6), false))
                    freeifaddrs(*ifap);
                    *ifap = NULL;
                    free(buf);
                    close(ioctl_sockfd);
                    close(sockfd);
                NULL_END
            } else {
                fprintf(
                    stderr, "Unknown address family: %d\n", ifa->ifa_family
                );
                continue;
            }
            struct ifaddrs *ifaddr = &outer->inner;
            outer->index = ifa->ifa_index;

            // calculate netmask
            ifaddr->ifa_netmask->sa_family = ifa->ifa_family;
            if (ifa->ifa_family == AF_INET) {
                struct sockaddr_in *sin =
                    (struct sockaddr_in *)ifaddr->ifa_netmask;
                sin->sin_addr.s_addr =
                    htonl(~((uint32_t)0) << (32 - ifa->ifa_prefixlen));
            } else { // AF_INET6
                struct sockaddr_in6 *sin6 =
                    (struct sockaddr_in6 *)ifaddr->ifa_netmask;
                size_t len = ifa->ifa_prefixlen / 8;
                size_t rem = ifa->ifa_prefixlen % 8;
                if (len) {
                    memset(sin6->sin6_addr.s6_addr, 0xff, len);
                }
                if (rem) {
                    sin6->sin6_addr.s6_addr[len] = 0xffU << (8 - rem);
                }
            }

            bool has_dstaddr = false, has_broadaddr = false;
            ssize_t rtl = IFA_PAYLOAD(nlh);
            for (struct rtattr *rta = IFA_RTA(ifa); RTA_OK(rta, rtl);
                 rta = RTA_NEXT(rta, rtl)) {
                // size_t payload = RTA_PAYLOAD(rta);
                void *data = RTA_DATA(rta);

                if (rta->rta_type == IFA_LABEL) {
                    strncpy(ifaddr->ifa_name, data, IFNAMSIZ);
                    ifaddr->ifa_name[IFNAMSIZ - 1] = '\0';
                } else if (rta->rta_type == IFA_ADDRESS) {
                    ifaddr->ifa_addr->sa_family = ifa->ifa_family;
                    if (ifa->ifa_family == AF_INET) {
                        memcpy(
                            &((struct sockaddr_in *)ifaddr->ifa_addr)->sin_addr,
                            data, sizeof(struct in_addr)
                        );
                    } else { // AF_INET6
                        struct sockaddr_in6 *sin6 =
                            (struct sockaddr_in6 *)ifaddr->ifa_addr;
                        memcpy(&sin6->sin6_addr, data, sizeof(struct in6_addr));
                        if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr)) {
                            sin6->sin6_scope_id = ifa->ifa_index;
                        }
                    }
                } else if (rta->rta_type == IFA_BROADCAST) {
                    has_broadaddr = true;
#ifdef IFADDRS_USE_UNION
                    has_dstaddr = false;
#endif
                    ifaddr->ifa_broadaddr->sa_family = ifa->ifa_family;
                    if (ifa->ifa_family == AF_INET) {
                        memcpy(
                            &((struct sockaddr_in *)ifaddr->ifa_broadaddr)
                                 ->sin_addr,
                            data, sizeof(struct in_addr)
                        );
                    } else { // AF_INET6
                        struct sockaddr_in6 *sin6 =
                            (struct sockaddr_in6 *)ifaddr->ifa_broadaddr;
                        memcpy(&sin6->sin6_addr, data, sizeof(struct in6_addr));
                        if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr)) {
                            sin6->sin6_scope_id = ifa->ifa_index;
                        }
                    }
                } else if (rta->rta_type == IFA_LOCAL) {
                    has_dstaddr = true;
#ifdef IFADDRS_USE_UNION
                    has_broadaddr = false;
#endif
                    ifaddr->ifa_dstaddr->sa_family = ifa->ifa_family;
                    if (ifa->ifa_family == AF_INET) {
                        memcpy(
                            &((struct sockaddr_in *)ifaddr->ifa_dstaddr)
                                 ->sin_addr,
                            data, sizeof(struct in_addr)
                        );
                    } else { // AF_INET6
                        struct sockaddr_in6 *sin6 =
                            (struct sockaddr_in6 *)ifaddr->ifa_dstaddr;
                        memcpy(&sin6->sin6_addr, data, sizeof(struct in6_addr));
                        if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr)) {
                            sin6->sin6_scope_id = ifa->ifa_index;
                        }
                    }
                }
            }

            if (has_dstaddr) {
                // swap dstaddr and addr for p2p interfaces
                struct sockaddr *tmp = ifaddr->ifa_dstaddr;
                ifaddr->ifa_dstaddr = ifaddr->ifa_addr;
                ifaddr->ifa_addr = tmp;
            }

#ifndef IFADDRS_USE_UNION
            if (!has_dstaddr) {
                free_dstaddr(ifaddr);
            }
            if (!has_broadaddr) {
                free_broadaddr(ifaddr);
            }
#else
            if (!has_broadaddr && !has_dstaddr) {
                free_broadaddr(ifaddr);
            }
#endif

            if (!use_getlink_result) {
                // handle ipv6 no IFA_LABEL
                if (!ifaddr->ifa_name[0]) {
                    if_indextoname(ifa->ifa_index, ifaddr->ifa_name);
                    if (!ifaddr->ifa_name[0]) {
                        free_ifaddr(outer);
                        continue;
                    }
                }

                struct ifreq ifr = {0};
                strcpy(ifr.ifr_name, ifaddr->ifa_name);
                ERR_NEG_WITH_RETRY(ioctl(ioctl_sockfd, SIOCGIFFLAGS, &ifr))
                    free_ifaddr(outer);
                    freeifaddrs(*ifap);
                    *ifap = NULL;
                    free(buf);
                    close(ioctl_sockfd);
                    close(sockfd);
                NULL_END
                ifaddr->ifa_flags = ifr.ifr_flags;
            }

            if (!ifp) {
                *ifap = ifaddr;
                ifp = ifaddr;
            } else {
                ifp->ifa_next = ifaddr;
                ifp = ifaddr;
            }
        }
    }

    free(buf);
    close(ioctl_sockfd);
    close(sockfd);
    return ifp;
}

static void
match_getaddr_with_getlink(struct ifaddrs *links, struct ifaddrs *addrs) {
    struct ifaddrs *lp = links;
    for (struct ifaddrs *a = addrs; a; a = a->ifa_next) {
        struct ifaddrs_internal *outer_a = TO_INTERNAL(a);
        bool matched = false;

        // assume kernel preserve order first, which is normally true
        while (!matched && lp) {
            struct ifaddrs_internal *outer_l = TO_INTERNAL(lp);
            if (outer_l->index == outer_a->index) {
                a->ifa_flags = lp->ifa_flags;
                if (!a->ifa_name[0]) {
                    strcpy(a->ifa_name, lp->ifa_name);
                }
                matched = true;
                break;
            }
            lp = lp->ifa_next;
        }

        // just to be extra sure
        if (!matched) {
            for (struct ifaddrs *l = links; l; l = l->ifa_next) {
                struct ifaddrs_internal *outer_l = TO_INTERNAL(l);
                if (outer_l->index == outer_a->index) {
                    a->ifa_flags = l->ifa_flags;
                    if (!a->ifa_name[0]) {
                        strcpy(a->ifa_name, l->ifa_name);
                    }
                    matched = true;
                    lp = l;
                    break;
                }
            }
        }
    }
}
#endif

// fallback ioctl implementation, no ipv6 support
static struct ifaddrs *
getifaddrs_ioctl(struct ifaddrs **ifap, bool get_hwaddr) {
    if (ifap == NULL) {
        errno = EFAULT;
        return NULL;
    }

    *ifap = NULL;

    int sockfd;
    ERR_NEG(sockfd = socket(AF_INET, SOCK_DGRAM, 0))
    NULL_END

    struct ifconf ifc = {0};
    ifc.ifc_len = 0;
    ifc.ifc_buf = NULL;
    ERR_NEG_WITH_RETRY(ioctl(sockfd, SIOCGIFCONF, &ifc))
        close(sockfd);
    NULL_END

    ERR_0(ifc.ifc_buf = calloc(1, ifc.ifc_len))
        close(sockfd);
    NULL_END

    ERR_NEG_WITH_RETRY(ioctl(sockfd, SIOCGIFCONF, &ifc))
        free(ifc.ifc_buf);
        close(sockfd);
    NULL_END

    struct ifreq *ifr = ifc.ifc_req;
    size_t n = ifc.ifc_len / sizeof(struct ifreq);

    struct ifaddrs *ifp = NULL;
    for (size_t i = 0; i < n; i++) {
        struct ifaddrs_internal *outer;
        ERR_0(outer = alloc_ifaddr(sizeof(struct sockaddr_in), false))
            freeifaddrs(*ifap);
            *ifap = NULL;
            free(ifc.ifc_buf);
            close(sockfd);
        NULL_END
        struct ifaddrs *ifaddr = &outer->inner;

        strncpy(ifaddr->ifa_name, ifr[i].ifr_name, IFNAMSIZ);
        ifaddr->ifa_name[IFNAMSIZ - 1] = '\0';

        memcpy(ifaddr->ifa_addr, &ifr[i].ifr_addr, sizeof(struct sockaddr_in));

        ERR_NEG_WITH_RETRY(ioctl(sockfd, SIOCGIFFLAGS, &ifr[i]))
            free_ifaddr(outer);
            freeifaddrs(*ifap);
            *ifap = NULL;
            free(ifc.ifc_buf);
            close(sockfd);
        NULL_END
        ifaddr->ifa_flags = ifr[i].ifr_flags;

        bool has_broadaddr = false, has_dstaddr = false;

        ERR_NEG_WITH_RETRY(ioctl(sockfd, SIOCGIFNETMASK, &ifr[i]))
            free_ifaddr(outer);
            freeifaddrs(*ifap);
            *ifap = NULL;
            free(ifc.ifc_buf);
            close(sockfd);
        NULL_END
        memcpy(
            ifaddr->ifa_netmask, &ifr[i].ifr_netmask, sizeof(struct sockaddr_in)
        );

        ERR_NEG_WITH_RETRY(ioctl(sockfd, SIOCGIFDSTADDR, &ifr[i]))
            free_ifaddr(outer);
            freeifaddrs(*ifap);
            *ifap = NULL;
            free(ifc.ifc_buf);
            close(sockfd);
        NULL_END
        if (!is_zero(
                (char *)&((struct sockaddr_in *)&ifr[i].ifr_dstaddr)->sin_addr,
                sizeof(struct in_addr)
            )) {
            has_dstaddr = true;
            memcpy(
                ifaddr->ifa_dstaddr, &ifr[i].ifr_dstaddr,
                sizeof(struct sockaddr_in)
            );
        }

        ERR_NEG_WITH_RETRY(ioctl(sockfd, SIOCGIFBRDADDR, &ifr[i]))
            free_ifaddr(outer);
            freeifaddrs(*ifap);
            *ifap = NULL;
            free(ifc.ifc_buf);
            close(sockfd);
        NULL_END
        if (!is_zero(
                (char *)&((struct sockaddr_in *)&ifr[i].ifr_broadaddr)
                    ->sin_addr,
                sizeof(struct in_addr)
            )) {
            has_broadaddr = true;
            memcpy(
                ifaddr->ifa_broadaddr, &ifr[i].ifr_broadaddr,
                sizeof(struct sockaddr_in)
            );
        }

#ifndef IFADDRS_USE_UNION
        if (!has_dstaddr) {
            free_dstaddr(ifaddr);
        }
        if (!has_broadaddr) {
            free_broadaddr(ifaddr);
        }
#else
        if (!has_broadaddr && !has_dstaddr) {
            free_broadaddr(ifaddr);
        }
#endif

        if (get_hwaddr) {
            struct ifaddrs_internal *hwaddr_outer;
            // fatal error if cannot allocate memory
            ERR_0(hwaddr_outer = alloc_ifaddr(sizeof(struct sockaddr_ll), true))
                free_ifaddr(outer);
                freeifaddrs(*ifap);
                *ifap = NULL;
                free(ifc.ifc_buf);
                close(sockfd);
            NULL_END
            struct ifaddrs *hwaddr = &hwaddr_outer->inner;

            // cannot get hardware broadcast address using ioctl
            free(hwaddr->ifa_broadaddr);
            hwaddr->ifa_broadaddr = NULL;

            hwaddr->ifa_flags = ifaddr->ifa_flags;
            strcpy(hwaddr->ifa_name, ifaddr->ifa_name);

            // if we cannot get it, just ignore
            bool ioctl_error = false;
            while (ioctl(sockfd, SIOCGIFHWADDR, &ifr[i]) < 0) {
                if (errno != EINTR) {
                    ioctl_error = true;
                    break;
                } else {
                    continue;
                }
            }
            if (!ioctl_error) {
                struct sockaddr_ll *sll =
                    (struct sockaddr_ll *)hwaddr->ifa_addr;
                sll->sll_family = AF_PACKET;
                memcpy(sll->sll_addr, ifr[i].ifr_hwaddr.sa_data, ETH_ALEN);
                sll->sll_halen = ETH_ALEN;
                sll->sll_hatype = ifr[i].ifr_hwaddr.sa_family;

                sll->sll_ifindex = if_nametoindex(ifaddr->ifa_name);
                if (sll->sll_ifindex != 0) {
                    if (!ifp) {
                        *ifap = hwaddr;
                        ifp = hwaddr;
                    } else {
                        ifp->ifa_next = hwaddr;
                        ifp = hwaddr;
                    }
                } else {
                    free_ifaddr(outer);
                }
            } else {
                free_ifaddr(outer);
            }
        }

        if (!ifp) {
            *ifap = ifaddr;
            ifp = ifaddr;
        } else {
            ifp->ifa_next = ifaddr;
            ifp = ifaddr;
        }
    }

    free(ifc.ifc_buf);
    close(sockfd);
    return ifp;
}
