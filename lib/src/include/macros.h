#define ERR(cond) if ((cond)) { \
    int save_errno = errno;

#define ERR_WITH_RETRY(expr) while ((expr)) { \
    int save_errno = errno; \
    if (save_errno == EINTR) { \
        continue; \
    } \

#define ERR_NEG(cond) ERR((cond) < 0)
#define ERR_NEG_WITH_RETRY(expr) ERR_WITH_RETRY((expr) < 0)
#define ERR_0(cond) ERR(!(cond))
#define ERR_0_WITH_RETRY(expr) ERR_WITH_RETRY(!(expr))

#define ERR_END errno = save_errno; \
    return -1; \
}

#define NULL_END errno = save_errno; \
    return NULL; \
}

#define CONTAINER_OF_UNCHECKED(ptr, type, member) \
    ((type *)((char *)(ptr) - offsetof(type, member)))
