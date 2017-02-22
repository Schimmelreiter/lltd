















---- iflist


static int get_interface_common(const int fd, struct ifreq *const ifr, struct interface *const info)
{
    struct ethtool_cmd  cmd;
    int                 result;

    /* Interface flags. */
    if (ioctl(fd, SIOCGIFFLAGS, ifr) == -1)
        info->flags = 0;
    else
        info->flags = ifr->ifr_flags;

    ifr->ifr_data = (void *)&cmd;
    cmd.cmd = ETHTOOL_GSET; /* "Get settings" */
    if (ioctl(fd, SIOCETHTOOL, ifr) == -1) {
        /* Unknown */
        info->speed = -1L;
        info->duplex = DUPLEX_UNKNOWN;
    } else {
        info->speed = ethtool_cmd_speed(&cmd);
        info->duplex = cmd.duplex;
    }

    do {
        result = close(fd);
    } while (result == -1 && errno == EINTR);
    if (result == -1)
        return errno;

    return 0;
}

int get_interface_by_index(const int index, struct interface *const info)
{
    int             socketfd, result;
    struct ifreq    ifr;

    if (index < 1 || !info)
        return errno = EINVAL;

    socketfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (socketfd == -1)
        return errno;

    ifr.ifr_ifindex = index;
    if (ioctl(socketfd, SIOCGIFNAME, &ifr) == -1) {
        do {
            result = close(socketfd);
        } while (result == -1 && errno == EINTR);
        return errno = ENOENT;
    }

    info->index = index;
    strncpy(info->name, ifr.ifr_name, IF_NAMESIZE);
    info->name[IF_NAMESIZE] = '\0';

    return get_interface_common(socketfd, &ifr, info);
}

int get_interface_by_name(const char *const name, struct interface *const info)
{
    int             socketfd, result;
    struct ifreq    ifr;

    if (!name || !*name || !info)
        return errno = EINVAL;

    socketfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (socketfd == -1)
        return errno;

    strncpy(ifr.ifr_name, name, IF_NAMESIZE);
    if (ioctl(socketfd, SIOCGIFINDEX, &ifr) == -1) {
        do {
            result = close(socketfd);
        } while (result == -1 && errno == EINTR);
        return errno = ENOENT;
    }

    info->index = ifr.ifr_ifindex;
    strncpy(info->name, name, IF_NAMESIZE);
    info->name[IF_NAMESIZE] = '\0';

    return get_interface_common(socketfd, &ifr, info);
}

int main(int argc, char *argv[])
{
    struct interface    iface;
    int                 arg;
    int                 status = 0;

    if (argc > 1 && (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help"))) {
        fprintf(stderr, "\n");
        fprintf(stderr, "Usage: %s { -h | --help }\n", argv[0]);
        fprintf(stderr, "       %s\n", argv[0]);
        fprintf(stderr, "       %s INTERFACE ...\n", argv[0]);
        fprintf(stderr, "\n");
        return 1;
    }

    if (argc > 1) {
        for (arg = 1; arg < argc; arg++) {
            if (get_interface_by_name(argv[arg], &iface) != 0) {
                fprintf(stderr, "%s: No such interface.\n", argv[arg]);
                status = 1;
                continue;
            }

            printf("%s: Interface %d", iface.name, iface.index);
            if (iface.flags & IFF_UP)
                printf(", up");
            if (iface.duplex == DUPLEX_FULL)
                printf(", full duplex");
            else
            if (iface.duplex == DUPLEX_HALF)
                printf(", half duplex");
            if (iface.speed > 0)
                printf(", %ld Mbps", iface.speed);
            printf("\n");
        }

    } else {
        for (arg = 1; ; arg++) {
            if (get_interface_by_index(arg, &iface) != 0)
                break;

            printf("%s: Interface %d", iface.name, iface.index);
            if (iface.flags & IFF_UP)
                printf(", up");
            if (iface.duplex == DUPLEX_FULL)
                printf(", full duplex");
            else
            if (iface.duplex == DUPLEX_HALF)
                printf(", half duplex");
            if (iface.speed > 0)
                printf(", %ld Mbps", iface.speed);
            printf("\n");
        }
    }

    return status;
}

