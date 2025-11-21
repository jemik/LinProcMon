#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>
#include <sys/socket.h>
#include <errno.h>

void handle_proc_event(struct cn_msg *cn_hdr) {
    struct proc_event *ev = (struct proc_event *)cn_hdr->data;

    if (ev->what == PROC_EVENT_EXEC) {
        pid_t pid = ev->event_data.exec.process_pid;
        pid_t ppid = ev->event_data.exec.process_tgid;
        printf("[EXEC] New process PID=%d PPID=%d\n", pid, ppid);
        // TODO: Call memory scanner here
    }
}

int main() {
    int nl_sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
    if (nl_sock == -1) {
        perror("socket");
        return 1;
    }

    struct sockaddr_nl sa = {
        .nl_family = AF_NETLINK,
        .nl_groups = CN_IDX_PROC,
        .nl_pid = getpid()
    };

    if (bind(nl_sock, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
        perror("bind");
        return 1;
    }

    struct {
        struct nlmsghdr nl_hdr;
        struct cn_msg cn_hdr;
        enum proc_cn_mcast_op op;
    } __attribute__((__packed__)) nl_packet;

    nl_packet.nl_hdr.nlmsg_len = sizeof(nl_packet);
    nl_packet.nl_hdr.nlmsg_type = NLMSG_DONE;
    nl_packet.nl_hdr.nlmsg_flags = 0;
    nl_packet.nl_hdr.nlmsg_seq = 0;
    nl_packet.nl_hdr.nlmsg_pid = getpid();

    nl_packet.cn_hdr.id.idx = CN_IDX_PROC;
    nl_packet.cn_hdr.id.val = CN_VAL_PROC;
    nl_packet.cn_hdr.len = sizeof(enum proc_cn_mcast_op);

    nl_packet.op = PROC_CN_MCAST_LISTEN;

    if (send(nl_sock, &nl_packet, sizeof(nl_packet), 0) == -1) {
        perror("send");
        return 1;
    }

    printf("🧩 Listening for process exec events...\n");

    while (1) {
        char buf[1024];
        int len = recv(nl_sock, buf, sizeof(buf), 0);
        if (len == -1) {
            if (errno == EINTR) continue;
            perror("recv");
            break;
        }

        struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
        while (NLMSG_OK(nlh, len)) {
            struct cn_msg *cn_hdr = NLMSG_DATA(nlh);
            handle_proc_event(cn_hdr);
            nlh = NLMSG_NEXT(nlh, len);
        }
    }

    return 0;
}