// uprobe.c
#include <stdio.h>
#include <unistd.h>
#include "hello.skel.h"

int main(void)
{
    struct hello_bpf *skel;
    int err;

    skel = hello_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "open_and_load failed\n");
        return 1;
    }

    /* Auto-attach: skeleton will attach uprobes/uretprobes for us */
    err = hello_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "attach failed: %d\n", err);
        return 1;
    }

    printf("Successfully started! Run ./target in another terminal.\n");

    while (1)
        sleep(1);

    hello_bpf__destroy(skel);
    return 0;
}

