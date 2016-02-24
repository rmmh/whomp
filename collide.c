#include <err.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <asm/unistd.h>
#include <linux/perf_event.h>

#define BITS_TESTED 24
#define BUF_SIZE (1L<<BITS_TESTED)

const int INSN_RET = 0xC3;  // 1 byte
const int INSN_JMP = 0xE9;  // 5 bytes: opcode + 4B displacement

//////////////////////////////////////////////
// xorshift128+ by Sebastiano Vigna
// from http://xorshift.di.unimi.it/xorshift128plus.c
uint64_t
xrand(void) {
    static uint64_t s[2] = {0x12345678L, 0xABCDEF123L};
    uint64_t s1 = s[0];
    const uint64_t s0 = s[1];
    s[0] = s0;
    s1 ^= s1 << 23; // a
    s[1] = s1 ^ s0 ^ (s1 >> 18) ^ (s0 >> 5); // b, c
    return s[1] + s0;
}
/////////////////////////////////////

long
perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
    int cpu, int group_fd, unsigned long flags)
{
    int ret;
    ret = syscall(__NR_perf_event_open, hw_event, pid, cpu,
     group_fd, flags);
    return ret;
}

int
open_perf_counter(void)
{
    int fd;
    struct perf_event_attr pe = {};
    pe.size = sizeof(struct perf_event_attr);

    // Haswell BACLEARS.ANY:
    // "Number of front end re-steers due to BPU misprediction."
    // Intel® 64 and IA-32 Architectures Software Developer’s Manual
    // Vol 3B -- 19-29
    // TODO: use libpfm4 to supply this value for different uarchs
    pe.type = PERF_TYPE_RAW;
    pe.config = 0x1FE6;

    pe.disabled = 1;
    pe.exclude_kernel = 1;
    pe.exclude_hv = 1;
    fd = perf_event_open(&pe, 0, -1, -1, 0);
    if (fd == -1)
        err(EXIT_FAILURE, "Error opening leader %llx", pe.config);
    return fd;
}

long
count_perf(int fd, void (*func)())
{
    long long count;
    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    func(); func(); // warm up?
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
    // running the function 10x makes any consistent perf events
    // occur repeatedly, helping to separate them from background noise
    func(); func(); func(); func(); func();
    func(); func(); func(); func(); func();
    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    if (read(fd, &count, sizeof(count)) != sizeof(count))
        err(EXIT_FAILURE, "unable to read perfctr");
    return count;
}

long
count_perf_min(int fd, void (*func)(), int iters)
{
    long min_count = LONG_MAX;
    for (int i = 0; i < iters; i++) {
        long count = count_perf(fd, func);
        if (count < min_count)
            min_count = count;
    }
    return min_count;
}

double
count_perf_average(int fd, void (*func)(), int iters)
{
    for (int i = 0; i < 10; i++)
        count_perf(fd, func);  // warm-up.

    long total = 0;
    for (int i = 0; i < iters; i++)
        total += count_perf(fd, func);
    return total / (double)iters;
}

void
write_jump(uint8_t *buf, int addr, int target)
{
    int offset = target - addr - 5;
    buf[addr] = INSN_JMP;
    buf[addr+1] = offset & 0xFF;
    buf[addr+2] = (offset >> 8) & 0xFF;
    buf[addr+3] = (offset >> 16) & 0xFF;
    buf[addr+4] = (offset >> 24) & 0xFF;
}

// returns true if putting a jump instruction
// at addr would squash another jump instruction
int
already_used(uint8_t *buf, int addr)
{
    for (int i = -4; i <= 4; i++) {
        if (addr + i < 0)
            continue;
        if (buf[addr + i] == INSN_JMP)
            return 1;
    }
    return 0;
}

int
main(int argc, char **argv)
{
    int fd = open_perf_counter();

    // Create a function from a series of unconditional jumps

    uint8_t *buf = mmap((void*)0x100000000,
                        BUF_SIZE,
                        PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                        -1, 0);
    if (buf == MAP_FAILED)
        err(EXIT_FAILURE, "unable to mmap");

    const int N_JUMPS = 410;
    int last = xrand() % (BUF_SIZE - 5);

    int jump_addrs[N_JUMPS];
    jump_addrs[0] = last;

    for (int i = 1; i < N_JUMPS; i++) {
        int target;
        do {
            target = xrand() % (BUF_SIZE - 5);
        } while (already_used(buf, target));
        write_jump(buf, last, target);
        jump_addrs[i] = target;
        last = target;
    }

    buf[last] = INSN_RET;

    void (*func)() = (void(*)())buf + jump_addrs[0];

    long clears = count_perf_min(fd, func, 5000);
    printf("BACLEARS: %ld\n", clears);

    // Try to find which jumps are causing mispredicts.
    for (int i = 1; i < N_JUMPS - 1; i++) {
        write_jump(buf, jump_addrs[i - 1], jump_addrs[i + 1]);  // skip this jump
        long modified_clears = count_perf_min(fd, func, 500);
        if (modified_clears < clears - 7)
            printf("!! %03d %06x %ld\n", i, jump_addrs[i], modified_clears);
        write_jump(buf, jump_addrs[i - 1], jump_addrs[i]);  // undo
    }

    close(fd);
}
