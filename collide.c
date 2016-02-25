#include <err.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <asm/unistd.h>
#include <linux/perf_event.h>

#define BITS_TESTED 31
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
open_perf_counter(int event)
{
    int fd;
    struct perf_event_attr pe = {};
    pe.size = sizeof(struct perf_event_attr);
    pe.type = PERF_TYPE_RAW;
    pe.config = event;
    pe.disabled = 1;
    pe.exclude_kernel = 1;
    pe.exclude_hv = 1;
    fd = perf_event_open(&pe, 0, -1, -1, 0);
    if (fd == -1)
        err(EXIT_FAILURE, "Error opening leader %llx", pe.config);
    return fd;
}

const struct {
    int model, event;
} model_events[] = {
// These event numbers are from
// Intel® 64 and IA-32 Architectures Software Developer’s Manual, Vol 3B
// "Number of front end re-steers due to BPU misprediction."
// (Sandy Bridge): "Counts the number of times the front end is resteered,
//      mainly when the BPU cannot provide a correct prediction and this is
//      corrected by other branch handling mechanisms at the front end."
// Nehalem: Sandy Bridge + " This can occur if the code has many branches
//      such that they cannot be consumed by the BPU. Each BACLEAR asserted
//      by the BAC generates approximately an 8 cycle bubble in the instruction
//      fetch pipeline."
// (NOTE: libpfm4 could supply these values as well)
    {0x4E, 0x1E6}, {0x5E, 0x1E6},  // 6th Gen: Skylake BACLEARS.ANY
    // 5th Gen: Broadwell appears to lack this event?
    // More likely it's the same as Haswell, but they didn't appear to document it.
    {0x3C, 0x1FE6}, {0x45, 0x1FE6}, {0x40, 0x1FE6}, // 4th Gen: Haswell BACLEARS.ANY
    {0x3A, 0x1FE6}, // 3rd Gen: Ivy Bridge BACLEARS.ANY
    {0x2A, 0x1E6}, {0x2D, 0x1E6},   // 2nd Gen: Sandy Bridge BACLEARS.ANY
    {0x25, 0x1E6}, {0x2C, 0x1E6}, {0x2C, 0x1E6}, // Westmere BACLEAR.CLEAR
    {0x1A, 0x1E6}, {0x1E, 0x1E6}, {0x1F, 0x1E6}, {0x2E, 0x1E6}, // Nehalem BACLEAR.CLEAR
    {0, 0}
};

int
determine_perf_event(void)
{
    FILE *cpuinfo = fopen("/proc/cpuinfo", "r");
    if (!cpuinfo)
        err(EXIT_FAILURE, "unable to open cpuinfo");
    int family = 0, model = 0;
    char *line = NULL;
    size_t size = 0;
    while (getline(&line, &size, cpuinfo) != -1) {
        char *saveptr = NULL;
        char *key = strtok_r(line, "\t:", &saveptr);
        char *value = strtok_r(NULL, "\t: ", &saveptr);
        if (key == NULL || value == NULL)
            break;
        if (!strcmp("vendor_id", key)) {
            if (!strcmp(key, "GenuineIntel\n"))
                errx(EXIT_FAILURE, "only works for Intel");
        } else if (!strcmp("cpu family", key)) {
            family = atoi(value);
        } else if (!strcmp("model", key)) {
            model = atoi(value);
        }
    }
    fclose(cpuinfo);
    if (family != 6)
        errx(EXIT_FAILURE, "unknown cpu family %d (expected 6)", family);
    for (int i = 0; model_events[i].model != 0; i++) {
        if (model_events[i].model == model)
            return model_events[i].event;
    }
    errx(EXIT_FAILURE, "unknown CPU model %d", model);
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
    int fd = open_perf_counter(determine_perf_event());

    // Create a function from a series of unconditional jumps

    uint8_t *buf = mmap((void*)0x100000000LL,
                        BUF_SIZE,
                        PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                        -1, 0);
    if (buf == MAP_FAILED)
        err(EXIT_FAILURE, "unable to mmap");

    const int N_JUMPS = 300;
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

    int mask = 0;
    int expected = 0;

    // Try to find which jumps are causing mispredicts.
    printf("N   addr      clears\n");
    for (int i = 1; i < N_JUMPS - 1; i++) {
        write_jump(buf, jump_addrs[i - 1], jump_addrs[i + 1]);  // skip this jump
        long modified_clears = count_perf_min(fd, func, 500);
        if (modified_clears < clears - 6) {
            uintptr_t addr = (uintptr_t)buf + jump_addrs[i];
            printf("%03d %8lx %ld\n", i, addr, modified_clears);
            if (mask == 0) {
                mask = (1L << BITS_TESTED) - 1;
                expected = addr;
            } else {
                mask ^= (mask & addr) ^ expected;
                expected &= mask;
            }
        }
        write_jump(buf, jump_addrs[i - 1], jump_addrs[i]);  // undo
    }
    printf("mask: %08x\n", mask);

    close(fd);
}
