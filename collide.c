#include <assert.h>
#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <asm/unistd.h>
#include <linux/perf_event.h>

const int INSN_RET = 0xC3;  // 1 byte
const int INSN_JMP = 0xE9;  // 5 bytes: opcode + 4B displacement

//////////////////////////////////////////////
// xorshift128+ by Sebastiano Vigna
// from http://xorshift.di.unimi.it/xorshift128plus.c
uint64_t s[2] = {0, 1};

uint64_t
xrand(void) {
    uint64_t s1 = s[0];
    const uint64_t s0 = s[1];
    s[0] = s0;
    s1 ^= s1 << 23; // a
    s[1] = s1 ^ s0 ^ (s1 >> 18) ^ (s0 >> 5); // b, c
    return s[1] + s0;
}

void
xsrand(uint64_t x) {
    // splitmix64 generator -- http://xorshift.di.unimi.it/splitmix64.c
    for (int i = 0; i <= 1; i++) {
        uint64_t z = (x += UINT64_C(0x9E3779B97F4A7C15));
        z = (z ^ (z >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)) * UINT64_C(0x94D049BB133111EB);
        s[i] = z ^ (z >> 31);
    }
}
/////////////////////////////////////

void
bind_to_cpu(int cpu)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set) < 0)
        err(EXIT_FAILURE, "Unable to set CPU affinity");
}


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
    struct perf_event_attr pe = { 0 };
    pe.size = sizeof(struct perf_event_attr);
    pe.type = PERF_TYPE_RAW;
    pe.config = event;
    pe.pinned = 1;
    fd = perf_event_open(&pe, 0, -1, -1, 0);
    if (fd == -1)
        err(EXIT_FAILURE, "Error opening leader %llx", pe.config);
    return fd;
}

struct cpu_model {
    char *name;
    int event;
    int models[5];
} cpu_models[] = {
// These event numbers are from
// Intel® 64 and IA-32 Architectures Software Developer’s Manual, Vol 3B
// Descriptions:
// "Number of front end re-steers due to BPU misprediction."
// Sandy Bridge: "Counts the number of times the front end is resteered,
//      mainly when the BPU cannot provide a correct prediction and this is
//      corrected by other branch handling mechanisms at the front end."
// Nehalem: "... This can occur if the code has many branches such that they
//      cannot be consumed by the BPU. Each BACLEAR asserted by the BAC
//      generates approximately an 8 cycle bubble in the instruction fetch
//      pipeline."
// (NOTE: libpfm4 could supply these values as well)
// BACLEARS.ANY:
    {"Skylake",      0x01E6, {0x4E, 0x5E}},
    {"Broadwell",    0x1FE6, {0x3D, 0x47, 0x56}}, // Undocumented event
    {"Haswell",      0x1FE6, {0x3C, 0x45, 0x46, 0x3F}},
    {"Ivy Bridge",   0x1FE6, {0x3A, 0x3E}},
    {"Sandy Bridge", 0x01E6, {0x2A, 0x2D}},
// BACLEAR.CLEAR:
    {"Westmere",     0x01E6, {0x25, 0x2C, 0x2F}},
    {"Nehalem",      0x01E6, {0x1A, 0x1E, 0x1F, 0x2E}},
    {"Core 2",       0x00E6, {0x17, 0x1D}},  // BACLEARS
    {}
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
    for (int i = 0; cpu_models[i].name; i++) {
        for (int *cpu_model = cpu_models[i].models; *cpu_model; cpu_model++) {
            if (*cpu_model == model) {
                int event = cpu_models[i].event;
                printf("# CPU: %s (%02X_%02XH => event %04X)\n",
                    cpu_models[i].name, family, model, event);
                return event;
            }
        }
    }
    errx(EXIT_FAILURE, "unknown CPU model %d", model);
}

static uint64_t
rdpmc(uint32_t ctr)
{
    uint32_t low, high;
    __asm__ volatile("rdpmc" : "=a" (low), "=d" (high) : "c" (ctr));
    return (uint64_t)low | (((uint64_t)high) << 32);
}

static void
serialize(void) {
    __asm__ __volatile__("xor %%eax, %%eax\n\tcpuid" : : : "rax", "rbx", "rcx", "rdx");
}

long
count_perf(void (*func)(void), int counter)
{
    // warm up
    func(); func(); func(); func(); func();
    func(); func(); func(); func(); func();

    serialize(); // prevent instructions prior to here from crossing the rdpmc
    uint64_t before = rdpmc(counter);
    serialize(); // prevent instructions after the rdpmc from jumping ahead
    func();
    serialize(); // ensure all the func() work is done
    uint64_t after = rdpmc(counter);
    serialize(); // prevent any instructions jumping ahead of the rdpmc

    return after - before;
}

// Return the minimum of repeated runs of count_perf(func),
// or the first result at or below thresh.
long
count_perf_min_below(void (*func)(), int iters, int thresh, int counter)
{
    long min_count = LONG_MAX;
    for (int i = 0; i < iters; i++) {
        long count = count_perf(func, counter);
        if (count < min_count)
            min_count = count;
        if (count <= thresh)
            return count;   // early exit
    }
    return min_count;
}

// Return the minimum of repeated runs of count_perf(func)
long
count_perf_min(void (*func)(), int iters, int counter)
{
    return count_perf_min_below(func, iters, 0, counter);
}

void
write_jump(uint8_t *buf, uint64_t addr, uint64_t target)
{
    int64_t offset = target - addr - 5;
    assert(INT32_MIN <= offset && offset <= INT32_MAX);
    assert(offset <= -10 || 0 <= offset);
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

void
usage(char **argv)
{
    errx(2, "usage: %s [-b BITS] [-s SEED] [-j JUMPS] [-r RUNS] [-m MASK_HEX]"
            " [-c CPU]",
         argv[0]);
}

int
main(int argc, char **argv)
{
    int opt;
    int cpu = 0, nbits = 31, jumps = 0, runs = 500;
    uint64_t seed = 0;

    // specify a set of bits that will be zero in each jump
    uint32_t clear_mask = 0;

    while ((opt = getopt(argc, argv, "hs:j:b:r:m:c:")) != -1) {
        errno = 0;
        char *endptr = NULL;
        switch (opt) {
            case 's': seed = strtoll(optarg, &endptr, 10); break;
            case 'b': nbits = strtol(optarg, &endptr, 10); break;
            case 'c': runs = strtol(optarg, &endptr, 10); break;
            case 'j': jumps = strtol(optarg, &endptr, 10); break;
            case 'r': runs = strtol(optarg, &endptr, 10); break;
            case 'm': clear_mask = strtol(optarg, &endptr, 16); break;
            case 'h':
            default:  usage(argv);
        }
        if (endptr == optarg || *endptr != '\0')
            err(EXIT_FAILURE, "bad number '%s'", optarg);
        if (errno)
            err(EXIT_FAILURE, "error parsing '%s'", optarg);
    }
    if (optind != argc)
        usage(argv);


    const uint64_t BUF_SIZE = 1ULL << nbits;

    // pessimistic lower bound
    int max_jumps = (1ULL << (nbits - __builtin_popcount(clear_mask))) / 9;
    if (max_jumps > 100000)
        max_jumps = 100000;

    #define CHECK_RANGE(var, name, lo, hi) \
        if (var < lo || var > hi) \
            errx(EXIT_FAILURE, name " must be in range [%d, %d]", lo, hi);

    CHECK_RANGE(nbits, "BITS", 8, 31);
    CHECK_RANGE(jumps, "JUMPS", 0, max_jumps);
    CHECK_RANGE(runs, "RUNS", 1, 1000000);

    if (jumps != 0) {
        max_jumps = jumps;
    }

    bind_to_cpu(cpu);
    int fd = open_perf_counter(determine_perf_event());

    struct perf_event_mmap_page *event_buf = (struct perf_event_mmap_page*)mmap(
            NULL, getpagesize(), PROT_READ, MAP_SHARED, fd, 0);
    if (event_buf == MAP_FAILED)
        err(EXIT_FAILURE, "unable to mmap event_buf");
    int counter = event_buf->index - 1;

    // Create a function from a series of unconditional jumps

    uint8_t *buf = mmap((void*)0x100000000LL,
                        BUF_SIZE,
                        PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                        -1, 0);
    if (buf == MAP_FAILED)
        err(EXIT_FAILURE, "unable to mmap");

    xsrand(seed);
    int last = xrand() % (BUF_SIZE - 5) & ~clear_mask;

    int jump_addrs[max_jumps];
    jump_addrs[0] = last;
    buf[last] = INSN_RET;
    void (*func)() = (void(*)())buf + jump_addrs[0];

    for (int i = 1; i < max_jumps; i++) {
        int target;
        do {
            target = (xrand() % (BUF_SIZE - 5)) & ~clear_mask;
        } while (already_used(buf, target) || abs(target - last) < 5);
        write_jump(buf, last, target);
        buf[target] = INSN_RET;
        jump_addrs[i] = target;
        last = target;
        if (jumps == 0 && count_perf_min(func, runs, counter) > 0) {
            jumps = i;
            break;
        }
    }

    printf("# -j%d -b%d -s%ld", jumps, nbits, seed);
    if (clear_mask)
        printf(" -m%04x", clear_mask);
    printf("\n");

    long clears = count_perf_min(func, runs * 10, counter);
    printf("BACLEARS: %ld\n", clears);

    if (clears == 0) {
        printf("Bailing: no event on every iteration\n");
        return 0;
    }

    int mask = 0;
    int expected = 0;

    // Try to find which jumps are causing mispredicts.
    printf("N   addr      clears\n");
    for (int i = 0; i < jumps; i++) {
        // skip this jump
        if (i == 0 && jumps > 1) {
            func += jump_addrs[1] - jump_addrs[0];
        } else if (i == jumps - 1) {
            buf[jump_addrs[i - 1]] = INSN_RET;
        } else {
            write_jump(buf, jump_addrs[i - 1], jump_addrs[i + 1]);
        }
        long modified_clears = count_perf_min(func, runs, counter);
        if (modified_clears != clears) {
            uintptr_t addr = (uintptr_t)buf + jump_addrs[i];
            printf("%03d %8lx %ld\n", i + 1, addr, modified_clears);
            if (mask == 0) {
                mask = BUF_SIZE - 1;
                expected = addr;
            } else {
                mask ^= (mask & addr) ^ expected;
                expected &= mask;
            }
        }
        // undo
        if (i == 0 && jumps > 1) {
            func -= jump_addrs[1] - jump_addrs[0];
        } else {
            write_jump(buf, jump_addrs[i - 1], jump_addrs[i]);
        }
    }
    printf("mask: %08x\n", mask);

    munmap(event_buf, getpagesize());
    close(fd);
}
