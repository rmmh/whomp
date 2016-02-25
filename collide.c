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
    pe.disabled = 1;
    pe.exclude_kernel = 1;
    pe.exclude_hv = 1;
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
    // Broadwell's BACLEAR.ANY event isn't documented (?)
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

inline uint64_t rdpmc(uint32_t ctr) {
    uint64_t to;
    __asm__ __volatile__(
            "rdpmc\n\t"
            "shl $0x20, %%rdx\n\t"
            "or %%rdx, %%rax\n\t"
            "mov %%rax, %0\n\t" : "=m"(to) : "c"(ctr) : "%rax", "%rdx");
    return to;
}

long
count_perf(int fd, void (*func)())
{
    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    func(); func(); // warm up?
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

    uint64_t before = rdpmc(0);
    // running the function 10x makes any consistent perf events
    // occur repeatedly, helping to separate them from background noise
    func(); func(); func(); func(); func();
    func(); func(); func(); func(); func();
    uint64_t after = rdpmc(0);

    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    return after - before;
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
bindToCpu(int cpu)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set) < 0)
        err(EXIT_FAILURE, "Unable to set CPU affinity");
}

void
usage(char **argv)
{
    errx(2, "usage: %s [-b BIT_COUNT] [-s SEED] [-j NUM_JUMPS] [-r RUNS]",
         argv[0]);
}

int
main(int argc, char **argv)
{
    int opt;
    int nbits = 31, jumps = 300, runs = 500;
    uint64_t seed = 0;

    while ((opt = getopt(argc, argv, "hs:j:b:r:")) != -1) {
        errno = 0;
        char *endptr = NULL;
        switch (opt) {
            case 's': seed = strtoll(optarg, &endptr, 10); break;
            case 'b': nbits = strtol(optarg, &endptr, 10); break;
            case 'j': jumps = strtol(optarg, &endptr, 10); break;
            case 'r': runs =  strtol(optarg, &endptr, 10); break;
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

    int max_jumps = BUF_SIZE / 9;    // pessimistic lower bound
    if (max_jumps > 1000000)
        max_jumps = 1000000;

    #define CHECK_RANGE(var, name, lo, hi) \
        if (var < lo || var > hi) \
            errx(EXIT_FAILURE, name " must be in range [%d, %d]", lo, hi);

    CHECK_RANGE(nbits, "BITS", 8, 31);
    CHECK_RANGE(jumps, "JUMPS", 0, max_jumps);
    CHECK_RANGE(runs, "RUNS", 1, 1000000);

    printf("# -j%d -b%d -s%ld\n", jumps, nbits, seed);

    int fd = open_perf_counter(determine_perf_event());

    bindToCpu(1);

    // Create a function from a series of unconditional jumps

    uint8_t *buf = mmap((void*)0x100000000LL,
                        BUF_SIZE,
                        PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                        -1, 0);
    if (buf == MAP_FAILED)
        err(EXIT_FAILURE, "unable to mmap");

    xsrand(seed);
    int last = xrand() % (BUF_SIZE - 5);

    int jump_addrs[jumps];
    jump_addrs[0] = last;

    for (int i = 1; i < jumps; i++) {
        int target;
        do {
            target = xrand() % (BUF_SIZE - 5);
        } while (already_used(buf, target) || abs(target - last) < 5);
        write_jump(buf, last, target);
        jump_addrs[i] = target;
        last = target;
    }

    buf[last] = INSN_RET;

    void (*func)() = (void(*)())buf + jump_addrs[0];

    long clears = count_perf_min(fd, func, runs * 10);
    printf("BACLEARS: %ld\n", clears);

    if (clears < 10) {
        printf("Bailing: no event on every iteration\n");
        return 0;
    }

    int mask = 0;
    int expected = 0;

    // Try to find which jumps are causing mispredicts.
    printf("N   addr      clears\n");
    for (int i = 1; i < jumps - 1; i++) {
        write_jump(buf, jump_addrs[i - 1], jump_addrs[i + 1]);  // skip this jump
        long modified_clears = count_perf_min(fd, func, runs);
        if (modified_clears < clears - 6) {
            uintptr_t addr = (uintptr_t)buf + jump_addrs[i];
            printf("%03d %8lx %ld\n", i, addr, modified_clears);
            if (mask == 0) {
                mask = BUF_SIZE - 1;
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
