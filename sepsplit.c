/*
 *  SEP firmware split tool
 *
 *  Copyright (c) 2017 xerub
 */

#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdint.h>
#include <mach-o/loader.h>

#define IS64(image) (*(uint8_t *)(image) & 1)

#define MACHO(p) ((*(unsigned int *)(p) & ~1) == 0xfeedface)
#define MIN(x,y) ((x) < (y) ? (x) : (y))

/* at offset 0x10f8 (pointer to it stored right after "legion2") */
struct sep_data_hdr_64_t {
    uint8_t kernel_uuid[16];
    uint64_t unknown0;
    uint64_t kernel_base_paddr;
    uint64_t kernel_max_paddr;
    uint64_t app_images_base_paddr;
    uint64_t app_images_max_paddr;
    uint64_t paddr_max; /* size of SEP firmware image */
    uint64_t unknown1;
    uint64_t unknown2;
    uint64_t unknown3;
    uint64_t init_base_paddr;
    uint64_t unknown4;
    uint64_t unknown5;
    uint64_t unknown6;
    uint64_t unknown7;
    uint64_t unknown8;
    uint64_t unknown9;
    char init_name[16];
    uint8_t init_uuid[16];
    uint64_t unknown10;
    uint64_t unknown11;
    uint64_t n_apps;
};

/* right after the above, from offset 0x11c0 */
struct sepapp_64_t {
    uint64_t phys_text;
    uint64_t size_text;
    uint64_t phys_data;
    uint64_t size_data;
    uint64_t virt;
    uint64_t entry;
    uint64_t unknown4;
    uint64_t unknown5;
    uint64_t unknown6;
    uint32_t minus_one;
    uint32_t unknown7;
    char app_name[16];
    uint8_t app_uuid[16];
    uint64_t unknown8;
};

static const struct sepapp_t {
    uint64_t phys;
    uint32_t virt;
    uint32_t size;
    uint32_t entry;
    char name[12];
    /*char hash[16];*/
} *apps;
static size_t sizeof_sepapp = sizeof(struct sepapp_t);

#define UCHAR_MAX 255

static unsigned char *
boyermoore_horspool_memmem(const unsigned char* haystack, size_t hlen,
                           const unsigned char* needle,   size_t nlen)
{
    size_t last, scan = 0;
    size_t bad_char_skip[UCHAR_MAX + 1]; /* Officially called:
                                          * bad character shift */

    /* Sanity checks on the parameters */
    if (nlen <= 0 || !haystack || !needle)
        return NULL;

    /* ---- Preprocess ---- */
    /* Initialize the table to default value */
    /* When a character is encountered that does not occur
     * in the needle, we can safely skip ahead for the whole
     * length of the needle.
     */
    for (scan = 0; scan <= UCHAR_MAX; scan = scan + 1)
        bad_char_skip[scan] = nlen;

    /* C arrays have the first byte at [0], therefore:
     * [nlen - 1] is the last byte of the array. */
    last = nlen - 1;

    /* Then populate it with the analysis of the needle */
    for (scan = 0; scan < last; scan = scan + 1)
        bad_char_skip[needle[scan]] = last - scan;

    /* ---- Do the matching ---- */

    /* Search the haystack, while the needle can still be within it. */
    while (hlen >= nlen)
    {
        /* scan from the end of the needle */
        for (scan = last; haystack[scan] == needle[scan]; scan = scan - 1)
            if (scan == 0) /* If the first byte matches, we've found it. */
                return (void *)haystack;

        /* otherwise, we need to skip some bytes and start again.
           Note that here we are getting the skip value based on the last byte
           of needle, no matter where we didn't match. So if needle is: "abcd"
           then we are skipping based on 'd' and that value will be 4, and
           for "abcdd" we again skip on 'd' but the value will be only 1.
           The alternative of pretending that the mismatched character was
           the last character is slower in the normal case (E.g. finding
           "abcd" in "...azcd..." gives 4 by using 'd' but only
           4-2==2 using 'z'. */
        hlen     -= bad_char_skip[haystack[last]];
        haystack += bad_char_skip[haystack[last]];
    }

    return NULL;
}

static void
overwrite_data_segment(unsigned char *p, const unsigned char *data_buf, size_t data_size)
{
    unsigned i;
    const struct mach_header *hdr = (struct mach_header *)p;
    const uint8_t *q = p + sizeof(struct mach_header);

    if (!MACHO(p)) {
        return;
    }
    if (IS64(p)) {
        q += 4;
    }

    for (i = 0; i < hdr->ncmds; i++) {
        const struct load_command *cmd = (struct load_command *)q;
        if (cmd->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (struct segment_command_64 *)q;
            if (strcmp(seg->segname, "__DATA") == 0) {
                memcpy(p + seg->fileoff, data_buf, MIN(data_size, seg->filesize));
                break;
            }
        }
        q = q + cmd->cmdsize;
    }
}

static size_t
restore_linkedit(uint8_t *p, size_t size)
{
    unsigned i;
    struct mach_header *hdr = (struct mach_header *)p;
    uint64_t min = -1;
    uint64_t delta = 0;
    int is64 = 0;
    uint8_t *q;

    if (size < 1024) {
        return -1;
    }
    if (!MACHO(p)) {
        return -1;
    }
    if (IS64(p)) {
        is64 = 4;
    }

    q = p + sizeof(struct mach_header) + is64;
    for (i = 0; i < hdr->ncmds; i++) {
        const struct load_command *cmd = (struct load_command *)q;
        if (cmd->cmd == LC_SEGMENT) {
            const struct segment_command *seg = (struct segment_command *)q;
            if (strcmp(seg->segname, "__PAGEZERO") && min > seg->vmaddr) {
                min = seg->vmaddr;
            }
        }
        if (cmd->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (struct segment_command_64 *)q;
            if (strcmp(seg->segname, "__PAGEZERO") && min > seg->vmaddr) {
                min = seg->vmaddr;
            }
        }
        q = q + cmd->cmdsize;
    }

    q = p + sizeof(struct mach_header) + is64;
    for (i = 0; i < hdr->ncmds; i++) {
        const struct load_command *cmd = (struct load_command *)q;
        if (cmd->cmd == LC_SEGMENT) {
            struct segment_command *seg = (struct segment_command *)q;
            if (!strcmp(seg->segname, "__LINKEDIT")) {
                delta = seg->vmaddr - min - seg->fileoff;
                seg->fileoff += delta;
            }
        }
        if (cmd->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)q;
            if (!strcmp(seg->segname, "__LINKEDIT")) {
                delta = seg->vmaddr - min - seg->fileoff;
                seg->fileoff += delta;
            }
        }
        if (cmd->cmd == LC_SYMTAB) {
            struct symtab_command *sym = (struct symtab_command *)q;
            if (sym->stroff) sym->stroff += delta;
            if (sym->symoff) sym->symoff += delta;
        }
        q = q + cmd->cmdsize;
    }

    return 0;
}

static size_t
calc_size(const uint8_t *p, size_t size)
{
    unsigned i;
    const struct mach_header *hdr = (struct mach_header *)p;
    const uint8_t *q = p + sizeof(struct mach_header);
    size_t end, tsize = 0;

    if (size < 1024) {
        return 0;
    }
    if (!MACHO(p)) {
        return 0;
    }
    if (IS64(p)) {
        q += 4;
    }

    for (i = 0; i < hdr->ncmds; i++) {
        const struct load_command *cmd = (struct load_command *)q;
        if (cmd->cmd == LC_SEGMENT) {
            const struct segment_command *seg = (struct segment_command *)q;
            end = seg->fileoff + seg->filesize;
            if (tsize < end) {
                tsize = end;
            }
        }
        if (cmd->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (struct segment_command_64 *)q;
            end = seg->fileoff + seg->filesize;
            if (tsize < end) {
                tsize = end;
            }
        }
        q = q + cmd->cmdsize;
    }

    return tsize;
}

uint8_t *kernel = MAP_FAILED;
size_t kernel_size = 0;
static int kernel_fd = -1;

static int
init_kernel(const char *filename)
{
    kernel_fd = open(filename, O_RDONLY);
    if (kernel_fd < 0) {
        return -1;
    }

    kernel_size = lseek(kernel_fd, 0, SEEK_END);

    kernel = mmap(NULL, kernel_size, PROT_READ, MAP_PRIVATE, kernel_fd, 0);
    if (kernel == MAP_FAILED) {
        close(kernel_fd);
        kernel_fd = -1;
        return -1;
    }

    return 0;
}

static void
term_kernel(void)
{
    munmap(kernel, kernel_size);
    close(kernel_fd);
}

static int
write_file(const char *name, const void *buf, size_t size)
{
    int fd;
    size_t sz;
    fd = open(name, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) {
        return -1;
    }
    sz = write(fd, buf, size);
    close(fd);
    return (sz == size) ? 0 : -1;
}

static int
restore_file(unsigned index, const unsigned char *buf, size_t size, int restore)
{
    int rv;
    void *tmp;
    char name[256];
    char tail[12 + 1];

    if (index == 1 && size > 4096) {
        unsigned char *toc = boyermoore_horspool_memmem(buf + size - 4096, 4096, (unsigned char *)"SEPOS       ", 12);
        if (toc) {
            unsigned char *p = boyermoore_horspool_memmem(toc + 1, 64, (unsigned char *)"SEP", 3);
            if (p) {
                sizeof_sepapp = p - toc;
            }
            apps = (struct sepapp_t *)(toc - offsetof(struct sepapp_t, name));
        }
    }

    if (apps && buf > (unsigned char *)apps) {
        char *p;
        memcpy(tail, apps->name, 12);
        for (p = tail + 12; p > tail && p[-1] == ' '; p--) {
            continue;
        }
        *p = '\0';
        printf("%-12s phys 0x%llx, virt 0x%x, size 0x%x, entry 0x%x\n", tail, apps->phys, apps->virt, apps->size, apps->entry);
        apps = (struct sepapp_t *)((char *)apps + sizeof_sepapp);
    } else {
        if (index == 0) {
            strcpy(tail, "boot");
            printf("%s\n", tail);
        } else if (index == 1) {
            strcpy(tail, "kernel");
            printf("%s\n", tail);
        } else {
            *tail = '\0';
            printf("macho%d\n", index);
        }
    }
    snprintf(name, sizeof(name), "sepdump%02u_%s", index, tail);
    if (!restore) {
        return write_file(name, buf, size);
    }
    tmp = malloc(size);
    if (!tmp) {
        return -1;
    }
    memcpy(tmp, buf, size);
    restore_linkedit(tmp, size);
    rv = write_file(name, tmp, size);
    free(tmp);
    return rv;
}

static int
split(int restore)
{
    size_t i;
    unsigned j = 0;
    size_t last = 0;
    for (i = 0; i < kernel_size; i += 4) {
        size_t sz = calc_size(kernel + i, kernel_size - i);
        if (sz) {
            restore_file(j++, kernel + last, i - last, restore);
            last = i;
            i += sz - 4;
        }
    }
    restore_file(j, kernel + last, i - last, restore);
    return 0;
}

static int
restore_file_simple (unsigned index, const char * tail, const unsigned char *buf, size_t size, const unsigned char *data_buf, size_t data_size)
{
    int rv;
    void *tmp;
    char name[256];

    snprintf(name, sizeof(name), "sepdump%02u_%s", index, tail);
    tmp = malloc(size);
    if (!tmp) {
        return -1;
    }
    memcpy(tmp, buf, size);
    restore_linkedit(tmp, size);
    if (data_buf) {
        overwrite_data_segment(tmp, data_buf, data_size);
    }
    rv = write_file(name, tmp, size);
    free(tmp);
    return rv;
}

static void
tail_from_name (char * tail, const char * app_name)
{
    char * p;

    memcpy(tail, app_name, 12);
    for (p = tail + 12; p > tail && p[-1] == ' '; p--) {
        continue;
    }
    *p = '\0';
}

static uint64_t
get_hdr_offset()
{
    unsigned char *legion2 = boyermoore_horspool_memmem (kernel, 4096 * 2, (unsigned char *)"Built by legion2", 16);
    return *(uint64_t *) (legion2 + 16);
}

static int
split_64(uint64_t hdr_offset)
{
    struct sep_data_hdr_64_t * hdr;
    char tail[12 + 1];
    int i;
    size_t sz;
    struct sepapp_64_t * apps;

    hdr = (struct sep_data_hdr_64_t *) (kernel + hdr_offset);
    write_file("sepdump00_boot", kernel, hdr->kernel_base_paddr);

    sz = calc_size(kernel + hdr->kernel_base_paddr, kernel_size - hdr->kernel_base_paddr);
    restore_file_simple(1, "kernel", kernel + hdr->kernel_base_paddr, sz, NULL, 0);

    sz = calc_size(kernel + hdr->init_base_paddr, kernel_size - hdr->init_base_paddr);
    tail_from_name(tail, hdr->init_name);
    restore_file_simple(2, tail, kernel + hdr->init_base_paddr, sz, NULL, 0);

    apps = (struct sepapp_64_t *) (((uint8_t *) hdr) + sizeof(struct sep_data_hdr_64_t));

    for (i = 0; i < hdr->n_apps; i++) {
        sz = calc_size(kernel + apps[i].phys_text, kernel_size - apps[i].phys_text);
        tail_from_name(tail, apps[i].app_name);
        restore_file_simple(i + 3, tail, kernel + apps[i].phys_text, sz, kernel + apps[i].phys_data, apps[i].size_data);
        printf("%-12s phys_text 0x%llx, virt 0x%llx, size_text 0x%llx, phys_data 0x%llx, size_data 0x%llx, entry 0x%llx\n",
                tail, apps[i].phys_text, apps[i].virt, apps[i].size_text, apps[i].phys_data, apps[i].size_data, apps[i].entry);
    }

    return 0;
}

int
main(int argc, char **argv)
{
    int rv;
    const char *krnl = (argc > 1) ? argv[1] : "sep";
    uint64_t hdr_offset;

    rv = init_kernel(krnl);
    if (rv) {
        fprintf(stderr, "[e] cannot read kernel\n");
        return -1;
    }

    hdr_offset = get_hdr_offset();
    if (hdr_offset == 0) {
        rv = split(1);
    } else {
        rv = split_64(hdr_offset);
    }

    term_kernel();
    return 0;
}
