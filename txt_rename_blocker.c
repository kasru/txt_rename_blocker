/*
 * File Rename Blocker Module (Linux 6.12)
 * Блокирует rename .txt файлов по сигнатуре из конфигурационного файла
 *
 * Как это работает:
 * 1. ftrace на do_renameat2 — перехват на входе функции
 * 2. kallsyms_lookup_name найден через kprobe, вызван как функция чтобы найти адрес override_function_with_return
 * 3. В хендлере для .txt: regs->ax = -EPERM + override_function_with_return(regs) — мгновенный возврат с EPERM, rename не выполняется
 * 4. Для не .txt: хендлер ничего не делает, rename проходит нормально
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/ftrace.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/uaccess.h>
#include <linux/err.h>
#include <linux/string.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Developer");
MODULE_DESCRIPTION("Prevent renaming .txt files with protected content header");
MODULE_VERSION("1.0");

#define HEADER_SIZE 16
#define CONFIG_PATH "/etc/txt_rename_blocker.cfg"

static unsigned long target_addr;
static void (*ovr_func)(struct pt_regs *);
static unsigned long (*kln_func)(const char *);
static char protected_header[HEADER_SIZE];
static bool header_configured;

static unsigned long find_sym(const char *name)
{
    if (!kln_func) {
        struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
        if (!register_kprobe(&kp)) {
            kln_func = (void *)kp.addr;
            unregister_kprobe(&kp);
        }
    }
    return kln_func ? kln_func(name) : 0;
}

/* Загрузка конфигурации */
static void read_config(void)
{
    struct file *f;
    loff_t pos = 0;
    ssize_t ret;

    f = filp_open(CONFIG_PATH, O_RDONLY, 0);
    if (IS_ERR(f)) {
        pr_warn("txt_rename_blocker: cannot open %s (%ld)\n",
            CONFIG_PATH, PTR_ERR(f));
        return;
    }

    ret = kernel_read(f, protected_header, HEADER_SIZE, &pos);
    if (ret < HEADER_SIZE) {
        pr_warn("txt_rename_blocker: %s too short (read %zd, need %d)\n",
            CONFIG_PATH, ret, HEADER_SIZE);
        fput(f);
        return;
    }

    header_configured = true;
    pr_info("txt_rename_blocker: read protected header from %s\n", CONFIG_PATH);
    fput(f);
}

/* Проверка расширения .txt */
static bool is_txt_file(const char *name)
{
    size_t len;

    len = strlen(name);
    if (len < 4)
        return false;

    return (strcmp(name + len - 4, ".txt") == 0);
}

/* Чтение начала файла */
static bool check_file_header(const char *path)
{
    struct file *f;
    loff_t pos = 0;
    char buf[HEADER_SIZE];

    if (!header_configured)
        return false;

    f = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(f))
        return false;

    if (kernel_read(f, buf, HEADER_SIZE, &pos) < HEADER_SIZE) {
        fput(f);
        return false;
    }
    fput(f);

    return memcmp(buf, protected_header, HEADER_SIZE) == 0;
}

static void notrace rename_handler(unsigned long ip, unsigned long parent_ip,
                   struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
    struct pt_regs *regs;
    struct filename *oldname;
    const char *name;

    regs = ftrace_get_regs(fregs);
    if (!regs)
        return;

#ifdef CONFIG_X86_64
    oldname = (struct filename *)regs->si;
#else
#error "txt_rename_blocker: only x86_64 supported"
#endif
    if (!oldname || IS_ERR(oldname) || !oldname->name)
        return;

    name = oldname->name;

    if (!is_txt_file(name))
        return;

    if (!check_file_header(name))
        return;

    regs->ax = -EPERM;
    if (ovr_func)
        ovr_func(regs);
}

static struct ftrace_ops fops_rename = {
    .func = rename_handler,
    .flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY,
};

static struct kprobe kp_finder = {
    .symbol_name = "do_renameat2",
};

/* Инициализация модуля */
static int __init txt_rename_blocker_init(void)
{
    int ret;
    unsigned long addr;

    read_config();

    ret = register_kprobe(&kp_finder);
    if (ret) {
        pr_err("txt_rename_blocker: cannot find do_renameat2: %d\n", ret);
        return ret;
    }
    target_addr = (unsigned long)kp_finder.addr;
    unregister_kprobe(&kp_finder);

    addr = find_sym("override_function_with_return");
    if (addr) {
        ovr_func = (void (*)(struct pt_regs *))addr;
        pr_info("txt_rename_blocker: override_function_with_return at 0x%lx\n",
            addr);
    } else {
        pr_err("txt_rename_blocker: override_function_with_return not found\n");
        return -ENXIO;
    }

    ret = ftrace_set_filter_ip(&fops_rename, target_addr, 0, 0);
    if (ret) {
        pr_err("txt_rename_blocker: ftrace_set_filter_ip failed: %d\n", ret);
        return ret;
    }

    ret = register_ftrace_function(&fops_rename);
    if (ret) {
        pr_err("txt_rename_blocker: register_ftrace failed: %d\n", ret);
        ftrace_set_filter_ip(&fops_rename, target_addr, 1, 0);
        return ret;
    }

    pr_info("txt_rename_blocker: loaded (header=%sconfigured)\n",
        header_configured ? "" : "not ");
    return 0;
}

/* Выгрузка модуля */
static void __exit txt_rename_blocker_exit(void)
{
    int ret;
    ret = unregister_ftrace_function(&fops_rename);
    if (ret)
        pr_err("txt_rename_blocker: unregister_ftrace failed: %d\n", ret);
    ftrace_set_filter_ip(&fops_rename, target_addr, 1, 0);
    pr_info("txt_rename_blocker: unloaded\n");
}

module_init(txt_rename_blocker_init);
module_exit(txt_rename_blocker_exit);
