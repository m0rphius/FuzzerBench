// FuzzerBench

#include <asm/apic.h>
#include <asm-generic/io.h>
#include <asm/mem_encrypt.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/namei.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <../arch/x86/include/asm/fpu/api.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/fdtable.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,12,0)
#include <asm/cacheflush.h>
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
#include <linux/kallsyms.h>
int (*set_memory_x)(unsigned long,  int) = 0;
int (*set_memory_nx)(unsigned long, int) = 0;

#else
#include <linux/set_memory.h>
#endif

#include "../common/FuzzerBench.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yonatan Rosen");

// __vmalloc has no longer the pgprot_t parameter, so we need to hook __vmalloc_node_range directly
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
void *(*kallsym__vmalloc_node_range)(unsigned long size, unsigned long align,
			unsigned long start, unsigned long end, gfp_t gfp_mask,
			pgprot_t prot, unsigned long vm_flags, int node,
			const void *caller);
#endif

// kallsyms_lookup_name is no longer supported; we use a kprobes to get the address
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
unsigned long kallsyms_lookup_name(const char* name) {
  struct kprobe kp = {
    .symbol_name    = name,
  };

  int ret = register_kprobe(&kp);
  if (ret < 0) {
    return 0;
  };

  unregister_kprobe(&kp);

  return (unsigned long) kp.addr;
}
#endif

// 4 Mb is the maximum that kmalloc supports on my machines
#define KMALLOC_MAX (4*1024*1024)

// If enabled, for cycle-by-cycle measurements, the output includes all of the measurement overhead; otherwise, only the cycles between adding the first
// instruction of the benchmark to the IDQ, and retiring the last instruction of the benchmark are considered.
int end_to_end = false;

// [ADDED]
char* runtime_code_baseK = NULL;
char* runtime_code_mainK = NULL;

size_t code_offset = 0;
size_t code_memory_size = 0;
size_t code_init_memory_size = 0;
size_t code_late_init_memory_size = 0;
size_t code_one_time_init_memory_size = 0;
size_t pfc_config_memory_size = 0;
size_t msr_config_memory_size = 0;
size_t runtime_code_base_memory_size = 0;
size_t runtime_code_base_len = 0;
size_t runtime_code_main_memory_size = 0;
size_t runtime_code_main_len = 0;
size_t runtime_one_time_init_code_memory_size = 0;

void** r14_segments = NULL;
size_t n_r14_segments = 0;

// [ADDED]
bool trace_ready = false;
char inputs_buffer[4*1024*1024];
static size_t inputs_size = 0;
int n_rep = 0;

static char trace[MAX_INPUTS][MAX_LINE_LEN];

static int read_file_into_buffer(const char *file_name, char **buf, size_t *buf_len, size_t *buf_memory_size) {
    struct file *filp = NULL;
    filp = filp_open(file_name, O_RDONLY, 0);
    if (IS_ERR(filp)) {
        pr_err("Error opening file %s\n", file_name);
        return -1;
    }

    struct path p;
    struct kstat ks;
    kern_path(file_name, 0, &p);

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,11,0)
	if (vfs_getattr(&p, &ks)) {
#else
	if (vfs_getattr(&p, &ks, 0, 0)) {
#endif
        pr_err("Error getting file attributes\n");
        return -1;
    }

    size_t file_size = ks.size;
    *buf_len = file_size;

    if (file_size + 1 > *buf_memory_size) {
        kfree(*buf);
        *buf_memory_size = max(2*(file_size + 1), PAGE_SIZE);
        *buf = kmalloc(*buf_memory_size, GFP_KERNEL);
        if (!*buf) {
            pr_err("Could not allocate memory for %s\n", file_name);
            *buf_memory_size = 0;
            filp_close(filp, NULL);
            return -1;
        }
    }

    loff_t pos = 0;
    kernel_read(filp, *buf, file_size, &pos);
    (*buf)[file_size] = '\0';

    path_put(&p);
    filp_close(filp, NULL);
    return 0;
}

static ssize_t code_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return code_length;
}
static ssize_t code_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    // Parse the given text file into buffer "code"
    read_file_into_buffer(buf, &code, &code_length, &code_memory_size);

    // Variables related to test structure
    long base_unroll_count = (basic_mode?0:unroll_count);
    long main_unroll_count = (basic_mode?unroll_count:2*unroll_count);
    long base_loop_count = (basic_mode?0:loop_count);
    long main_loop_count = loop_count;
    char *measurement_template;

    if (n_programmable_counters >= 4) {
        if (no_mem) {
                measurement_template = (char*)&measurement_template_Intel_noMem_4;
        } else {
            measurement_template = (char*)&measurement_template_Intel_4;
        }
    } else {
        if (no_mem) {
            measurement_template = (char*)&measurement_template_Intel_noMem_2;
        } else {
            measurement_template = (char*)&measurement_template_Intel_2;
        }
    }
    create_runtime_code(measurement_template, base_unroll_count, base_loop_count, true);
    create_runtime_code(measurement_template, main_unroll_count, main_loop_count, false);
    
    return count;
}

static struct kobj_attribute code_attribute = __ATTR(code, 0664, code_show, code_store);

static ssize_t init_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return 0;
}
static ssize_t init_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    read_file_into_buffer(buf, &code_init, &code_init_length, &code_init_memory_size);
    return count;
}
static struct kobj_attribute code_init_attribute =__ATTR(init, 0660, init_show, init_store);

static ssize_t late_init_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return 0;
}
static ssize_t late_init_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    read_file_into_buffer(buf, &code_late_init, &code_late_init_length, &code_late_init_memory_size);
    return count;
}
static struct kobj_attribute code_late_init_attribute =__ATTR(late_init, 0660, late_init_show, late_init_store);

static ssize_t one_time_init_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return 0;
}
static ssize_t one_time_init_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    read_file_into_buffer(buf, &code_one_time_init, &code_one_time_init_length, &code_one_time_init_memory_size);
    size_t new_runtime_one_time_init_code_memory_size = 10000 + code_one_time_init_memory_size;
    if (new_runtime_one_time_init_code_memory_size > runtime_one_time_init_code_memory_size) {
        runtime_one_time_init_code_memory_size = new_runtime_one_time_init_code_memory_size;
        vfree(runtime_one_time_init_code);
        #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
        runtime_one_time_init_code = kallsym__vmalloc_node_range(runtime_one_time_init_code_memory_size, 1, VMALLOC_START, VMALLOC_END, GFP_KERNEL, PAGE_KERNEL_EXEC, 0, NUMA_NO_NODE, __builtin_return_address(0));
        #else
        runtime_one_time_init_code = __vmalloc(runtime_one_time_init_code_memory_size, GFP_KERNEL, PAGE_KERNEL_EXEC);
        #endif
        if (!runtime_one_time_init_code) {
            runtime_one_time_init_code_memory_size = 0;
            pr_err("failed to allocate executable memory\n");
        }
    }
    return count;
}
static struct kobj_attribute code_one_time_init_attribute =__ATTR(one_time_init, 0660, one_time_init_show, one_time_init_store);

static ssize_t config_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    ssize_t count = 0;
    for (int i=0; i<n_pfc_configs; i++) {
        if (is_Intel_CPU) {
            count += snprintf(&(buf[count]), PAGE_SIZE-count, "%02lx.%02lx %s\n", pfc_configs[i].evt_num, pfc_configs[i].umask, pfc_configs[i].description);
        } else {
            count += snprintf(&(buf[count]), PAGE_SIZE-count, "%03lx.%02lx %s\n", pfc_configs[i].evt_num, pfc_configs[i].umask, pfc_configs[i].description);
        }
        if (count > PAGE_SIZE) {
            return PAGE_SIZE-1;
        }
    }
    return count;
}
static ssize_t config_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    size_t pfc_config_length;
    read_file_into_buffer(buf, &pfc_config_file_content, &pfc_config_length, &pfc_config_memory_size);
    parse_counter_configs();
    return count;
}
static struct kobj_attribute config_attribute =__ATTR(config, 0664, config_show, config_store);

static ssize_t msr_config_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    ssize_t count = 0;
    for (int i=0; i<n_msr_configs; i++) {
        struct msr_config config = msr_configs[i];
        for (int j=0; j<config.n_wrmsr; j++) {
            count += sprintf(&(buf[count]), "msr_%lX=0x%lX", config.wrmsr[j], config.wrmsr_val[j]);
            if (j<config.n_wrmsr-1) count += sprintf(&(buf[count]), ".");
        }
        count += sprintf(&(buf[count]), " msr_%lX %s\n", config.rdmsr, config.description);
    }
    return count;
}
static ssize_t msr_config_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    size_t msr_config_length;
    read_file_into_buffer(buf, &msr_config_file_content, &msr_config_length, &msr_config_memory_size);
    parse_msr_configs();
    return count;
}
static struct kobj_attribute msr_config_attribute =__ATTR(msr_config, 0660, msr_config_show, msr_config_store);

static ssize_t fixed_counters_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%d\n", use_fixed_counters);
}
static ssize_t fixed_counters_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    sscanf(buf, "%d", &use_fixed_counters);
    return count;
}
static struct kobj_attribute fixed_counters_attribute =__ATTR(fixed_counters, 0660, fixed_counters_show, fixed_counters_store);

static ssize_t unroll_count_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%ld\n", unroll_count);
}
static ssize_t unroll_count_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    sscanf(buf, "%ld", &unroll_count);
    return count;
}
static struct kobj_attribute unroll_count_attribute =__ATTR(unroll_count, 0660, unroll_count_show, unroll_count_store);

static ssize_t loop_count_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%ld\n", loop_count);
}
static ssize_t loop_count_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    sscanf(buf, "%ld", &loop_count);
    return count;
}
static struct kobj_attribute loop_count_attribute =__ATTR(loop_count, 0660, loop_count_show, loop_count_store);

static ssize_t n_measurements_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%ld\n", n_measurements);
}
static ssize_t n_measurements_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    long old_n_measurements = n_measurements;
    sscanf(buf, "%ld", &n_measurements);

    if (old_n_measurements < n_measurements) {
        for (int i=0; i<MAX_PROGRAMMABLE_COUNTERS; i++) {
            kfree(measurement_results[i]);
            kfree(measurement_results_base[i]);
            measurement_results[i] = kmalloc(n_measurements*sizeof(int64_t), GFP_KERNEL);
            measurement_results_base[i] = kmalloc(n_measurements*sizeof(int64_t), GFP_KERNEL);
            if (!measurement_results[i] || !measurement_results_base[i]) {
                pr_err("Could not allocate memory for measurement_results\n");
                return 0;
            }
            memset(measurement_results[i], 0, n_measurements*sizeof(int64_t));
            memset(measurement_results_base[i], 0, n_measurements*sizeof(int64_t));
        }
    }
    return count;
}
static struct kobj_attribute n_measurements_attribute =__ATTR(n_measurements, 0660, n_measurements_show, n_measurements_store);

static ssize_t warm_up_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%ld\n", warm_up_count);
}
static ssize_t warm_up_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    sscanf(buf, "%ld", &warm_up_count);
    return count;
}
static struct kobj_attribute warm_up_attribute =__ATTR(warm_up, 0660, warm_up_show, warm_up_store);

static ssize_t initial_warm_up_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%ld\n", initial_warm_up_count);
}
static ssize_t initial_warm_up_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    sscanf(buf, "%ld", &initial_warm_up_count);
    return count;
}
static struct kobj_attribute initial_warm_up_attribute =__ATTR(initial_warm_up, 0660, initial_warm_up_show, initial_warm_up_store);

static ssize_t alignment_offset_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%zu\n", alignment_offset);
}
static ssize_t alignment_offset_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    sscanf(buf, "%zu", &alignment_offset);
    return count;
}
static struct kobj_attribute alignment_offset_attribute =__ATTR(alignment_offset, 0660, alignment_offset_show, alignment_offset_store);

static ssize_t end_to_end_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%d\n", end_to_end);
}
static ssize_t end_to_end_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    sscanf(buf, "%d", &end_to_end);
    return count;
}
static struct kobj_attribute end_to_end_attribute =__ATTR(end_to_end, 0660, end_to_end_show, end_to_end_store);

static ssize_t drain_frontend_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%d\n", drain_frontend);
}
static ssize_t drain_frontend_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    sscanf(buf, "%d", &drain_frontend);
    return count;
}
static struct kobj_attribute drain_frontend_attribute =__ATTR(drain_frontend, 0660, drain_frontend_show, drain_frontend_store);

static ssize_t basic_mode_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%d\n", basic_mode);
}
static ssize_t basic_mode_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    sscanf(buf, "%d", &basic_mode);
    return count;
}
static struct kobj_attribute basic_mode_attribute =__ATTR(basic_mode, 0660, basic_mode_show, basic_mode_store);

static ssize_t no_mem_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%d\n", no_mem);
}
static ssize_t no_mem_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    sscanf(buf, "%d", &no_mem);
    return count;
}
static struct kobj_attribute no_mem_attribute =__ATTR(no_mem, 0660, no_mem_show, no_mem_store);

static ssize_t no_normalization_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%d\n", no_normalization);
}
static ssize_t no_normalization_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    sscanf(buf, "%d", &no_normalization);
    return count;
}
static struct kobj_attribute no_normalization_attribute =__ATTR(no_normalization, 0660, no_normalization_show, no_normalization_store);

static ssize_t output_range_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%d\n", output_range);
}
static ssize_t output_range_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    sscanf(buf, "%d", &output_range);
    return count;
}
static struct kobj_attribute output_range_attribute =__ATTR(output_range, 0660, output_range_show, output_range_store);

static ssize_t agg_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%d\n", aggregate_function);
}
static ssize_t agg_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    if (!strncmp(buf, "min", 3)) {
        aggregate_function = MIN;
    } else if (!strncmp(buf, "max", 3)) {
        aggregate_function = MAX;
    } else if (!strncmp(buf, "med", 3)) {
        aggregate_function = MED;
    } else {
        aggregate_function = AVG_20_80;
    }
    return count;
}
static struct kobj_attribute agg_attribute =__ATTR(agg, 0660, agg_show, agg_store);

int cmpPtr(const void *a, const void *b) {
    if (*(void**)a == *(void**)b) return 0;
    else if (*(void**)a == NULL) return 1;
    else if (*(void**)b == NULL) return -1;
    else if (*(void**)a < *(void**)b) return -1;
    else return 1;
}

static ssize_t r14_size_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    if (n_r14_segments == 0 || !r14_segments[0]) return sprintf(buf, "0\n");

    void* prev_virt_addr = r14_segments[0];
    phys_addr_t prev_phys_addr = virt_to_phys(prev_virt_addr);

    size_t i;
    for (i=1; i<n_r14_segments; i++) {
        void* cur_virt_addr = r14_segments[i];
        phys_addr_t cur_phys_addr = virt_to_phys(cur_virt_addr);

        if ((cur_virt_addr - prev_virt_addr != KMALLOC_MAX) || (cur_phys_addr - prev_phys_addr != KMALLOC_MAX)) {
            pr_err("No physically contiguous memory area of the requested size found.\n");
            pr_err("Try rebooting your computer.\n");
            break;
        }

        prev_virt_addr = cur_virt_addr;
        prev_phys_addr = cur_phys_addr;
    }

    phys_addr_t phys_addr = virt_to_phys(r14_segments[0]);
    return sprintf(buf, "R14 size: %zu MB\nVirtual address: 0x%px\nPhysical address: %pa\n", i*KMALLOC_MAX/(1024*1024), r14_segments[0], &phys_addr);
}
static ssize_t r14_size_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    if (n_r14_segments > 0) {
        for (int i=0; i<n_r14_segments; i++) {
            kfree(r14_segments[i]);
        }
    } else {
        vfree(runtime_r14 - RUNTIME_R_SIZE/2);
    }

    size_t size_MB = 0;
    sscanf(buf, "%zu", &size_MB);
    n_r14_segments = (size_MB*1024*1024 + (KMALLOC_MAX-1)) / KMALLOC_MAX;
    vfree(r14_segments);
    r14_segments = vmalloc(n_r14_segments * sizeof(void*));

    for (size_t i=0; i<n_r14_segments; i++) {
        r14_segments[i] = kmalloc(KMALLOC_MAX, GFP_KERNEL|__GFP_COMP);
    }

    sort(r14_segments, n_r14_segments, sizeof(void*), cmpPtr, NULL);
    runtime_r14 = r14_segments[0];

    return count;
}
static struct kobj_attribute r14_size_attribute =__ATTR(r14_size, 0660, r14_size_show, r14_size_store);

size_t print_r14_length = 8;
static ssize_t print_r14_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    size_t count = sprintf(buf, "0x");
    for (size_t i=0; i<print_r14_length && i<PAGE_SIZE-3; i++) {
        count += sprintf(&(buf[count]), "%02x", ((unsigned char*)runtime_r14)[i]);
    }
    count += sprintf(&(buf[count]), "\n");
    return count;
}
static ssize_t print_r14_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    sscanf(buf, "%zu", &print_r14_length);
    return count;
}
static struct kobj_attribute print_r14_attribute =__ATTR(print_r14, 0660, print_r14_show, print_r14_store);

static ssize_t code_offset_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%zu\n", code_offset);
}
static ssize_t code_offset_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    sscanf(buf, "%zu", &code_offset);
    return count;
}
static struct kobj_attribute code_offset_attribute =__ATTR(code_offset, 0660, code_offset_show, code_offset_store);

static ssize_t addresses_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    size_t count = 0;
    count += sprintf(&(buf[count]), "R14: 0x%px\n", runtime_r14);
    count += sprintf(&(buf[count]), "RDI: 0x%px\n", runtime_rdi);
    count += sprintf(&(buf[count]), "RSI: 0x%px\n", runtime_rsi);
    count += sprintf(&(buf[count]), "RBP: 0x%px\n", runtime_rbp);
    count += sprintf(&(buf[count]), "RSP: 0x%px\n", runtime_rsp);
    return count;
}
static ssize_t addresses_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    return 0;
}
static struct kobj_attribute addresses_attribute =__ATTR(addresses, 0660, addresses_show, addresses_store);

static ssize_t verbose_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%d\n", verbose);
}
static ssize_t verbose_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    sscanf(buf, "%d", &verbose);
    return count;
}
static struct kobj_attribute verbose_attribute =__ATTR(verbose, 0660, verbose_show, verbose_store);

static ssize_t clear_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    code_length = 0;
    code_init_length = 0;
    code_late_init_length = 0;
    code_one_time_init_length = 0;
    return 0;
}
static ssize_t clear_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    return 0;
}
static struct kobj_attribute clear_attribute =__ATTR(clear, 0660, clear_show, clear_store);

static ssize_t reset_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    n_measurements = N_MEASUREMENTS_DEFAULT;
    unroll_count = UNROLL_COUNT_DEFAULT;
    loop_count = LOOP_COUNT_DEFAULT;
    warm_up_count = WARM_UP_COUNT_DEFAULT;
    initial_warm_up_count = INITIAL_WARM_UP_COUNT_DEFAULT;

    no_mem = NO_MEM_DEFAULT;
    no_normalization = NO_NORMALIZATION_DEFAULT;
    basic_mode = BASIC_MODE_DEFAULT;
    use_fixed_counters = USE_FIXED_COUNTERS_DEFAULT;
    aggregate_function = AGGREGATE_FUNCTION_DEFAULT;
    output_range = OUTPUT_RANGE_DEFAULT;
    verbose = VERBOSE_DEFAULT;
    alignment_offset = ALIGNMENT_OFFSET_DEFAULT;
    drain_frontend = DRAIN_FRONTEND_DEFAULT;
    end_to_end = false;
    // [ADDED]

    code_init_length = 0;
    code_late_init_length = 0;
    code_one_time_init_length = 0;
    code_length = 0;
    code_offset = 0;
    n_pfc_configs = 0;
    n_msr_configs = 0;
    n_rep = 0;
    trace_ready = false;
    return 0;
}
static ssize_t reset_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    return 0;
}
static struct kobj_attribute reset_attribute =__ATTR(reset, 0660, reset_show, reset_store);

// [ADDED] "-num_inputs"
static ssize_t num_inputs_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%d\n", num_inputs);
}
static ssize_t num_inputs_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    sscanf(buf, "%d", &num_inputs);
    return count;
}
static struct kobj_attribute num_inputs_attribute = __ATTR(num_inputs, 0660, num_inputs_show, num_inputs_store);

// [ADDED] "-seed"
static ssize_t seed_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%ld\n", seed);
}
static ssize_t seed_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    sscanf(buf, "%ld", &seed);
    return count;
}
static struct kobj_attribute seed_attribute = __ATTR(seed, 0660, seed_show, seed_store);

// [ADDED] "-n_reps" (number of repetitions on each input group)
static ssize_t n_rep_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%d\n", n_rep);
}
static ssize_t n_rep_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    sscanf(buf, "%d", &n_rep);
    return count;
}
static struct kobj_attribute n_reps_attribute = __ATTR(n_rep, 0660, n_rep_show, n_rep_store);

// [ADDED] used for transferring inputs from the python fuzzer to the kernel module
static ssize_t inputs_read(struct file* file, struct kobject *kobj, struct bin_attribute *attr, 
                    char *buf, loff_t pos, size_t count){   
    if (pos >= inputs_size)
        return 0;
    
    if (pos + count > inputs_size)
        count = inputs_size - pos;
    
    memcpy(buf, inputs_buffer + pos, count);
    return count;
}

static ssize_t inputs_write(struct file* file, struct kobject *kobj, struct bin_attribute *attr, 
                     char *buf, loff_t pos, size_t count){ 
    if (pos + count >= sizeof(inputs_buffer)){
        return -ENOSPC;
    }

    memcpy(inputs_buffer + pos, buf, count);
    inputs_size = max(inputs_size, pos + count);

    return count;
}
static struct bin_attribute inputs_bin_attribute = {.attr = {.name = "inputs", .mode=0666}, 
                                                    .size=1024*1024,
                                                .read=inputs_read, 
                                                .write=inputs_write};

// Remove the old trace_show and trace_attribute
// static ssize_t trace_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) { ... }
// static struct kobj_attribute trace_attribute = __ATTR(trace, 0664, trace_show, NULL);

static int run_FuzzerBench(struct seq_file *m, void *v);

// [ADDED] binary sysfs attribute for trace
static ssize_t trace_read(struct file *file, struct kobject *kobj, struct bin_attribute *attr,
                          char *buf, loff_t off, size_t count)
{
    // To handle multiple reads due to paged reading
    if (off == 0) {
        if (run_FuzzerBench(NULL, NULL) != 0){
            pr_err("Error running FuzzerBench\n");
            return 0;
        }
    }

    // Flatten the trace into a temporary buffer (static to avoid stack overflow)
    static char trace_flat[MAX_INPUTS * MAX_LINE_LEN];
    size_t total = 0;
    for (int i = 0; i < num_inputs; i++) {
        if (trace[i][0] == '\0') continue;
        int len = snprintf(trace_flat + total, sizeof(trace_flat) - total, "%s\n", trace[i]);
        if (len < 0 || total + len >= sizeof(trace_flat)) break;
        total += len;
    }

    // Handle offset/count for paged reading
    if (off >= total)
        return 0;
    if (off + count > total)
        count = total - off;
    memcpy(buf, trace_flat + off, count);
    return count;
}

static struct bin_attribute trace_bin_attribute = {
    .attr = { .name = "trace", .mode = 0666 },
    .size = MAX_INPUTS * MAX_LINE_LEN,
    .read = trace_read,
};

// [ADDED] to control the core on which the experiment is executed
static ssize_t cpu_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%d\n", cpu);
}
static ssize_t cpu_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    sscanf(buf, "%d", &cpu);
    return count;
}
static struct kobj_attribute cpu_attribute = __ATTR(cpu, 0664, cpu_show, cpu_store);


uint32_t prev_LVTT = 0;
uint32_t prev_LVTTHMR = 0;
uint32_t prev_LVTPC = 0;
uint32_t prev_LVT0 = 0;
uint32_t prev_LVT1 = 0;
uint32_t prev_LVTERR = 0;
uint32_t prev_APIC_TMICT = 0;
uint64_t prev_deadline = 0;

static void restore_interrupts_preemption(void) {
    apic->write(APIC_LVTT, prev_LVTT);
    apic->write(APIC_LVTTHMR, prev_LVTTHMR);
    apic->write(APIC_LVTPC, prev_LVTPC);
    apic->write(APIC_LVT0, prev_LVT0);
    apic->write(APIC_LVT1, prev_LVT1);
    apic->write(APIC_LVTERR, prev_LVTERR);
    apic->write(APIC_TMICT, prev_APIC_TMICT);
    if (supports_tsc_deadline) {
        asm volatile("mfence");
        write_msr(MSR_IA32_TSC_DEADLINE, max(1ULL, prev_deadline));
    }
    prev_LVTT = prev_LVTTHMR = prev_LVTPC = prev_LVT0 = prev_LVT1 = prev_LVTERR = prev_APIC_TMICT = prev_deadline = 0;

    put_cpu();
}

static void disable_interrupts_preemption(void) {
    if (prev_LVTT || prev_LVTTHMR || prev_LVTPC || prev_LVT0 || prev_LVT1 || prev_LVTERR) {
        // The previous call to disable_interrupts_preemption() was not followed by a call to restore_interrupts_preemption().
        restore_interrupts_preemption();
    }

    // disable preemption
    get_cpu();

    // We mask interrupts in the APIC LVT. We do not mask all maskable interrupts using the cli instruction, as on some
    // microarchitectures, pending interrupts that are masked via the cli instruction can reduce the retirement rate
    // (e.g., on ICL to 4 uops/cycle).
    prev_LVTT = apic->read(APIC_LVTT);
    prev_LVTTHMR = apic->read(APIC_LVTTHMR);
    prev_LVTPC = apic->read(APIC_LVTPC);
    prev_LVT0 = apic->read(APIC_LVT0);
    prev_LVT1 = apic->read(APIC_LVT1);
    prev_LVTERR = apic->read(APIC_LVTERR);
    prev_APIC_TMICT = apic->read(APIC_TMICT);
    if (supports_tsc_deadline) {
        prev_deadline = read_msr(MSR_IA32_TSC_DEADLINE);
        write_msr(MSR_IA32_TSC_DEADLINE, 0);
    }

    apic->write(APIC_LVTT, prev_LVTT | APIC_LVT_MASKED);
    apic->write(APIC_LVTTHMR, prev_LVTTHMR | APIC_LVT_MASKED);
    apic->write(APIC_LVTPC, prev_LVTPC | APIC_LVT_MASKED);
    apic->write(APIC_LVT0, prev_LVT0 | APIC_LVT_MASKED);
    apic->write(APIC_LVT1, prev_LVT1 | APIC_LVT_MASKED);
    apic->write(APIC_LVTERR, prev_LVTERR | APIC_LVT_MASKED);
}

static bool check_memory_allocations(void) {
    for (int i=0; i<MAX_PROGRAMMABLE_COUNTERS; i++) {
        if (!measurement_results[i] || !measurement_results_base[i]) {
            pr_err("Could not allocate memory for measurement_results\n");
            return false;
        }
    }

    size_t req_code_length = code_offset + get_required_runtime_code_length();
    if (req_code_length > runtime_code_base_memory_size) {
        pr_err("Maximum supported code size %zu kB; requested %zu kB\n", runtime_code_base_memory_size/1024, req_code_length/1024);
        return false;
    }

    return true;
}

static int write_buffer_to_file(const char *filename, const void *data, size_t size) {
    struct file *filp;
    loff_t pos = 0;
    ssize_t written;

    filp = filp_open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (IS_ERR(filp)) {
        pr_err("filp_open failed: %ld\n", PTR_ERR(filp));
        return PTR_ERR(filp);
    }

    // No need for set_fs(), use kernel_write directly
    written = kernel_write(filp, data, size, &pos);

    filp_close(filp, NULL);

    if (written < 0)
        pr_err("kernel_write failed: %zd\n", written);

    return written;
}

static int run_FuzzerBench(struct seq_file *m, void *v) {
    if (!check_memory_allocations()) {
        return -1;
    }
    struct task_struct *task = current;
    cpumask_t mask;
    cpumask_clear(&mask);
    cpumask_set_cpu(cpu, &mask);
    set_cpus_allowed_ptr(task, &mask);

    kernel_fpu_begin();
    disable_interrupts_preemption();


    clear_perf_counter_configurations();
    clear_perf_counters();
    clear_overflow_status_bits();
    enable_perf_ctrs_globally();
    
    char buf[100];
    /*********************************
     * Programmable counters.
     ********************************/
    int n_used_counters = n_programmable_counters;
    if (n_used_counters >= 4) {
        n_used_counters = 4;

    } else {
        n_used_counters = 2;
    
    }

    // Prepare inputs for the benchmark code (num_inputs groups of random values to rax, rbx, rcx, rdx)
    // The benchmark code will use these values as inputs for the benchmark code
    // Inject the constant register inputs
    int32_t *regs = (int32_t *)inputs_buffer;

    size_t offsetI = 0x3D;
    for (int i=0; i < NUM_CONSTANT_REGS; i++){
        *(int32_t *)(&runtime_code_base[offsetI + i*7 + 3]) = regs[i];
        *(int32_t *)(&runtime_code_main[offsetI + i*7 + 3]) = regs[i];
    }

    int32_t* changing_regs = regs + NUM_CONSTANT_REGS;

    // Repeat experiment n_inputs times
    for (int inp = 0; inp < warm_up_count + num_inputs; inp++){
        // Inject the changing register inputs 
        int group_ind = n_rep*(num_inputs + warm_up_count)*NUM_CHANGING_REGS + inp*NUM_CHANGING_REGS;
        offsetI = 0x21;
        for (int i=0; i < NUM_CHANGING_REGS; i++){
            *(int32_t *)(&runtime_code_base[offsetI + i*7 + 3]) = changing_regs[group_ind + i];
            *(int32_t *)(&runtime_code_main[offsetI + i*7 + 3]) = changing_regs[group_ind + i];
        }
        
        // Put all inputs (for debugging)
        // int len = scnprintf(buf_ptr, MAX_LINE_LEN, "[%d,%d,%d,%d,%d,%d,%d,%d]\n", regs[0], regs[1], regs[2], regs[3], 
        // changing_regs[group_ind], changing_regs[group_ind+1], changing_regs[group_ind+2], changing_regs[group_ind+3]);
        // size_t offset = len;
        // buf_ptr[offset] = '\0';

        // Values for writing measurement results
        
        char *buf_ptr;
        int len; size_t offset;
        if (inp >= warm_up_count){
            buf_ptr = trace[inp-warm_up_count];
            len = scnprintf(buf_ptr, MAX_LINE_LEN, "[%d,%d]: ", n_rep, inp-warm_up_count);
            offset = len;
            buf_ptr[offset] = '\0';
        } 
        

        size_t next_pfc_config = 0;
        while (next_pfc_config < n_pfc_configs) {
            run_initial_warmup_experiment();
            char* pfc_descriptions[MAX_PROGRAMMABLE_COUNTERS] = {0};
            next_pfc_config = configure_perf_ctrs_programmable(next_pfc_config, true, true, n_used_counters, 0, pfc_descriptions);
            // on some microarchitectures (e.g., Broadwell), some events (e.g., L1 misses) are not counted properly if only the OS field is set
            
            run_inputted_experiment(measurement_results_base, n_used_counters, true);
            run_inputted_experiment(measurement_results, n_used_counters, false);
            
            if (inp >= warm_up_count){
                for (size_t c=0; c < n_used_counters; c++) {
                    if (pfc_descriptions[c]) {
                        int64_t agg = get_aggregate_value(measurement_results[c], n_measurements, no_normalization?1:100, aggregate_function);
                        int64_t agg_base = get_aggregate_value(measurement_results_base[c], n_measurements, no_normalization?1:100, aggregate_function);
                        int64_t result = normalize(agg-agg_base);
                        if (offset < MAX_LINE_LEN - 32) {  // Leave room for result
                            int len = scnprintf(buf_ptr + offset, MAX_LINE_LEN - offset,
                                                " %lld.%.2lld", ll_abs(result/100), ll_abs(result%100));
                            buf_ptr[offset + len] = '\0';
                            offset += len;
                        }
                    }
                }
            }
        }
    }
    
    restore_interrupts_preemption();
    kernel_fpu_end();
    n_rep += 1;
    return 0;
}

// Unlike with run_experiment(), create_runtime_code() needs to be called before calling run_experiment_with_freeze_on_PMI().
// If n_used_counters is > 0, the programmable counters from 0 to n_used_counters-1 are read; otherwise, the fixed counters are read.
// pmi_counter: 0-2: fixed counters, 3-n: programmable counters
// pmi_counter_val: value that is written to pmi_counter before each measurement
static void run_experiment_with_freeze_on_PMI(int64_t* results[], int n_used_counters, int pmi_counter, uint64_t pmi_counter_val, bool base) {
    if (pmi_counter <= 2) {
        set_bit_in_msr(MSR_IA32_FIXED_CTR_CTRL, pmi_counter*4 + 3);
    } else {
        set_bit_in_msr(MSR_IA32_PERFEVTSEL0 + (pmi_counter - 3), 20);
    }

    char* run_code = base ? runtime_code_base : runtime_code_main;

    for (long ri=-warm_up_count; ri<n_measurements; ri++) {
        disable_perf_ctrs_globally();
        clear_perf_counters();
        clear_overflow_status_bits();

        if (pmi_counter <= 2) {
            write_msr(MSR_IA32_FIXED_CTR0 + pmi_counter, pmi_counter_val);
        } else {
            write_msr(MSR_IA32_PMC0 + (pmi_counter - 3), pmi_counter_val);
        }

        ((void(*)(void))run_code)();

        if (n_used_counters > 0) {
            for (int c=0; c<n_used_counters; c++) {
                results[c][max(0L, ri)] = read_pmc(c);
            }
        } else {
            for (int c=0; c<3; c++) {
                results[c][max(0L, ri)] = read_pmc(0x40000000 + c);
            }
        }
    }

    if (pmi_counter <= 2) {
        clear_bit_in_msr(MSR_IA32_FIXED_CTR_CTRL, pmi_counter*4 + 3);
    } else {
        clear_bit_in_msr(MSR_IA32_PERFEVTSEL0 + (pmi_counter - 3), 20);
    }
}

static uint64_t get_max_FF_ctr_value(void) {
    return ((uint64_t)1 << Intel_FF_ctr_width) - 1;
}

static uint64_t get_max_programmable_ctr_value(void) {
    return ((uint64_t)1 << Intel_programmable_ctr_width) - 1;
}

static uint64_t get_end_to_end_cycles(void) {
    run_experiment_with_freeze_on_PMI(measurement_results, 0, 0, 0, true);
    uint64_t cycles = get_aggregate_value(measurement_results[FIXED_CTR_CORE_CYCLES], n_measurements, 1, aggregate_function);
    print_verbose("End-to-end cycles: %llu\n", cycles);
    return cycles;
}

static uint64_t get_end_to_end_retired(void) {
    run_experiment_with_freeze_on_PMI(measurement_results, 0, 0, 0, true);
    uint64_t retired = get_aggregate_value(measurement_results[FIXED_CTR_INST_RETIRED], n_measurements, 1, aggregate_function);
    print_verbose("End-to-end retired instructions: %llu\n", retired);
    return retired;
}

// Returns the cycle with which the fixed cycle counter has to be programmed such that the programmable counters are frozen immediately after retiring the last
// instruction of the benchmark (if include_lfence is true, after retiring the lfence instruction that follows the code of the benchmark).
static uint64_t get_cycle_last_retired(bool include_lfence) {
    uint64_t perfevtsel2 = (uint64_t)0xC0 | (1ULL << 17) | (1ULL << 22); // Instructions retired
    // we use counter 2 here, because the counters 0 and 1 do not freeze at the same time on some microarchitectures
    write_msr(MSR_IA32_PERFEVTSEL0+2, perfevtsel2);

    uint64_t last_applicable_instr = get_end_to_end_retired() - 258 + include_lfence;

    run_experiment_with_freeze_on_PMI(measurement_results, 0, 3 + 2, get_max_programmable_ctr_value() - last_applicable_instr, true);
    uint64_t time_to_last_retired = get_aggregate_value(measurement_results[1], n_measurements, 1, aggregate_function);

    // The counters freeze a few cycles after an overflow happens; additionally the programmable and fixed counters do not freeze (or do not start) at exactly
    // the same time. In the following, we search for the value that we have to write to the fixed counter such that the programmable counters stop immediately
    // after the last applicable instruction is retired.
    uint64_t cycle_last_retired = 0;
    for (int64_t cycle=time_to_last_retired; cycle>=0; cycle--) {
        run_experiment_with_freeze_on_PMI(measurement_results, 3, FIXED_CTR_CORE_CYCLES, get_max_FF_ctr_value() - cycle, true);
        if (get_aggregate_value(measurement_results[2], n_measurements, 1, aggregate_function) < last_applicable_instr) {
            cycle_last_retired = cycle+1;
            break;
        }
    }
    print_verbose("Last instruction of benchmark retired in cycle: %llu\n", cycle_last_retired);
    return cycle_last_retired;
}

// Returns the cycle with which the fixed cycle counter has to be programmed such that the programmable counters are frozen in the cycle in which the first
// instruction of the benchmark is added to the IDQ.
static uint64_t get_cycle_first_added_to_IDQ(uint64_t cycle_last_retired_empty) {
    uint64_t perfevtsel2 = (uint64_t)0x79 | ((uint64_t)0x04 << 8) | (1ULL << 22) | (1ULL << 17); // IDQ.MITE_UOPS
    write_msr(MSR_IA32_PERFEVTSEL0+2, perfevtsel2);

    uint64_t cycle_first_added_to_IDQ = 0;
    uint64_t prev_uops = 0;
    for (int64_t cycle=cycle_last_retired_empty-3; cycle>=0; cycle--) {
        run_experiment_with_freeze_on_PMI(measurement_results, 3, FIXED_CTR_CORE_CYCLES, get_max_FF_ctr_value() - cycle, true);
        uint64_t uops = get_aggregate_value(measurement_results[2], n_measurements, 1, aggregate_function);

        if ((prev_uops != 0) && (prev_uops - uops > 1)) {
            cycle_first_added_to_IDQ = cycle + 1;
            break;
        }
        prev_uops = uops;
    }
    print_verbose("First instruction added to IDQ in cycle: %llu\n", cycle_first_added_to_IDQ);
    return cycle_first_added_to_IDQ;
}

// Programs the fixed cycle counter such that it overflows in the specified cycle, runs the benchmark,
// and stores the measurements of the programmable counters in results.
static void perform_measurements_for_cycle(uint64_t cycle, uint64_t* results, uint64_t* results_min, uint64_t* results_max) {
    // on several microarchitectures, the counters 0 or 1 do not freeze at the same time as the other counters
    int avoid_counters = 0;
    if (displ_model == 0x97) { // Alder Lake
        avoid_counters = (1 << 0);
    } else if ((Intel_perf_mon_ver >= 3) && (Intel_perf_mon_ver <= 4) && (displ_model >= 0x3A)) {
        avoid_counters = (1 << 1);
    }

    // the higher counters don't count some of the events properly (e.g., D1.01 on RKL)
    int n_used_counters = 4;

    size_t next_pfc_config = 0;
    while (next_pfc_config < n_pfc_configs) {
        size_t cur_pfc_config = next_pfc_config;
        char* pfc_descriptions[MAX_PROGRAMMABLE_COUNTERS] = {0};
        next_pfc_config = configure_perf_ctrs_programmable(next_pfc_config, true, true, n_used_counters, avoid_counters, pfc_descriptions);

        run_experiment_with_freeze_on_PMI(measurement_results, n_used_counters, FIXED_CTR_CORE_CYCLES, get_max_FF_ctr_value() - cycle, true);

        for (size_t c=0; c<n_used_counters; c++) {
            if (pfc_descriptions[c]) {
                results[cur_pfc_config] = get_aggregate_value(measurement_results[c], n_measurements, 1, aggregate_function);
                if (results_min) results_min[cur_pfc_config] = get_aggregate_value(measurement_results[c], n_measurements, 1, MIN);
                if (results_max) results_max[cur_pfc_config] = get_aggregate_value(measurement_results[c], n_measurements, 1, MAX);
                cur_pfc_config++;
            }
        }
    }
}

static int run_FuzzerBench_cycle_by_cycle(struct seq_file *m, void *v) {
    if (is_AMD_CPU) {
        pr_err("Cycle-by-cycle measurements are not supported on AMD CPUs\n");
        return -1;
    }
    if (n_programmable_counters < 4) {
        pr_err("Cycle-by-cycle measurements require at least four programmable counters\n");
        return -1;
    }
    if (!check_memory_allocations()) {
        return -1;
    }

    kernel_fpu_begin();
    disable_interrupts_preemption();

    clear_perf_counter_configurations();
    enable_freeze_on_PMI();
    configure_perf_ctrs_FF_Intel(0, 1);

    char* measurement_template;
    if (no_mem) {
        measurement_template = (char*)&measurement_cycleByCycle_template_Intel_noMem;
    } else {
        measurement_template = (char*)&measurement_cycleByCycle_template_Intel;
    }

    create_runtime_code(measurement_template, 0, 0, true); // empty benchmark

    uint64_t cycle_last_retired_empty = get_cycle_last_retired(false);
    uint64_t* results_empty = vmalloc(sizeof(uint64_t[n_pfc_configs]));
    perform_measurements_for_cycle(cycle_last_retired_empty, results_empty, NULL, NULL);


    uint64_t cycle_last_retired_empty_with_lfence = get_cycle_last_retired(true);
    uint64_t* results_empty_with_lfence = vmalloc(sizeof(uint64_t[n_pfc_configs]));
    perform_measurements_for_cycle(cycle_last_retired_empty_with_lfence, results_empty_with_lfence, NULL, NULL);

    uint64_t first_cycle = 0;
    uint64_t last_cycle = 0;

    if (!end_to_end) {
        first_cycle = get_cycle_first_added_to_IDQ(cycle_last_retired_empty);
    }

    create_runtime_code(measurement_template, unroll_count, loop_count, false);

    if (end_to_end) {
        last_cycle = get_end_to_end_cycles();
    } else {
        // Here, we take the cycle after retiring the lfence instruction because some uops of the lfence might retire in the same cycle
        // as the last instruction of the benchmark; this way it is easier to determine the correct count for the number of retired uops.
        last_cycle = get_cycle_last_retired(true);
    }

    uint64_t (*results)[n_pfc_configs] = vmalloc(sizeof(uint64_t[last_cycle+1][n_pfc_configs]));
    uint64_t (*results_min)[n_pfc_configs] = output_range?vmalloc(sizeof(uint64_t[last_cycle+1][n_pfc_configs])):NULL;
    uint64_t (*results_max)[n_pfc_configs] = output_range?vmalloc(sizeof(uint64_t[last_cycle+1][n_pfc_configs])):NULL;

    for (uint64_t cycle=first_cycle; cycle<=last_cycle; cycle++) {
        perform_measurements_for_cycle(cycle, results[cycle], output_range?results_min[cycle]:NULL, output_range?results_max[cycle]:NULL);
    }

    disable_perf_ctrs_globally();
    disable_freeze_on_PMI();
    clear_overflow_status_bits();
    clear_perf_counter_configurations();

    restore_interrupts_preemption();
    kernel_fpu_end();

    for (size_t i=0; i<n_pfc_configs; i++) {
        seq_printf(m, "%s", pfc_configs[i].description);
        seq_printf(m, ",%lld", results_empty[i]);
        seq_printf(m, ",%lld", results_empty_with_lfence[i]);
        for (long cycle=first_cycle; cycle<=last_cycle; cycle++) {
            seq_printf(m, ",%lld", results[cycle][i]);
            if (output_range) seq_printf(m, ",%lld,%lld", results_min[cycle][i], results_max[cycle][i]);
        }
        seq_printf(m, "\n");
    }

    vfree(results_empty);
    vfree(results_empty_with_lfence);
    vfree(results);
    return 0;
}

static int open_FuzzerBench(struct inode *inode, struct file *file) {
    return single_open_size(file, run_FuzzerBench, NULL, (n_pfc_configs + n_msr_configs + 4*use_fixed_counters) * 128);
}

static int open_FuzzerBenchCycleByCycle(struct inode *inode, struct file *file) {
    return single_open_size(file, run_FuzzerBench_cycle_by_cycle, NULL, n_pfc_configs * 4096);
}

// in kernel 5.6, the struct for fileops has changed
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops proc_file_fops_FuzzerBench = {
    .proc_lseek = seq_lseek,
    .proc_open = open_FuzzerBench,
    .proc_read = seq_read,
    .proc_release = single_release,
};
static const struct proc_ops proc_file_fops_FuzzerBenchCycleByCycle = {
    .proc_lseek = seq_lseek,
    .proc_open = open_FuzzerBenchCycleByCycle,
    .proc_read = seq_read,
    .proc_release = single_release,
};
#else
static const struct file_operations proc_file_fops_FuzzerBench = {
    .llseek = seq_lseek,
    .open = open_FuzzerBench,
    .owner = THIS_MODULE,
    .read = seq_read,
    .release = single_release,
};
static const struct file_operations proc_file_fops_FuzzerBenchCycleByCycle = {
    .llseek = seq_lseek,
    .open = open_FuzzerBenchCycleByCycle,
    .owner = THIS_MODULE,
    .read = seq_read,
    .release = single_release,
};
#endif

static struct kobject* fuzzerBench_kobj;

static int __init fuzzerBench_init(void) {
    pr_info("Initializing FuzzerBench kernel module...\n");
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
    set_memory_x = (void*)kallsyms_lookup_name("set_memory_x");
    set_memory_nx = (void*)kallsyms_lookup_name("set_memory_nx");
    #endif
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    kallsym__vmalloc_node_range = (void*)kallsyms_lookup_name("__vmalloc_node_range");
    #endif
    if (check_cpuid()) {
        return -1;
    }

    for (int i=0; i<MAX_PROGRAMMABLE_COUNTERS; i++) {
        measurement_results[i] = kmalloc(n_measurements*sizeof(int64_t), GFP_KERNEL);
        measurement_results_base[i] = kmalloc(n_measurements*sizeof(int64_t), GFP_KERNEL);
        if (!measurement_results[i] || !measurement_results_base[i]) {
            pr_err("Could not allocate memory for measurement_results\n");
            return -1;
        }
        memset(measurement_results[i], 0, n_measurements*sizeof(int64_t));
        memset(measurement_results_base[i], 0, n_measurements*sizeof(int64_t));
    }

    // vmalloc addresses are page aligned
    runtime_r14 = vmalloc(RUNTIME_R_SIZE);
    runtime_rbp = vmalloc(RUNTIME_R_SIZE);
    runtime_rdi = vmalloc(RUNTIME_R_SIZE);
    runtime_rsi = vmalloc(RUNTIME_R_SIZE);
    runtime_rsp = vmalloc(RUNTIME_R_SIZE);
    if (!runtime_r14 || !runtime_rbp || !runtime_rdi || !runtime_rsi || !runtime_rsp) {
        pr_err("Could not allocate memory for runtime_r*\n");
        return -1;
    }
    memset(runtime_r14, 0, RUNTIME_R_SIZE);
    memset(runtime_rbp, 0, RUNTIME_R_SIZE);
    memset(runtime_rdi, 0, RUNTIME_R_SIZE);
    memset(runtime_rsi, 0, RUNTIME_R_SIZE);
    memset(runtime_rsp, 0, RUNTIME_R_SIZE);
    runtime_r14 += RUNTIME_R_SIZE/2;
    runtime_rbp += RUNTIME_R_SIZE/2;
    runtime_rdi += RUNTIME_R_SIZE/2;
    runtime_rsi += RUNTIME_R_SIZE/2;
    runtime_rsp += RUNTIME_R_SIZE/2;

    runtime_code_baseK = kmalloc(KMALLOC_MAX, GFP_KERNEL);
    if (!runtime_code_baseK) {
        pr_err("Could not allocate memory for runtime_code_baseK\n");
        return -1;
    }
    runtime_code_base_memory_size = KMALLOC_MAX;
    set_memory_x((unsigned long)runtime_code_baseK, runtime_code_base_memory_size/PAGE_SIZE);
    runtime_code_base = runtime_code_baseK;

    // [ADDED]
    runtime_code_mainK = kmalloc(KMALLOC_MAX, GFP_KERNEL);
    if (!runtime_code_mainK) {
        pr_err("Could not allocate memory for runtime_code_mainK\n");
        return -1;
    }
    runtime_code_main_memory_size = KMALLOC_MAX;
    set_memory_x((unsigned long)runtime_code_mainK, runtime_code_main_memory_size/PAGE_SIZE);
    runtime_code_main = runtime_code_mainK;


    fuzzerBench_kobj = kobject_create_and_add("FuzzerBench", kernel_kobj->parent);
    if (!fuzzerBench_kobj) {
        pr_err("failed to create and add FuzzerBench\n");
        return -1;
    }
    
    int error = sysfs_create_file(fuzzerBench_kobj, &clear_attribute.attr);
    // error |= init_input_parser();
    error |= sysfs_create_file(fuzzerBench_kobj, &reset_attribute.attr);
    error |= sysfs_create_file(fuzzerBench_kobj, &code_attribute.attr);
    error |= sysfs_create_file(fuzzerBench_kobj, &code_init_attribute.attr);
    error |= sysfs_create_file(fuzzerBench_kobj, &code_late_init_attribute.attr);
    error |= sysfs_create_file(fuzzerBench_kobj, &code_one_time_init_attribute.attr);
    error |= sysfs_create_file(fuzzerBench_kobj, &config_attribute.attr);
    error |= sysfs_create_file(fuzzerBench_kobj, &msr_config_attribute.attr);
    error |= sysfs_create_file(fuzzerBench_kobj, &fixed_counters_attribute.attr);
    error |= sysfs_create_file(fuzzerBench_kobj, &loop_count_attribute.attr);
    error |= sysfs_create_file(fuzzerBench_kobj, &unroll_count_attribute.attr);
    error |= sysfs_create_file(fuzzerBench_kobj, &n_measurements_attribute.attr);
    error |= sysfs_create_file(fuzzerBench_kobj, &warm_up_attribute.attr);
    error |= sysfs_create_file(fuzzerBench_kobj, &initial_warm_up_attribute.attr);
    error |= sysfs_create_file(fuzzerBench_kobj, &alignment_offset_attribute.attr);
    error |= sysfs_create_file(fuzzerBench_kobj, &end_to_end_attribute.attr);
    error |= sysfs_create_file(fuzzerBench_kobj, &drain_frontend_attribute.attr);
    error |= sysfs_create_file(fuzzerBench_kobj, &agg_attribute.attr);
    error |= sysfs_create_file(fuzzerBench_kobj, &output_range_attribute.attr);
    error |= sysfs_create_file(fuzzerBench_kobj, &basic_mode_attribute.attr);
    error |= sysfs_create_file(fuzzerBench_kobj, &no_mem_attribute.attr);
    error |= sysfs_create_file(fuzzerBench_kobj, &no_normalization_attribute.attr);
    error |= sysfs_create_file(fuzzerBench_kobj, &r14_size_attribute.attr);
    error |= sysfs_create_file(fuzzerBench_kobj, &print_r14_attribute.attr);
    error |= sysfs_create_file(fuzzerBench_kobj, &code_offset_attribute.attr);
    error |= sysfs_create_file(fuzzerBench_kobj, &addresses_attribute.attr);
    error |= sysfs_create_file(fuzzerBench_kobj, &verbose_attribute.attr);
    // [ADDED] creating files for the new arguments "-num_inputs" and "-seed"
    error |= sysfs_create_file(fuzzerBench_kobj, &num_inputs_attribute.attr);
    error |= sysfs_create_file(fuzzerBench_kobj, &seed_attribute.attr);
    error |= sysfs_create_file(fuzzerBench_kobj, &n_reps_attribute.attr);
    error |= sysfs_create_file(fuzzerBench_kobj, &cpu_attribute.attr);
    error |= sysfs_create_bin_file(fuzzerBench_kobj, &trace_bin_attribute);
    error |= sysfs_create_bin_file(fuzzerBench_kobj, &inputs_bin_attribute);

    if (error) {
        pr_err("failed to create file in /sys/FuzzerBench/\n");
        return error;
    }

    struct proc_dir_entry* proc_file_entry = proc_create("FuzzerBench", 0, NULL, &proc_file_fops_FuzzerBench);
    struct proc_dir_entry* proc_file_entry2 = proc_create("FuzzerBenchCycleByCycle", 0, NULL, &proc_file_fops_FuzzerBenchCycleByCycle);
    if(proc_file_entry == NULL || proc_file_entry2 == NULL) {
        pr_err("failed to create file in /proc/\n");
        return -1;
    }

    return 0;
}

static void __exit fuzzerBench_exit(void) {
    kfree(code);
    kfree(code_init);
    kfree(code_late_init);
    kfree(code_one_time_init);
    kfree(pfc_config_file_content);
    kfree(msr_config_file_content);
    vfree(runtime_one_time_init_code);
    vfree(runtime_rbp - RUNTIME_R_SIZE/2);
    vfree(runtime_rdi - RUNTIME_R_SIZE/2);
    vfree(runtime_rsi - RUNTIME_R_SIZE/2);
    vfree(runtime_rsp - RUNTIME_R_SIZE/2);

    if (runtime_code_base) {
        set_memory_nx((unsigned long)runtime_code_base, runtime_code_base_memory_size/PAGE_SIZE);
        kfree(runtime_code_base);
    }

    if (runtime_code_main) {
        set_memory_nx((unsigned long)runtime_code_main, runtime_code_main_memory_size/PAGE_SIZE);
        kfree(runtime_code_main);
    }

    if (n_r14_segments > 0) {
        for (int i=0; i<n_r14_segments; i++) {
            kfree(r14_segments[i]);
        }
    } else {
        vfree(runtime_r14 - RUNTIME_R_SIZE/2);
    }

    for (int i=0; i<MAX_PROGRAMMABLE_COUNTERS; i++) {
        kfree(measurement_results[i]);
        kfree(measurement_results_base[i]);
    }

    kobject_put(fuzzerBench_kobj);
    remove_proc_entry("FuzzerBench", NULL);
    remove_proc_entry("FuzzerBenchCycleByCycle", NULL);
}

module_init(fuzzerBench_init);
module_exit(fuzzerBench_exit);
