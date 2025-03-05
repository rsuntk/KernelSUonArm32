#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/version.h>

#include "../klog.h" // IWYU pragma: keep
#include "selinux.h"
#include "sepolicy.h"
#include "ss/services.h"
#include "linux/lsm_audit.h"
#include "xfrm.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
#define SELINUX_POLICY_INSTEAD_SELINUX_SS
#endif

#define KERNEL_SU_DOMAIN "su"
#define KERNEL_SU_FILE "ksu_file"
#define KERNEL_EXEC_TYPE "ksu_exec"
#define ALL NULL

static struct policydb *get_policydb(void)
{
	struct policydb *db;
// selinux_state does not exists before 4.19
#ifdef KSU_COMPAT_USE_SELINUX_STATE
#ifdef SELINUX_POLICY_INSTEAD_SELINUX_SS
	struct selinux_policy *policy = rcu_dereference(selinux_state.policy);
	db = &policy->policydb;
#else
	struct selinux_ss *ss = rcu_dereference(selinux_state.ss);
	db = &ss->policydb;
#endif
#else
	db = &policydb;
#endif
	return db;
}

void apply_kernelsu_rules()
{
	if (!getenforce()) {
		pr_info("SELinux permissive or disabled, apply rules!\n");
	}

	rcu_read_lock();
	struct policydb *db = get_policydb();

	ksu_permissive(db, KERNEL_SU_DOMAIN);
	ksu_typeattribute(db, KERNEL_SU_DOMAIN, "mlstrustedsubject");
	ksu_typeattribute(db, KERNEL_SU_DOMAIN, "netdomain");
	ksu_typeattribute(db, KERNEL_SU_DOMAIN, "bluetoothdomain");

	// Create unconstrained file type
	ksu_type(db, KERNEL_SU_FILE, "file_type");
	ksu_typeattribute(db, KERNEL_SU_FILE, "mlstrustedobject");
	ksu_allow(db, ALL, KERNEL_SU_FILE, ALL, ALL);

	// allow all!
	ksu_allow(db, KERNEL_SU_DOMAIN, ALL, ALL, ALL);

	// allow us do any ioctl
	if (db->policyvers >= POLICYDB_VERSION_XPERMS_IOCTL) {
		ksu_allowxperm(db, KERNEL_SU_DOMAIN, ALL, "blk_file", ALL);
		ksu_allowxperm(db, KERNEL_SU_DOMAIN, ALL, "fifo_file", ALL);
		ksu_allowxperm(db, KERNEL_SU_DOMAIN, ALL, "chr_file", ALL);
		ksu_allowxperm(db, KERNEL_SU_DOMAIN, ALL, "file", ALL);
	}

	// we need to save allowlist in /data/adb/ksu
	ksu_allow(db, "kernel", "adb_data_file", "dir", ALL);
	ksu_allow(db, "kernel", "adb_data_file", "file", ALL);
	// we need to search /data/app
	ksu_allow(db, "kernel", "apk_data_file", "file", "open");
	ksu_allow(db, "kernel", "apk_data_file", "dir", "open");
	ksu_allow(db, "kernel", "apk_data_file", "dir", "read");
	ksu_allow(db, "kernel", "apk_data_file", "dir", "search");
	// we may need to do mount on shell
	ksu_allow(db, "kernel", "shell_data_file", "file", ALL);
	// we need to read /data/system/packages.list
	ksu_allow(db, "kernel", "kernel", "capability", "dac_override");
	// Android 10+:
	// http://aospxref.com/android-12.0.0_r3/xref/system/sepolicy/private/file_contexts#512
	ksu_allow(db, "kernel", "packages_list_file", "file", ALL);
	// Kernel 4.4
	ksu_allow(db, "kernel", "packages_list_file", "dir", ALL);
	// Android 9-:
	// http://aospxref.com/android-9.0.0_r61/xref/system/sepolicy/private/file_contexts#360
	ksu_allow(db, "kernel", "system_data_file", "file", ALL);
	ksu_allow(db, "kernel", "system_data_file", "dir", ALL);
	// our ksud triggered by init
	ksu_allow(db, "init", "adb_data_file", "file", ALL);
	ksu_allow(db, "init", "adb_data_file", "dir", ALL); // #1289
	ksu_allow(db, "init", KERNEL_SU_DOMAIN, ALL, ALL);
	
	// we need to umount modules in zygote
	ksu_allow(db, "zygote", "adb_data_file", "dir", "search");

	// copied from Magisk rules
	// suRights
	ksu_allow(db, "servicemanager", KERNEL_SU_DOMAIN, "dir", "search");
	ksu_allow(db, "servicemanager", KERNEL_SU_DOMAIN, "dir", "read");
	ksu_allow(db, "servicemanager", KERNEL_SU_DOMAIN, "file", "open");
	ksu_allow(db, "servicemanager", KERNEL_SU_DOMAIN, "file", "read");
	ksu_allow(db, "servicemanager", KERNEL_SU_DOMAIN, "process", "getattr");
	ksu_allow(db, ALL, KERNEL_SU_DOMAIN, "process", "sigchld");

	// allowLog
	ksu_allow(db, "logd", KERNEL_SU_DOMAIN, "dir", "search");
	ksu_allow(db, "logd", KERNEL_SU_DOMAIN, "file", "read");
	ksu_allow(db, "logd", KERNEL_SU_DOMAIN, "file", "open");
	ksu_allow(db, "logd", KERNEL_SU_DOMAIN, "file", "getattr");

	// dumpsys
	ksu_allow(db, ALL, KERNEL_SU_DOMAIN, "fd", "use");
	ksu_allow(db, ALL, KERNEL_SU_DOMAIN, "fifo_file", "write");
	ksu_allow(db, ALL, KERNEL_SU_DOMAIN, "fifo_file", "read");
	ksu_allow(db, ALL, KERNEL_SU_DOMAIN, "fifo_file", "open");
	ksu_allow(db, ALL, KERNEL_SU_DOMAIN, "fifo_file", "getattr");

	// bootctl
	ksu_allow(db, "hwservicemanager", KERNEL_SU_DOMAIN, "dir", "search");
	ksu_allow(db, "hwservicemanager", KERNEL_SU_DOMAIN, "file", "read");
	ksu_allow(db, "hwservicemanager", KERNEL_SU_DOMAIN, "file", "open");
	ksu_allow(db, "hwservicemanager", KERNEL_SU_DOMAIN, "process",
		  "getattr");

	// For mounting loop devices, mirrors, tmpfs
	ksu_allow(db, "kernel", ALL, "file", "read");
	ksu_allow(db, "kernel", ALL, "file", "write");

	// Allow all binder transactions
	ksu_allow(db, ALL, KERNEL_SU_DOMAIN, "binder", ALL);

	// Allow system server kill su process
	ksu_allow(db, "system_server", KERNEL_SU_DOMAIN, "process", "getpgid");
	ksu_allow(db, "system_server", KERNEL_SU_DOMAIN, "process", "sigkill");

	rcu_read_unlock();
}

int handle_sepolicy(unsigned long arg3, void __user *arg4)
{
	pr_info("sepol: skip kernel sepol driver");
	return 0;
}
