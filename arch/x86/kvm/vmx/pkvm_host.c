// SPDX-License-Identifier: GPL-2.0
#include <linux/kvm_host.h>
#include <asm/kvm_pkvm.h>

static int pkvm_check_processor_compat(void)
{
	return pkvm_hypercall(check_processor_compatibility);
}

static int pkvm_enable_virtualization_cpu(void)
{
	return pkvm_hypercall(enable_virtualization_cpu);
}

static void pkvm_disable_virtualization_cpu(void)
{
	/*
	 * The pKVM hypervisor doesn't support disabling VMX via this PV
	 * interface due to security concerns. As a result, the CPU will remain
	 * in VMX non-root mode during shutting down or rebooting if there is no
	 * hardware level reset. In this case, if INIT-SIPI are send, they will
	 * cause vmexits to the pKVM hypervisor rather than the operations
	 * associated with these events. Handling such vmexits is not supported
	 * by the pKVM hypervisor.
	 */
}

struct kvm_x86_ops pkvm_host_vt_x86_ops __initdata = {
	.name = KBUILD_MODNAME,

	.check_processor_compatibility = pkvm_check_processor_compat,

	.enable_virtualization_cpu = pkvm_enable_virtualization_cpu,
	.disable_virtualization_cpu = pkvm_disable_virtualization_cpu,
	.emergency_disable_virtualization_cpu = pkvm_disable_virtualization_cpu,
};
