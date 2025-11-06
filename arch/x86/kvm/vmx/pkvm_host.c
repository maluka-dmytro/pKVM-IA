// SPDX-License-Identifier: GPL-2.0
#include <linux/kvm_host.h>
#include <asm/kvm_pkvm.h>
#include "pkvm_constants.h"
#include "x86_ops.h"
#include "vmx.h"

static void *kvm_host_va(phys_addr_t phys)
{
	return __va(phys);
}

static void host_free_pkvm_page_range(struct pkvm_page_range range)
{
	void *vaddr = __va(range.addr);
	u64 nr_pages = range.nr_pages;

	if (WARN_ON_ONCE(!nr_pages))
		return;

	if (nr_pages > 1)
		free_pages_exact(vaddr, nr_pages << PAGE_SHIFT);
	else
		free_page((unsigned long)vaddr);
}

static void host_free_pkvm_memcache(struct pkvm_memcache *mc)
{
	free_pkvm_memcache(mc, host_free_pkvm_page_range, kvm_host_va);
}

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

static int pkvm_vm_init(struct kvm *kvm)
{
	void *pkvm_vm;
	int ret;

	/*
	 * Some of struct kvm elements are initialized by the vmx_vm_init()
	 * which can be leveraged by the pKVM host as this initialization is
	 * simple and no VMX hardware involved.
	 */
	ret = vmx_vm_init(kvm);
	if (ret)
		return ret;

	pkvm_vm = alloc_pages_exact(PKVM_VMX_VM_SIZE, GFP_KERNEL_ACCOUNT);
	if (!pkvm_vm)
		return -ENOMEM;

	ret = pkvm_hypercall(vm_init, __pa(kvm), __pa(pkvm_vm));
	if (ret < 0)
		goto free_page;

	kvm->arch.pkvm_vm_handle = ret;

	if (pkvm_is_protected_vm(kvm))
		kvm->arch.has_protected_state = true;

	return 0;

free_page:
	free_pages_exact(pkvm_vm, PKVM_VMX_VM_SIZE);
	return ret;
}

static void pkvm_vm_destroy(struct kvm *kvm)
{
	union pkvm_hc_data inout = { 0 };
	int ret;

	inout.vm_handle = kvm->arch.pkvm_vm_handle;
	ret = pkvm_hypercall_inout(vm_destroy, &inout);
	if (ret)
		return;

	host_free_pkvm_memcache(&inout.memcache);

	vmx_vm_destroy(kvm);
}

struct kvm_x86_ops pkvm_host_vt_x86_ops __initdata = {
	.name = KBUILD_MODNAME,

	.check_processor_compatibility = pkvm_check_processor_compat,

	.enable_virtualization_cpu = pkvm_enable_virtualization_cpu,
	.disable_virtualization_cpu = pkvm_disable_virtualization_cpu,
	.emergency_disable_virtualization_cpu = pkvm_disable_virtualization_cpu,

	.vm_size = sizeof(struct kvm_vmx),
	.vm_init = pkvm_vm_init,
	.vm_destroy = pkvm_vm_destroy,

	.vcpu_precreate = vmx_vcpu_precreate,
};
