// SPDX-License-Identifier: GPL-2.0
#include <linux/types.h>
#include <linux/kvm_host.h>
#include <asm/fpu/xcr.h>
#include <asm/pkvm_spinlock.h>
#include "debug.h"
#include "fpu.h"
#include "init_finalize.h"
#include "lapic.h"
#include "mem_protect.h"
#include "memory.h"
#include "pkvm.h"
#include "trace.h"
#include "../x86.h"
#include "../lapic.h"

/*
 * Needed by kvm_spurious_fault() which is a generic fault function for the
 * vendor operations, e.g., vmx ops or svm ops. The pKVM hypervisor doesn't
 * have the knowledge about the platform reboot or shutdown, so kvm_rebooting
 * is always false in the pKVM hypervisor.
 */
__visible bool kvm_rebooting;

/*
 * Needed by code sharing with the KVM. As the pKVM hypervisor requires to have
 * a second level page table to translate GPA to HPA, set tdp_enabled as true.
 */
bool tdp_enabled = true;

struct pkvm_hyp *pkvm_hyp;
DEFINE_PER_CPU(struct pkvm_pcpu *, phys_cpu);
DEFINE_PER_CPU(struct kvm_vcpu *, host_vcpu);

/* The maximum number of VMs under pkvm. */
#define MAX_PKVM_VMS		64

static DECLARE_BITMAP(pkvm_vms_bitmap, MAX_PKVM_VMS);
static DEFINE_PKVM_SPINLOCK(pkvm_vms_lock);
static struct pkvm_vm_ref {
	/* Reference counter to indicate if pkvm_vm is in use */
	atomic_t refcount;
	/* Point to pkvm_vm in pkvm */
	struct pkvm_vm *pkvm_vm;
} pkvm_vms_ref[MAX_PKVM_VMS];

/*
 * Represents the actual, extended kvm_vcpu structure size. It is initialized as
 * the size of struct kvm_vcpu. And if the vendor code extends kvm_vcpu instance
 * via embedding struct kvm_vcpu to its specific structure, this size should also
 * be extended by the vendor code.
 */
size_t kvm_vcpu_sz = sizeof(struct kvm_vcpu);

/* The current loaded guest vcpu */
static DEFINE_PER_CPU(struct kvm_vcpu*, cur_guest_vcpu);

static int __pkvm_vcpu_free(struct pkvm_vm *pkvm_vm, int vcpu_handle,
			    struct pkvm_memcache *mc);

static int pkvm_enable_virtualization_cpu(void)
{
	kvm_user_return_msr_cpu_online();

	return kvm_x86_call(enable_virtualization_cpu)();
}

static int allocate_pkvm_vm_handle(struct pkvm_vm *pkvm_vm)
{
	struct pkvm_vm_ref *pkvm_vm_ref;
	int idx;

	pkvm_spin_lock(&pkvm_vms_lock);

	idx = find_next_zero_bit(pkvm_vms_bitmap, MAX_PKVM_VMS, 0);
	if (idx == MAX_PKVM_VMS) {
		pkvm_spin_unlock(&pkvm_vms_lock);
		return -ENOMEM;
	}
	__set_bit(idx, pkvm_vms_bitmap);

	pkvm_vm_ref = &pkvm_vms_ref[idx];
	pkvm_vm_ref->pkvm_vm = pkvm_vm;
	atomic_set(&pkvm_vm_ref->refcount, 1);

	pkvm_spin_unlock(&pkvm_vms_lock);

	return idx;
}

static struct pkvm_vm *free_pkvm_vm_handle(int handle)
{
	struct pkvm_vm_ref *pkvm_vm_ref;
	struct pkvm_vm *pkvm_vm = NULL;
	int idx = handle;

	if (idx < 0 || idx >= MAX_PKVM_VMS)
		return NULL;

	pkvm_spin_lock(&pkvm_vms_lock);

	idx = array_index_nospec(idx, MAX_PKVM_VMS);
	pkvm_vm_ref = &pkvm_vms_ref[idx];
	if (atomic_cmpxchg(&pkvm_vm_ref->refcount, 1, 0) != 1) {
		pkvm_err("VM%d is busy, refcount %d\n", handle,
			 atomic_read(&pkvm_vm_ref->refcount));
		goto out;
	}

	pkvm_vm = pkvm_vm_ref->pkvm_vm;
	pkvm_vm_ref->pkvm_vm = NULL;

	__clear_bit(idx, pkvm_vms_bitmap);
out:
	pkvm_spin_unlock(&pkvm_vms_lock);
	return pkvm_vm;
}

static int pkvm_vm_init(phys_addr_t host_kvm_pa, phys_addr_t pkvm_vm_pa)
{
	struct pkvm_vm *pkvm_vm;
	size_t size;
	u8 vm_type;
	int ret;

	size = PAGE_ALIGN(PKVM_VM_BASE_SIZE + kvm_x86_ops.vm_size);
	ret = pkvm_host_donate_hyp(pkvm_vm_pa, size, true);
	if (ret)
		return ret;

	pkvm_vm = __pkvm_va(pkvm_vm_pa);
	pkvm_vm->size = size;

	ret = pkvm_host_share_hyp(host_kvm_pa, kvm_x86_ops.vm_size);
	if (ret)
		goto undonate;

	pkvm_vm->shared_kvm = __pkvm_va(host_kvm_pa);
	vm_type = pkvm_vm->shared_kvm->arch.vm_type;
	if (!kvm_is_vm_type_supported(vm_type)) {
		ret = -EOPNOTSUPP;
		goto unshare;
	}

	pkvm_vm->kvm.arch.vm_type = vm_type;

	pkvm_spin_lock_init(&pkvm_vm->lock);

	ret = allocate_pkvm_vm_handle(pkvm_vm);
	if (ret < 0)
		goto unshare;
	pkvm_vm->kvm.arch.pkvm_vm_handle = ret;

	ret = kvm_x86_call(vm_init)(&pkvm_vm->kvm);
	if (ret)
		goto free_handle;

	return pkvm_vm->kvm.arch.pkvm_vm_handle;

free_handle:
	free_pkvm_vm_handle(pkvm_vm->kvm.arch.pkvm_vm_handle);
unshare:
	pkvm_host_unshare_hyp(host_kvm_pa, kvm_x86_ops.vm_size);
undonate:
	pkvm_hyp_donate_host(__pkvm_pa(pkvm_vm), size, false);
	return ret;
}

static void teardown_donated_memory(struct pkvm_memcache *mc, void *addr, size_t size)
{
	/*
	 * The pKVM hypervisor will push the memory range [addr, addr + size)
	 * to the memcache and donate to the host. The memory range should be
	 * PAGE_SIZE aligned. If not, it must be a code bug.
	 */
	BUG_ON(!PAGE_ALIGNED(addr) || !PAGE_ALIGNED(size));

	pkvm_clear_memory(addr, size);

	push_pkvm_memcache(mc, addr, size, pkvm_virt_to_host_gpa);

	/*
	 * Sensitive data in this memory range has been already cleared
	 * by push_mem_to_memcache(). Now this memory is used as
	 * memcache to store the information about the memory pages for
	 * the host to free, so cannot clear it. So undonate without
	 * clearing.
	 */
	pkvm_hyp_donate_host(__pkvm_pa(addr), size, false);
}

static void pkvm_vm_destroy(int vm_handle, struct pkvm_memcache *mc)
{
	struct pkvm_vm *pkvm_vm = free_pkvm_vm_handle(vm_handle);
	int i;

	if (!pkvm_vm)
		return;

	/*
	 * Normally all the created pkvm_vcpus should have been freed already
	 * by the vcpu_free PV interface. In case any pkvm_vcpu is still not
	 * freed, try to free it here.
	 */
	for (i = 0; i < pkvm_vm->kvm.created_vcpus; i++)
		__pkvm_vcpu_free(pkvm_vm, i, mc);

	kvm_x86_call(vm_destroy)(&pkvm_vm->kvm);

	pkvm_host_unshare_hyp(__pkvm_pa(pkvm_vm->shared_kvm), kvm_x86_call(vm_size));

	teardown_donated_memory(mc, (void *)pkvm_vm, pkvm_vm->size);
}

static int attach_pkvm_vcpu_to_vm(struct pkvm_vm *pkvm_vm, struct pkvm_vcpu *pkvm_vcpu)
{
	struct kvm *kvm = &pkvm_vm->kvm;
	int vcpu_handle;

	pkvm_spin_lock(&pkvm_vm->lock);

	if (kvm->created_vcpus == KVM_MAX_VCPUS) {
		pkvm_spin_unlock(&pkvm_vm->lock);
		return -EINVAL;
	}
	vcpu_handle = kvm->created_vcpus++;
	pkvm_vcpu->vcpu.arch.pkvm_vcpu_handle = vcpu_handle;
	pkvm_vcpu->pkvm_vm = pkvm_vm;
	pkvm_vm->vcpus[vcpu_handle] = pkvm_vcpu;

	pkvm_spin_unlock(&pkvm_vm->lock);

	atomic_set(&pkvm_vm->vcpu_refs[vcpu_handle], 1);

	return vcpu_handle;
}

static struct pkvm_vcpu *detach_pkvm_vcpu_from_vm(struct pkvm_vm *pkvm_vm, int vcpu_handle)
{
	int refcount = atomic_cmpxchg(&pkvm_vm->vcpu_refs[vcpu_handle], 1, 0);
	struct pkvm_vcpu *pkvm_vcpu;

	if (refcount > 1) {
		/* The pkvm_vcpu is in use and cannot be detached. */
		pkvm_err("VM%d vcpu%d is busy, refcount %d\n",
			 pkvm_vm->kvm.arch.pkvm_vm_handle,
			 vcpu_handle, refcount);
		return NULL;
	} else if (refcount == 0) {
		/* No pkvm_vcpu is attached. */
		return NULL;
	}

	BUG_ON(refcount != 1);

	pkvm_spin_lock(&pkvm_vm->lock);

	pkvm_vcpu = pkvm_vm->vcpus[vcpu_handle];
	pkvm_vm->vcpus[vcpu_handle] = NULL;

	pkvm_spin_unlock(&pkvm_vm->lock);

	return pkvm_vcpu;
}

static int setup_vcpu_lapic(struct kvm_vcpu *vcpu)
{
	struct pkvm_vcpu *pkvm_vcpu = to_pkvm_vcpu(vcpu);
	struct kvm_lapic *shared_apic, *apic;
	struct kvm_vcpu *shared_vcpu;
	void *apic_regs = NULL;
	phys_addr_t apic_pa;
	size_t apic_size;
	int ret;

	shared_vcpu = pkvm_vcpu->shared_vcpu;
	if (!lapic_in_kernel(pkvm_vcpu->shared_vcpu))
		return 0;

	/*
	 * The host allocates contiguous memory pages for the pkvm_vcpu
	 * structure, including the struct kvm_lapic memory page if lapic
	 * is emulated.
	 */
	apic_pa = __pkvm_pa(pkvm_vcpu) + pkvm_vcpu->size;
	apic_size = PAGE_ALIGN(sizeof(struct kvm_lapic));
	ret = pkvm_host_donate_hyp(apic_pa, apic_size, true);
	if (ret)
		return ret;

	/*
	 * Increase pkvm_vcpu->size with the size of donated struct kvm_lapic
	 * memory pages.
	 */
	pkvm_vcpu->size += apic_size;
	apic = __pkvm_va(apic_pa);

	shared_apic = kern_pkvm_va(shared_vcpu->arch.apic);
	/*
	 * Temporary sharing host's apic page to access its elements for setting
	 * up pKVM's apic page. It will be unshared after that.
	 */
	ret = pkvm_host_share_hyp(__pkvm_pa(shared_apic), apic_size);
	if (ret)
		goto undonate_apic;

	apic_regs = kern_pkvm_va(shared_apic->regs);
	if (!apic_regs) {
		ret = -EINVAL;
		goto unshare_apic;
	}

	ret = pkvm_host_share_hyp(__pkvm_pa(apic_regs), PAGE_SIZE);
	if (ret)
		goto unshare_apic;

	apic->regs = apic_regs;
	apic->apicv_active = shared_apic->apicv_active;
	apic->nr_lvt_entries = kvm_apic_calc_nr_lvt_entries(vcpu);
	apic->vcpu = vcpu;

	pkvm_host_unshare_hyp(__pkvm_pa(shared_apic), apic_size);

	vcpu->arch.apic = apic;

	return 0;

unshare_apic:
	pkvm_host_unshare_hyp(__pkvm_pa(shared_apic), apic_size);
undonate_apic:
	pkvm_hyp_donate_host(apic_pa, apic_size, false);
	pkvm_vcpu->size -= apic_size;
	return ret;
}

static void unsetup_vcpu_lapic(struct kvm_vcpu *vcpu, struct pkvm_memcache *mc)
{
	struct kvm_lapic *apic = xchg(&vcpu->arch.apic, NULL);

	if (!apic)
		return;

	pkvm_host_unshare_hyp(__pkvm_pa(apic->regs), PAGE_SIZE);

	/*
	 * Only undonate the apic memory pages if there is no pkvm_memcache. If
	 * there is, those pages will be undonated via the pkvm_memcache.
	 */
	if (!mc) {
		size_t apic_size = PAGE_ALIGN(sizeof(struct kvm_lapic));

		pkvm_hyp_donate_host(__pkvm_pa(apic), apic_size, false);
		to_pkvm_vcpu(vcpu)->size -= apic_size;
	}
}

static int __vcpu_create(struct kvm *kvm, struct kvm_vcpu *vcpu, struct fpstate *fps)
{
	struct pkvm_vcpu *pkvm_vcpu = to_pkvm_vcpu(vcpu);
	int ret = kvm_x86_call(vcpu_precreate)(kvm);

	if (ret)
		return ret;

	vcpu->kvm = kvm;
	/* Set cpu to -1 to indicate it is not loaded on any CPU */
	vcpu->cpu = -1;

	vcpu->vcpu_id = pkvm_vcpu->shared_vcpu->vcpu_id;
	vcpu->arch.apic_base = pkvm_vcpu->shared_vcpu->arch.apic_base;
	vcpu->arch.last_vmentry_cpu = -1;
	vcpu->arch.regs_avail = ~0;
	vcpu->arch.regs_dirty = ~0;
	vcpu->arch.pat = MSR_IA32_CR_PAT_DEFAULT;
	vcpu->arch.arch_capabilities = kvm_get_arch_capabilities();
	vcpu->arch.msr_platform_info = MSR_PLATFORM_INFO_CPUID_FAULT;

	vcpu->arch.mce_banks = (void *)pkvm_vcpu + PKVM_VCPU_BASE_SIZE + kvm_vcpu_sz;
	vcpu->arch.mci_ctl2_banks = (void *)vcpu->arch.mce_banks +
				    KVM_MCE_SIZE;
	vcpu->arch.mcg_cap = KVM_MAX_MCE_BANKS;

	ret = setup_vcpu_lapic(vcpu);
	if (ret)
		return ret;

	vcpu->arch.guest_fpu.fpstate = fps;
	pkvm_init_guest_fpu(&vcpu->arch.guest_fpu);
	if (pkvm_is_protected_vcpu(vcpu))
		fpstate_set_confidential(&vcpu->arch.guest_fpu);

	ret = kvm_x86_call(vcpu_create)(vcpu);
	if (ret)
		unsetup_vcpu_lapic(vcpu, NULL);

	return ret;
}

static void __vcpu_free(struct kvm_vcpu *vcpu, struct pkvm_memcache *mc)
{
	kvm_x86_call(vcpu_free)(vcpu);

	unsetup_vcpu_lapic(vcpu, mc);
}

static int pkvm_vcpu_create(int vm_handle, phys_addr_t host_vcpu_pa,
			    phys_addr_t pkvm_vcpu_pa, phys_addr_t fpu_pa)
{
	struct pkvm_vcpu *pkvm_vcpu;
	size_t vcpu_size, fps_size;
	struct pkvm_vm *pkvm_vm;
	struct fpstate *fps;
	int ret;

	pkvm_vm = pkvm_get_vm(vm_handle);
	if (!pkvm_vm)
		return -EINVAL;

	vcpu_size = PAGE_ALIGN(PKVM_VCPU_BASE_SIZE +
			       kvm_vcpu_sz +
			       KVM_MCE_SIZE +
			       KVM_MCI_CTL2_SIZE);
	ret = pkvm_host_donate_hyp(pkvm_vcpu_pa, vcpu_size, true);
	if (ret)
		goto put_vm;

	pkvm_vcpu = __pkvm_va(pkvm_vcpu_pa);
	pkvm_vcpu->size = vcpu_size;

	fps_size = pkvm_guest_initial_fpstate_size(&pkvm_vm->kvm);
	ret = pkvm_host_donate_hyp(fpu_pa, fps_size, true);
	if (ret)
		goto undonate_vcpu;

	fps = __pkvm_va(fpu_pa);
	fps->size = fps_size;

	ret = pkvm_host_share_hyp(host_vcpu_pa, kvm_vcpu_sz);
	if (ret)
		goto undonate_fps;

	pkvm_vcpu->shared_vcpu = __pkvm_va(host_vcpu_pa);

	ret = __vcpu_create(&pkvm_vm->kvm, &pkvm_vcpu->vcpu, fps);
	if (ret)
		goto unshare_vcpu;

	ret = attach_pkvm_vcpu_to_vm(pkvm_vm, pkvm_vcpu);
	if (ret < 0)
		goto destroy_vcpu;

	pkvm_put_vm(pkvm_vm);

	return pkvm_vcpu->vcpu.arch.pkvm_vcpu_handle;

destroy_vcpu:
	__vcpu_free(&pkvm_vcpu->vcpu, NULL);
unshare_vcpu:
	pkvm_host_unshare_hyp(host_vcpu_pa, kvm_vcpu_sz);
undonate_fps:
	pkvm_hyp_donate_host(__pkvm_pa(fps), fps_size, false);
undonate_vcpu:
	pkvm_hyp_donate_host(__pkvm_pa(pkvm_vcpu), vcpu_size, false);
put_vm:
	pkvm_put_vm(pkvm_vm);
	return ret;
}

static int __pkvm_vcpu_free(struct pkvm_vm *pkvm_vm, int vcpu_handle, struct pkvm_memcache *mc)
{
	struct pkvm_vcpu *pkvm_vcpu = detach_pkvm_vcpu_from_vm(pkvm_vm, vcpu_handle);
	struct fpstate *fps;

	if (!pkvm_vcpu)
		return -EINVAL;

	__vcpu_free(&pkvm_vcpu->vcpu, mc);

	pkvm_host_unshare_hyp(__pkvm_pa(pkvm_vcpu->shared_vcpu), kvm_vcpu_sz);

	fps = pkvm_vcpu->vcpu.arch.guest_fpu.fpstate;
	teardown_donated_memory(mc, fps, fps->size);
	teardown_donated_memory(mc, pkvm_vcpu, pkvm_vcpu->size);

	return 0;
}

static int pkvm_vcpu_free(int vm_handle, int vcpu_handle, struct pkvm_memcache *mc)
{
	struct pkvm_vm *pkvm_vm;
	int ret;

	if (vcpu_handle < 0 || vcpu_handle >= KVM_MAX_VCPUS)
		return -EINVAL;

	pkvm_vm = pkvm_get_vm(vm_handle);
	if (!pkvm_vm)
		return -EINVAL;

	ret = __pkvm_vcpu_free(pkvm_vm, array_index_nospec(vcpu_handle, KVM_MAX_VCPUS), mc);

	pkvm_put_vm(pkvm_vm);
	return ret;
}

static struct kvm_vcpu *load_kvm_vcpu(struct kvm_vcpu *vcpu)
{
	if (!vcpu || vcpu->cpu != raw_smp_processor_id())
		return NULL;

	kvm_x86_call(vcpu_load)(vcpu, raw_smp_processor_id());

	return vcpu;
}

static void switch_to_host_vcpu(void)
{
	BUG_ON(!load_kvm_vcpu(this_cpu_read(host_vcpu)));
}

static struct kvm_vcpu *switch_to_cur_guest_vcpu(void)
{
	return load_kvm_vcpu(this_cpu_read(cur_guest_vcpu));
}

static int pkvm_vcpu_load(int vm_handle, int vcpu_handle)
{
	struct pkvm_vcpu *pkvm_vcpu = pkvm_get_vcpu(vm_handle, vcpu_handle);
	int cpu = raw_smp_processor_id();
	struct kvm_vcpu *vcpu;
	int loaded_cpu;
	int ret = 0;

	if (!pkvm_vcpu)
		return -EINVAL;

	vcpu = &pkvm_vcpu->vcpu;
	loaded_cpu = cmpxchg(&vcpu->cpu, -1, cpu);
	if (loaded_cpu == -1) {
		/*
		 * Get the pkvm_vcpu to prevent it from being freed via the
		 * vcpu_free PV interface while it is still loaded. If the
		 * obtained pkvm_vcpu is not the same as the original one, it
		 * must be a pkvm bug.
		 */
		BUG_ON(pkvm_vcpu != pkvm_get_vcpu(vm_handle, vcpu_handle));

		kvm_x86_call(vcpu_load)(vcpu, cpu);

		this_cpu_write(cur_guest_vcpu, vcpu);

		/* Switch to host vCPU as a guest vCPU was just loaded. */
		switch_to_host_vcpu();
	} else if (loaded_cpu == cpu) {
		/* The guest vCPU was already loaded on this CPU. */
		this_cpu_write(cur_guest_vcpu, vcpu);
	} else {
		/* The guest vCPU was already loaded on another CPU. */
		ret = -EBUSY;
	}

	pkvm_put_vcpu(pkvm_vcpu);

	return ret;
}

static int pkvm_vcpu_put(int vm_handle, int vcpu_handle)
{
	struct pkvm_vcpu *pkvm_vcpu = pkvm_get_vcpu(vm_handle, vcpu_handle);
	int cpu = raw_smp_processor_id(), loaded_cpu, ret = 0;
	struct kvm_vcpu *vcpu;

	if (!pkvm_vcpu)
		return -EINVAL;

	vcpu = &pkvm_vcpu->vcpu;
	loaded_cpu = cmpxchg(&vcpu->cpu, cpu, -1);
	if (loaded_cpu == cpu) {
		/*
		 * The current active vCPU is the host vCPU. Switch to the guest
		 * vCPU in case vcpu_put operation requires.
		 */
		kvm_x86_call(vcpu_load)(vcpu, cpu);

		/*
		 * Another guest vCPU may have already been loaded on this CPU
		 * thus the cur_guest_vcpu may be overridden. So only set the
		 * cur_guest_vcpu as NULL if it points to the guest vCPU being
		 * put.
		 */
		if (vcpu == this_cpu_read(cur_guest_vcpu))
			this_cpu_write(cur_guest_vcpu, NULL);

		kvm_x86_call(vcpu_put)(vcpu);

		/*
		 * Put this pkvm_vcpu to allow it to be freed via the vcpu_free PV
		 * interface.
		 */
		pkvm_put_vcpu(pkvm_vcpu);

		/* Switch to the host vCPU as a guest vCPU was just loaded. */
		switch_to_host_vcpu();
	} else if (loaded_cpu != -1) {
		/* The guest vCPU was not loaded on this CPU. */
		ret = -EBUSY;
	}

	pkvm_put_vcpu(pkvm_vcpu);

	return ret;
}

static bool is_kvm_vcpu_accessible(struct kvm_vcpu *vcpu, unsigned long fn)
{
	/*
	 * There is no isolation between non-protected VMs and the host, thus
	 * it is not necessary to audit any PV interfaces for an npVM.
	 */
	if (!pkvm_is_protected_vcpu(vcpu))
		return true;

	switch (fn) {
	case __pkvm__update_exception_bitmap:
	case __pkvm__set_efer:
	case __pkvm__set_msr:
	case __pkvm__get_msr:
	case __pkvm__cache_reg:
	case __pkvm__set_cr4:
	case __pkvm__post_set_cr3:
	case __pkvm__set_cr0:
	case __pkvm__set_rflags:
	case __pkvm__get_rflags:
	case __pkvm__set_dr7:
	case __pkvm__vcpu_reset:
	case __pkvm__set_segment:
	case __pkvm__get_segment:
	case __pkvm__get_segment_base:
	case __pkvm__set_idt:
	case __pkvm__get_idt:
	case __pkvm__set_gdt:
	case __pkvm__get_gdt:
	case __pkvm__flush_tlb_all:
	case __pkvm__flush_tlb_current:
	case __pkvm__flush_tlb_gva:
	case __pkvm__flush_tlb_guest:
	case __pkvm__set_interrupt_shadow:
	case __pkvm__get_interrupt_shadow:
	case __pkvm__set_nmi_mask:
		/*
		 * As the host needs to pre-configure the pVM's vCPU state for
		 * booting, the protection for pVM is only enforced by the pKVM
		 * hypervisor once the vCPU has started running.
		 */
		return !kvm_vcpu_has_run(vcpu);
	default:
		break;
	}

	return true;
}

static void pkvm_update_exception_bitmap(struct pkvm_vcpu *pkvm_vcpu)
{
	struct kvm_vcpu *vcpu;

	vcpu = &pkvm_vcpu->vcpu;

	/*
	 * The guest_debug will impact what exceptions should be intercepted
	 * for the debugging purpose. Debugging npVMs from the host side is
	 * allowed thus updating its guest_debug flags accordingly, but not
	 * allowed for pVM.
	 */
	if (!pkvm_is_protected_vcpu(vcpu))
		vcpu->guest_debug = pkvm_vcpu->shared_vcpu->guest_debug;

	kvm_x86_call(update_exception_bitmap)(vcpu);
}

static int pkvm_set_efer(struct pkvm_vcpu *pkvm_vcpu, u64 efer)
{
	return kvm_x86_call(set_efer)(&pkvm_vcpu->vcpu, efer);
}

static int pkvm_set_msr(struct pkvm_vcpu *pkvm_vcpu, u32 index, u64 data)
{
	return kvm_msr_write(&pkvm_vcpu->vcpu, index, data);
}

static int pkvm_get_msr(struct pkvm_vcpu *pkvm_vcpu, struct msr_data *msr)
{
	return kvm_msr_read(&pkvm_vcpu->vcpu, msr->index, &msr->data);
}

static int pkvm_cache_reg(struct pkvm_vcpu *pkvm_vcpu, enum kvm_reg reg,
			  union pkvm_hc_data *out)
{
	struct kvm_vcpu *vcpu = &pkvm_vcpu->vcpu;

	kvm_x86_call(cache_reg)(vcpu, reg);

	switch (reg) {
	case VCPU_REGS_RSP:
		out->rsp = vcpu->arch.regs[VCPU_REGS_RSP];
		break;
	case VCPU_REGS_RIP:
		out->rip = vcpu->arch.regs[VCPU_REGS_RIP];
		break;
	case VCPU_EXREG_PDPTR: {
		struct kvm_mmu *mmu = vcpu->arch.walk_mmu;

		out->pdptrs[0] = mmu->pdptrs[0];
		out->pdptrs[1] = mmu->pdptrs[1];
		out->pdptrs[2] = mmu->pdptrs[2];
		out->pdptrs[3] = mmu->pdptrs[3];
		break;
	}
	case VCPU_EXREG_CR0:
		out->cr0 = vcpu->arch.cr0;
		break;
	case VCPU_EXREG_CR3:
		out->cr3 = vcpu->arch.cr3;
		break;
	case VCPU_EXREG_CR4:
		out->cr4 = vcpu->arch.cr4;
		break;
	default:
		return -EOPNOTSUPP;
	}

	return 0;
}

static void pkvm_set_cr4(struct pkvm_vcpu *pkvm_vcpu, unsigned long cr4)
{
	kvm_x86_call(set_cr4)(&pkvm_vcpu->vcpu, cr4);
}

static void pkvm_post_set_cr3(struct pkvm_vcpu *pkvm_vcpu, unsigned long cr3)
{
	kvm_x86_call(post_set_cr3)(&pkvm_vcpu->vcpu, cr3);
}

static void pkvm_set_cr0(struct pkvm_vcpu *pkvm_vcpu, unsigned long cr0)
{
	kvm_x86_call(set_cr0)(&pkvm_vcpu->vcpu, cr0);
}

static void pkvm_set_rflags(struct pkvm_vcpu *pkvm_vcpu, unsigned long val)
{
	kvm_x86_call(set_rflags)(&pkvm_vcpu->vcpu, val);
}

static unsigned long pkvm_get_rflags(struct pkvm_vcpu *pkvm_vcpu)
{
	return kvm_x86_call(get_rflags)(&pkvm_vcpu->vcpu);
}

static void pkvm_set_dr7(struct pkvm_vcpu *pkvm_vcpu, unsigned long val)
{
	unsigned long dr7 = val;
	struct kvm_vcpu *vcpu;

	vcpu = &pkvm_vcpu->vcpu;
	kvm_x86_call(set_dr7)(vcpu, dr7);
	vcpu->arch.switch_db_regs &= ~KVM_DEBUGREG_BP_ENABLED;
	if (dr7 & DR7_BP_EN_MASK)
		vcpu->arch.switch_db_regs |= KVM_DEBUGREG_BP_ENABLED;
}

static void pkvm_reset_vcpu(struct pkvm_vcpu *pkvm_vcpu, bool init_event)
{
	kvm_vcpu_reset(&pkvm_vcpu->vcpu, init_event);
}

static void pkvm_set_segment(struct pkvm_vcpu *pkvm_vcpu, struct kvm_segment *var, int seg)
{
	kvm_x86_call(set_segment)(&pkvm_vcpu->vcpu, var, seg);
}

static void pkvm_get_segment(struct pkvm_vcpu *pkvm_vcpu, struct kvm_segment *var, int seg)
{
	kvm_x86_call(get_segment)(&pkvm_vcpu->vcpu, var, seg);
}

static u64 pkvm_get_segment_base(struct pkvm_vcpu *pkvm_vcpu, int seg)
{
	return kvm_x86_call(get_segment_base)(&pkvm_vcpu->vcpu, seg);
}

static void pkvm_access_idt(struct pkvm_vcpu *pkvm_vcpu,
			    struct desc_ptr *desc, bool set)
{
	if (set)
		kvm_x86_call(set_idt)(&pkvm_vcpu->vcpu, desc);
	else
		kvm_x86_call(get_idt)(&pkvm_vcpu->vcpu, desc);
}

static void pkvm_access_gdt(struct pkvm_vcpu *pkvm_vcpu,
			    struct desc_ptr *desc, bool set)
{
	if (set)
		kvm_x86_call(set_gdt)(&pkvm_vcpu->vcpu, desc);
	else
		kvm_x86_call(get_gdt)(&pkvm_vcpu->vcpu, desc);
}

static void pkvm_flush_tlb_all(struct pkvm_vcpu *pkvm_vcpu)
{
	kvm_x86_call(flush_tlb_all)(&pkvm_vcpu->vcpu);
}

static void pkvm_flush_tlb_current(struct pkvm_vcpu *pkvm_vcpu)
{
	kvm_x86_call(flush_tlb_current)(&pkvm_vcpu->vcpu);
}

static void pkvm_flush_tlb_gva(struct pkvm_vcpu *pkvm_vcpu, gva_t addr)
{
	kvm_x86_call(flush_tlb_gva)(&pkvm_vcpu->vcpu, addr);
}

static void pkvm_flush_tlb_guest(struct pkvm_vcpu *pkvm_vcpu)
{
	kvm_x86_call(flush_tlb_guest)(&pkvm_vcpu->vcpu);
}

static void pkvm_set_interrupt_shadow(struct pkvm_vcpu *pkvm_vcpu, int mask)
{
	kvm_x86_call(set_interrupt_shadow)(&pkvm_vcpu->vcpu, mask);
}

static u32 pkvm_get_interrupt_shadow(struct pkvm_vcpu *pkvm_vcpu)
{
	return kvm_x86_call(get_interrupt_shadow)(&pkvm_vcpu->vcpu);
}

static void pkvm_enable_nmi_window(struct pkvm_vcpu *pkvm_vcpu)
{
	kvm_x86_call(enable_nmi_window)(&pkvm_vcpu->vcpu);
}

static void pkvm_enable_irq_window(struct pkvm_vcpu *pkvm_vcpu)
{
	kvm_x86_call(enable_irq_window)(&pkvm_vcpu->vcpu);
}

static int __pkvm_interrupt_allowed(struct pkvm_vcpu *pkvm_vcpu, bool for_injection)
{
	struct kvm_vcpu *vcpu = &pkvm_vcpu->vcpu;

	if (!for_injection ||
	    (!kvm_event_needs_reinjection(vcpu) &&
	     !vcpu->arch.exception.pending))
		return kvm_x86_call(interrupt_allowed)(vcpu, for_injection);

	return -EBUSY;
}

static int pkvm_interrupt_allowed(struct pkvm_vcpu *pkvm_vcpu, bool for_injection)
{
	return __pkvm_interrupt_allowed(pkvm_vcpu, for_injection);
}

static int __pkvm_nmi_allowed(struct pkvm_vcpu *pkvm_vcpu, bool for_injection)
{
	struct kvm_vcpu *vcpu = &pkvm_vcpu->vcpu;

	if (!for_injection ||
	    (!kvm_event_needs_reinjection(vcpu) &&
	     !vcpu->arch.exception.pending))
		return kvm_x86_call(nmi_allowed)(vcpu, for_injection);

	return -EBUSY;
}

static int pkvm_nmi_allowed(struct pkvm_vcpu *pkvm_vcpu, bool for_injection)
{
	return __pkvm_nmi_allowed(pkvm_vcpu, for_injection);
}

static bool pkvm_get_nmi_mask(struct pkvm_vcpu *pkvm_vcpu)
{
	return kvm_x86_call(get_nmi_mask)(&pkvm_vcpu->vcpu);
}

static void pkvm_set_nmi_mask(struct pkvm_vcpu *pkvm_vcpu, bool masked)
{
	kvm_x86_call(set_nmi_mask)(&pkvm_vcpu->vcpu, masked);
}

static void pkvm_inject_irq(struct pkvm_vcpu *pkvm_vcpu)
{
	struct kvm_vcpu *vcpu = &pkvm_vcpu->vcpu;

	if (WARN_ON_ONCE(__pkvm_interrupt_allowed(pkvm_vcpu, true) <= 0))
		return;

	vcpu->arch.interrupt.soft = pkvm_vcpu->shared_vcpu->arch.interrupt.soft;
	vcpu->arch.interrupt.nr = pkvm_vcpu->shared_vcpu->arch.interrupt.nr;
	kvm_x86_call(inject_irq)(vcpu, false);
}

static void pkvm_inject_nmi(struct pkvm_vcpu *pkvm_vcpu)
{
	if (WARN_ON_ONCE(__pkvm_nmi_allowed(pkvm_vcpu, true) <= 0))
		return;

	kvm_x86_call(inject_nmi)(&pkvm_vcpu->vcpu);
}

static void pkvm_inject_exception(struct pkvm_vcpu *pkvm_vcpu)
{
	struct kvm_vcpu *vcpu = &pkvm_vcpu->vcpu;

	if (WARN_ON_ONCE(pkvm_is_protected_vcpu(vcpu)))
		return;

	vcpu->arch.exception = pkvm_vcpu->shared_vcpu->arch.exception;
	kvm_x86_call(inject_exception)(vcpu);
}

static void pkvm_cancel_injection(struct pkvm_vcpu *pkvm_vcpu)
{
	struct kvm_vcpu *vcpu, *shared_vcpu;

	vcpu = &pkvm_vcpu->vcpu;
	kvm_x86_call(cancel_injection)(vcpu);

	shared_vcpu = pkvm_vcpu->shared_vcpu;
	if (vcpu->arch.nmi_injected) {
		shared_vcpu->arch.nmi_injected = true;
		vcpu->arch.nmi_injected = false;
	} else if (vcpu->arch.interrupt.injected) {
		kvm_queue_interrupt(shared_vcpu, vcpu->arch.interrupt.nr,
				    vcpu->arch.interrupt.soft);
		kvm_clear_interrupt_queue(vcpu);
	} else if (!pkvm_is_protected_vcpu(vcpu) && vcpu->arch.exception.injected) {
		/*
		 * For the pVM, the exception can only be injected and canceled
		 * by the pkvm hypervisor.
		 * For the npVM, the exception can be injected and caceled by
		 * both sides.
		 */
		shared_vcpu->arch.exception = vcpu->arch.exception;
		kvm_clear_exception_queue(vcpu);
	}
}

static void pkvm_update_cr8_intercept(struct pkvm_vcpu *pkvm_vcpu, int tpr, int irr)
{
	kvm_x86_call(update_cr8_intercept)(&pkvm_vcpu->vcpu, tpr, irr);
}

static int pkvm_vcpu_handle_host_hypercall(unsigned long nr, union pkvm_hc_data *in,
					   union pkvm_hc_data *out)
{
	struct pkvm_vcpu *pkvm_vcpu;
	struct kvm_vcpu *vcpu;
	int ret = 0;

	vcpu = switch_to_cur_guest_vcpu();
	if (!vcpu)
		return -EINVAL;

	if (!is_kvm_vcpu_accessible(vcpu, nr)) {
		ret = -EPERM;
		goto out;
	}

	pkvm_vcpu = to_pkvm_vcpu(vcpu);
	switch (nr) {
	case __pkvm__update_exception_bitmap:
		pkvm_update_exception_bitmap(pkvm_vcpu);
		break;
	case __pkvm__set_efer:
		ret = pkvm_set_efer(pkvm_vcpu, (u64)in->val1);
		break;
	case __pkvm__set_msr:
		ret = pkvm_set_msr(pkvm_vcpu, (u32)in->val1, (u64)in->val2);
		break;
	case __pkvm__get_msr:
		ret = pkvm_get_msr(pkvm_vcpu, &in->msr);
		out->msr.data = in->msr.data;
		break;
	case __pkvm__cache_reg:
		ret = pkvm_cache_reg(pkvm_vcpu, (enum kvm_reg)in->val1, out);
		break;
	case __pkvm__set_cr4:
		pkvm_set_cr4(pkvm_vcpu, (unsigned long)in->val1);
		break;
	case __pkvm__post_set_cr3:
		pkvm_post_set_cr3(pkvm_vcpu, in->val1);
		break;
	case __pkvm__set_cr0:
		pkvm_set_cr0(pkvm_vcpu, (unsigned long)in->val1);
		break;
	case __pkvm__set_rflags:
		pkvm_set_rflags(pkvm_vcpu, in->val1);
		break;
	case __pkvm__get_rflags:
		out->rflags = pkvm_get_rflags(pkvm_vcpu);
		break;
	case __pkvm__set_dr7:
		pkvm_set_dr7(pkvm_vcpu, in->val1);
		break;
	case __pkvm__vcpu_reset:
		pkvm_reset_vcpu(pkvm_vcpu, (bool)in->val1);
		break;
	case __pkvm__set_segment:
		pkvm_set_segment(pkvm_vcpu, &in->seg_val, in->seg);
		break;
	case __pkvm__get_segment:
		pkvm_get_segment(pkvm_vcpu, &out->seg_val, in->seg);
		break;
	case __pkvm__get_segment_base:
		out->seg_val.base = pkvm_get_segment_base(pkvm_vcpu, in->seg);
		break;
	case __pkvm__set_idt:
		pkvm_access_idt(pkvm_vcpu, &in->desc, true);
		break;
	case __pkvm__get_idt:
		pkvm_access_idt(pkvm_vcpu, &out->desc, false);
		break;
	case __pkvm__set_gdt:
		pkvm_access_gdt(pkvm_vcpu, &in->desc, true);
		break;
	case __pkvm__get_gdt:
		pkvm_access_gdt(pkvm_vcpu, &out->desc, false);
		break;
	case __pkvm__flush_tlb_all:
		pkvm_flush_tlb_all(pkvm_vcpu);
		break;
	case __pkvm__flush_tlb_current:
		pkvm_flush_tlb_current(pkvm_vcpu);
		break;
	case __pkvm__flush_tlb_gva:
		pkvm_flush_tlb_gva(pkvm_vcpu, (gva_t)in->val1);
		break;
	case __pkvm__flush_tlb_guest:
		pkvm_flush_tlb_guest(pkvm_vcpu);
		break;
	case __pkvm__set_interrupt_shadow:
		pkvm_set_interrupt_shadow(pkvm_vcpu, (int)in->val1);
		break;
	case __pkvm__get_interrupt_shadow:
		out->intr_shadow = pkvm_get_interrupt_shadow(pkvm_vcpu);
		break;
	case __pkvm__enable_nmi_window:
		pkvm_enable_nmi_window(pkvm_vcpu);
		break;
	case __pkvm__enable_irq_window:
		pkvm_enable_irq_window(pkvm_vcpu);
		break;
	case __pkvm__interrupt_allowed:
		ret = pkvm_interrupt_allowed(pkvm_vcpu, (bool)in->val1);
		break;
	case __pkvm__nmi_allowed:
		ret = pkvm_nmi_allowed(pkvm_vcpu, (bool)in->val1);
		break;
	case __pkvm__get_nmi_mask:
		out->nmi_mask = pkvm_get_nmi_mask(pkvm_vcpu);
		break;
	case __pkvm__set_nmi_mask:
		pkvm_set_nmi_mask(pkvm_vcpu, (bool)in->val1);
		break;
	case __pkvm__inject_irq:
		pkvm_inject_irq(pkvm_vcpu);
		break;
	case __pkvm__inject_nmi:
		pkvm_inject_nmi(pkvm_vcpu);
		break;
	case __pkvm__inject_exception:
		pkvm_inject_exception(pkvm_vcpu);
		break;
	case __pkvm__cancel_injection:
		pkvm_cancel_injection(pkvm_vcpu);
		break;
	case __pkvm__update_cr8_intercept:
		pkvm_update_cr8_intercept(pkvm_vcpu, (int)in->val1, (int)in->val2);
		break;
	default:
		ret = -EINVAL;
		break;
	}

out:
	switch_to_host_vcpu();
	return ret;
}

int pkvm_handle_host_hypercall(unsigned long nr, union pkvm_hc_data *in,
			       union pkvm_hc_data *out)
{
	int ret = 0;

	switch (nr) {
	case __pkvm__init_finalize:
		ret = pkvm_init_finalize((struct pkvm_mem_info *)in->val1, in->val2,
					 (struct pkvm_init_ops *)in->val3);
		break;
	case __pkvm__enable_vmexit_trace:
		pkvm_enable_vmexit_trace(in->val1);
		break;
	case __pkvm__dump_vmexit_trace:
		ret = pkvm_dump_vmexit_trace(pkvm_host_gpa_to_phys(in->val1), in->val2);
		break;
	case __pkvm__check_processor_compatibility:
		ret = kvm_x86_call(check_processor_compatibility)();
		break;
	case __pkvm__enable_virtualization_cpu:
		ret = pkvm_enable_virtualization_cpu();
		break;
	case __pkvm__vm_init:
		ret = pkvm_vm_init(pkvm_host_gpa_to_phys(in->val1),
				   pkvm_host_gpa_to_phys(in->val2));
		break;
	case __pkvm__vm_destroy:
		pkvm_vm_destroy(in->vm_handle, &out->memcache);
		break;
	case __pkvm__vcpu_create:
		ret = pkvm_vcpu_create(in->val1, pkvm_host_gpa_to_phys(in->val2),
				       pkvm_host_gpa_to_phys(in->val3),
				       pkvm_host_gpa_to_phys(in->val4));
		break;
	case __pkvm__vcpu_free:
		ret = pkvm_vcpu_free(in->vm_handle, in->vcpu_handle, &out->memcache);
		break;
	case __pkvm__vcpu_load:
		ret = pkvm_vcpu_load((int)in->val1, (int)in->val2);
		break;
	case __pkvm__vcpu_put:
		ret = pkvm_vcpu_put((int)in->val1, (int)in->val2);
		break;
	default:
		ret = pkvm_vcpu_handle_host_hypercall(nr, in, out);
		break;
	}

	return ret;
}

void pkvm_kick_vcpu(struct kvm_vcpu *vcpu)
{
	/* No need to kick if a vcpu is already out of guest mode */
	if (kvm_vcpu_exiting_guest_mode(vcpu) != IN_GUEST_MODE)
		return;

	pkvm_lapic_send_init(READ_ONCE(vcpu->cpu));
}

int pkvm_x86_vendor_init(struct kvm_x86_init_ops *ops)
{
	int r;

	memset(&kvm_caps, 0, sizeof(kvm_caps));

	kvm_caps.supported_vm_types = BIT(KVM_X86_DEFAULT_VM) |
				      BIT(KVM_X86_PKVM_PROTECTED_VM);
	kvm_caps.supported_mce_cap = MCG_CTL_P | MCG_SER_P;

	if (boot_cpu_has(X86_FEATURE_XSAVE)) {
		kvm_host.xcr0 = xgetbv(XCR_XFEATURE_ENABLED_MASK);
		kvm_caps.supported_xcr0 = kvm_host.xcr0 & KVM_SUPPORTED_XCR0;
	}

	if (boot_cpu_has(X86_FEATURE_XSAVES)) {
		rdmsrq(MSR_IA32_XSS, kvm_host.xss);
		kvm_caps.supported_xss = kvm_host.xss & KVM_SUPPORTED_XSS;
	}

	rdmsrq_safe(MSR_EFER, &kvm_host.efer);

	if (boot_cpu_has(X86_FEATURE_ARCH_CAPABILITIES))
		rdmsrq(MSR_IA32_ARCH_CAPABILITIES, kvm_host.arch_capabilities);

	r = ops->hardware_setup();
	if (r)
		return r;

	memcpy(&kvm_x86_ops, ops->runtime_ops, sizeof(kvm_x86_ops));

	if (!kvm_cpu_cap_has(X86_FEATURE_XSAVES))
		kvm_caps.supported_xss = 0;

	if (!kvm_cpu_cap_has(X86_FEATURE_SHSTK) &&
	    !kvm_cpu_cap_has(X86_FEATURE_IBT))
		kvm_caps.supported_xss &= ~XFEATURE_MASK_CET_ALL;

	if ((kvm_caps.supported_xss & XFEATURE_MASK_CET_ALL) != XFEATURE_MASK_CET_ALL) {
		kvm_cpu_cap_clear(X86_FEATURE_SHSTK);
		kvm_cpu_cap_clear(X86_FEATURE_IBT);
		kvm_caps.supported_xss &= ~XFEATURE_MASK_CET_ALL;
	}

	return 0;
}

struct pkvm_vm *pkvm_get_vm(int vm_handle)
{
	struct pkvm_vm_ref *pkvm_vm_ref;
	int idx = vm_handle;

	if (idx < 0 || idx >= MAX_PKVM_VMS)
		return NULL;

	idx = array_index_nospec(idx, MAX_PKVM_VMS);
	pkvm_vm_ref = &pkvm_vms_ref[idx];

	return atomic_inc_not_zero(&pkvm_vm_ref->refcount) ? pkvm_vm_ref->pkvm_vm : NULL;
}

void pkvm_put_vm(struct pkvm_vm *pkvm_vm)
{
	int idx = pkvm_vm->kvm.arch.pkvm_vm_handle;
	struct pkvm_vm_ref *pkvm_vm_ref;

	if (idx < 0 || idx >= MAX_PKVM_VMS)
		return;

	pkvm_vm_ref = &pkvm_vms_ref[idx];

	WARN_ON(atomic_dec_if_positive(&pkvm_vm_ref->refcount) <= 0);
}

struct pkvm_vcpu *pkvm_get_vcpu(int vm_handle, int vcpu_handle)
{
	struct pkvm_vm *pkvm_vm;

	if (vcpu_handle < 0 || vcpu_handle >= KVM_MAX_VCPUS)
		return NULL;

	pkvm_vm = pkvm_get_vm(vm_handle);
	if (!pkvm_vm)
		return NULL;

	vcpu_handle = array_index_nospec(vcpu_handle, KVM_MAX_VCPUS);
	if (atomic_inc_not_zero(&pkvm_vm->vcpu_refs[vcpu_handle]))
		return pkvm_vm->vcpus[vcpu_handle];

	pkvm_put_vm(pkvm_vm);
	return NULL;
}

void pkvm_put_vcpu(struct pkvm_vcpu *pkvm_vcpu)
{
	int vcpu_handle = pkvm_vcpu->vcpu.arch.pkvm_vcpu_handle;

	WARN_ON(atomic_dec_if_positive(&pkvm_vcpu->pkvm_vm->vcpu_refs[vcpu_handle]) <= 0);

	pkvm_put_vm(pkvm_vcpu->pkvm_vm);
}

unsigned long pkvm_pcpu_tss(int cpu)
{
#ifdef CONFIG_PKVM_X86_DEBUG
	return (unsigned long)&get_cpu_entry_area(cpu)->tss.x86_tss;
#else
	struct pkvm_pcpu *pcpu = per_cpu(phys_cpu, cpu);

	return (unsigned long)&pcpu->tss;
#endif
}
