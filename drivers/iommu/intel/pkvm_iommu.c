// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright © 2026 Google.
 *
 */

#define pr_fmt(fmt)     "DMAR: pkvm: " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include "iommu.h"
#include "pasid.h"
#include "../iommu-pages.h"

int __init pkvm_host_prepare_iommu(void)
{
	struct dmar_drhd_unit *drhd;
	struct intel_iommu *iommu;
	int ret;

	down_write(&dmar_global_lock);
	ret = dmar_table_init();
	if (ret) {
		pr_err("Failed to initialize DMAR table!\n");
		goto out;
	}

	ret = -ENODEV;
	for_each_iommu(iommu, drhd) {
		unsigned int pgsz_mask = 1 << PG_LEVEL_4K;
		unsigned int pglvl_mask = 0;

		if (drhd->ignored) {
			pr_warn("iommu%d ignored, but pKVM needs iommu to be enabled!\n",
				iommu->seq_id);
			goto out;
		}

		if (readl(iommu->reg + DMAR_GSTS_REG) & DMA_GSTS_TES) {
			pr_warn("iommu%d: Translation enabled before initialization!\n",
					iommu->seq_id);
			goto out;
		}

		/*
		 * Since pKVM is not expected to be supported on ancient hardware which
		 * requires write buffer flushing, require cap_rwbf=0 for simplicity.
		 */
		if (cap_rwbf(iommu->cap)) {
			pr_warn("iommu%d: CAP.RWBF=1 is not supported!\n", iommu->seq_id);
			goto out;
		}

		/* pKVM expects Queued Invalidation support for simplicity and efficiency */
		if (!ecap_qis(iommu->ecap)) {
			pr_warn("iommu%d: queued Invalidation not supported!\n", iommu->seq_id);
			goto out;
		}

		if (cap_sagaw(iommu->cap) & IOMMU_PGT_4LEVEL)
			pglvl_mask |= IOMMU_PGT_4LEVEL;
		if (cap_sagaw(iommu->cap) & IOMMU_PGT_5LEVEL)
			pglvl_mask |= IOMMU_PGT_5LEVEL;

		if (cap_super_page_val(iommu->cap) & BIT(0))
			pgsz_mask |= 1 << PG_LEVEL_2M;
		if (cap_super_page_val(iommu->cap) & BIT(1))
			pgsz_mask |= 1 << PG_LEVEL_1G;

		if (!pglvl_mask) {
			pr_warn("iommu%d: No supported page levels\n", iommu->seq_id);
			goto out;
		}

		pkvm_sym(iommu_pglvl_mask) &= pglvl_mask;
		pkvm_sym(iommu_pgsz_mask) &= pgsz_mask;
	}

	ret = pkvm_scan_satc_devs(pkvm_sym(satc_devs), &pkvm_sym(nr_satc_devs),
				  PKVM_MAX_SATC_DEVS);
	if (ret)
		goto out;

	pkvm_sym(intel_iommu_sm) = intel_iommu_sm;
	pkvm_sym(intel_iommu_superpage) = intel_iommu_superpage;

	for_each_iommu(iommu, drhd) {
		struct intel_iommu_info info = {
			.reg_phys = iommu->reg_phys,
			.reg_size = iommu->reg_size,
			.cap = iommu->cap,
			.ecap = iommu->ecap,
			.seq_id = iommu->seq_id,
			.agaw = iommu->agaw,
			.msagaw = iommu->msagaw,
		};

		ret = pkvm_sym(prepare_iommu)(&info);
		if (ret)
			goto out;
	}
out:
	up_write(&dmar_global_lock);
	return ret;
}

int __init pkvm_host_init_iommu(void)
{
	return intel_iommu_init();
}

int pv_iec_flush(struct intel_iommu *iommu, bool global, int index, int mask)
{
	union pkvm_hc_data d = { 0 };
	struct iommu_hc_data *data = (struct iommu_hc_data *)&d;

	data->iec_flush.phys = iommu->reg_phys;
	data->iec_flush.global = global;
	data->iec_flush.index = index;
	data->iec_flush.mask = mask;
	data->hc_num = iec_flush;
	return pkvm_hypercall_inout(iommu_hypercall, &d, &d);
}

int pv_context_clear(u64 phys, u8 bus, u8 devfn, struct device_domain_info *info)
{
	union pkvm_hc_data d = { 0 };
	struct iommu_hc_data *data = (struct iommu_hc_data *)&d;

	data->clear_ce.phys = phys;
	data->clear_ce.bus = bus;
	data->clear_ce.devfn = devfn;
	data->clear_ce.ats_qdep = info ? info->ats_qdep : 0;
	data->clear_ce.ats_supported = info ? info->ats_supported : 0;
	data->clear_ce.ats_enabled = info ? info->ats_enabled : 0;
	data->hc_num = clear_ce;

	return pkvm_hypercall_inout(iommu_hypercall, &d, &d);
}

int pv_context_mapping(struct intel_iommu *iommu, struct device_domain_info *info,
		       u8 bus, u8 devfn, u64 pgd_gpa, u16 did, u8 agaw)
{
	union pkvm_hc_data d = { 0 };
	struct iommu_hc_data *data = (struct iommu_hc_data *)&d;
	int ret;

	data->set_lm_ce.phys = iommu->reg_phys;
	data->set_lm_ce.pgd_gpa = pgd_gpa;
	data->set_lm_ce.did = did;
	data->set_lm_ce.bus = bus;
	data->set_lm_ce.devfn = devfn;
	data->set_lm_ce.agaw = agaw;
	data->set_lm_ce.ats_qdep = info->ats_qdep;
	data->set_lm_ce.ats_supported = info->ats_supported;
	data->set_lm_ce.ats_enabled = info->ats_enabled;
	data->hc_num = set_lm_ce;

	iommu_lock(iommu);
	ret = pkvm_hypercall_inout(iommu_hypercall, &d, &d);
	if (ret == -ENOMEM) {
		void *ts_page = iommu_alloc_pages_node_sz(iommu->node, GFP_ATOMIC, SZ_4K);

		if (!ts_page) {
			pr_err("iommu%d: failed to allocate context page\n", iommu->seq_id);
			iommu_unlock(iommu);
			return -ENOMEM;
		}
		data->set_lm_ce.ts_page_gpa = virt_to_phys(ts_page);
		ret = pkvm_hypercall_inout(iommu_hypercall, &d, &d);

		/*
		 * If the hypervisor used ts_page_gpa, it will be set to 0.
		 * Free the page if hypervisor didn't use the page.
		 */
		if (data->set_lm_ce.ts_page_gpa)
			iommu_free_pages(phys_to_virt(data->set_lm_ce.ts_page_gpa));
	}
	iommu_unlock(iommu);

	return ret;
}

int pv_pasid_table_setup(struct intel_iommu *iommu, struct device_domain_info *info,
			 u8 bus, u8 devfn)
{
	union pkvm_hc_data d = { 0 };
	struct iommu_hc_data *data = (struct iommu_hc_data *)&d;
	int ret;

	data->set_sm_ce.phys = iommu->reg_phys;
	data->set_sm_ce.pasid_table_gpa = virt_to_phys(info->pasid_table->table);
	data->set_sm_ce.max_pasid = info->pasid_table->max_pasid;
	data->set_sm_ce.bus = bus;
	data->set_sm_ce.devfn = devfn;
	data->set_sm_ce.ats_supported = info->ats_supported;
	data->set_sm_ce.ats_enabled = info->ats_enabled;
	data->set_sm_ce.pasid_supported = info->pasid_supported;
	data->set_sm_ce.pasid_enabled = info->pasid_enabled;
	data->set_sm_ce.ats_qdep = info->ats_qdep;
	data->hc_num = set_sm_ce;

	iommu_lock(iommu);
	ret = pkvm_hypercall_inout(iommu_hypercall, &d, &d);
	if (ret == -ENOMEM) {
		void *context = iommu_alloc_pages_node_sz(iommu->node, GFP_ATOMIC, SZ_4K);

		if (!context) {
			pr_err("iommu%d: failed to allocate context page\n", iommu->seq_id);
			iommu_unlock(iommu);
			return -ENOMEM;
		}
		data->set_sm_ce.ts_page_gpa = virt_to_phys(context);
		ret = pkvm_hypercall_inout(iommu_hypercall, &d, &d);

		if (data->set_sm_ce.ts_page_gpa)
			iommu_free_pages(phys_to_virt(data->set_sm_ce.ts_page_gpa));
	}
	iommu_unlock(iommu);

	return ret;
}

int pv_pasid_setup_fl(struct device_domain_info *info, phys_addr_t fsptptr,
		      u32 pasid, u16 did, u16 old_did, int flags)
{
	union pkvm_hc_data d = { 0 };
	struct iommu_hc_data *data = (struct iommu_hc_data *)&d;
	struct intel_iommu *iommu = info->iommu;
	int ret;

	data->pasid_setup_fl.phys = iommu->reg_phys;
	data->pasid_setup_fl.fsptptr_gpa = fsptptr;
	data->pasid_setup_fl.pasid_dir_gpa = virt_to_phys(info->pasid_table->table);
	data->pasid_setup_fl.pasid = pasid;
	data->pasid_setup_fl.flags = flags;
	data->pasid_setup_fl.did = did;
	data->pasid_setup_fl.old_did = old_did;
	data->pasid_setup_fl.bus = info->bus;
	data->pasid_setup_fl.devfn = info->devfn;
	data->pasid_setup_fl.ats_qdep = info->ats_qdep;
	data->pasid_setup_fl.ats_enabled = info->ats_enabled;
	data->pasid_setup_fl.ats_supported = info->ats_supported;
	data->hc_num = pasid_setup_fl;

	iommu_lock(iommu);
	ret = pkvm_hypercall_inout(iommu_hypercall, &d, &d);
	if (ret == -ENOMEM) {
		void *ts_page = iommu_alloc_pages_node_sz(iommu->node, GFP_ATOMIC, SZ_4K);

		if (!ts_page) {
			pr_err("iommu%d: failed to allocate pasid table page\n", iommu->seq_id);
			iommu_unlock(iommu);
			return -ENOMEM;
		}
		data->pasid_setup_fl.ts_page_gpa = virt_to_phys(ts_page);
		ret = pkvm_hypercall_inout(iommu_hypercall, &d, &d);

		if (data->pasid_setup_fl.ts_page_gpa)
			iommu_free_pages(phys_to_virt(data->pasid_setup_fl.ts_page_gpa));
	}
	iommu_unlock(iommu);

	return ret;
}

int pv_pasid_setup_sl(struct device_domain_info *info, phys_addr_t ssptptr,
		      u8 agaw, u32 pasid, u16 did, u16 old_did)
{
	union pkvm_hc_data d = { 0 };
	struct iommu_hc_data *data = (struct iommu_hc_data *)&d;
	struct intel_iommu *iommu = info->iommu;
	int ret;

	data->pasid_setup_sl.phys = iommu->reg_phys;
	data->pasid_setup_sl.ssptptr_gpa = ssptptr;
	data->pasid_setup_sl.pasid_dir_gpa = virt_to_phys(info->pasid_table->table);
	data->pasid_setup_sl.pasid = pasid;
	data->pasid_setup_sl.did = did;
	data->pasid_setup_sl.old_did = old_did;
	data->pasid_setup_sl.bus = info->bus;
	data->pasid_setup_sl.devfn = info->devfn;
	data->pasid_setup_sl.agaw = agaw;
	data->pasid_setup_sl.ats_qdep = info->ats_qdep;
	data->pasid_setup_sl.ats_supported = info->ats_supported;
	data->pasid_setup_sl.ats_enabled = info->ats_enabled;
	data->hc_num = pasid_setup_sl;

	iommu_lock(iommu);
	ret = pkvm_hypercall_inout(iommu_hypercall, &d, &d);
	if (ret == -ENOMEM) {
		void *ts_page = iommu_alloc_pages_node_sz(iommu->node, GFP_ATOMIC, SZ_4K);

		if (!ts_page) {
			pr_err("iommu%d: failed to allocate pasid table page\n", iommu->seq_id);
			iommu_unlock(iommu);
			return -ENOMEM;
		}
		data->pasid_setup_sl.ts_page_gpa = virt_to_phys(ts_page);
		ret = pkvm_hypercall_inout(iommu_hypercall, &d, &d);

		if (data->pasid_setup_sl.ts_page_gpa)
			iommu_free_pages(phys_to_virt(data->pasid_setup_sl.ts_page_gpa));
	}
	iommu_unlock(iommu);

	return ret;
}

int pv_pasid_teardown(struct device_domain_info *info, u32 pasid)
{
	union pkvm_hc_data d = { 0 };
	struct iommu_hc_data *data = (struct iommu_hc_data *)&d;
	struct intel_iommu *iommu = info->iommu;

	data->pasid_teardown.phys = iommu->reg_phys;
	data->pasid_teardown.pasid = pasid;
	data->pasid_teardown.bus = info->bus;
	data->pasid_teardown.devfn = info->devfn;
	data->pasid_teardown.ats_qdep = info->ats_qdep;
	data->pasid_teardown.ats_enabled = info->ats_enabled;
	data->pasid_teardown.ats_supported = info->ats_supported;
	data->hc_num = pasid_teardown;

	return pkvm_hypercall_inout(iommu_hypercall, &d, &d);
}

int pv_alloc_domain(struct device_domain_info *info, struct dmar_domain *domain)
{
	union pkvm_hc_data d = { 0 };
	struct iommu_hc_data *data = (struct iommu_hc_data *)&d;
	int ret;

	data->alloc_domain.phys = info->iommu->reg_phys;
	data->alloc_domain.bdf = PCI_DEVID(info->bus, info->devfn);
	data->alloc_domain.use_first_level = domain->use_first_level;
	data->alloc_domain.pgd_gpa = virt_to_phys(domain->pgd);
	data->alloc_domain.gaw = domain->gaw;
	data->alloc_domain.agaw = domain->agaw;
	data->alloc_domain.max_addr = domain->max_addr;
	data->alloc_domain.iommu_coherency = domain->iommu_coherency;
	data->alloc_domain.iommu_superpage = domain->iommu_superpage;
	data->hc_num = alloc_domain;

	ret = pkvm_hypercall_inout(iommu_hypercall, &d, &d);
	if (ret)
		pr_err("%s: pkvm failed to alloc domain for device[%x:%x.%x] (err=%d)\n", __func__,
		       info->bus, PCI_SLOT(info->devfn), PCI_FUNC(info->devfn), ret);

	return ret;
}

static phys_addr_t host_pa(void *addr)
{
	return __pa(addr);
}

static void *host_va(phys_addr_t phys)
{
	return __va(phys);
}

static int fill_domain_memcache(struct pkvm_memcache *mc, unsigned long nr_pages,
				int nid, gfp_t gfp)
{
	while (mc->count < nr_pages) {
		phys_addr_t *p = iommu_alloc_pages_node_sz(nid, gfp, SZ_4K);

		if (!p)
			return -ENOMEM;

		push_pkvm_memcache(mc, p, PAGE_SIZE, host_pa);
	}

	return 0;
}

static void free_domain_memcache(struct pkvm_memcache *mc)
{
	while (mc->count) {
		struct pkvm_page_range page_range;

		page_range = pop_pkvm_memcache(mc, host_va);
		iommu_free_pages(__va(page_range.addr));
	}
}

int pv_free_domain(struct dmar_domain *domain)
{
	union pkvm_hc_data d = { 0 };
	struct iommu_hc_data *data = (struct iommu_hc_data *)&d;
	int ret;

	data->free_domain.pgd_gpa = virt_to_phys(domain->pgd);
	data->hc_num = free_domain;
	ret = pkvm_hypercall_inout(iommu_hypercall, &d, &d);
	free_domain_memcache(&data->free_domain.mc);
	return ret;
}

int pv_domain_mapping(struct dmar_domain *domain, unsigned long iov_pfn,
		      unsigned long phys_pfn, unsigned long nr_pages,
		      int prot, int gfp)
{
	union pkvm_hc_data d = { 0 };
	struct domain_map_data *data = (struct domain_map_data *)&d;
	int ret;

	data->pgd_gpa = virt_to_phys(domain->pgd),
	data->iov_pfn = iov_pfn,
	data->phys_pfn = phys_pfn,
	data->nr_pages = nr_pages,
	data->prot = prot,

	ret = pkvm_hypercall_inout(iommu_domain_map, &d, &d);
	if (ret == -ENOMEM) {
		ret = fill_domain_memcache(&data->mc,
					   __pkvm_pgtable_max_pages(nr_pages),
					  domain->nid, gfp);
		if (ret) {
			pr_err("%s: failed to allocate memcache pages(err=%d)\n",
			       __func__, ret);
			return ret;
		}
		ret = pkvm_hypercall_inout(iommu_domain_map, &d, &d);
	}
	if (ret) {
		pr_err("%s: domain map[iov_pfn: %lx, pfn: %lx, nr_pages: %lu] failed (err=%d)\n",
		       __func__, iov_pfn, phys_pfn, nr_pages, ret);

		/*
		 * pKVM would not have drained the memcache on
		 * hypercall failure. Free it if not empty.
		 */
		free_domain_memcache(&data->mc);
	}
	domain->has_mappings = true;
	return ret;
}

int pv_domain_unmapping(struct dmar_domain *domain, unsigned long start_pfn,
			unsigned long last_pfn)
{
	int ret = pkvm_hypercall(iommu_domain_unmap, virt_to_phys(domain->pgd),
				 start_pfn, last_pfn);

	if (ret)
		pr_err("%s: domain unmap[start_pfn: %lx, last_pfn: %lx failed (err=%d)\n",
		       __func__, start_pfn, last_pfn, ret);
	return ret;
}
