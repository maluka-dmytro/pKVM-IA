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

int pv_qi_submit_sync(struct intel_iommu *iommu, struct qi_desc *desc,
		      unsigned int count, unsigned long options)
{
	union pkvm_hc_data d = { 0 };
	struct iommu_hc_data *data = (struct iommu_hc_data *)&d;
	struct qi_desc *desc_ptr;
	int ret;

	desc_ptr = kcalloc(count, sizeof(struct qi_desc), GFP_ATOMIC);
	if (!desc_ptr)
		return -ENOMEM;

	memcpy(desc_ptr, desc, count * sizeof(struct qi_desc));
	data->qi_submit.desc_gpa = virt_to_phys(desc_ptr);
	data->qi_submit.phys = iommu->reg_phys;
	data->qi_submit.count = count;
	data->qi_submit.options = options;
	data->hc_num = qi_submit;

	ret = pkvm_hypercall_inout(iommu_hypercall, &d, &d);
	kfree(desc_ptr);
	return ret;
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
