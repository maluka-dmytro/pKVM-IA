// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright © 2026 Google.
 *
 */
#include <asm/kvm_pkvm.h>
#include <linux/pci.h>
#include "pkvm/mmu.h"
#include "pkvm/vmx/ept.h"
#include "pkvm/memory.h"
#include "pkvm/pkvm.h"
#include "pkvm/debug.h"
#include "iommu_hc.h"
#include "../iommu.h"

int pkvm_iommu_qi_submit(struct qi_submit_data *data)
{
	struct intel_iommu *iommu = iommu_from_phys(data->phys);

	if (!iommu)
		return -EINVAL;

	BUG_ON(!iommu->qi);

	return qi_submit_sync(iommu, pkvm_host_gpa_to_virt(data->desc_gpa),
			      data->count, data->options);
}

int pkvm_iommu_clear_ce(struct clear_ce_data *data)
{
	struct intel_iommu *iommu = iommu_from_phys(data->phys);
	u16 bdf = PCI_DEVID(data->bus, data->devfn);
	struct device_domain_info info;

	if (!iommu)
		return -EINVAL;

	if (data->ats_qdep > PCI_ATS_MAX_QDEP)
		return -EINVAL;

	if (is_dev_in_satc(bdf)) {
		/*
		 * Device is in SATC and optimistically assuming that a well crafted SATC
		 * would contain only physical functions, its safe to set pfsid = bdf.
		 * TODO: We should probably be verifying SATC for existence of only
		 * physical functions during pkvm initialization.
		 */
		if (ecap_dit(iommu->ecap))
			info.pfsid = bdf;
	} else if (data->ats_enabled || data->ats_supported) {
		return -EPERM;
	}

	info.iommu = iommu;
	info.bus = data->bus;
	info.devfn = data->devfn;
	info.ats_qdep = data->ats_qdep;
	info.ats_supported = data->ats_supported;
	info.ats_enabled = data->ats_enabled;

	pkvm_dbg("%s: dev[%x:%x], ats_qdep: %d\n",
		 __func__, data->bus, data->devfn, data->ats_qdep);
	domain_context_clear_one(&info, data->bus, data->devfn);

	return 0;
}

static int accept_ts_page_donation(struct intel_iommu *iommu, u64 *ts_page_gpa)
{
	iommu_lock(iommu);
	if (*ts_page_gpa && !iommu->ts_page) {
		u64 ts_page = pkvm_host_gpa_to_phys(*ts_page_gpa);
		int ret = pkvm_host_donate_hyp_share_ro(ts_page, VTD_PAGE_SIZE, true);

		if (ret) {
			iommu_unlock(iommu);
			pkvm_err("iommu%d: failed to write protect translation structure page(err=%d)!\n",
				 iommu->seq_id, ret);
			return ret;
		}
		iommu->ts_page = __pkvm_va(ts_page);
		*ts_page_gpa = 0ULL;
	}
	iommu_unlock(iommu);

	return 0;
}

int pkvm_iommu_set_lm_ce(struct set_lm_ce_data *data)
{
	struct intel_iommu *iommu = iommu_from_phys(data->phys);
	u16 bdf = PCI_DEVID(data->bus, data->devfn);
	struct device_domain_info info = { 0 };
	struct dmar_domain domain = { 0 };
	int ret;

	if (!iommu)
		return -EINVAL;

	if (data->ats_qdep > PCI_ATS_MAX_QDEP)
		return -EINVAL;

	if (is_dev_in_satc(bdf)) {
		if (ecap_dit(iommu->ecap))
			info.pfsid = bdf;
	} else if (data->ats_enabled || data->ats_supported) {
		return -EPERM;
	}

	info.bus = data->bus;
	info.devfn = data->devfn;
	info.iommu = iommu;
	if (data->did == FLPT_DEFAULT_DID) {
		/*
		 * Passthrough will break pkvm security guarantees as
		 * device would be able to access the whole physical
		 * memory range. Use Second stage translation with host ept
		 * as second stage pagetable so as to limit device access
		 * to host memory.
		 */
		domain.pgd = __pkvm_va(pkvm_host_ept_root());
		domain.agaw = level_to_agaw(pkvm_host_ept_level());
		info.ats_qdep = 0;
		info.ats_supported = 0;
		info.ats_enabled = 0;
	} else {
		if (data->agaw != iommu->agaw)
			return -EINVAL;

		domain.pgd = pkvm_host_gpa_to_virt(data->pgd_gpa);
		domain.agaw = data->agaw;
		info.ats_qdep = data->ats_qdep;
		info.ats_supported = data->ats_supported;
		info.ats_enabled = data->ats_enabled;
	}

	ret = accept_ts_page_donation(iommu, &data->ts_page_gpa);
	if (ret)
		return ret;

	pkvm_dbg("%s: dev[%x:%x], did: %d, pgd: %p, agaw: %d\n", __func__,
		 data->bus, data->devfn, data->did, domain.pgd, domain.agaw);
	return domain_context_mapping_one(&domain, iommu, &info, data->did,
					  data->bus, data->devfn);
}
