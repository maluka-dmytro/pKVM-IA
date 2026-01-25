/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright © 2026 Google
 */

#ifndef _PKVM_INTEL_IOMMU_HC_H_
#define _PKVM_INTEL_IOMMU_HC_H_

#include <asm/kvm_pkvm.h>

enum iommu_hc_num {
	qi_submit,
	clear_ce,
	set_lm_ce,
};

struct qi_submit_data {
	u64 phys;
	u64 desc_gpa;
	u32 options;
	u32 count;
};

struct clear_ce_data {
	u64 phys;
	u8 bus;
	u8 devfn;
	u8 ats_qdep;
	u8 ats_enabled: 1;
	u8 ats_supported: 1;
};

struct set_lm_ce_data {
	u64 phys;
	u64 pgd_gpa;
	u64 ts_page_gpa;
	u16 did;
	u8 bus;
	u8 devfn;
	u8 agaw;
	u8 ats_qdep;
	u8 ats_enabled: 1;
	u8 ats_supported: 1;
};

struct iommu_hc_data {
	union {
		struct qi_submit_data qi_submit;
		struct clear_ce_data clear_ce;
		struct set_lm_ce_data set_lm_ce;
	};
	u8 hc_num;
};
static_assert(sizeof(struct iommu_hc_data) <= PKVM_HC_DATA_MAX_NUM * sizeof(u64));

int pkvm_iommu_qi_submit(struct qi_submit_data *data);
int pkvm_iommu_clear_ce(struct clear_ce_data *data);
int pkvm_iommu_set_lm_ce(struct set_lm_ce_data *data);
#endif /* _PKVM_INTEL_IOMMU_HC_H_ */
