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
	set_sm_ce,
	pasid_setup_fl,
	pasid_setup_sl,
	pasid_teardown,
	alloc_domain,
	free_domain,
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

struct set_sm_ce_data {
	u64 phys;
	u64 pasid_table_gpa;
	u64 ts_page_gpa;
	u32 max_pasid;
	u8 bus;
	u8 devfn;
	u8 ats_qdep;
	u8 ats_enabled: 1;
	u8 ats_supported: 1;
	u8 pasid_supported: 3;
	u8 pasid_enabled: 1;
};

struct pasid_setup_fl_data {
	u64 phys;
	u64 fsptptr_gpa;
	u64 pasid_dir_gpa;
	u64 ts_page_gpa;
	u32 pasid;
	u32 flags;
	u16 did;
	u16 old_did; /* replace_fl */
	u8 bus;
	u8 devfn;
	u8 ats_qdep;
	u8 ats_enabled: 1;
	u8 ats_supported: 1;
};

struct pasid_setup_sl_data {
	u64 phys;
	u64 ssptptr_gpa;
	u64 pasid_dir_gpa;
	u64 ts_page_gpa;
	u32 pasid;
	u16 did;
	u16 old_did; /* replace_sl */
	u8 bus;
	u8 devfn;
	u8 agaw;
	u8 ats_qdep;
	u8 ats_enabled: 1;
	u8 ats_supported: 1;
};

struct pasid_teardown_data {
	u64 phys;
	u32 pasid;
	u8 bus;
	u8 devfn;
	u8 ats_qdep;
	u8 ats_enabled: 1;
	u8 ats_supported: 1;
};

struct alloc_domain_data {
	u64 phys;
	u64 max_addr;
	u64 pgd_gpa;
	u16 bdf;
	u16 gaw;
	u8 agaw;
	u8 iommu_superpage;
	u8 iommu_coherency;
	u8 use_first_level;
};

struct free_domain_data {
	u64 pgd_gpa;
};

struct iommu_hc_data {
	union {
		struct qi_submit_data qi_submit;
		struct clear_ce_data clear_ce;
		struct set_lm_ce_data set_lm_ce;
		struct set_sm_ce_data set_sm_ce;
		struct pasid_setup_fl_data pasid_setup_fl;
		struct pasid_setup_sl_data pasid_setup_sl;
		struct pasid_teardown_data pasid_teardown;
		struct alloc_domain_data alloc_domain;
		struct free_domain_data free_domain;
	};
	u8 hc_num;
};
static_assert(sizeof(struct iommu_hc_data) <= PKVM_HC_DATA_MAX_NUM * sizeof(u64));

int pkvm_iommu_qi_submit(struct qi_submit_data *data);
int pkvm_iommu_clear_ce(struct clear_ce_data *data);
int pkvm_iommu_set_lm_ce(struct set_lm_ce_data *data);
int pkvm_iommu_set_sm_ce(struct set_sm_ce_data *data);
int pkvm_iommu_pasid_setup_fl(struct pasid_setup_fl_data *data);
int pkvm_iommu_pasid_setup_sl(struct pasid_setup_sl_data *data);
int pkvm_iommu_pasid_teardown(struct pasid_teardown_data *data);
int pkvm_iommu_alloc_domain(struct alloc_domain_data *data);
int pkvm_iommu_free_domain(struct free_domain_data *data);
#endif /* _PKVM_INTEL_IOMMU_HC_H_ */
