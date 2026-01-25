/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright © 2026 Google
 */

#ifndef _PKVM_INTEL_IOMMU_H_
#define _PKVM_INTEL_IOMMU_H_

/* expose pkvm_enabled() when !CONFIG_PKVM_X86 */
#include <asm/kvm_host.h>
#include <asm/kvm_pkvm.h>

#define PKVM_MAX_SATC_DEVS	16

/* Page table level represented by IOMMU cap SAGAW bits */
#define IOMMU_PGT_4LEVEL	BIT(2)
#define IOMMU_PGT_5LEVEL	BIT(3)

struct intel_iommu_info {
	u64 reg_phys;
	u64 reg_size;
	u64 cap;
	u64 ecap;
	int seq_id;
	int agaw;
	int msagaw;
};

struct qi_desc;
struct intel_iommu;
struct device_domain_info;

#ifdef CONFIG_PKVM_INTEL
#include "pkvm/iommu_hc.h"

extern u16 pkvm_sym(satc_devs)[];
extern int pkvm_sym(nr_satc_devs);

extern unsigned int pkvm_sym(iommu_pglvl_mask);
extern unsigned int pkvm_sym(iommu_pgsz_mask);

extern int pkvm_sym(intel_iommu_sm);
extern int pkvm_sym(intel_iommu_superpage);

PKVM_DECLARE(int, prepare_iommu, (struct intel_iommu_info *info));

#ifndef __PKVM_HYP__
static inline u64 pkvm_readq(void __iomem *reg, unsigned long reg_phys, unsigned long offset)
{
	union pkvm_hc_data d;

	if (!pkvm_enabled())
		return readq(reg + offset);

	pkvm_hypercall_out(iommu_mmio_read, &d, reg_phys + offset, sizeof(u64));
	return d.iommu_mmio_read.val;
}

static inline u32 pkvm_readl(void __iomem *reg, unsigned long reg_phys, unsigned long offset)
{
	union pkvm_hc_data d;

	if (!pkvm_enabled())
		return readl(reg + offset);

	pkvm_hypercall_out(iommu_mmio_read, &d, reg_phys + offset, sizeof(u32));
	return (u32)d.iommu_mmio_read.val;
}

static inline void pkvm_writeq(void __iomem *reg, unsigned long reg_phys,
			       unsigned long offset, u64 val)
{
	if (pkvm_enabled())
		pkvm_hypercall(iommu_mmio_write, reg_phys + offset, sizeof(u64), val);
	else
		writeq(val, reg + offset);
}

static inline void pkvm_writel(void __iomem *reg, unsigned long reg_phys,
			       unsigned long offset, u32 val)
{
	if (pkvm_enabled())
		pkvm_hypercall(iommu_mmio_write, reg_phys + offset, sizeof(u32), val);
	else
		writel(val, reg + offset);
}

int __init pkvm_scan_satc_devs(u16 satc_devs[], int *nr_satc_devs, int max_satc_devs);

int __init pkvm_host_prepare_iommu(void);
int __init pkvm_host_init_iommu(void);

int pv_qi_submit_sync(struct intel_iommu *iommu, struct qi_desc *desc,
		      unsigned int count, unsigned long options);
int pv_context_clear(u64 phys, u8 bus, u8 devfn, struct device_domain_info *info);
int pv_context_mapping(struct intel_iommu *iommu, struct device_domain_info *info,
		       u8 bus, u8 devfn, u64 pgd_gpa, u16 did, u8 agaw);
#else /* __PKVM_HYP__ */
static inline bool iommu_supports_2m_page(void)
{
	return iommu_pgsz_mask & (1 << PG_LEVEL_2M);
}

static inline bool iommu_supports_1g_page(void)
{
	return iommu_pgsz_mask & (1 << PG_LEVEL_1G);
}

static inline bool iommu_supports_5levels(void)
{
	return iommu_pglvl_mask & IOMMU_PGT_5LEVEL;
}

struct intel_iommu *iommu_from_phys(unsigned long phys);
static inline bool is_iommu_mmio(unsigned long phys)
{
	return !!iommu_from_phys(phys);
}

bool overlaps_iommu_mmio(unsigned long phys, unsigned long size);
bool is_dev_in_satc(u16 bdf);
bool pkvm_iommu_paging_structure_coherency(void);

/*
 * Get the page donated by host for constructing
 * translation structures(context/pasid).
 */
#define pkvm_iommu_ts_page(iommu)	\
({					\
	void *ts_page = iommu->ts_page;	\
	iommu->ts_page = NULL;		\
	ts_page;			\
})

int pkvm_intel_iommu_init(void);
#endif /* !__PKVM_HYP__ */
#else /* !CONFIG_PKVM_INTEL */
static inline int pv_qi_submit_sync(struct intel_iommu *iommu,
				    struct qi_desc *desc, unsigned int count,
				    unsigned long options)
{
	return -EOPNOTSUPP;
}
static inline int pv_context_clear(u64 phys, u8 bus, u8 devfn,
				   struct device_domain_info *info)
{
	return -EOPNOTSUPP;
}
static inline int pv_context_mapping(struct intel_iommu *iommu,
				     struct device_domain_info *info,
				     u8 bus, u8 devfn, u64 pgd_gpa, u16 did, u8 agaw)
{
	return -EOPNOTSUPP;
}
#endif /* CONFIG_PKVM_INTEL */
#endif /* _PKVM_INTEL_IOMMU_H_ */
