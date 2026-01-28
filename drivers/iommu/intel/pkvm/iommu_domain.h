/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2026 Google. */

#ifndef _PKVM_IOMMU_DOMAIN_H_
#define _PKVM_IOMMU_DOMAIN_H_

extern struct dmar_domain pt_domain;
void init_pt_domain(void);

struct dmar_domain *pkvm_alloc_iommu_domain(struct alloc_domain_data *data);
struct dmar_domain *pkvm_get_iommu_domain(void *pgd);
struct dmar_domain *pkvm_get_iommu_domain_noref(void *pgd);
void pkvm_put_iommu_domain(struct dmar_domain *domain);
int pkvm_free_iommu_domain(struct dmar_domain *domain, struct pkvm_memcache *teardown_mc);
int pkvm_iommu_domain_map(struct domain_map_data *in, struct domain_map_data *out);
int pkvm_iommu_domain_unmap(u64 pgd_gpa, u64 start_pfn, u64 last_pfn);
#endif

