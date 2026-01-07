/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2026 Google. */

#ifndef _PKVM_IOMMU_DOMAIN_H_
#define _PKVM_IOMMU_DOMAIN_H_

struct dmar_domain *pkvm_alloc_iommu_domain(void *pgd);
struct dmar_domain *pkvm_get_iommu_domain(void *pgd);
struct dmar_domain *pkvm_get_iommu_domain_noref(void *pgd);
void pkvm_put_iommu_domain(struct dmar_domain *domain);
int pkvm_free_iommu_domain(struct dmar_domain *domain);
#endif

