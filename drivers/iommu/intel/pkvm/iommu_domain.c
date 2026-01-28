// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2026 Google. */


#include <linux/hashtable.h>
#include <linux/bug.h>
#include <asm/pkvm_spinlock.h>
#include "pkvm/debug.h"
#include "pkvm/memory.h"
#include "../iommu.h"
#include "iommu_hc.h"
#include "iommu_domain.h"

/*
 * TODO: Make this a dynamic value.
 */
#define MAX_IOMMU_DOMAIN_NUM	128
static DEFINE_HASHTABLE(iommu_domain_hasht, 8);
static DECLARE_BITMAP(iommu_domains_bitmap, MAX_IOMMU_DOMAIN_NUM);
static struct dmar_domain iommu_domains[MAX_IOMMU_DOMAIN_NUM];
static pkvm_spinlock_t iommu_domain_lock = __PKVM_SPINLOCK_UNLOCKED;
struct dmar_domain pt_domain;

void init_pt_domain(void)
{
	INIT_LIST_HEAD(&pt_domain.cache_tags);
	pkvm_spin_lock_init(&pt_domain.cache_lock);
	WRITE_ONCE(pt_domain.qi_batch, &pt_domain._qi_batch);
}

static inline struct dmar_domain *__pkvm_get_iommu_domain_locked(void *pgd, bool inc_ref)
{
	struct dmar_domain *domain;

	hash_for_each_possible(iommu_domain_hasht, domain, hnode, (u64)pgd) {
		if (domain->pgd != pgd)
			continue;

		if (inc_ref && WARN_ON_ONCE(!atomic_inc_not_zero(&domain->refcount)))
			return NULL;

		return domain;
	}

	return NULL;
}

struct dmar_domain *pkvm_get_iommu_domain(void *pgd)
{
	struct dmar_domain *domain;

	pkvm_spin_lock(&iommu_domain_lock);
	domain = __pkvm_get_iommu_domain_locked(pgd, true);
	pkvm_spin_unlock(&iommu_domain_lock);

	return domain;
}

/*
 * Retrieve the domain without incrementing refcount.
 * This api is useful when there is a refcount on the domain
 * and refcount is guaranteed to be not dropped.
 */
struct dmar_domain *pkvm_get_iommu_domain_noref(void *pgd)
{
	struct dmar_domain *domain;

	pkvm_spin_lock(&iommu_domain_lock);
	domain = __pkvm_get_iommu_domain_locked(pgd, false);
	pkvm_spin_unlock(&iommu_domain_lock);

	return domain;
}

void pkvm_put_iommu_domain(struct dmar_domain *domain)
{
	WARN_ON_ONCE(atomic_dec_and_test(&domain->refcount));
}

int pkvm_acquire_domain_cache_tag_assign(void *pgd, int did, u32 pasid,
					 struct device_domain_info *info)
{
	struct dev_iommu dev_iommu = { 0 };
	struct dmar_domain *domain;
	struct device dev = { 0 };
	int ret;

	dev_iommu.priv = (void *)info;
	dev.iommu = &dev_iommu;
	if (did == FLPT_DEFAULT_DID) {
		cache_tag_assign_domain(&pt_domain, did, &dev, pasid);
		return 0;
	}

	domain = pkvm_get_iommu_domain(pgd);
	if (!domain) {
		pkvm_err("%s: Failed to locate domain with pgd: %p\n",
			 __func__, pgd);
		return -EFAULT;
	}

	ret = cache_tag_assign_domain(domain, did, &dev, pasid);
	if (ret) {
		pkvm_put_iommu_domain(domain);
		return ret;
	}
	return 0;
}

void pkvm_release_domain_cache_tag_unassign(void *pgd, int did, u32 pasid,
					    struct device_domain_info *info)
{
	struct dev_iommu dev_iommu = { 0 };
	struct dmar_domain *domain;
	struct device dev = { 0 };

	dev_iommu.priv = (void *)info;
	dev.iommu = &dev_iommu;
	if (did == FLPT_DEFAULT_DID) {
		cache_tag_unassign_domain(&pt_domain, did, &dev, pasid);
		return;
	}

	domain = pkvm_get_iommu_domain_noref(pgd);
	BUG_ON(!domain);

	cache_tag_unassign_domain(domain, did, &dev, pasid);
	pkvm_put_iommu_domain(domain);
}

/*
 * memcache helper functions.
 */

static int refill_domain_memcache(struct dmar_domain *domain,
				  struct pkvm_memcache *host_mc)
{
	struct pkvm_memcache *mc = &domain->mc;
	unsigned long min_pages;

	/*
	 * Host expects pKVM to drain the memcache fully as it is
	 * not persistent. Host makes the hypercall without memcache
	 * the first time and passes memcache next time only if the
	 * initial hypercall failed with ENOMEM.
	 */
	min_pages = mc->count + host_mc->count;
	while (mc->count < min_pages) {
		phys_addr_t *p;
		struct pkvm_page_range page_range;

		page_range = pop_pkvm_memcache(host_mc, pkvm_host_gpa_to_virt);
		p = pkvm_host_gpa_to_virt(page_range.addr);

		if (!p)
			return -ENOMEM;

		if (WARN_ON(pkvm_host_donate_hyp_share_ro(__pkvm_pa(p), VTD_PAGE_SIZE, true)))
			return -EBUSY;
		push_pkvm_memcache(mc, p, PAGE_SIZE, hyp_virt_to_phys);
	}

	return 0;
}

static void free_domain_memcache(struct dmar_domain *domain,
				 struct pkvm_memcache *teardown_mc)
{
	struct pkvm_memcache *mc = &domain->mc;

	while (mc->count) {
		void *addr;
		struct pkvm_page_range page_range;

		page_range = pop_pkvm_memcache(mc, hyp_phys_to_virt);
		addr = hyp_phys_to_virt(page_range.addr);

		push_pkvm_memcache(teardown_mc, addr, PAGE_SIZE, pkvm_virt_to_host_gpa);
		pkvm_hyp_donate_host(page_range.addr, VTD_PAGE_SIZE, false);
	}
}

int pkvm_free_iommu_domain(struct dmar_domain *domain, struct pkvm_memcache *teardown_mc)
{
	if (atomic_cmpxchg(&domain->refcount, 1, 0) != 1) {
		pkvm_err("%s: domain[pgd:%p] has users, refcount %d\n",
			 __func__, domain->pgd, atomic_read(&domain->refcount));
		return -EBUSY;
	}

	/* Unmap any remaining mappings. */
	domain_unmap(domain, 0, DOMAIN_MAX_PFN(domain->gaw), NULL);
	free_domain_memcache(domain, teardown_mc);
	/*
	 * pgd was not allocated through memcache, but its safe to return to
	 * memcache as the teardown mc frees it the same way host driver frees
	 * the pages.
	 */
	push_pkvm_memcache(teardown_mc, domain->pgd, PAGE_SIZE, pkvm_virt_to_host_gpa);

	pkvm_dbg("%s: freeing domain[pgd: %p], freed pages: %lu\n",
		 __func__, domain->pgd, teardown_mc->count);

	pkvm_spin_lock(&iommu_domain_lock);
	hash_del(&domain->hnode);
	__clear_bit(domain->index, iommu_domains_bitmap);
	memset(domain, 0, sizeof(struct dmar_domain));
	pkvm_spin_unlock(&iommu_domain_lock);

	return 0;
}

struct dmar_domain *pkvm_alloc_iommu_domain(struct alloc_domain_data *data)
{
	void *pgd = pkvm_host_gpa_to_virt(data->pgd_gpa);
	struct dmar_domain *domain;
	unsigned long index;

	pkvm_spin_lock(&iommu_domain_lock);
	domain = __pkvm_get_iommu_domain_locked(pgd, false);
	if (unlikely(domain)) {
		pkvm_spin_unlock(&iommu_domain_lock);
		return ERR_PTR(-EEXIST);
	}

	index = find_first_zero_bit(iommu_domains_bitmap, MAX_IOMMU_DOMAIN_NUM);
	if (index < MAX_IOMMU_DOMAIN_NUM) {
		__set_bit(index, iommu_domains_bitmap);
		domain = &iommu_domains[index];
		INIT_LIST_HEAD(&domain->cache_tags);
		domain->pgd = pgd;
		domain->use_first_level = data->use_first_level;
		domain->iommu_superpage = data->iommu_superpage;
		domain->iommu_coherency = data->iommu_coherency;
		domain->agaw = data->agaw;
		domain->gaw = data->gaw;
		domain->max_addr = data->max_addr;
		domain->index = index;
		domain->qi_batch = &domain->_qi_batch;
		atomic_set(&domain->refcount, 1);
		pkvm_spin_lock_init(&domain->lock);
		pkvm_spin_lock_init(&domain->cache_lock);
		hash_add(iommu_domain_hasht, &domain->hnode, (u64)pgd);
		pkvm_dbg("%s: allocated domain pgd: %p\n", __func__, pgd);
	} else {
		domain = ERR_PTR(-ENOMEM);
	}
	pkvm_spin_unlock(&iommu_domain_lock);

	return domain;
}

int pkvm_iommu_domain_map(struct domain_map_data *in, struct domain_map_data *out)
{
	struct dmar_domain *domain;
	u64 size;
	int ret;

	/* Check for possible overfows that may have security implications */
	if (check_mul_overflow(in->nr_pages, VTD_PAGE_SIZE, &size))
		return -EINVAL;
	if (in->iov_pfn + in->nr_pages < in->iov_pfn)
		return -EINVAL;
	if ((in->iov_pfn << VTD_PAGE_SHIFT) < in->iov_pfn)
		return -EINVAL;
	if ((in->iov_pfn << VTD_PAGE_SHIFT) + size < in->iov_pfn)
		return -EINVAL;
	if ((in->phys_pfn << VTD_PAGE_SHIFT) < in->phys_pfn)
		return -EINVAL;
	if ((in->phys_pfn << VTD_PAGE_SHIFT) + size < in->phys_pfn)
		return -EINVAL;

	domain = pkvm_get_iommu_domain(pkvm_host_gpa_to_virt(in->pgd_gpa));
	if(!domain) {
		pkvm_err("%s, failed to get the domain [pgd:%llx]\n",
				__func__, in->pgd_gpa);
		return -EINVAL;
	}

	pkvm_spin_lock(&domain->lock);
	if (in->mc.count) {
		ret = refill_domain_memcache(domain, &in->mc);
		if (ret) {
			pkvm_err("pkvm: %s: failed to refill memcache for domain[pgd: %p] (err=%d)\n",
				 __func__, domain->pgd, ret);
			goto out_unlock;
		}
	}
	if (domain->mc.count < __pkvm_pgtable_max_pages(in->nr_pages)) {
		ret = -ENOMEM;
		goto out_unlock;
	}

	ret = domain_map(domain, in->iov_pfn, in->phys_pfn, in->nr_pages, in->prot, 0);

out_unlock:
	pkvm_spin_unlock(&domain->lock);
	pkvm_put_iommu_domain(domain);

	*out = *in;
	return ret;
}

int pkvm_iommu_domain_unmap(u64 pgd_gpa, u64 start_pfn, u64 last_pfn)
{
	struct dmar_domain *domain;

	domain = pkvm_get_iommu_domain(pkvm_host_gpa_to_virt(pgd_gpa));
	if (!domain) {
		pkvm_err("%s, failed to get the domain [pgd:%llx]\n",
				__func__, pgd_gpa);
		return -EINVAL;
	}

	pkvm_spin_lock(&domain->lock);
	domain_unmap(domain, start_pfn, last_pfn, NULL);
	pkvm_spin_unlock(&domain->lock);

	pkvm_put_iommu_domain(domain);

	return 0;
}
