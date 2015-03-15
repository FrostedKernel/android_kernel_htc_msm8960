/*
 * Compressed RAM block device
 *
 * Copyright (C) 2008, 2009, 2010  Nitin Gupta
 *               2012, 2013 Minchan Kim
 *
 * This code is released using a dual license strategy: BSD/GPL
 * You can choose the licence that better fits your requirements.
 *
 * Released under the terms of 3-clause BSD License
 * Released under the terms of GNU General Public License Version 2.0
 *
 * Project home: http://compcache.googlecode.com
 */

#define KMSG_COMPONENT "zram"
#define pr_fmt(fmt) KMSG_COMPONENT ": " fmt

#ifdef CONFIG_ZRAM_DEBUG
#define DEBUG
#endif

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/bio.h>
#include <linux/bitops.h>
#include <linux/blkdev.h>
#include <linux/buffer_head.h>
#include <linux/device.h>
#include <linux/genhd.h>
#include <linux/highmem.h>
#include <linux/slab.h>
<<<<<<< HEAD:drivers/staging/zram/zram_drv.c
#include <linux/crypto.h>
#include <linux/cpu.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
=======
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/ratelimit.h>
#include <linux/err.h>
>>>>>>> cm/cm-12.0:drivers/block/zram/zram_drv.c

#include "zram_drv.h"

#define ZRAM_COMPRESSOR_DEFAULT "lz4"

/* Globals */
static int zram_major;
<<<<<<< HEAD:drivers/staging/zram/zram_drv.c
struct zram *zram_devices;
=======
static struct zram *zram_devices;
static const char *default_compressor = "lz4";

/*
 * We don't need to see memory allocation errors more than once every 1
 * second to know that a problem is occurring.
 */
#define ALLOC_ERROR_LOG_RATE_MS 1000
>>>>>>> cm/cm-12.0:drivers/block/zram/zram_drv.c

/* Module params (documentation at end) */
static unsigned int num_devices = 1;

<<<<<<< HEAD:drivers/staging/zram/zram_drv.c
static void zram_stat_inc(u32 *v)
=======
#define ZRAM_ATTR_RO(name)						\
static ssize_t zram_attr_##name##_show(struct device *d,		\
				struct device_attribute *attr, char *b)	\
{									\
	struct zram *zram = dev_to_zram(d);				\
	return scnprintf(b, PAGE_SIZE, "%llu\n",			\
		(u64)atomic64_read(&zram->stats.name));			\
}									\
static struct device_attribute dev_attr_##name =			\
	__ATTR(name, S_IRUGO, zram_attr_##name##_show, NULL);

static inline int init_done(struct zram *zram)
{
	return zram->meta != NULL;
}

static inline struct zram *dev_to_zram(struct device *dev)
>>>>>>> cm/cm-12.0:drivers/block/zram/zram_drv.c
{
	*v = *v + 1;
}

static void zram_stat_dec(u32 *v)
{
<<<<<<< HEAD:drivers/staging/zram/zram_drv.c
	*v = *v - 1;
}

/* Cryptographic API features */
static char *zram_compressor = ZRAM_COMPRESSOR_DEFAULT;
static struct crypto_comp * __percpu *zram_comp_pcpu_tfms;

enum comp_op {
	ZRAM_COMPOP_COMPRESS,
	ZRAM_COMPOP_DECOMPRESS
};

static int zram_comp_op(enum comp_op op, const u8 *src, unsigned int slen,
			u8 *dst, unsigned int *dlen)
{
	struct crypto_comp *tfm;
	int ret;

	tfm = *per_cpu_ptr(zram_comp_pcpu_tfms, get_cpu());
	switch (op) {
	case ZRAM_COMPOP_COMPRESS:
		ret = crypto_comp_compress(tfm, src, slen, dst, dlen);
		break;
	case ZRAM_COMPOP_DECOMPRESS:
		ret = crypto_comp_decompress(tfm, src, slen, dst, dlen);
		break;
	default:
		ret = -EINVAL;
	}
	put_cpu();

	return ret;
}

static int __init zram_comp_init(void)
=======
	struct zram *zram = dev_to_zram(dev);

	return scnprintf(buf, PAGE_SIZE, "%llu\n", zram->disksize);
}

static ssize_t initstate_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	u32 val;
	struct zram *zram = dev_to_zram(dev);

	down_read(&zram->init_lock);
	val = init_done(zram);
	up_read(&zram->init_lock);

	return scnprintf(buf, PAGE_SIZE, "%u\n", val);
}

static ssize_t orig_data_size_show(struct device *dev,
		struct device_attribute *attr, char *buf)
>>>>>>> cm/cm-12.0:drivers/block/zram/zram_drv.c
{
	int ret;
	ret = crypto_has_comp(zram_compressor, 0, 0);
	if (!ret) {
		pr_info("%s is not available\n", zram_compressor);
		zram_compressor = ZRAM_COMPRESSOR_DEFAULT;
		ret = crypto_has_comp(zram_compressor, 0, 0);
		if (!ret)
			return -ENODEV;
	}
	pr_info("using %s compressor\n", zram_compressor);

	/* alloc percpu transforms */
	zram_comp_pcpu_tfms = alloc_percpu(struct crypto_comp *);
	if (!zram_comp_pcpu_tfms)
		return -ENOMEM;

<<<<<<< HEAD:drivers/staging/zram/zram_drv.c
	return 0;
}

static inline void zram_comp_exit(void)
{
	/* free percpu transforms */
	if (zram_comp_pcpu_tfms)
		free_percpu(zram_comp_pcpu_tfms);
}


/* Crypto API features: percpu code */
#define ZRAM_DSTMEM_ORDER 1
static DEFINE_PER_CPU(u8 *, zram_dstmem);

static int zram_comp_cpu_up(int cpu)
{
	struct crypto_comp *tfm;

	tfm = crypto_alloc_comp(zram_compressor, 0, 0);
	if (IS_ERR(tfm))
		return NOTIFY_BAD;
	*per_cpu_ptr(zram_comp_pcpu_tfms, cpu) = tfm;
	return NOTIFY_OK;
}

static void zram_comp_cpu_down(int cpu)
{
	struct crypto_comp *tfm;

	tfm = *per_cpu_ptr(zram_comp_pcpu_tfms, cpu);
	crypto_free_comp(tfm);
	*per_cpu_ptr(zram_comp_pcpu_tfms, cpu) = NULL;
}

static int zram_cpu_notifier(struct notifier_block *nb,
				unsigned long action, void *pcpu)
{
	int ret;
	int cpu = (long) pcpu;

	switch (action) {
	case CPU_UP_PREPARE:
		ret = zram_comp_cpu_up(cpu);
		if (ret != NOTIFY_OK) {
			pr_err("zram: can't allocate compressor xform\n");
			return ret;
		}
		per_cpu(zram_dstmem, cpu) = (void *)__get_free_pages(
			GFP_KERNEL | __GFP_REPEAT, ZRAM_DSTMEM_ORDER);
		break;
	case CPU_DEAD:
	case CPU_UP_CANCELED:
		zram_comp_cpu_down(cpu);
		free_pages((unsigned long) per_cpu(zram_dstmem, cpu),
			    ZRAM_DSTMEM_ORDER);
		per_cpu(zram_dstmem, cpu) = NULL;
		break;
	default:
		break;
	}
	return NOTIFY_OK;
}

static struct notifier_block zram_cpu_notifier_block = {
	.notifier_call = zram_cpu_notifier
};

/* Helper function releasing tfms from online cpus */
static inline void zram_comp_cpus_down(void)
{
	int cpu;

	get_online_cpus();
	for_each_online_cpu(cpu) {
		void *pcpu = (void *)(long)cpu;
		zram_cpu_notifier(&zram_cpu_notifier_block,
				  CPU_UP_CANCELED, pcpu);
	}
	put_online_cpus();
}

static int zram_cpu_init(void)
{
	int ret;
	unsigned int cpu;

	ret = register_cpu_notifier(&zram_cpu_notifier_block);
	if (ret) {
		pr_err("zram: can't register cpu notifier\n");
		goto out;
	}

	get_online_cpus();
	for_each_online_cpu(cpu) {
		void *pcpu = (void *)(long)cpu;
		if (zram_cpu_notifier(&zram_cpu_notifier_block,
				      CPU_UP_PREPARE, pcpu) != NOTIFY_OK)
			goto cleanup;
	}
	put_online_cpus();
	return ret;

cleanup:
	zram_comp_cpus_down();

out:
	put_online_cpus();
	return -ENOMEM;
=======
	return scnprintf(buf, PAGE_SIZE, "%llu\n",
		(u64)(atomic64_read(&zram->stats.pages_stored)) << PAGE_SHIFT);
}

static ssize_t mem_used_total_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	u64 val = 0;
	struct zram *zram = dev_to_zram(dev);
	struct zram_meta *meta = zram->meta;

	down_read(&zram->init_lock);
	if (init_done(zram))
		val = zs_get_total_size_bytes(meta->mem_pool);
	up_read(&zram->init_lock);

	return scnprintf(buf, PAGE_SIZE, "%llu\n", val);
}

static ssize_t max_comp_streams_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	int val;
	struct zram *zram = dev_to_zram(dev);

	down_read(&zram->init_lock);
	val = zram->max_comp_streams;
	up_read(&zram->init_lock);

	return scnprintf(buf, PAGE_SIZE, "%d\n", val);
}

static ssize_t max_comp_streams_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t len)
{
	int num;
	struct zram *zram = dev_to_zram(dev);
	int ret;

	ret = kstrtoint(buf, 0, &num);
	if (ret < 0)
		return ret;
	if (num < 1)
		return -EINVAL;

	down_write(&zram->init_lock);
	if (init_done(zram)) {
		if (!zcomp_set_max_streams(zram->comp, num)) {
			pr_info("Cannot change max compression streams\n");
			ret = -EINVAL;
			goto out;
		}
	}

	zram->max_comp_streams = num;
	ret = len;
out:
	up_write(&zram->init_lock);
	return ret;
}

static ssize_t comp_algorithm_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	size_t sz;
	struct zram *zram = dev_to_zram(dev);

	down_read(&zram->init_lock);
	sz = zcomp_available_show(zram->compressor, buf);
	up_read(&zram->init_lock);

	return sz;
}

static ssize_t comp_algorithm_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t len)
{
	struct zram *zram = dev_to_zram(dev);
	down_write(&zram->init_lock);
	if (init_done(zram)) {
		up_write(&zram->init_lock);
		pr_info("Can't change algorithm for initialized device\n");
		return -EBUSY;
	}
	strlcpy(zram->compressor, buf, sizeof(zram->compressor));
	up_write(&zram->init_lock);
	return len;
}

/* flag operations needs meta->tb_lock */
static int zram_test_flag(struct zram_meta *meta, u32 index,
			enum zram_pageflags flag)
{
	return meta->table[index].value & BIT(flag);
}

static void zram_set_flag(struct zram_meta *meta, u32 index,
			enum zram_pageflags flag)
{
	meta->table[index].value |= BIT(flag);
>>>>>>> cm/cm-12.0:drivers/block/zram/zram_drv.c
}
/* end of Cryptographic API features */

static void zram_stat64_add(struct zram *zram, u64 *v, u64 inc)
{
<<<<<<< HEAD:drivers/staging/zram/zram_drv.c
	spin_lock(&zram->stat64_lock);
	*v = *v + inc;
	spin_unlock(&zram->stat64_lock);
=======
	meta->table[index].value &= ~BIT(flag);
}

static size_t zram_get_obj_size(struct zram_meta *meta, u32 index)
{
	return meta->table[index].value & (BIT(ZRAM_FLAG_SHIFT) - 1);
}

static void zram_set_obj_size(struct zram_meta *meta,
					u32 index, size_t size)
{
	unsigned long flags = meta->table[index].value >> ZRAM_FLAG_SHIFT;

	meta->table[index].value = (flags << ZRAM_FLAG_SHIFT) | size;
>>>>>>> cm/cm-12.0:drivers/block/zram/zram_drv.c
}

static void zram_stat64_sub(struct zram *zram, u64 *v, u64 dec)
{
	spin_lock(&zram->stat64_lock);
	*v = *v - dec;
	spin_unlock(&zram->stat64_lock);
}

static void zram_stat64_inc(struct zram *zram, u64 *v)
{
	zram_stat64_add(zram, v, 1);
}

static int zram_test_flag(struct zram *zram, u32 index,
			enum zram_pageflags flag)
{
<<<<<<< HEAD:drivers/staging/zram/zram_drv.c
	return zram->table[index].flags & BIT(flag);
=======
	zs_destroy_pool(meta->mem_pool);
	vfree(meta->table);
	kfree(meta);
>>>>>>> cm/cm-12.0:drivers/block/zram/zram_drv.c
}

static void zram_set_flag(struct zram *zram, u32 index,
			enum zram_pageflags flag)
{
<<<<<<< HEAD:drivers/staging/zram/zram_drv.c
	zram->table[index].flags |= BIT(flag);
=======
	size_t num_pages;
	struct zram_meta *meta = kmalloc(sizeof(*meta), GFP_KERNEL);
	if (!meta)
		goto out;

	num_pages = disksize >> PAGE_SHIFT;
	meta->table = vzalloc(num_pages * sizeof(*meta->table));
	if (!meta->table) {
		pr_err("Error allocating zram address table\n");
		goto free_meta;
	}

	meta->mem_pool = zs_create_pool(GFP_NOIO | __GFP_HIGHMEM |
					__GFP_NOWARN);
	if (!meta->mem_pool) {
		pr_err("Error creating memory pool\n");
		goto free_table;
	}

	return meta;

free_table:
	vfree(meta->table);
free_meta:
	kfree(meta);
	meta = NULL;
out:
	return meta;
>>>>>>> cm/cm-12.0:drivers/block/zram/zram_drv.c
}

static void zram_clear_flag(struct zram *zram, u32 index,
			enum zram_pageflags flag)
{
	zram->table[index].flags &= ~BIT(flag);
}

static int page_zero_filled(void *ptr)
{
	unsigned int pos;
	unsigned long *page;

	page = (unsigned long *)ptr;

	for (pos = 0; pos != PAGE_SIZE / sizeof(*page); pos++) {
		if (page[pos])
			return 0;
	}

	return 1;
}

<<<<<<< HEAD:drivers/staging/zram/zram_drv.c
static void zram_free_page(struct zram *zram, size_t index)
{
	unsigned long handle = zram->table[index].handle;
	u16 size = zram->table[index].size;
=======
static void handle_zero_page(struct bio_vec *bvec)
{
	struct page *page = bvec->bv_page;
	void *user_mem;

	user_mem = kmap_atomic(page);
	if (is_partial_io(bvec))
		memset(user_mem + bvec->bv_offset, 0, bvec->bv_len);
	else
		clear_page(user_mem);
	kunmap_atomic(user_mem);

	flush_dcache_page(page);
}


/*
 * To protect concurrent access to the same index entry,
 * caller should hold this table index entry's bit_spinlock to
 * indicate this index entry is accessing.
 */
static void zram_free_page(struct zram *zram, size_t index)
{
	struct zram_meta *meta = zram->meta;
	unsigned long handle = meta->table[index].handle;
>>>>>>> cm/cm-12.0:drivers/block/zram/zram_drv.c

	if (unlikely(!handle)) {
		/*
		 * No memory is allocated for zero filled pages.
		 * Simply clear zero page flag.
		 */
<<<<<<< HEAD:drivers/staging/zram/zram_drv.c
		if (zram_test_flag(zram, index, ZRAM_ZERO)) {
			zram_clear_flag(zram, index, ZRAM_ZERO);
			zram_stat_dec(&zram->stats.pages_zero);
=======
		if (zram_test_flag(meta, index, ZRAM_ZERO)) {
			zram_clear_flag(meta, index, ZRAM_ZERO);
			atomic64_dec(&zram->stats.zero_pages);
>>>>>>> cm/cm-12.0:drivers/block/zram/zram_drv.c
		}
		return;
	}

<<<<<<< HEAD:drivers/staging/zram/zram_drv.c
	if (unlikely(size > max_zpage_size))
		zram_stat_dec(&zram->stats.bad_compress);

	zs_free(zram->mem_pool, handle);

	if (size <= PAGE_SIZE / 2)
		zram_stat_dec(&zram->stats.good_compress);

	zram_stat64_sub(zram, &zram->stats.compr_size,
			zram->table[index].size);
	zram_stat_dec(&zram->stats.pages_stored);

	zram->table[index].handle = 0;
	zram->table[index].size = 0;
}

static void handle_zero_page(struct bio_vec *bvec)
{
	struct page *page = bvec->bv_page;
	void *user_mem;

	user_mem = kmap_atomic(page);
	memset(user_mem + bvec->bv_offset, 0, bvec->bv_len);
	kunmap_atomic(user_mem);

	flush_dcache_page(page);
}

static inline int is_partial_io(struct bio_vec *bvec)
{
	return bvec->bv_len != PAGE_SIZE;
=======
	zs_free(meta->mem_pool, handle);

	atomic64_sub(zram_get_obj_size(meta, index),
			&zram->stats.compr_data_size);
	atomic64_dec(&zram->stats.pages_stored);

	meta->table[index].handle = 0;
	zram_set_obj_size(meta, index, 0);
>>>>>>> cm/cm-12.0:drivers/block/zram/zram_drv.c
}

static int zram_decompress_page(struct zram *zram, char *mem, u32 index)
{
	int ret = 0;
<<<<<<< HEAD:drivers/staging/zram/zram_drv.c
	size_t clen = PAGE_SIZE;
	unsigned char *cmem;
	unsigned long handle = zram->table[index].handle;

	if (!handle || zram_test_flag(zram, index, ZRAM_ZERO)) {
		memset(mem, 0, PAGE_SIZE);
		return 0;
	}

	cmem = zs_map_object(zram->mem_pool, handle, ZS_MM_RO);
	if (zram->table[index].size == PAGE_SIZE)
		memcpy(mem, cmem, PAGE_SIZE);
	else
		ret = zram_comp_op(ZRAM_COMPOP_DECOMPRESS, cmem,
				zram->table[index].size, mem, &clen);

	zs_unmap_object(zram->mem_pool, handle);

	/* Should NEVER happen. Return bio error if it does. */
	if (unlikely(ret != 0)) {
		pr_err("Decompression failed! err=%d, page=%u\n", ret, index);
		zram_stat64_inc(zram, &zram->stats.failed_reads);
=======
	unsigned char *cmem;
	struct zram_meta *meta = zram->meta;
	unsigned long handle;
	size_t size;

	bit_spin_lock(ZRAM_ACCESS, &meta->table[index].value);
	handle = meta->table[index].handle;
	size = zram_get_obj_size(meta, index);

	if (!handle || zram_test_flag(meta, index, ZRAM_ZERO)) {
		bit_spin_unlock(ZRAM_ACCESS, &meta->table[index].value);
		clear_page(mem);
		return 0;
	}

	cmem = zs_map_object(meta->mem_pool, handle, ZS_MM_RO);
	if (size == PAGE_SIZE)
		copy_page(mem, cmem);
	else
		ret = zcomp_decompress(zram->comp, cmem, size, mem);
	zs_unmap_object(meta->mem_pool, handle);
	bit_spin_unlock(ZRAM_ACCESS, &meta->table[index].value);

	/* Should NEVER happen. Return bio error if it does. */
	if (unlikely(ret)) {
		pr_err("Decompression failed! err=%d, page=%u\n", ret, index);
>>>>>>> cm/cm-12.0:drivers/block/zram/zram_drv.c
		return ret;
	}

	return 0;
}

static int zram_bvec_read(struct zram *zram, struct bio_vec *bvec,
			  u32 index, int offset, struct bio *bio)
{
	int ret;
	struct page *page;
	unsigned char *user_mem, *uncmem = NULL;

	page = bvec->bv_page;

<<<<<<< HEAD:drivers/staging/zram/zram_drv.c
	if (unlikely(!zram->table[index].handle) ||
			zram_test_flag(zram, index, ZRAM_ZERO)) {
=======
	bit_spin_lock(ZRAM_ACCESS, &meta->table[index].value);
	if (unlikely(!meta->table[index].handle) ||
			zram_test_flag(meta, index, ZRAM_ZERO)) {
		bit_spin_unlock(ZRAM_ACCESS, &meta->table[index].value);
>>>>>>> cm/cm-12.0:drivers/block/zram/zram_drv.c
		handle_zero_page(bvec);
		return 0;
	}
	bit_spin_unlock(ZRAM_ACCESS, &meta->table[index].value);

	if (is_partial_io(bvec))
		/* Use  a temporary buffer to decompress the page */
		uncmem = kmalloc(PAGE_SIZE, GFP_NOIO);

	user_mem = kmap_atomic(page);
	if (!is_partial_io(bvec))
		uncmem = user_mem;

	if (!uncmem) {
		pr_info("Unable to allocate temp memory\n");
		ret = -ENOMEM;
		goto out_cleanup;
	}

	ret = zram_decompress_page(zram, uncmem, index);
	/* Should NEVER happen. Return bio error if it does. */
<<<<<<< HEAD:drivers/staging/zram/zram_drv.c
	if (unlikely(ret != 0)) {
		pr_err("Decompression failed! err=%d, page=%u\n", ret, index);
		zram_stat64_inc(zram, &zram->stats.failed_reads);
=======
	if (unlikely(ret))
>>>>>>> cm/cm-12.0:drivers/block/zram/zram_drv.c
		goto out_cleanup;
	}

	if (is_partial_io(bvec))
		memcpy(user_mem + bvec->bv_offset, uncmem + offset,
				bvec->bv_len);

	flush_dcache_page(page);
	ret = 0;
out_cleanup:
	kunmap_atomic(user_mem);
	if (is_partial_io(bvec))
		kfree(uncmem);
	return ret;
}

static int zram_bvec_write(struct zram *zram, struct bio_vec *bvec, u32 index,
			   int offset)
{
	int ret = 0;
	size_t clen;
	unsigned long handle;
	struct page *page;
	unsigned char *user_mem, *cmem, *src, *uncmem = NULL;
<<<<<<< HEAD:drivers/staging/zram/zram_drv.c

	page = bvec->bv_page;
	src = zram->compress_buffer;

=======
	struct zram_meta *meta = zram->meta;
	static unsigned long zram_rs_time;
	struct zcomp_strm *zstrm;
	bool locked = false;

	page = bvec->bv_page;
>>>>>>> cm/cm-12.0:drivers/block/zram/zram_drv.c
	if (is_partial_io(bvec)) {
		/*
		 * This is a partial IO. We need to read the full page
		 * before to write the changes.
		 */
		uncmem = kmalloc(PAGE_SIZE, GFP_NOIO);
		if (!uncmem) {
			pr_info("Error allocating temp memory!\n");
			ret = -ENOMEM;
			goto out;
		}
		ret = zram_decompress_page(zram, uncmem, index);
		if (ret)
			goto out;
	}

<<<<<<< HEAD:drivers/staging/zram/zram_drv.c
	/*
	 * System overwrites unused sectors. Free memory associated
	 * with this sector now.
	 */
	if (zram->table[index].handle ||
	    zram_test_flag(zram, index, ZRAM_ZERO))
		zram_free_page(zram, index);

=======
	zstrm = zcomp_strm_find(zram->comp);
	locked = true;
>>>>>>> cm/cm-12.0:drivers/block/zram/zram_drv.c
	user_mem = kmap_atomic(page);

	if (is_partial_io(bvec)) {
		memcpy(uncmem + offset, user_mem + bvec->bv_offset,
		       bvec->bv_len);
		kunmap_atomic(user_mem);
		user_mem = NULL;
	} else {
		uncmem = user_mem;
	}

	if (page_zero_filled(uncmem)) {
<<<<<<< HEAD:drivers/staging/zram/zram_drv.c
		if (!is_partial_io(bvec))
			kunmap_atomic(user_mem);
		zram_stat_inc(&zram->stats.pages_zero);
		zram_set_flag(zram, index, ZRAM_ZERO);
=======
		kunmap_atomic(user_mem);
		/* Free memory associated with this sector now. */
		bit_spin_lock(ZRAM_ACCESS, &meta->table[index].value);
		zram_free_page(zram, index);
		zram_set_flag(meta, index, ZRAM_ZERO);
		bit_spin_unlock(ZRAM_ACCESS, &meta->table[index].value);

		atomic64_inc(&zram->stats.zero_pages);
>>>>>>> cm/cm-12.0:drivers/block/zram/zram_drv.c
		ret = 0;
		goto out;
	}

<<<<<<< HEAD:drivers/staging/zram/zram_drv.c
	ret = zram_comp_op(ZRAM_COMPOP_COMPRESS, uncmem,
			   PAGE_SIZE, src, &clen);

=======
	ret = zcomp_compress(zram->comp, zstrm, uncmem, &clen);
>>>>>>> cm/cm-12.0:drivers/block/zram/zram_drv.c
	if (!is_partial_io(bvec)) {
		kunmap_atomic(user_mem);
		user_mem = NULL;
		uncmem = NULL;
	}

<<<<<<< HEAD:drivers/staging/zram/zram_drv.c
	if (unlikely(ret != 0)) {
=======
	if (unlikely(ret)) {
>>>>>>> cm/cm-12.0:drivers/block/zram/zram_drv.c
		pr_err("Compression failed! err=%d\n", ret);
		goto out;
	}
	src = zstrm->buffer;
	if (unlikely(clen > max_zpage_size)) {
<<<<<<< HEAD:drivers/staging/zram/zram_drv.c
		zram_stat_inc(&zram->stats.bad_compress);
=======
>>>>>>> cm/cm-12.0:drivers/block/zram/zram_drv.c
		clen = PAGE_SIZE;
		if (is_partial_io(bvec))
			src = uncmem;
	}

	handle = zs_malloc(zram->mem_pool, clen);
	if (!handle) {
		pr_info("Error allocating memory for compressed "
			"page: %u, size=%zu\n", index, clen);
		ret = -ENOMEM;
		goto out;
	}
	cmem = zs_map_object(zram->mem_pool, handle, ZS_MM_WO);

	if ((clen == PAGE_SIZE) && !is_partial_io(bvec))
		src = kmap_atomic(page);
	memcpy(cmem, src, clen);
	if ((clen == PAGE_SIZE) && !is_partial_io(bvec))
		kunmap_atomic(src);

<<<<<<< HEAD:drivers/staging/zram/zram_drv.c
	zs_unmap_object(zram->mem_pool, handle);

	zram->table[index].handle = handle;
	zram->table[index].size = clen;

	/* Update stats */
	zram_stat64_add(zram, &zram->stats.compr_size, clen);
	zram_stat_inc(&zram->stats.pages_stored);
	if (clen <= PAGE_SIZE / 2)
		zram_stat_inc(&zram->stats.good_compress);

=======
	zcomp_strm_release(zram->comp, zstrm);
	locked = false;
	zs_unmap_object(meta->mem_pool, handle);

	/*
	 * Free memory associated with this sector
	 * before overwriting unused sectors.
	 */
	bit_spin_lock(ZRAM_ACCESS, &meta->table[index].value);
	zram_free_page(zram, index);

	meta->table[index].handle = handle;
	zram_set_obj_size(meta, index, clen);
	bit_spin_unlock(ZRAM_ACCESS, &meta->table[index].value);

	/* Update stats */
	atomic64_add(clen, &zram->stats.compr_data_size);
	atomic64_inc(&zram->stats.pages_stored);
>>>>>>> cm/cm-12.0:drivers/block/zram/zram_drv.c
out:
	if (locked)
		zcomp_strm_release(zram->comp, zstrm);
	if (is_partial_io(bvec))
		kfree(uncmem);
<<<<<<< HEAD:drivers/staging/zram/zram_drv.c

	if (ret)
		zram_stat64_inc(zram, &zram->stats.failed_writes);
=======
>>>>>>> cm/cm-12.0:drivers/block/zram/zram_drv.c
	return ret;
}

static int zram_bvec_rw(struct zram *zram, struct bio_vec *bvec, u32 index,
			int offset, struct bio *bio)
{
	int ret;
	int rw = bio_data_dir(bio);

	if (rw == READ) {
<<<<<<< HEAD:drivers/staging/zram/zram_drv.c
		down_read(&zram->lock);
=======
		atomic64_inc(&zram->stats.num_reads);
>>>>>>> cm/cm-12.0:drivers/block/zram/zram_drv.c
		ret = zram_bvec_read(zram, bvec, index, offset, bio);
	} else {
<<<<<<< HEAD:drivers/staging/zram/zram_drv.c
		down_write(&zram->lock);
=======
		atomic64_inc(&zram->stats.num_writes);
>>>>>>> cm/cm-12.0:drivers/block/zram/zram_drv.c
		ret = zram_bvec_write(zram, bvec, index, offset);
	}

	if (unlikely(ret)) {
		if (rw == READ)
			atomic64_inc(&zram->stats.failed_reads);
		else
			atomic64_inc(&zram->stats.failed_writes);
	}

	return ret;
}

<<<<<<< HEAD:drivers/staging/zram/zram_drv.c
static void update_position(u32 *index, int *offset, struct bio_vec *bvec)
=======
/*
 * zram_bio_discard - handler on discard request
 * @index: physical block index in PAGE_SIZE units
 * @offset: byte offset within physical block
 */
static void zram_bio_discard(struct zram *zram, u32 index,
			     int offset, struct bio *bio)
{
	size_t n = bio->bi_size;
	struct zram_meta *meta = zram->meta;

	/*
	 * zram manages data in physical block size units. Because logical block
	 * size isn't identical with physical block size on some arch, we
	 * could get a discard request pointing to a specific offset within a
	 * certain physical block.  Although we can handle this request by
	 * reading that physiclal block and decompressing and partially zeroing
	 * and re-compressing and then re-storing it, this isn't reasonable
	 * because our intent with a discard request is to save memory.  So
	 * skipping this logical block is appropriate here.
	 */
	if (offset) {
		if (n <= (PAGE_SIZE - offset))
			return;

		n -= (PAGE_SIZE - offset);
		index++;
	}

	while (n >= PAGE_SIZE) {
		bit_spin_lock(ZRAM_ACCESS, &meta->table[index].value);
		zram_free_page(zram, index);
		bit_spin_unlock(ZRAM_ACCESS, &meta->table[index].value);
		index++;
		n -= PAGE_SIZE;
	}
}

static void zram_reset_device(struct zram *zram, bool reset_capacity)
{
	size_t index;
	struct zram_meta *meta;

	down_write(&zram->init_lock);
	if (!init_done(zram)) {
		up_write(&zram->init_lock);
		return;
	}

	meta = zram->meta;
	/* Free all pages that are still in this zram device */
	for (index = 0; index < zram->disksize >> PAGE_SHIFT; index++) {
		unsigned long handle = meta->table[index].handle;
		if (!handle)
			continue;

		zs_free(meta->mem_pool, handle);
	}

	zcomp_destroy(zram->comp);
	zram->max_comp_streams = 1;

	zram_meta_free(zram->meta);
	zram->meta = NULL;
	/* Reset stats */
	memset(&zram->stats, 0, sizeof(zram->stats));

	zram->disksize = 0;
	if (reset_capacity)
		set_capacity(zram->disk, 0);

	up_write(&zram->init_lock);

	/*
	 * Revalidate disk out of the init_lock to avoid lockdep splat.
	 * It's okay because disk's capacity is protected by init_lock
	 * so that revalidate_disk always sees up-to-date capacity.
	 */
	if (reset_capacity)
		revalidate_disk(zram->disk);
}

static ssize_t disksize_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t len)
{
	u64 disksize;
	struct zcomp *comp;
	struct zram_meta *meta;
	struct zram *zram = dev_to_zram(dev);
	int err;

	disksize = memparse(buf, NULL);
	if (!disksize)
		return -EINVAL;

	disksize = PAGE_ALIGN(disksize);
	meta = zram_meta_alloc(disksize);
	if (!meta)
		return -ENOMEM;

	comp = zcomp_create(zram->compressor, zram->max_comp_streams);
	if (IS_ERR(comp)) {
		pr_info("Cannot initialise %s compressing backend\n",
				zram->compressor);
		err = PTR_ERR(comp);
		goto out_free_meta;
	}

	down_write(&zram->init_lock);
	if (init_done(zram)) {
		pr_info("Cannot change disksize for initialized device\n");
		err = -EBUSY;
		goto out_destroy_comp;
	}

	zram->meta = meta;
	zram->comp = comp;
	zram->disksize = disksize;
	set_capacity(zram->disk, zram->disksize >> SECTOR_SHIFT);
	up_write(&zram->init_lock);

	/*
	 * Revalidate disk out of the init_lock to avoid lockdep splat.
	 * It's okay because disk's capacity is protected by init_lock
	 * so that revalidate_disk always sees up-to-date capacity.
	 */
	revalidate_disk(zram->disk);

	return len;

out_destroy_comp:
	up_write(&zram->init_lock);
	zcomp_destroy(comp);
out_free_meta:
	zram_meta_free(meta);
	return err;
}

static ssize_t reset_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t len)
>>>>>>> cm/cm-12.0:drivers/block/zram/zram_drv.c
{
	if (*offset + bvec->bv_len >= PAGE_SIZE)
		(*index)++;
	*offset = (*offset + bvec->bv_len) % PAGE_SIZE;
}

static void __zram_make_request(struct zram *zram, struct bio *bio)
{
	int i, offset;
	u32 index;
	struct bio_vec *bvec;

<<<<<<< HEAD:drivers/staging/zram/zram_drv.c
	switch (rw) {
	case READ:
		zram_stat64_inc(zram, &zram->stats.num_reads);
		break;
	case WRITE:
		zram_stat64_inc(zram, &zram->stats.num_writes);
		break;
	}

	index = bio->bi_sector >> SECTORS_PER_PAGE_SHIFT;
=======
        index = bio->bi_sector >> SECTORS_PER_PAGE_SHIFT;
>>>>>>> cm/cm-12.0:drivers/block/zram/zram_drv.c
	offset = (bio->bi_sector & (SECTORS_PER_PAGE - 1)) << SECTOR_SHIFT;

	if (unlikely(bio->bi_rw & REQ_DISCARD)) {
		zram_bio_discard(zram, index, offset, bio);
		bio_endio(bio, 0);
		return;
	}

	bio_for_each_segment(bvec, bio, i) {
		int max_transfer_size = PAGE_SIZE - offset;

		if (bvec->bv_len > max_transfer_size) {
			/*
			 * zram_bvec_rw() can only make operation on a single
			 * zram page. Split the bio vector.
			 */
			struct bio_vec bv;

			bv.bv_page = bvec->bv_page;
			bv.bv_len = max_transfer_size;
			bv.bv_offset = bvec->bv_offset;

			if (zram_bvec_rw(zram, &bv, index, offset, bio) < 0)
				goto out;

			bv.bv_len = bvec->bv_len - max_transfer_size;
			bv.bv_offset += max_transfer_size;
			if (zram_bvec_rw(zram, &bv, index + 1, 0, bio) < 0)
				goto out;
		} else
			if (zram_bvec_rw(zram, bvec, index, offset, bio) < 0)
				goto out;

		update_position(&index, &offset, bvec);
	}

	set_bit(BIO_UPTODATE, &bio->bi_flags);
	bio_endio(bio, 0);
	return;

out:
	bio_io_error(bio);
}

/*
 * Check if request is within bounds and aligned on zram logical blocks.
 */
static inline int valid_io_request(struct zram *zram, struct bio *bio)
{
	if (unlikely(
		(bio->bi_sector >= (zram->disksize >> SECTOR_SHIFT)) ||
		(bio->bi_sector & (ZRAM_SECTOR_PER_LOGICAL_BLOCK - 1)) ||
		(bio->bi_size & (ZRAM_LOGICAL_BLOCK_SIZE - 1)))) {

		return 0;
	}

	/* I/O request is valid */
	return 1;
}

/*
 * Handler function for all zram I/O requests.
 */
static void zram_make_request(struct request_queue *queue, struct bio *bio)
{
	struct zram *zram = queue->queuedata;

	down_read(&zram->init_lock);
	if (unlikely(!init_done(zram)))
		goto error;

	if (!valid_io_request(zram, bio)) {
		zram_stat64_inc(zram, &zram->stats.invalid_io);
		goto error;
	}

	__zram_make_request(zram, bio);
	up_read(&zram->init_lock);

	return;

error:
	up_read(&zram->init_lock);
	bio_io_error(bio);
}

<<<<<<< HEAD:drivers/staging/zram/zram_drv.c
void __zram_reset_device(struct zram *zram)
{
	size_t index;

	if (!zram->init_done)
		return;

	zram->init_done = 0;

	/* Free various per-device buffers */
	kfree(zram->compress_workmem);
	free_pages((unsigned long)zram->compress_buffer, 1);

	zram->compress_workmem = NULL;
	zram->compress_buffer = NULL;

	/* Free all pages that are still in this zram device */
	for (index = 0; index < zram->disksize >> PAGE_SHIFT; index++) {
		unsigned long handle = zram->table[index].handle;
		if (!handle)
			continue;

		zs_free(zram->mem_pool, handle);
	}

	vfree(zram->table);
	zram->table = NULL;

	zs_destroy_pool(zram->mem_pool);
	zram->mem_pool = NULL;

	/* Reset stats */
	memset(&zram->stats, 0, sizeof(zram->stats));

	zram->disksize = 0;
	set_capacity(zram->disk, 0);
}

void zram_reset_device(struct zram *zram)
{
	down_write(&zram->init_lock);
	__zram_reset_device(zram);
	up_write(&zram->init_lock);
}

/* zram->init_lock should be held */
int zram_init_device(struct zram *zram)
{
	int ret;
	size_t num_pages;

	if (zram->disksize > 2 * (totalram_pages << PAGE_SHIFT)) {
		pr_info(
		"There is little point creating a zram of greater than "
		"twice the size of memory since we expect a 2:1 compression "
		"ratio. Note that zram uses about 0.1%% of the size of "
		"the disk when not in use so a huge zram is "
		"wasteful.\n"
		"\tMemory Size: %lu kB\n"
		"\tSize you selected: %llu kB\n"
		"Continuing anyway ...\n",
		(totalram_pages << PAGE_SHIFT) >> 10, zram->disksize >> 10
		);
	}

	zram->compress_buffer =
		(void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, 1);
	if (!zram->compress_buffer) {
		pr_err("Error allocating compressor buffer space\n");
		ret = -ENOMEM;
		goto fail_no_table;
	}

	num_pages = zram->disksize >> PAGE_SHIFT;
	zram->table = vzalloc(num_pages * sizeof(*zram->table));
	if (!zram->table) {
		pr_err("Error allocating zram address table\n");
		ret = -ENOMEM;
		goto fail_no_table;
	}

	/* zram devices sort of resembles non-rotational disks */
	queue_flag_set_unlocked(QUEUE_FLAG_NONROT, zram->disk->queue);

	zram->mem_pool = zs_create_pool("zram", GFP_NOIO | __GFP_HIGHMEM);
	if (!zram->mem_pool) {
		pr_err("Error creating memory pool\n");
		ret = -ENOMEM;
		goto fail;
	}

	zram->init_done = 1;

	pr_debug("Initialization done!\n");
	return 0;

fail_no_table:
	/* To prevent accessing table entries during cleanup */
	zram->disksize = 0;
fail:
	__zram_reset_device(zram);
	pr_err("Initialization failed: err=%d\n", ret);
	return ret;
}

=======
>>>>>>> cm/cm-12.0:drivers/block/zram/zram_drv.c
static void zram_slot_free_notify(struct block_device *bdev,
				unsigned long index)
{
	struct zram *zram;
<<<<<<< HEAD:drivers/staging/zram/zram_drv.c

	zram = bdev->bd_disk->private_data;
	zram_free_page(zram, index);
	zram_stat64_inc(zram, &zram->stats.notify_free);
=======
	struct zram_meta *meta;

	zram = bdev->bd_disk->private_data;
	meta = zram->meta;

	bit_spin_lock(ZRAM_ACCESS, &meta->table[index].value);
	zram_free_page(zram, index);
	bit_spin_unlock(ZRAM_ACCESS, &meta->table[index].value);
	atomic64_inc(&zram->stats.notify_free);
>>>>>>> cm/cm-12.0:drivers/block/zram/zram_drv.c
}

static const struct block_device_operations zram_devops = {
	.swap_slot_free_notify = zram_slot_free_notify,
	.owner = THIS_MODULE
};

<<<<<<< HEAD:drivers/staging/zram/zram_drv.c
=======
static DEVICE_ATTR(disksize, S_IRUGO | S_IWUSR,
		disksize_show, disksize_store);
static DEVICE_ATTR(initstate, S_IRUGO, initstate_show, NULL);
static DEVICE_ATTR(reset, S_IWUSR, NULL, reset_store);
static DEVICE_ATTR(orig_data_size, S_IRUGO, orig_data_size_show, NULL);
static DEVICE_ATTR(mem_used_total, S_IRUGO, mem_used_total_show, NULL);
static DEVICE_ATTR(max_comp_streams, S_IRUGO | S_IWUSR,
		max_comp_streams_show, max_comp_streams_store);
static DEVICE_ATTR(comp_algorithm, S_IRUGO | S_IWUSR,
		comp_algorithm_show, comp_algorithm_store);

ZRAM_ATTR_RO(num_reads);
ZRAM_ATTR_RO(num_writes);
ZRAM_ATTR_RO(failed_reads);
ZRAM_ATTR_RO(failed_writes);
ZRAM_ATTR_RO(invalid_io);
ZRAM_ATTR_RO(notify_free);
ZRAM_ATTR_RO(zero_pages);
ZRAM_ATTR_RO(compr_data_size);

static struct attribute *zram_disk_attrs[] = {
	&dev_attr_disksize.attr,
	&dev_attr_initstate.attr,
	&dev_attr_reset.attr,
	&dev_attr_num_reads.attr,
	&dev_attr_num_writes.attr,
	&dev_attr_failed_reads.attr,
	&dev_attr_failed_writes.attr,
	&dev_attr_invalid_io.attr,
	&dev_attr_notify_free.attr,
	&dev_attr_zero_pages.attr,
	&dev_attr_orig_data_size.attr,
	&dev_attr_compr_data_size.attr,
	&dev_attr_mem_used_total.attr,
	&dev_attr_max_comp_streams.attr,
	&dev_attr_comp_algorithm.attr,
	NULL,
};

static struct attribute_group zram_disk_attr_group = {
	.attrs = zram_disk_attrs,
};

>>>>>>> cm/cm-12.0:drivers/block/zram/zram_drv.c
static int create_device(struct zram *zram, int device_id)
{
	int ret = 0;

	init_rwsem(&zram->init_lock);
<<<<<<< HEAD:drivers/staging/zram/zram_drv.c
	spin_lock_init(&zram->stat64_lock);
=======
>>>>>>> cm/cm-12.0:drivers/block/zram/zram_drv.c

	zram->queue = blk_alloc_queue(GFP_KERNEL);
	if (!zram->queue) {
		pr_err("Error allocating disk queue for device %d\n",
			device_id);
		ret = -ENOMEM;
		goto out;
	}

	blk_queue_make_request(zram->queue, zram_make_request);
	zram->queue->queuedata = zram;

	 /* gendisk structure */
	zram->disk = alloc_disk(1);
	if (!zram->disk) {
		blk_cleanup_queue(zram->queue);
		pr_warn("Error allocating disk structure for device %d\n",
			device_id);
		ret = -ENOMEM;
		goto out;
	}

	zram->disk->major = zram_major;
	zram->disk->first_minor = device_id;
	zram->disk->fops = &zram_devops;
	zram->disk->queue = zram->queue;
	zram->disk->private_data = zram;
	snprintf(zram->disk->disk_name, 16, "zram%d", device_id);

	/* Actual capacity set using syfs (/sys/block/zram<id>/disksize */
	set_capacity(zram->disk, 0);
	/* zram devices sort of resembles non-rotational disks */
	queue_flag_set_unlocked(QUEUE_FLAG_NONROT, zram->disk->queue);
	/*
	 * To ensure that we always get PAGE_SIZE aligned
	 * and n*PAGE_SIZED sized I/O requests.
	 */
	blk_queue_physical_block_size(zram->disk->queue, PAGE_SIZE);
	blk_queue_logical_block_size(zram->disk->queue,
					ZRAM_LOGICAL_BLOCK_SIZE);
	blk_queue_io_min(zram->disk->queue, PAGE_SIZE);
	blk_queue_io_opt(zram->disk->queue, PAGE_SIZE);
	zram->disk->queue->limits.discard_granularity = PAGE_SIZE;
	zram->disk->queue->limits.max_discard_sectors = UINT_MAX;
	/*
	 * zram_bio_discard() will clear all logical blocks if logical block
	 * size is identical with physical block size(PAGE_SIZE). But if it is
	 * different, we will skip discarding some parts of logical blocks in
	 * the part of the request range which isn't aligned to physical block
	 * size.  So we can't ensure that all discarded logical blocks are
	 * zeroed.
	 */
	if (ZRAM_LOGICAL_BLOCK_SIZE == PAGE_SIZE)
		zram->disk->queue->limits.discard_zeroes_data = 1;
	else
		zram->disk->queue->limits.discard_zeroes_data = 0;
	queue_flag_set_unlocked(QUEUE_FLAG_DISCARD, zram->disk->queue);

	add_disk(zram->disk);

	ret = sysfs_create_group(&disk_to_dev(zram->disk)->kobj,
				&zram_disk_attr_group);
	if (ret < 0) {
		pr_warn("Error creating sysfs group");
		goto out;
	}
<<<<<<< HEAD:drivers/staging/zram/zram_drv.c

	zram->init_done = 0;
=======
	strlcpy(zram->compressor, default_compressor, sizeof(zram->compressor));
	zram->meta = NULL;
	zram->max_comp_streams = 1;
	return 0;
>>>>>>> cm/cm-12.0:drivers/block/zram/zram_drv.c

out:
	return ret;
}

static void destroy_device(struct zram *zram)
{
	sysfs_remove_group(&disk_to_dev(zram->disk)->kobj,
			&zram_disk_attr_group);

	if (zram->disk) {
		del_gendisk(zram->disk);
		put_disk(zram->disk);
	}

	if (zram->queue)
		blk_cleanup_queue(zram->queue);
}

unsigned int zram_get_num_devices(void)
{
	return num_devices;
}

static int __init zram_init(void)
{
	int ret, dev_id;

	/* Initialize Cryptographic API */
	pr_info("Loading Crypto API features\n");
	if (zram_comp_init()) {
		pr_err("Compressor initialization failed\n");
		ret = -ENOMEM;
		goto out;
	}

	if (zram_cpu_init()) {
		pr_err("Per-cpu initialization failed\n");
		ret = -ENOMEM;
		goto free_comp;
	}

	if (num_devices > max_num_devices) {
		pr_warn("Invalid value for num_devices: %u\n",
				num_devices);
		ret = -EINVAL;
		goto free_cpu_comp;
	}

	zram_major = register_blkdev(0, "zram");
	if (zram_major <= 0) {
		pr_warn("Unable to get major number\n");
		ret = -EBUSY;
		goto free_cpu_comp;
	}

	/* Allocate the device array and initialize each one */
	zram_devices = kzalloc(num_devices * sizeof(struct zram), GFP_KERNEL);
	if (!zram_devices) {
		ret = -ENOMEM;
		goto unregister;
	}

	for (dev_id = 0; dev_id < num_devices; dev_id++) {
		ret = create_device(&zram_devices[dev_id], dev_id);
		if (ret)
			goto free_devices;
	}

	pr_info("Created %u device(s) ...\n", num_devices);

	return 0;

free_devices:
	while (dev_id)
		destroy_device(&zram_devices[--dev_id]);
	kfree(zram_devices);
unregister:
	unregister_blkdev(zram_major, "zram");
free_cpu_comp:
	zram_comp_cpus_down();
free_comp:
	zram_comp_exit();
out:
	return ret;
}

static void __exit zram_exit(void)
{
	int i;
	struct zram *zram;

	for (i = 0; i < num_devices; i++) {
		zram = &zram_devices[i];

		destroy_device(zram);
		zram_reset_device(zram);
	}

	unregister_blkdev(zram_major, "zram");

	kfree(zram_devices);
	zram_comp_cpus_down();
	zram_comp_exit();
	pr_debug("Cleanup done!\n");
}

module_param(num_devices, uint, 0);
MODULE_PARM_DESC(num_devices, "Number of zram devices");

module_init(zram_init);
module_exit(zram_exit);

module_param_named(compressor, zram_compressor, charp, 0);
MODULE_PARM_DESC(compressor, "Compressor type");

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Nitin Gupta <ngupta@vflare.org>");
MODULE_DESCRIPTION("Compressed RAM Block Device");
