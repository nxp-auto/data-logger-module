/*
 * Copyright 2018-2021 NXP
 *
 * SPDX-License-Identifier: GPL-2.0
 *
 */
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/uio.h>
#include <linux/slab.h>
#include <linux/gfp.h>
#include <linux/kref.h>
#include <linux/time.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/mman.h>
#include <linux/kallsyms.h>
#include <linux/falloc.h>

#include "bbox_file.h"

#define BBOX_FILE_STAT
//#define BBOX_FILE_LOG

#define NAME_SIZE 20
#define MAX_AIO_REQ_NUM 1024
#define MAX_AIO_BUFF_LEN (0x20000)
#define ALLOCATED_FILE_LEN (0x80000000)
#define PATH_BUF_SIZE 1024
#define AIO_REQ_BUSY_FLAG 0x1

struct aio_req {
	uint32_t len;
	uint32_t flags;
	void *buff;
	struct bbox_file *bfile;
	struct kiocb iocb;
};

#define BBOX_FILE_CLOSED 0
#define BBOX_FILE_OPEN 1
struct bbox_file {
	uint16_t state; /*CLOSED, CLOSING*/
	struct file *fp;
	struct file *s_fp;
	char name[NAME_SIZE];
	struct aio_req *curr_req;
	loff_t pos;
	struct bbox_ioctx *ioctx;
};

struct bbox_ioctx {
	atomic_t refcount;
	uint16_t free_head;
	uint16_t req_num;
	struct aio_req *reqs;
	void *cache;
	struct bbox_file bfile;
	char path_buf[PATH_BUF_SIZE];
#ifdef BBOX_FILE_STAT
	struct {
		uint32_t open_cnt;
		uint32_t close_cnt;
		uint64_t write_cnt;
		uint64_t complete_cnt;
		uint64_t queue_cnt;
	} stat;
#endif
};

struct {
	const char *path;
	const char *s_path;
	struct file *logfp;
	struct file *s_logfp;
	uint16_t max_file_num;
} g_bbox_file_d;

#define LOCAL_VAL_NUM 1
#define LOCAL_TASK_NUM 2
struct task_local_storage {
	atomic_t used;
	long task;
	long val[LOCAL_VAL_NUM];
} g_tls[LOCAL_TASK_NUM];

struct aio_req *new_aio_req(struct bbox_file * bfile);
int bbox_file_aio_submit(struct bbox_file *bfile);


#define SET_LOCAL_VAL(key, val) set_local_val((key), (val))
#define GET_LOCAL_VAL(key) get_local_val(key)

static void local_val_init(void)
{
	int i;

	for (i = 0; i < LOCAL_TASK_NUM; i++)
		atomic_set(&g_tls[i].used, 0);
}

static long set_local_val(int key, long val)
{
	long old_val = 0;
	long task = (long)current;
	int i;

	if (key >= LOCAL_VAL_NUM)
		return 0;
	
	for (i = 0; i < LOCAL_TASK_NUM; i++) {
		if (atomic_inc_return(&g_tls[i].used) == 1) {
			g_tls[i].task = task;
			g_tls[i].val[key] = val;
			break;
		}
		atomic_dec(&g_tls[i].used);
		if (task == g_tls[i].task) {
			old_val = g_tls[i].val[key];
			g_tls[i].val[key] = val;
			break;
		}
	}

	return old_val;
}

static long get_local_val(int key)
{
	long task = (long)current;
	int i;

	if (key >= LOCAL_VAL_NUM)
		return 0;
	
	for (i = 0; i < LOCAL_TASK_NUM; i++) {
		if (atomic_read(&g_tls[i].used) > 0 
			&& g_tls[i].task == task) {
			return g_tls[i].val[key];
		}
	}
	
	return 0;
}

int bbox_file_create_ioctx(struct bbox_ioctx **ioctx)
{
	struct bbox_ioctx *ctx = kzalloc(sizeof(struct bbox_ioctx), GFP_KERNEL);
	int ret;
	
	if (!ctx) {
		pr_warn("%s: kmalloc fail\n", __FUNCTION__);
		return -ENOMEM;
	}

	ctx->req_num = MAX_AIO_REQ_NUM;
	ctx->reqs = kzalloc(sizeof(struct aio_req) * MAX_AIO_REQ_NUM, GFP_KERNEL);
	if (!ctx->reqs) {
		pr_warn("kzalloc aio_req fail\n");
		goto L_free_ctx;
	}
	
	ctx->cache = (void*)vm_mmap(NULL, 0, MAX_AIO_BUFF_LEN * MAX_AIO_REQ_NUM,
			       PROT_READ|PROT_WRITE,
			       MAP_PRIVATE, 0);
	if (IS_ERR_OR_NULL(ctx->cache)) {
		pr_warn("vm_mmap().ret = %d\n", PTR_ERR_OR_ZERO(ctx->cache));
		goto L_free_reqs;
	}
	
	atomic_set(&ctx->refcount, 1);
	
	if (ioctx)
		*ioctx = ctx;
	SET_LOCAL_VAL(0, (long)ctx);
	pr_info("%s: create ioctx: %lx\n", __FUNCTION__, (long)ctx);
	return 0;
	
L_free_reqs:
	kfree(ctx->reqs);
L_free_ctx:
	kfree(ctx);
	return ret;
}

void bbox_file_destory_ioctx(struct bbox_ioctx *ioctx)
{
	struct bbox_ioctx *ctx = (void*)GET_LOCAL_VAL(0);
	
	if (ioctx != 0 && ioctx != ctx) {
		pr_warn("Invalid ioctx %lx\n", (long)ioctx);
		return;
	}
	
	pr_info("%s: destroy ioctx: %lx\n", __FUNCTION__, (long)ctx);
	
	/* wait all IO finish */	
	while (atomic_read(&ctx->refcount) != 1)
		schedule_timeout(1);
	atomic_set(&ctx->refcount, 0);
	
	vm_munmap((unsigned long)ctx->cache, MAX_AIO_BUFF_LEN * MAX_AIO_REQ_NUM);
	kfree(ctx->reqs);

#ifdef BBOX_FILE_STAT
	pr_warn("open_cnt = %u", ctx->stat.open_cnt);
	pr_warn("close_cnt = %u", ctx->stat.close_cnt);
	pr_warn("write_cnt = %llu", ctx->stat.write_cnt);
	pr_warn("queue_cnt = %llu", ctx->stat.queue_cnt);
	pr_warn("complete_cnt = %llu\n", ctx->stat.complete_cnt);
#endif
	kfree(ctx);
}

static int kernel_stat(const char *name, struct kstat *stat)
{
	mm_segment_t old_fs;
	ssize_t res;

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	/* The cast to a user pointer is valid due to the set_fs() */
	res = vfs_stat((__force const char __user *)name, stat);
	set_fs(old_fs);
	return res;
}


static bool is_dir(const char *path)
{
	struct kstat stat;

	if (kernel_stat(path, &stat) < 0)
		return false;
	return S_ISDIR(stat.mode)? true : false;
}

#ifdef BBOX_FILE_LOG
static int bbox_file_log(void *buf, int size, const char *fmt, ...)
{
	if (g_bbox_file_d.logfp) {
		struct timespec64 ts;
		va_list args;
		int len;
		
		/* format log */
		ktime_get_real_ts64(&ts);
		len = snprintf(buf, size, "[%llu.%09lu]", ts.tv_sec, ts.tv_nsec);
		va_start(args, fmt);
		len += vsnprintf(buf + len, size - len, fmt, args);
		va_end(args);
			
		(void)kernel_write(g_bbox_file_d.logfp, buf, len, &g_bbox_file_d.logfp->f_pos);
		if (g_bbox_file_d.s_logfp)
			(void)kernel_write(g_bbox_file_d.s_logfp, buf, len, &g_bbox_file_d.s_logfp->f_pos);
		return len;
	}
	return 0;
}
#endif

int bbox_file_init(unsigned int max_num, const char *path, const char *secure_path, const char *log_filename)
{	
	if (max_num == 0
		|| !path
		|| max_num > 256)
		return -EINVAL;
	
	if (!is_dir(path))
		return -ENOTDIR;
	if (secure_path && !is_dir(secure_path))
		return -ENOTDIR;

	if (g_bbox_file_d.max_file_num > 0)
		return -EALREADY;

	local_val_init();
	
	g_bbox_file_d.path = kstrdup(path, GFP_KERNEL);
	if (secure_path)
		g_bbox_file_d.s_path = kstrdup(secure_path, GFP_KERNEL);

#ifdef BBOX_FILE_LOG
	if (log_filename) {
		char *buff = kmalloc(PATH_BUF_SIZE, GFP_KEREL);
		
		snprintf(buff, PATH_BUF_SIZE, "%s/%s", path, log_filename);
		g_bbox_file_d.logfp = filp_open(buff, O_CREAT|O_WRONLY|O_APPEND, 0644);

		if (secure_path) {
			snprintf(buff, PATH_BUF_SIZE, "%s/%s", secure_path, log_filename);
			g_bbox_file_d.s_logfp = filp_open(buff, O_CREAT|O_WRONLY|O_APPEND, 0644);
		}
		bbox_file_log(buff, PATH_BUF_SIZE, "Init\n");
		kfree(buff);
	}
#endif

	g_bbox_file_d.max_file_num = max_num;
	return 0;
}

void bbox_file_uninit(void)
{
#ifdef BBOX_FILE_LOG
	char path[100];
#endif

	if (g_bbox_file_d.max_file_num == 0)
		return;
	
	pr_info("bbox_file_uninit\n");
#ifdef BBOX_FILE_LOG
	bbox_file_log(path, 100, "Uninit\n");

	if (g_bbox_file_d.logfp) {
		filp_close(g_bbox_file_d.logfp, NULL);
		g_bbox_file_d.logfp = NULL;
	}
	if (g_bbox_file_d.s_logfp) {
		filp_close(g_bbox_file_d.s_logfp, NULL);
		g_bbox_file_d.s_logfp = NULL;
	}
#endif
	g_bbox_file_d.max_file_num = 0;
		
	kfree(g_bbox_file_d.path);
	g_bbox_file_d.path = NULL;
	
	kfree(g_bbox_file_d.s_path);
	g_bbox_file_d.s_path = NULL;
}

static void delete_aio_req(struct aio_req *req)
{
	struct bbox_file * bfile = req->bfile;

	req->flags = 0;
	atomic_dec(&bfile->ioctx->refcount);
}

struct bbox_file *bbox_file_open(const char *filename, int flags)
{
	struct bbox_ioctx *ctx = (void*)GET_LOCAL_VAL(0);
	struct bbox_file *bfile = &ctx->bfile;
#ifdef BBOX_FILE_LOG
	char buff[NAME_SIZE + 100];
#endif

	if (!filename)
		return NULL;

	//pr_info("%s: ioctx: %lx\n", __FUNCTION__, (long)ctx);
	
	if (bfile->state != BBOX_FILE_CLOSED) {
		pr_warn("%s: only support one file is opened\n", __FUNCTION__);
		return NULL;
	}
	
	snprintf(ctx->path_buf, PATH_BUF_SIZE, "%s/%s", g_bbox_file_d.path, filename);
	bfile->fp = filp_open(ctx->path_buf, O_CREAT|O_RDWR|O_TRUNC|O_DIRECT, 0644);
	bfile->s_fp = NULL;
	if (g_bbox_file_d.s_path) {
		snprintf(ctx->path_buf, PAGE_SIZE, "%s/%s", g_bbox_file_d.s_path, filename);
		bfile->s_fp = filp_open(ctx->path_buf, O_CREAT|O_RDWR|O_TRUNC, 0644);
	}
#ifdef BBOX_FILE_STAT
	ctx->stat.open_cnt++;
#endif
	if (IS_ERR_OR_NULL(bfile->fp)) {
		pr_warn("open file error %d\n", PTR_ERR_OR_ZERO(bfile->fp));
		return NULL;
	}
	
#ifdef BBOX_FILE_LOG
	bbox_file_log(buff, sizeof(buff), "Create,%s\n", filename);
#endif

	strncpy(bfile->name, filename, NAME_SIZE);
	bfile->name[NAME_SIZE-1] = 0;
	bfile->curr_req = NULL;
	bfile->pos = 0;
	bfile->state = BBOX_FILE_OPEN;
	bfile->ioctx = ctx;
	return bfile;
}
EXPORT_SYMBOL(bbox_file_open);

static void copy_to_file_cache(void *cache, const void *from, unsigned long n)
{
	if (_copy_to_user(cache, from, n))
		;
}

int bbox_file_write(struct bbox_file *bfile, const void *buff, unsigned int size)
{
	ssize_t res = size;
	int ret;
	uint32_t len;
	
	if (!bfile->curr_req) {
		bfile->curr_req = new_aio_req(bfile);
		if (!bfile->curr_req)
			return -ENOMEM;
	}

	while ((size + bfile->curr_req->len) > MAX_AIO_BUFF_LEN) {
		if (bfile->curr_req->len < MAX_AIO_BUFF_LEN) {
			copy_to_file_cache(bfile->curr_req->buff + bfile->curr_req->len,
					buff, (MAX_AIO_BUFF_LEN - bfile->curr_req->len));
			bfile->curr_req->len = MAX_AIO_BUFF_LEN;
			buff += (MAX_AIO_BUFF_LEN - bfile->curr_req->len);
			size -= (MAX_AIO_BUFF_LEN - bfile->curr_req->len);
		}
		len = bfile->curr_req->len;
		ret = bbox_file_aio_submit(bfile);
		if (ret < 0)
			return ret;
		bfile->pos += len;
		bfile->curr_req = new_aio_req(bfile);
		if (!bfile->curr_req)
			return -ENOMEM;
	}
	
	copy_to_file_cache(bfile->curr_req->buff + bfile->curr_req->len,
				buff, size);
	bfile->curr_req->len += size;
	return (int)res;
}
EXPORT_SYMBOL(bbox_file_write);

int bbox_file_close(struct bbox_file *bfile)
{
#ifdef BBOX_FILE_LOG
	char buff[NAME_SIZE + 100];
#endif
	
	if (unlikely(!bfile || bfile->state == BBOX_FILE_CLOSED))
		return -EINVAL;

	//pr_info("%s: ioctx: %lx\n", __FUNCTION__, (long)bfile->ioctx);

#ifdef BBOX_FILE_STAT
	bfile->ioctx->stat.close_cnt++;
#endif

#ifdef BBOX_FILE_LOG
	bbox_file_log(buff, sizeof(buff), "Close,%s,%lu\n", bfile->name, bfile->fp->f_pos);
#endif

	if (bfile->curr_req) {
		/* submit or release requstion */
		if (bfile->curr_req->len) {
			if (bbox_file_aio_submit(bfile) < 0)
				delete_aio_req(bfile->curr_req);
			else
				bfile->pos += bfile->curr_req->len;
		} else
			delete_aio_req(bfile->curr_req);
	}
	
	filp_close(bfile->fp, NULL);
	if (bfile->s_fp)
		filp_close(bfile->s_fp, NULL);
	bfile->state = BBOX_FILE_CLOSED;
	return 0;
}
EXPORT_SYMBOL(bbox_file_close);

uint64_t bbox_file_pos(struct bbox_file *bfile)
{
	return bfile->pos;
}
EXPORT_SYMBOL(bbox_file_pos);

static void aio_complete_rw(struct kiocb *kiocb, long res, long res2)
{
	struct aio_req *req = container_of(kiocb, struct aio_req, iocb);
	
	if (kiocb->ki_flags & IOCB_WRITE) {
		struct inode *inode = file_inode(kiocb->ki_filp);

		/*
		 * Tell lockdep we inherited freeze protection from submission
		 * thread.
		 */
		if (S_ISREG(inode->i_mode))
			__sb_writers_acquired(inode->i_sb, SB_FREEZE_WRITE);
		file_end_write(kiocb->ki_filp);
	}
	fput(kiocb->ki_filp);
	delete_aio_req(req);
#ifdef BBOX_FILE_STAT
	req->bfile->ioctx->stat.complete_cnt++;
#endif
}

struct aio_req *new_aio_req(struct bbox_file * bfile)
{
	struct bbox_ioctx *ctx = bfile->ioctx;
	struct aio_req *req = &ctx->reqs[ctx->free_head];
	
	while (req->flags & AIO_REQ_BUSY_FLAG)
		schedule_timeout(1);

	req->buff = ctx->cache + (uint32_t)MAX_AIO_BUFF_LEN * ctx->free_head;
	ctx->free_head = (ctx->free_head + 1) & (ctx->req_num - 1);
	
	req->flags = AIO_REQ_BUSY_FLAG;
	req->len = 0;
	req->bfile = bfile;
	init_sync_kiocb(&req->iocb, bfile->fp);
	req->iocb.ki_flags &= ~IOCB_HIPRI;
	req->iocb.ki_pos = bfile->pos;
	req->iocb.ki_complete = aio_complete_rw;
	req->iocb.private = NULL;
	atomic_inc(&bfile->ioctx->refcount);
	return req;
}

struct aio_req *new_s_aio_req(struct bbox_file * bfile, struct aio_req *req)
{
	struct bbox_ioctx *ctx = bfile->ioctx;
	struct aio_req *s_req = &ctx->reqs[ctx->free_head];
	
	while (req->flags & AIO_REQ_BUSY_FLAG)
		schedule_timeout(1);
	ctx->free_head = (ctx->free_head + 1) & (ctx->req_num - 1);
	memcpy(s_req, req, sizeof(*req));
	s_req->iocb.ki_filp = bfile->s_fp;
	atomic_inc(&bfile->ioctx->refcount);
	return req;
}

static int aio_write_submit(struct aio_req *req)
{
	struct iovec iov = { .iov_base = (void __user *)req->buff, .iov_len = req->len};
	struct iov_iter iter;
	struct file *file;
	int ret;
#ifdef BBOX_FILE_STAT
	struct bbox_ioctx *ctx = req->bfile->ioctx;
	
	ctx->stat.write_cnt++;
#endif
	req->iocb.ki_flags |= WRITE;
	iov_iter_init(&iter, WRITE, &iov, 1, req->len);
	file = req->iocb.ki_filp;

	/*
	 * Open-code file_start_write here to grab freeze protection,
	 * which will be released by another thread in
	 * aio_complete_rw().  Fool lockdep by telling it the lock got
	 * released so that it doesn't complain about the held lock when
	 * we return to userspace.
	 */
	if (S_ISREG(file_inode(file)->i_mode)) {
		__sb_start_write(file_inode(file)->i_sb, SB_FREEZE_WRITE, true);
		__sb_writers_release(file_inode(file)->i_sb, SB_FREEZE_WRITE);
	}
	req->iocb.ki_flags |= IOCB_WRITE;
	req->iocb.ki_flags |= 1<<30;
	if (req->len & (512-1))
		req->iocb.ki_flags &= ~(IOCB_DIRECT | IOCB_NOWAIT);

	get_file(file);
	
	/* increase inode->i_size for aio */
	i_size_write(file_inode(file), req->iocb.ki_pos + req->len);
	ret = call_write_iter(file, &req->iocb, &iter);
	
	if (ret > 0) {
		req->iocb.ki_complete(&req->iocb, ret, 0);
		return ret;
	}
	if (ret == -EIOCBQUEUED) {
		#ifdef BBOX_FILE_STAT
		ctx->stat.queue_cnt++;
		#endif
		return iov.iov_len;
	}
	fput(file);
	pr_warn("aio req.ret = %d\n", (int)ret);
	return ret;	
}

int bbox_file_aio_submit(struct bbox_file *bfile)
{
	int s_ret;
	struct aio_req *s_req;
	
	if (unlikely(bfile->s_fp)) {
		s_req = new_s_aio_req(bfile, bfile->curr_req);
		if (s_req) {
			s_ret = aio_write_submit(s_req);
			if (s_ret < 0)
				delete_aio_req(s_req);
		}		
	}
	
	return aio_write_submit(bfile->curr_req);
}

