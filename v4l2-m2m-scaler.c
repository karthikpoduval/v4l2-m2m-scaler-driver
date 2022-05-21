// SPDX-License-Identifier: GPL-2.0+
/*
 * Virtual (QEMU based) mem-2-mem scaler device driver
 * based on ima-m2m_scaler.c
 *
 * Copyright (c) 2022 Karthik Poduval <karthik.poduval@gmail.com>
 */

#include <linux/module.h>
#include <linux/platform_device.h>
#include <media/v4l2-mem2mem.h>
#include <media/v4l2-device.h>
#include <media/v4l2-ioctl.h>
#include <media/v4l2-common.h>
#include <media/videobuf2-dma-contig.h>
#include <media/v4l2-event.h>


#define MEM2MEM_NAME		"virtual-v4l2-m2m-scaler"

// the only suported format by M2M Scaler
#define FORMAT V4L2_PIX_FMT_RGB24

#define MAX_WIDTH (1400) 
#define MAX_HEIGHT (800) 

#define FMT_OUTPUT	(0)
#define FMT_CAPTURE	(1)
#define FMT_MAX	(2)

#define DEFAULT_WIDTH	(640)
#define DEFAULT_HEIGHT	(480)

static int debug;
module_param(debug, int, 0644);
MODULE_PARM_DESC(debug, "debug level (0-3)");

struct m2m_scaler {
	struct v4l2_device	v4l2_dev;
	struct video_device	video_dev;
	void __iomem		*mmio;
	struct v4l2_m2m_dev	*m2m_dev;
	struct mutex 		lock;
};

struct m2m_scaler_ctx {	
	struct v4l2_fh		fh;
	struct m2m_scaler	*device;
	struct v4l2_format 	fmt[2];
	uint64_t 		sequence;
};


static inline struct m2m_scaler_ctx *file2ctx(struct file *file)
{
	return container_of(file->private_data, struct m2m_scaler_ctx, fh);
}


/*
 * mem2mem callbacks
 */
static void m2m_scaler_device_run(void *priv)
{
	struct m2m_scaler_ctx *ctx = priv;
	struct vb2_v4l2_buffer *src_buf, *dst_buf;

	src_buf = v4l2_m2m_next_src_buf(ctx->fh.m2m_ctx);
	dst_buf = v4l2_m2m_next_dst_buf(ctx->fh.m2m_ctx);

	/* program the scaler to start */
}

static irqreturn_t m2m_scaler_irq_handler(int irq, void *dev_id)
{

	return IRQ_HANDLED;
}

static struct v4l2_format* m2m_scaler_get_format(struct m2m_scaler_ctx *ctx, enum v4l2_buf_type type)
{
	struct m2m_scaler *device = ctx->device;
	struct v4l2_device *v4l2_dev = &device->v4l2_dev;

	switch (type) {
		case V4L2_BUF_TYPE_VIDEO_OUTPUT:
			return &ctx->fmt[FMT_OUTPUT];

		case V4L2_BUF_TYPE_VIDEO_CAPTURE:
			return &ctx->fmt[FMT_CAPTURE];

		default:
			v4l2_err(v4l2_dev, "Unknown type \n");
			return ERR_PTR(-EINVAL);
	}
}

/*
 * video ioctls
 */
static int m2m_scaler_querycap(struct file *file, void *priv,
			   struct v4l2_capability *cap)
{
	strscpy(cap->driver, MEM2MEM_NAME, sizeof(cap->driver));
	strscpy(cap->card, MEM2MEM_NAME, sizeof(cap->card));
	snprintf(cap->bus_info, sizeof(cap->bus_info),
			"platform:%s", MEM2MEM_NAME);
	return 0;
}
static int m2m_scaler_try_fmt(struct file *file, void*priv, struct v4l2_format *f)
{
	if(f->fmt.pix.pixelformat != FORMAT)
		f->fmt.pix.pixelformat = FORMAT;

	if(f->fmt.pix.width > MAX_WIDTH)
		f->fmt.pix.width = MAX_WIDTH;
	
	if(f->fmt.pix.height > MAX_HEIGHT)
		f->fmt.pix.width = MAX_HEIGHT;

	return 0;
}
static int m2m_scaler_enum_fmt(struct file *file, void *priv,
				struct v4l2_fmtdesc *f)
{
	struct m2m_scaler_ctx *ctx = (struct m2m_scaler_ctx *) priv;
	struct v4l2_format *fmt;
	
	fmt = m2m_scaler_get_format(ctx, f->type);

	if(IS_ERR(fmt))
		return -EINVAL;

	/* only one format supported */
	if(f->index > 1)
		return -EINVAL;
	
	f->pixelformat = FORMAT;

	return 0;	
}

static int m2m_scaler_g_fmt(struct file *file, void *priv,
				struct v4l2_format *f)
{
	struct m2m_scaler_ctx *ctx = (struct m2m_scaler_ctx *) priv;
	struct v4l2_format *fmt;

	fmt = m2m_scaler_get_format(ctx, f->type);

	if(IS_ERR(fmt))
		return -EINVAL;

	f->fmt.pix = fmt->fmt.pix;
	
	return 0;	
}

static int m2m_scaler_s_fmt(struct file *file, void *priv,
			     struct v4l2_format *f)
{
	struct m2m_scaler_ctx *ctx = (struct m2m_scaler_ctx *) priv;
	struct v4l2_format *fmt;
	
	m2m_scaler_try_fmt(file, priv, f);

	fmt = m2m_scaler_get_format(ctx, f->type);

	if(IS_ERR(fmt))
		return -EINVAL;

	fmt->fmt.pix = f->fmt.pix;

	return 0;	
}



static const struct v4l2_ioctl_ops m2m_scaler_ioctl_ops = {
	.vidioc_querycap	= m2m_scaler_querycap,

	.vidioc_enum_fmt_vid_cap = m2m_scaler_enum_fmt,
	.vidioc_g_fmt_vid_cap	= m2m_scaler_g_fmt,
	.vidioc_try_fmt_vid_cap	= m2m_scaler_try_fmt,
	.vidioc_s_fmt_vid_cap	= m2m_scaler_s_fmt,

	.vidioc_enum_fmt_vid_out = m2m_scaler_enum_fmt,
	.vidioc_g_fmt_vid_out	= m2m_scaler_g_fmt,
	.vidioc_try_fmt_vid_out	= m2m_scaler_try_fmt,
	.vidioc_s_fmt_vid_out	= m2m_scaler_s_fmt,

	.vidioc_reqbufs		= v4l2_m2m_ioctl_reqbufs,
	.vidioc_querybuf	= v4l2_m2m_ioctl_querybuf,
	.vidioc_qbuf		= v4l2_m2m_ioctl_qbuf,
	.vidioc_dqbuf		= v4l2_m2m_ioctl_dqbuf,
	.vidioc_prepare_buf	= v4l2_m2m_ioctl_prepare_buf,
	.vidioc_create_bufs	= v4l2_m2m_ioctl_create_bufs,
	.vidioc_expbuf		= v4l2_m2m_ioctl_expbuf,

	.vidioc_streamon	= v4l2_m2m_ioctl_streamon,
	.vidioc_streamoff	= v4l2_m2m_ioctl_streamoff,

	//.vidioc_subscribe_event = v4l2_ctrl_subscribe_event,
	//.vidioc_unsubscribe_event = v4l2_event_unsubscribe,
};


/*
 * Queue operations
 */
static int m2m_scaler_queue_setup(struct vb2_queue *vq,
			   unsigned int *nbuffers, unsigned int *nplanes,
			   unsigned int sizes[], struct device *alloc_devs[])
{
	struct m2m_scaler_ctx *ctx = vb2_get_drv_priv(vq);
	struct m2m_scaler *device = ctx->device;
	struct v4l2_device *v4l2_dev = &device->v4l2_dev;
	unsigned int count = *nbuffers;

	struct v4l2_format *fmt;

	fmt = m2m_scaler_get_format(ctx, vq->type);
	if(IS_ERR(fmt))
		return -EINVAL;

	*nplanes = 1;	
	sizes[0] = fmt->fmt.pix.sizeimage;

	v4l2_dbg(1, debug, v4l2_dev, "get %d buffer(s) of size %d each.\n", count, sizes[0]);

	return 0;
}

static int m2m_scaler_buf_prepare(struct vb2_buffer *vb)
{
	struct m2m_scaler_ctx *ctx = vb2_get_drv_priv(vb->vb2_queue);
	struct m2m_scaler *device = ctx->device;
	struct v4l2_device *v4l2_dev = &device->v4l2_dev;

	struct v4l2_format *fmt;

	fmt = m2m_scaler_get_format(ctx, vb->type);
	if(IS_ERR(fmt))
		return -EINVAL;


	v4l2_dbg(1, debug, v4l2_dev, "type: %d\n", vb->vb2_queue->type);

	vb2_set_plane_payload(vb, 0, fmt->fmt.pix.sizeimage);

	return 0;
}

static void m2m_scaler_buf_queue(struct vb2_buffer *vb)
{
	struct vb2_v4l2_buffer *vbuf = to_vb2_v4l2_buffer(vb);
	struct m2m_scaler_ctx *ctx = vb2_get_drv_priv(vb->vb2_queue);

	v4l2_m2m_buf_queue(ctx->fh.m2m_ctx, vbuf);
}

static int m2m_scaler_start_streaming(struct vb2_queue *q, unsigned int count)
{
	struct m2m_scaler_ctx *ctx = vb2_get_drv_priv(q);

	ctx->sequence = 0;
	return 0;
}

static void m2m_scaler_stop_streaming(struct vb2_queue *q)
{
	struct m2m_scaler_ctx *ctx = vb2_get_drv_priv(q);
	struct vb2_v4l2_buffer *vbuf;

	for (;;) {
		if (V4L2_TYPE_IS_OUTPUT(q->type))
			vbuf = v4l2_m2m_src_buf_remove(ctx->fh.m2m_ctx);
		else
			vbuf = v4l2_m2m_dst_buf_remove(ctx->fh.m2m_ctx);
		if (vbuf == NULL)
			return;
		v4l2_m2m_buf_done(vbuf, VB2_BUF_STATE_ERROR);
	}
}

static const struct vb2_ops m2m_scaler_qops = {
	.queue_setup	 = m2m_scaler_queue_setup,
	.buf_prepare	 = m2m_scaler_buf_prepare,
	.buf_queue	 = m2m_scaler_buf_queue,
	.start_streaming = m2m_scaler_start_streaming,
	.stop_streaming  = m2m_scaler_stop_streaming,
	.wait_prepare	 = vb2_ops_wait_prepare,
	.wait_finish	 = vb2_ops_wait_finish,
};

static int queue_init(void *priv, struct vb2_queue *src_vq,
		      struct vb2_queue *dst_vq)
{
	struct m2m_scaler_ctx *ctx = priv;
	int ret;

	src_vq->type = V4L2_BUF_TYPE_VIDEO_OUTPUT;
	src_vq->io_modes = VB2_MMAP | VB2_DMABUF;
	src_vq->drv_priv = ctx;
	src_vq->buf_struct_size = sizeof(struct v4l2_m2m_buffer);
	src_vq->ops = &m2m_scaler_qops;
	src_vq->mem_ops = &vb2_dma_contig_memops;
	src_vq->timestamp_flags = V4L2_BUF_FLAG_TIMESTAMP_COPY;
	src_vq->lock = &ctx->device->lock;
	src_vq->dev = ctx->device->v4l2_dev.dev;

	ret = vb2_queue_init(src_vq);
	if (ret)
		return ret;

	dst_vq->type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	dst_vq->io_modes = VB2_MMAP | VB2_DMABUF;
	dst_vq->drv_priv = ctx;
	dst_vq->buf_struct_size = sizeof(struct v4l2_m2m_buffer);
	dst_vq->ops = &m2m_scaler_qops;
	dst_vq->mem_ops = &vb2_dma_contig_memops;
	dst_vq->timestamp_flags = V4L2_BUF_FLAG_TIMESTAMP_COPY;
	dst_vq->lock = &ctx->device->lock;
	dst_vq->dev = ctx->device->v4l2_dev.dev;

	return vb2_queue_init(dst_vq);
}

/*
 * File operations
 */
static int m2m_scaler_open(struct file *file)
{
	struct m2m_scaler *device = video_drvdata(file);
	struct m2m_scaler_ctx *ctx = NULL;
	struct v4l2_device *v4l2_dev = &device->v4l2_dev;
	int rc = 0;

	if (mutex_lock_interruptible(&device->lock))
		return -ERESTARTSYS;
	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx) {
		rc = -ENOMEM;
		goto open_unlock;
	}

	v4l2_fh_init(&ctx->fh, video_devdata(file));
	file->private_data = &ctx->fh;
	ctx->device = device;

	ctx->fh.m2m_ctx = v4l2_m2m_ctx_init(device->m2m_dev, ctx, &queue_init);

	if (IS_ERR(ctx->fh.m2m_ctx)) {
		rc = PTR_ERR(ctx->fh.m2m_ctx);

		v4l2_fh_exit(&ctx->fh);
		kfree(ctx);
		goto open_unlock;
	}

	v4l2_fh_add(&ctx->fh);

	/* set default format */
	ctx->fmt[FMT_OUTPUT].type = V4L2_BUF_TYPE_VIDEO_OUTPUT;
	ctx->fmt[FMT_OUTPUT].fmt.pix.pixelformat = FORMAT;
	ctx->fmt[FMT_OUTPUT].fmt.pix.width = DEFAULT_WIDTH;
	ctx->fmt[FMT_OUTPUT].fmt.pix.height = DEFAULT_HEIGHT;
	ctx->fmt[FMT_CAPTURE].type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	ctx->fmt[FMT_CAPTURE].fmt.pix.pixelformat = FORMAT;
	ctx->fmt[FMT_CAPTURE].fmt.pix.width = DEFAULT_WIDTH;
	ctx->fmt[FMT_CAPTURE].fmt.pix.height = DEFAULT_HEIGHT;

	v4l2_dbg(1, debug, v4l2_dev, "Created instance: %p, m2m_ctx: %p\n", ctx, ctx->fh.m2m_ctx);

open_unlock:
	mutex_unlock(&device->lock);
	return rc;
}

static int m2m_scaler_release(struct file *file)
{
	struct m2m_scaler *device = video_drvdata(file);
	struct m2m_scaler_ctx *ctx = file2ctx(file);
	struct v4l2_device *v4l2_dev = &device->v4l2_dev;

	v4l2_dbg(1, debug, v4l2_dev, "Releasing instance %p\n", ctx);

	v4l2_fh_del(&ctx->fh);
	v4l2_fh_exit(&ctx->fh);
	mutex_lock(&device->lock);
	v4l2_m2m_ctx_release(ctx->fh.m2m_ctx);
	mutex_unlock(&device->lock);
	kfree(ctx);

	return 0;
}


static const struct v4l2_file_operations m2m_scaler_fops = {
	.owner		= THIS_MODULE,
	.open		= m2m_scaler_open,
	.release	= m2m_scaler_release,
	.poll		= v4l2_m2m_fop_poll,
	.unlocked_ioctl	= video_ioctl2,
	.mmap		= v4l2_m2m_fop_mmap,
};

static const struct video_device m2m_scaler_video_dev = {
	.name		= MEM2MEM_NAME,
	.vfl_dir	= VFL_DIR_M2M,
	.fops		= &m2m_scaler_fops,
	.device_caps	= V4L2_CAP_VIDEO_M2M | V4L2_CAP_STREAMING,
	.ioctl_ops	= &m2m_scaler_ioctl_ops,
	.minor		= -1,
	.release	= video_device_release_empty,
};

static const struct v4l2_m2m_ops m2m_ops = {
	.device_run	= m2m_scaler_device_run,
};

static int m2m_scaler_probe(struct platform_device *pdev)
{
	struct m2m_scaler *device;
	struct device *dev = &pdev->dev;
	struct resource *res;
	struct video_device *vfd;
	int irq;
	int ret;

	device = devm_kzalloc(dev, sizeof(*device), GFP_KERNEL);
	if(!device)
		return -ENOMEM;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	device->mmio = devm_ioremap_resource(dev, res);
	if (IS_ERR(device->mmio))
		return PTR_ERR(device->mmio);

	irq = platform_get_irq(pdev, 0);
	if (irq < 0)
		return irq;

	ret = devm_request_threaded_irq(dev, irq, NULL, m2m_scaler_irq_handler,
			IRQF_ONESHOT, dev_name(dev), dev);
	if (ret < 0) {
		dev_err(dev, "Failed to request irq: %d\n", ret);
		return ret;
	}

	ret = v4l2_device_register(&pdev->dev, &device->v4l2_dev);
	if (ret) {
		dev_err(dev, "could not register video device rc=%d\n", ret);
		return ret;
	}
	
	device->video_dev = m2m_scaler_video_dev;
	vfd = &device->video_dev;
	vfd->lock = &device->lock;
	vfd->v4l2_dev = &device->v4l2_dev;

	/* set the video device private data structure to struct m2m_scaler
	 * instance */
	video_set_drvdata(vfd, device);

	/* also set the platform private to the same */
	platform_set_drvdata(pdev, device);
	
	snprintf(vfd->name, sizeof(vfd->name), "%s", MEM2MEM_NAME);

	device->m2m_dev = v4l2_m2m_init(&m2m_ops);

	return 0;
}

static int m2m_scaler_remove(struct platform_device *pdev)
{

	return 0;
}

static const struct of_device_id m2m_scaler_dt_ids[] = {
	{ .compatible = "virtual,m2m-scaler", .data = NULL },
	{ },
};
MODULE_DEVICE_TABLE(of, m2m_scaler_dt_ids);

static struct platform_driver m2m_scaler_driver = {
	.probe		= m2m_scaler_probe,
	.remove		= m2m_scaler_remove,
	.driver		= {
		.name	= MEM2MEM_NAME,
		.of_match_table = m2m_scaler_dt_ids,
	},
};

module_platform_driver(m2m_scaler_driver);

MODULE_DESCRIPTION("Virtual (QEMU Based) mem2mem scaler");
MODULE_AUTHOR("Karthik Poduval <karthik.poduval@gmail.com>");
MODULE_LICENSE("GPL");
