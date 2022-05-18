// SPDX-License-Identifier: GPL-2.0+
/*
 * Virtual (QEMU based) mem-2-mem scaler device driver
 *
 * Copyright (c) 2022 Karthik Poduval <karthik.poduval@gmail.com>
 */

#include <linux/module.h>
#include <linux/platform_device.h>
#include <media/v4l2-mem2mem.h>
#include <media/v4l2-device.h>
#include <media/v4l2-ioctl.h>

#define MEM2MEM_NAME		"virtual-v4l2-m2m-scaler"

struct m2m_scaler {
	struct v4l2_device	v4l2_dev;
	struct video_device	video_dev;
	void __iomem		*mmio;
	struct v4l2_m2m_dev	*m2m_dev;
};

struct m2m_scaler_ctx {	
	struct v4l2_fh		fh;
	struct m2m_scaler	*device;
};

static irqreturn_t m2m_scaler_irq_handler(int irq, void *dev_id)
{

	return IRQ_HANDLED;
}

static int m2m_scaler_probe(struct platform_device *pdev)
{
	struct m2m_scaler *device;
	struct device *dev = &pdev->dev;
	struct resource *res;
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
