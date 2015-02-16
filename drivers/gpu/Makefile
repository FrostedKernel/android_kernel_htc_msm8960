obj-y			+= drm/ vga/ stub/ ion/
ifeq ($(CONFIG_ARCH_APQ8064),y)
obj-$(CONFIG_MSM_KGSL)	+= msm2/
else
obj-$(CONFIG_MSM_KGSL)	+= msm/
endif
obj-$(CONFIG_KCONTROL_GPU_MODULE_MSM)	+= kcontrol_module/
