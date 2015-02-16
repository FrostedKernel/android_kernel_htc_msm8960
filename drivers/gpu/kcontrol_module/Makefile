obj-$(CONFIG_KCONTROL_GPU_MODULE_MSM) += kcontrol_gpu_msm.o

kcontrol_gpu_msm-y	:= kcontrol_module_msm.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	
