obj-$(CONFIG_VSOCKETS) += vsock.o
obj-$(CONFIG_VMWARE_VMCI_VSOCKETS) += vmw_vsock_vmci_transport.o
obj-$(CONFIG_VIRTIO_VSOCKETS) += vmw_vsock_virtio_transport.o
obj-$(CONFIG_VIRTIO_VSOCKETS_COMMON) += vmw_vsock_virtio_transport_common.o
obj-m += hvsock_transport.o

vsock-y += af_vsock.o vsock_addr.o

vmw_vsock_vmci_transport-y += vmci_transport.o vmci_transport_notify.o \
	vmci_transport_notify_qstate.o

vmw_vsock_virtio_transport-y += virtio_transport.o

vmw_vsock_virtio_transport_common-y += virtio_transport_common.o

hvsock_transport-y += hyperv_transport.o
