/*
 * Hyper-V transport for vsock
 *
 * Copyright (c) 2017, Microsoft Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 */
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/hyperv.h>
#include <net/sock.h>
#include <net/af_vsock.h>

struct vmpipe_proto_header {
	u32 pkt_type;
	u32 data_size;
};

#define HVSOCK_HEADER_LEN	(sizeof(struct vmpacket_descriptor) + \
				 sizeof(struct vmpipe_proto_header))

/* See 'prev_indices' in hv_ringbuffer_read(), hv_ringbuffer_write() */
#define PREV_INDICES_LEN	(sizeof(u64))

#define HVSOCK_PKT_LEN(payload_len)	(HVSOCK_HEADER_LEN + \
					ALIGN((payload_len), 8) + \
					PREV_INDICES_LEN)

/* The host side's design of the feature requires 6 exact 4KB pages for
 * recv/send rings respectively -- this is suboptimal considering memory
 * consumption, however unluckily we have to live with it, before the
 * host comes up with a better design in the future.
 */
#define PAGE_SIZE_4K		4096
#define RINGBUFFER_HVSOCK_RCV_SIZE (PAGE_SIZE_4K * 6)
#define RINGBUFFER_HVSOCK_SND_SIZE (PAGE_SIZE_4K * 6)

/* The MTU is 16KB per the host side's design.
 * In future, the buffer can be elimiated when we switch to use the coming
 * new VMBus ringbuffer "in-place consumption" APIs, by which we can
 * directly copy data from VMBus ringbuffer into the userspace buffer.
 */
#define HVSOCK_MTU_SIZE		(1024 * 16)
struct hvs_recv_buf {
	/* The length of the payload data not delivered to userland yet */
	u32 data_len;

	/* The offset of the data */
	u32 data_off;

	/* The header before the payload data */
	struct vmpipe_proto_header hdr;

	/* The payload */
	u8 data[HVSOCK_MTU_SIZE];
};

/* In the VM, actually we can send up to HVSOCK_MTU_SIZE bytes of payload,
 * but for now let's use a smaller size to minimize the dynamically-allocated
 * buffer. Note: the buffer can be elimiated in future when we add new VMBus
 * ringbuffer APIs that allow us to directly copy data from userspace buf to
 * VMBus ringbuffer.
 */
#define HVSOCK_MAX_SND_SIZE_BY_VM 4096
struct hvs_send_buf {
	/* The header before the payload data */
	struct vmpipe_proto_header hdr;

	/* The payload */
	u8 data[HVSOCK_MAX_SND_SIZE_BY_VM];
};

#define MAX_LISTEN_PORT			((u32)0x7FFFFFFF)
#define MAX_VM_LISTEN_PORT		MAX_LISTEN_PORT
#define MAX_HOST_LISTEN_PORT		MAX_LISTEN_PORT
#define MIN_HOST_EPHEMERAL_PORT		(MAX_HOST_LISTEN_PORT + 1)

/* Per-socket state (accessed via vsk->trans) */
struct hvsock {
	struct vsock_sock *vsk;

	uuid_le		vm_srv_id;
	uuid_le		host_srv_id;

	struct vmbus_channel *chan;
	struct hvs_send_buf *send;
	struct hvs_recv_buf *recv;
};

/* 00000000-facb-11e6-bd58-64006a7986d3 */
static const uuid_le srv_id_template =
	UUID_LE(0x00000000, 0xfacb, 0x11e6, 0xbd, 0x58,
		0x64, 0x00, 0x6a, 0x79, 0x86, 0xd3);

static inline
bool is_valid_srv_id(const uuid_le *id)
{
	return !memcmp(&id->b[4], &srv_id_template.b[4], sizeof(uuid_le) - 4);
}

static inline
unsigned int get_port_by_srv_id(const uuid_le *svr_id)
{
	return *((unsigned int *)svr_id);
}

static inline
void hvs_addr_init(struct sockaddr_vm *addr, const uuid_le *svr_id)
{
	unsigned int port = get_port_by_srv_id(svr_id);

	vsock_addr_init(addr, VMADDR_CID_ANY, port);
}

static inline
void hvs_remote_addr_init(struct sockaddr_vm *remote,
			  struct sockaddr_vm *local)
{
	static u32 host_ephemeral_port = MIN_HOST_EPHEMERAL_PORT;
	struct sock *sk;

	vsock_addr_init(remote, VMADDR_CID_ANY, VMADDR_PORT_ANY);

	while (1) {
		/* wrap around ? */
		if (host_ephemeral_port < MIN_HOST_EPHEMERAL_PORT)
			host_ephemeral_port = MIN_HOST_EPHEMERAL_PORT;

		remote->svm_port = host_ephemeral_port++;

		sk = vsock_find_connected_socket(remote, local);
		if (!sk) {
			/* found an available ephemeral port */
			return;
		}

		/* release refcnt got in vsock_find_connected_socket */
		sock_put(sk);
	}
}

static
bool hvs_channel_readable(struct vmbus_channel *chan)
{
	u32 read, dummy;

	hv_get_ringbuffer_availbytes(&chan->inbound, &read, &dummy);

	/* 0-size payload means FIN */
	return read >= HVSOCK_PKT_LEN(0);
}

static
int hvs_channel_readable_payload(struct vmbus_channel *chan)
{
	u32 read, dummy;

	hv_get_ringbuffer_availbytes(&chan->inbound, &read, &dummy);

	if (read > HVSOCK_PKT_LEN(0)) {
		/* At least we have 1 byte to read. We don't need to return
		 * the exact readable bytes: see vsock_stream_recvmsg() ->
		 * vsock_stream_has_data().
		 */
		return 1;
	}

	if (read == HVSOCK_PKT_LEN(0)) {
		/* 0-size payload means FIN */
		return 0;
	}

	/* No payload or FIN */
	return -1;
}

static inline
size_t hvs_channel_writable_bytes(struct vmbus_channel *chan)
{
	u32 avl_write_bytes, dummy;
	size_t ret;

	hv_get_ringbuffer_availbytes(&chan->outbound,
				     &dummy,
				     &avl_write_bytes);

	/* The ringbuffer mustn't be 100% full, and we should reserve a
	 * zero-length-payload packet for the FIN: see hv_ringbuffer_write()
	 * and hvs_shutdown().
	 */
	if (avl_write_bytes <= HVSOCK_PKT_LEN(1) + HVSOCK_PKT_LEN(0))
		return 0;

	ret = avl_write_bytes - HVSOCK_PKT_LEN(1) - HVSOCK_PKT_LEN(0);

	return round_down(ret, 8);
}

static int hvs_get_send_buf(struct hvsock *hvs)
{
	hvs->send = vzalloc(sizeof(*hvs->send));
	return hvs->send ? 0 : -ENOMEM;
}

static void hvs_put_send_buf(struct hvsock *hvs)
{
	vfree(hvs->send);
	hvs->send = NULL;
}

static int hvs_send_data(struct hvsock *hvs, size_t to_write)
{
	struct vmbus_channel *chan = hvs->chan;

	hvs->send->hdr.pkt_type = 1;
	hvs->send->hdr.data_size = to_write;
	return vmbus_sendpacket(chan, &hvs->send->hdr,
				sizeof(hvs->send->hdr) + to_write,
				0, VM_PKT_DATA_INBAND, 0);
}

static int hvs_get_recv_buf(struct hvsock *hvs)
{
	hvs->recv = vzalloc(sizeof(*hvs->recv));
	return hvs->recv ? 0 : -ENOMEM;
}

static void hvs_put_recv_buf(struct hvsock *hvs)
{
	vfree(hvs->recv);
	hvs->recv = NULL;
}

static int hvs_recv_data(struct hvsock *hvs, u32 *payload_len)
{
	struct vmbus_channel *chan = hvs->chan;
	u32 buffer_actual_len;
	u64 dummy_req_id;
	int ret;

	ret = vmbus_recvpacket(chan, &hvs->recv->hdr,
			       sizeof(hvs->recv->hdr) +
			       sizeof(hvs->recv->data),
			       &buffer_actual_len, &dummy_req_id);

	if (!ret) {
		if (buffer_actual_len >= sizeof(hvs->recv->hdr))
			*payload_len = hvs->recv->hdr.data_size;
		else
			ret = -ENODATA;
	} else {
		if (ret == -EAGAIN)
			ret = -ENODATA;
	}

	return ret;
}

static void hvs_close_connection(struct vmbus_channel *chan)
{
	struct sock *sk = get_per_channel_state(chan);
	struct vsock_sock *vsk = vsock_sk(sk);

	sk->sk_state = SS_UNCONNECTED;
	sock_set_flag(sk, SOCK_DONE);
	vsk->peer_shutdown |= SEND_SHUTDOWN | RCV_SHUTDOWN;

	sk->sk_state_change(sk);
}

static void hvs_channel_cb(void *ctx)
{
	struct sock *sk = (struct sock *)ctx;
	struct vsock_sock *vsk = vsock_sk(sk);
	struct hvsock *hvs = vsk->trans;
	struct vmbus_channel *chan = hvs->chan;

	if (hvs_channel_readable(chan))
		sk->sk_data_ready(sk);

	/* mark it writable only if there is enough space */
	if (hvs_channel_writable_bytes(chan) >= PAGE_SIZE_4K)
		sk->sk_write_space(sk);
}

static void hvs_open_connection(struct vmbus_channel *chan)
{
	uuid_le *if_instance, *if_type;
	unsigned char conn_from_host;

	struct sockaddr_vm addr;
	struct sock *sk, *new = NULL;
	struct vsock_sock *vnew;
	struct hvsock *hvs, *hvs_new;
	int ret;

	if_type = &chan->offermsg.offer.if_type;
	if_instance = &chan->offermsg.offer.if_instance;
	conn_from_host = chan->offermsg.offer.u.pipe.user_def[0];

	/* The host or the VM should only listen in a port in
	 * [0, MAX_LISTEN_PORT]
	 */
	if (!is_valid_srv_id(if_type) ||
	    get_port_by_srv_id(if_type) > MAX_LISTEN_PORT)
		return;

	hvs_addr_init(&addr, conn_from_host ? if_type : if_instance);
	sk = vsock_find_bound_socket(&addr);
	if (!sk)
		return;

	if ((conn_from_host && sk->sk_state != VSOCK_SS_LISTEN) ||
	    (!conn_from_host && sk->sk_state != SS_CONNECTING))
		goto out;

	if (conn_from_host) {
		if (sk->sk_ack_backlog >= sk->sk_max_ack_backlog)
			goto out;

		new = __vsock_create(sock_net(sk), NULL, sk, GFP_KERNEL,
				     sk->sk_type, 0);
		if (!new)
			goto out;

		new->sk_state = SS_CONNECTING;
		vnew = vsock_sk(new);
		hvs_new = vnew->trans;
		hvs_new->chan = chan;
	} else {
		hvs = vsock_sk(sk)->trans;
		hvs->chan = chan;
	}

	set_channel_read_mode(chan, HV_CALL_DIRECT);
	ret = vmbus_open(chan, RINGBUFFER_HVSOCK_SND_SIZE,
			 RINGBUFFER_HVSOCK_RCV_SIZE, NULL, 0,
			 hvs_channel_cb, conn_from_host ? new : sk);
	if (ret != 0) {
		if (conn_from_host) {
			hvs_new->chan = NULL;
			sock_put(new);
		} else {
			hvs->chan = NULL;
		}
		goto out;
	}

	set_per_channel_state(chan, conn_from_host ? new : sk);
	vmbus_set_chn_rescind_callback(chan, hvs_close_connection);

	/* see hvs_channel_cb() and hvs_notify_poll_out()  */
	set_channel_pending_send_size(chan, HVSOCK_PKT_LEN(PAGE_SIZE_4K) + 1);

	if (conn_from_host) {
		new->sk_state = SS_CONNECTED;
		sk->sk_ack_backlog++;

		hvs_addr_init(&vnew->local_addr, if_type);
		hvs_remote_addr_init(&vnew->remote_addr, &vnew->local_addr);

		hvs_new->vm_srv_id = *if_type;
		hvs_new->host_srv_id = *if_instance;

		vsock_insert_connected(vnew);
		vsock_enqueue_accept(sk, new);
	} else {
		sk->sk_state = SS_CONNECTED;
		sk->sk_socket->state = SS_CONNECTED;

		vsock_insert_connected(vsock_sk(sk));
	}

	sk->sk_state_change(sk);

out:
	/* Release refcnt obtained when we called vsock_find_bound_socket() */
	sock_put(sk);
}

static u32 hvs_get_local_cid(void)
{
	return VMADDR_CID_ANY;
}

static int hvs_sock_init(struct vsock_sock *vsk, struct vsock_sock *psk)
{
	struct hvsock *hvs;

	hvs = kzalloc(sizeof(*hvs), GFP_KERNEL);
	if (!hvs)
		return -ENOMEM;

	vsk->trans = hvs;
	hvs->vsk = vsk;

	return 0;
}

static void hvs_destruct(struct vsock_sock *vsk)
{
	struct hvsock *hvs = vsk->trans;
	struct vmbus_channel *chan = hvs->chan;

	vfree(hvs->send);
	vfree(hvs->recv);
	kfree(hvs);

	if (!chan)
		return;

	vmbus_hvsock_device_unregister(chan);
}

static void hvs_release(struct vsock_sock *vsk)
{
	vsock_remove_sock(vsk);
}

static int hvs_connect(struct vsock_sock *vsk)
{
	struct hvsock *h = vsk->trans;

	h->vm_srv_id = srv_id_template;
	h->host_srv_id = srv_id_template;

	*((u32 *)&h->vm_srv_id) = vsk->local_addr.svm_port;
	*((u32 *)&h->host_srv_id) = vsk->remote_addr.svm_port;

	return vmbus_send_tl_connect_request(&h->vm_srv_id, &h->host_srv_id);
}

static int hvs_shutdown(struct vsock_sock *vsk, int mode)
{
	struct hvsock *hvs;
	int ret;

	if (!(mode & SEND_SHUTDOWN))
		return 0;

	hvs = vsk->trans;
	ret = hvs_get_send_buf(hvs);
	if (ret < 0)
		return ret;

	/* It can't fail: see hvs_channel_writable_bytes(). */
	(void)hvs_send_data(hvs, 0);

	hvs_put_send_buf(hvs);
	return 0;
}

static int hvs_dgram_bind(struct vsock_sock *vsk, struct sockaddr_vm *addr)
{
	return -EOPNOTSUPP;
}

static int hvs_dgram_dequeue(struct vsock_sock *vsk, struct msghdr *msg,
			     size_t len, int flags)
{
	return -EOPNOTSUPP;
}

static int hvs_dgram_enqueue(struct vsock_sock *vsk,
			     struct sockaddr_vm *remote, struct msghdr *msg,
			     size_t dgram_len)
{
	return -EOPNOTSUPP;
}

static bool hvs_dgram_allow(u32 cid, u32 port)
{
	return false;
}

static ssize_t hvs_stream_dequeue(struct vsock_sock *vsk, struct msghdr *msg,
				  size_t len, int flags)
{
	struct hvsock *hvs = vsk->trans;
	bool need_refill = !hvs->recv;
	u32 payload_len = 0, to_read;
	int ret;

	if (flags & MSG_PEEK)
		return -EOPNOTSUPP;

	if (need_refill) {
		ret = hvs_get_recv_buf(hvs);
		if (ret < 0)
			return ret;

		ret = hvs_recv_data(hvs, &payload_len);
		if (ret < 0 || payload_len == 0 ||
		    payload_len > sizeof(hvs->recv->data)) {
			hvs_put_recv_buf(hvs);
			return -EIO;
		}

		hvs->recv->data_len = payload_len;
		hvs->recv->data_off = 0;
	}

	to_read = min_t(u32, len, hvs->recv->data_len);

	ret = memcpy_to_msg(msg,
			    hvs->recv->data + hvs->recv->data_off, to_read);
	if (ret != 0)
		return ret;

	hvs->recv->data_len -= to_read;

	if (hvs->recv->data_len == 0)
		hvs_put_recv_buf(hvs);
	else
		hvs->recv->data_off += to_read;

	return to_read;
}

static ssize_t hvs_stream_enqueue(struct vsock_sock *vsk, struct msghdr *msg,
				  size_t len)
{
	struct hvsock *hvs = vsk->trans;
	struct vmbus_channel *chan = hvs->chan;
	size_t to_write, max_writable;
	int ret;

	max_writable = hvs_channel_writable_bytes(chan);

	to_write = min_t(size_t, len, max_writable);
	to_write = min_t(size_t, to_write, sizeof(hvs->send->data));

	ret = hvs_get_send_buf(hvs);
	if (ret < 0)
		return ret;

	ret = memcpy_from_msg(hvs->send->data, msg, to_write);
	if (ret != 0) {
		hvs_put_send_buf(hvs);
		return ret;
	}

	ret = hvs_send_data(hvs, to_write);
	hvs_put_send_buf(hvs);
	if (ret != 0)
		return ret;

	return to_write;
}

static s64 hvs_stream_has_data(struct vsock_sock *vsk)
{
	struct hvsock *hvs = vsk->trans;
	s64 ret;

	switch (hvs_channel_readable_payload(hvs->chan)) {
	case 1:
		ret = 1;
		break;
	case 0:
		vsk->peer_shutdown |= SEND_SHUTDOWN;
		ret = 0;
		break;
	default: /* -1 */
		ret = 0;
		break;
	}

	return ret;
}

static s64 hvs_stream_has_space(struct vsock_sock *vsk)
{
	struct hvsock *hvs = vsk->trans;

	return hvs_channel_writable_bytes(hvs->chan);
}

static u64 hvs_stream_rcvhiwat(struct vsock_sock *vsk)
{
	struct hvsock *hvs = vsk->trans;

	return sizeof(hvs->recv->data) + 1;
}

static bool hvs_stream_is_active(struct vsock_sock *vsk)
{
	struct hvsock *hvs = vsk->trans;

	return hvs->chan != NULL;
}

static bool hvs_stream_allow(u32 cid, u32 port)
{
	static const u32 valid_cids[] = {
		VMADDR_CID_ANY,
		VMADDR_CID_HOST,
	};
	int i;

	/* The host's port range (MAX_HOST_LISTEN_PORT, 0xFFFFFFFF] is reserved
	 * as ephemeral ports, which are used as the host's local ports when
	 * the host initiates connections.
	 */
	if (port > MAX_HOST_LISTEN_PORT)
		return false;

	for (i = 0; i < ARRAY_SIZE(valid_cids); i++) {
		if (cid == valid_cids[i])
			return true;
	}

	return false;
}

static
int hvs_notify_poll_in(struct vsock_sock *vsk, size_t target, bool *readable)
{
	struct hvsock *hvs = vsk->trans;

	*readable = hvs_channel_readable(hvs->chan);
	return 0;
}

static
int hvs_notify_poll_out(struct vsock_sock *vsk, size_t target, bool *writable)
{
	/* report writable only if there is enough space */
	*writable = hvs_stream_has_space(vsk) >= PAGE_SIZE_4K;

	return 0;
}

static
int hvs_notify_recv_init(struct vsock_sock *vsk, size_t target,
			 struct vsock_transport_recv_notify_data *d)
{
	return 0;
}

static
int hvs_notify_recv_pre_block(struct vsock_sock *vsk, size_t target,
			      struct vsock_transport_recv_notify_data *d)
{
	return 0;
}

static
int hvs_notify_recv_pre_dequeue(struct vsock_sock *vsk, size_t target,
				struct vsock_transport_recv_notify_data *d)
{
	return 0;
}

static
int hvs_notify_recv_post_dequeue(struct vsock_sock *vsk, size_t target,
				 ssize_t copied, bool data_read,
				 struct vsock_transport_recv_notify_data *d)
{
	return 0;
}

static
int hvs_notify_send_init(struct vsock_sock *vsk,
			 struct vsock_transport_send_notify_data *d)
{
	return 0;
}

static
int hvs_notify_send_pre_block(struct vsock_sock *vsk,
			      struct vsock_transport_send_notify_data *d)
{
	return 0;
}

static
int hvs_notify_send_pre_enqueue(struct vsock_sock *vsk,
				struct vsock_transport_send_notify_data *d)
{
	return 0;
}

static
int hvs_notify_send_post_enqueue(struct vsock_sock *vsk, ssize_t written,
				 struct vsock_transport_send_notify_data *d)
{
	return 0;
}

static void hvs_set_buffer_size(struct vsock_sock *vsk, u64 val)
{
	/* ignored. */
}

static void hvs_set_min_buffer_size(struct vsock_sock *vsk, u64 val)
{
	/* ignored. */
}

static void hvs_set_max_buffer_size(struct vsock_sock *vsk, u64 val)
{
	/* ignored. */
}

static u64 hvs_get_buffer_size(struct vsock_sock *vsk)
{
	return -ENOPROTOOPT;
}

static u64 hvs_get_min_buffer_size(struct vsock_sock *vsk)
{
	return -ENOPROTOOPT;
}

static u64 hvs_get_max_buffer_size(struct vsock_sock *vsk)
{
	return -ENOPROTOOPT;
}

static struct vsock_transport hvs_transport = {
	.get_local_cid            = hvs_get_local_cid,

	.init                     = hvs_sock_init,
	.destruct                 = hvs_destruct,
	.release                  = hvs_release,
	.connect                  = hvs_connect,
	.shutdown                 = hvs_shutdown,

	.dgram_bind               = hvs_dgram_bind,
	.dgram_dequeue            = hvs_dgram_dequeue,
	.dgram_enqueue            = hvs_dgram_enqueue,
	.dgram_allow              = hvs_dgram_allow,

	.stream_dequeue           = hvs_stream_dequeue,
	.stream_enqueue           = hvs_stream_enqueue,
	.stream_has_data          = hvs_stream_has_data,
	.stream_has_space         = hvs_stream_has_space,
	.stream_rcvhiwat          = hvs_stream_rcvhiwat,
	.stream_is_active         = hvs_stream_is_active,
	.stream_allow             = hvs_stream_allow,

	.notify_poll_in           = hvs_notify_poll_in,
	.notify_poll_out          = hvs_notify_poll_out,
	.notify_recv_init         = hvs_notify_recv_init,
	.notify_recv_pre_block    = hvs_notify_recv_pre_block,
	.notify_recv_pre_dequeue  = hvs_notify_recv_pre_dequeue,
	.notify_recv_post_dequeue = hvs_notify_recv_post_dequeue,
	.notify_send_init         = hvs_notify_send_init,
	.notify_send_pre_block    = hvs_notify_send_pre_block,
	.notify_send_pre_enqueue  = hvs_notify_send_pre_enqueue,
	.notify_send_post_enqueue = hvs_notify_send_post_enqueue,

	.set_buffer_size          = hvs_set_buffer_size,
	.set_min_buffer_size      = hvs_set_min_buffer_size,
	.set_max_buffer_size      = hvs_set_max_buffer_size,
	.get_buffer_size          = hvs_get_buffer_size,
	.get_min_buffer_size      = hvs_get_min_buffer_size,
	.get_max_buffer_size      = hvs_get_max_buffer_size,
};

static int hvs_probe(struct hv_device *hdev,
		     const struct hv_vmbus_device_id *dev_id)
{
	struct vmbus_channel *chan = hdev->channel;

	hvs_open_connection(chan);

	/* Always return success to suppress the unnecessary
	 * error message in vmbus_probe(): on error the host will rescind
	 * the device in 30 seconds and we can do cleanup at that time.
	 */
	return 0;
}

static int hvs_remove(struct hv_device *hdev)
{
	struct vmbus_channel *chan = hdev->channel;

	vmbus_close(chan);

	return 0;
}

/* This isn't really used. See vmbus_match() and vmbus_probe(). */
static const struct hv_vmbus_device_id id_table[] = {
	{},
};

static struct hv_driver hvs_drv = {
	.name		= "hv_sock",
	.hvsock		= true,
	.id_table	= id_table,
	.probe		= hvs_probe,
	.remove		= hvs_remove,
};

static int __init hvs_init(void)
{
	int ret;

	if (vmbus_proto_version < VERSION_WIN10)
		return -ENODEV;

	ret = vmbus_driver_register(&hvs_drv);
	if (ret != 0)
		return ret;

	ret = vsock_core_init(&hvs_transport);
	if (ret) {
		vmbus_driver_unregister(&hvs_drv);
		return ret;
	}

	return 0;
}

static void __exit hvs_exit(void)
{
	vsock_core_exit();
	vmbus_driver_unregister(&hvs_drv);
}

module_init(hvs_init);
module_exit(hvs_exit);

MODULE_LICENSE("GPL");
