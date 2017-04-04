/*
 * Hyper-V transport for vsock
 *
 * Copyright (c) 2016 Microsoft Corporation.
 *
 * GPL v2
 */
#include <linux/spinlock.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/atomic.h>
#include <linux/uuid.h>
#include <linux/hyperv.h>
#include <linux/vmalloc.h>
#include <linux/mutex.h>
#include <net/sock.h>
#include <net/af_vsock.h>

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
struct hvsock_recv_buf {
	unsigned int data_len;
	unsigned int data_offset;

	struct vmpipe_proto_header hdr;
	u8 buf[HVSOCK_MTU_SIZE];
};

/* In the VM, actually we can send up to HVSOCK_MTU_SIZE bytes of payload,
 * but for now let's use a smaller size to minimize the dynamically-allocated
 * buffer. Note: the buffer can be elimiated in future when we add new VMBus
 * ringbuffer APIs that allow us to directly copy data from userspace buf to
 * VMBus ringbuffer.
 */
#define HVSOCK_MAX_SND_SIZE_BY_VM (1024 * 4)
struct hvsock_send_buf {
	struct vmpipe_proto_header hdr;
	u8 buf[HVSOCK_MAX_SND_SIZE_BY_VM];
};

/* Per-socket state (accessed via vsk->trans) */
struct hv_vsock_sock {
	struct vsock_sock *vsk;

	uuid_le		vm_srv_id;
	uuid_le		host_srv_id;

	struct vmbus_channel *chan;
	struct hvsock_send_buf *send;
	struct hvsock_recv_buf *recv;
};

static const uuid_le template = UUID_LE(0, 0xcea8, 0x4576,
			0x92, 0xd6, 0xe0, 0x72, 0xdd, 0xd2, 0xc4, 0x22);

static bool is_good_svr_guid(const uuid_le *id)
{
	return memcmp(&id->b[4], &template.b[4], 16-4) == 0;
}

static unsigned int get_port(const uuid_le *id)
{
	WARN_ON(!is_good_svr_guid(id));
	return *((unsigned int *)&id->b[0]);
}

static unsigned int get_port2(const uuid_le *id)
{
	return *((unsigned int *)&id->b[0]);
}

static void get_ringbuffer_rw_status(struct vmbus_channel *chan,
				     bool *can_read, bool *can_write)
{
	u32 avl_read_bytes, avl_write_bytes, dummy;

	if (can_read) {
		hv_get_ringbuffer_availbytes(&chan->inbound,
					     &avl_read_bytes,
					     &dummy);
		/* 0-size payload means FIN */
		*can_read = avl_read_bytes >= HVSOCK_PKT_LEN(0);
	}

	if (can_write) {
		hv_get_ringbuffer_availbytes(&chan->outbound,
					     &dummy,
					     &avl_write_bytes);

		/* We only write if there is enough space */
		*can_write = avl_write_bytes > HVSOCK_PKT_LEN(PAGE_SIZE_4K);
	}
}

static size_t get_ringbuffer_writable_bytes(struct vmbus_channel *chan)
{
	u32 avl_write_bytes, dummy;
	size_t ret;

	hv_get_ringbuffer_availbytes(&chan->outbound,
				     &dummy,
				     &avl_write_bytes);

	/* The ringbuffer mustn't be 100% full, and we should reserve a
	 * zero-length-payload packet for the FIN: see hv_ringbuffer_write()
	 * and hvsock_shutdown().
	 */
	if (avl_write_bytes < HVSOCK_PKT_LEN(1) + HVSOCK_PKT_LEN(0))
		return 0;
	ret = avl_write_bytes - HVSOCK_PKT_LEN(1) - HVSOCK_PKT_LEN(0);

	return round_down(ret, 8);
}

static int hvsock_get_send_buf(struct hv_vsock_sock *hvs)
{
	BUG_ON(hvs->send != NULL);
	hvs->send = vzalloc(sizeof(*hvs->send));
	return hvs->send ? 0 : -ENOMEM;
}

static void hvsock_put_send_buf(struct hv_vsock_sock *hvs)
{
	vfree(hvs->send);
	hvs->send = NULL;
}

static int hvsock_send_data(struct vmbus_channel *chan,
			    struct hv_vsock_sock *hvs,
			    size_t to_write)
{
	hvs->send->hdr.pkt_type = 1;
	hvs->send->hdr.data_size = to_write;
	return vmbus_sendpacket(chan, &hvs->send->hdr,
				sizeof(hvs->send->hdr) + to_write,
				0, VM_PKT_DATA_INBAND, 0);
}

static int hvsock_get_recv_buf(struct hv_vsock_sock *hvs)
{
	if (hvs->recv != NULL)
		return 0;

	hvs->recv = vzalloc(sizeof(*hvs->recv));
	return hvs->recv ? 0 : -ENOMEM;
}

static void hvsock_put_recv_buf(struct hv_vsock_sock *hvs)
{
	BUG_ON(hvs->recv == NULL);
	vfree(hvs->recv);
	hvs->recv = NULL;
}

static int hvsock_recv_data(struct vmbus_channel *chan,
			    struct hv_vsock_sock *hvs,
			    size_t *payload_len)
{
	u32 buffer_actual_len;
	u64 dummy_req_id;
	int ret;

	ret = vmbus_recvpacket(chan, &hvs->recv->hdr,
			       sizeof(hvs->recv->hdr) +
			       sizeof(hvs->recv->buf),
			       &buffer_actual_len, &dummy_req_id);
	if (ret != 0 || buffer_actual_len <= sizeof(hvs->recv->hdr))
		*payload_len = 0;
	else
		*payload_len = hvs->recv->hdr.data_size;

	return ret;
}

static void hvsock_on_channel_cb(void *ctx)
{
	struct sock *sk = (struct sock *)ctx;
	struct vsock_sock *vsk;
	struct hv_vsock_sock *hvs;
	bool can_read, can_write;

	vsk = vsock_sk(sk);
	hvs = vsk->trans;

	BUG_ON(!hvs->chan);

	get_ringbuffer_rw_status(hvs->chan, &can_read, &can_write);

	if (can_read)
		sk->sk_data_ready(sk);

	if (can_write)
		sk->sk_write_space(sk);
}

static void hvsock_close_connection(struct vmbus_channel *chan)
{
	struct sock *sk = get_per_channel_state(chan);
	struct vsock_sock *vsk = vsock_sk(sk);
	//struct hv_vsock_sock *hvs = vsk->trans;

//	mutex_lock(&hvsock_mutex);

//	sk = hvsock_find_connected_socket_by_channel(chan);
//
//	/* The guest has already closed the connection? */
//	if (!sk)
//		goto out;
//
	sk->sk_state = SS_UNCONNECTED;
	sock_set_flag(sk, SOCK_DONE);
	vsk->peer_shutdown |= SEND_SHUTDOWN | RCV_SHUTDOWN;

	sk->sk_state_change(sk);
//out:
//	mutex_unlock(&hvsock_mutex);
}

static void hvsock_open_connection(struct vmbus_channel *chan)
{
	//struct hv_vsock_sock *hvs = NULL, *new_hvs = NULL;
	uuid_le *if_instance, *if_type, if_addr;
	unsigned char conn_from_host;

	struct sockaddr_vm addr;
	struct sock *sk, *child = NULL;
	struct vsock_sock *vchild;
	struct hv_vsock_sock *hvs, *hvs_child;
	int ret;

	if_type = &chan->offermsg.offer.if_type;
	if_instance = &chan->offermsg.offer.if_instance;
	conn_from_host = chan->offermsg.offer.u.pipe.user_def[0];
	if_addr =  conn_from_host ? *if_type : *if_instance;

	if (!is_good_svr_guid(&if_addr)) {
		goto out;
	}
	//mutex_lock(&hvsock_mutex);

	vsock_addr_init(&addr, VMADDR_CID_ANY, get_port(&if_addr));

	sk = vsock_find_bound_socket(&addr);
	if (!sk) {
		goto out;
	}

	if ((conn_from_host && sk->sk_state != VSOCK_SS_LISTEN) ||
	    (!conn_from_host && sk->sk_state != SS_CONNECTING)) {
		goto out;
	}

	if (conn_from_host) {
		if (sk->sk_ack_backlog >= sk->sk_max_ack_backlog) {
			goto out;
		}

		child = __vsock_create(sock_net(sk), NULL, sk, GFP_KERNEL,
			       sk->sk_type, 0);
		if (!child) {
			goto out;
		}

		child->sk_state = SS_CONNECTING;
		vchild = vsock_sk(child);
		vsock_addr_init(&vchild->local_addr, VMADDR_CID_ANY, get_port(if_type));
		vsock_addr_init(&vchild->remote_addr, VMADDR_CID_ANY, get_port2(if_instance)); //FIXME:  guid/port mapping???

		hvs_child = vchild->trans;
		hvs_child->chan = chan;
		hvs_child->vm_srv_id = *if_type;
		hvs_child->host_srv_id = *if_instance;
	} else {
		hvs = vsock_sk(sk)->trans;
		hvs->chan = chan;
	}

	set_channel_read_mode(chan, HV_CALL_DIRECT);
	ret = vmbus_open(chan, RINGBUFFER_HVSOCK_SND_SIZE,
			 RINGBUFFER_HVSOCK_RCV_SIZE, NULL, 0,
			 hvsock_on_channel_cb, conn_from_host ? child : sk);
	if (ret != 0) {
		if (conn_from_host) {
			hvs_child->chan = NULL;
			sock_put(child);
		} else {
			hvs->chan = NULL;
		}
		goto out;
	}

	set_per_channel_state(chan, conn_from_host ? child : sk);
	vmbus_set_chn_rescind_callback(chan, hvsock_close_connection);

	/* see get_ringbuffer_rw_status() */
	set_channel_pending_send_size(chan,
				      HVSOCK_PKT_LEN(PAGE_SIZE_4K) + 1);

	if (conn_from_host) {
		child->sk_state = SS_CONNECTED;
		sk->sk_ack_backlog++;

		vsock_insert_connected(vchild);
		vsock_enqueue_accept(sk, child);
	} else {
		sk->sk_state = SS_CONNECTED;
		sk->sk_socket->state = SS_CONNECTED;

		vsock_insert_connected(vsock_sk(sk));
	}

	sk->sk_state_change(sk);

	/* Release refcnt obtained when we fetched this socket out of the
	 * bound or connected list.
	 */
	sock_put(sk);
out:
	ret = 88888;
	//mutex_unlock(&hvsock_mutex);
}

static int hvsock_probe(struct hv_device *hdev,
			const struct hv_vmbus_device_id *dev_id)
{
	struct vmbus_channel *chan = hdev->channel;

	hvsock_open_connection(chan);

	/* We always return success to suppress the unnecessary
	 * error message in vmbus_probe(): on error the host will rescind
	 * the offer in 30 seconds and we can do cleanup at that time.
	 */
	return 0;
}

static int hvsock_remove(struct hv_device *hdev)
{
	struct vmbus_channel *chan = hdev->channel;

	vmbus_close(chan);

	return 0;
}

/* It's not really used. See vmbus_match() and vmbus_probe(). */
static const struct hv_vmbus_device_id id_table[] = {
	{},
};

static struct hv_driver hvsock_drv = {
	.name		= "hv_sock",
	.hvsock		= true,
	.id_table	= id_table,
	.probe		= hvsock_probe,
	.remove		= hvsock_remove,
};

//TODO: add MODULE_DEVICE_TABLE

static u32 hv_transport_get_local_cid(void)
{
	return VMADDR_CID_ANY;
}

static int hv_transport_do_socket_init(struct vsock_sock *vsk,
				    struct vsock_sock *psk __attribute__((unused)))
{
	struct hv_vsock_sock *hvs;

	hvs = kzalloc(sizeof(*hvs), GFP_KERNEL);
	if (!hvs)
		return -ENOMEM;

	vsk->trans = hvs;
	hvs->vsk = vsk;

	return 0;
}

static void hv_transport_destruct(struct vsock_sock *vsk)
{
	struct hv_vsock_sock *hvs = vsk->trans;
	struct vmbus_channel *chan = hvs->chan;

	vfree(hvs->send);
	vfree(hvs->recv);
	kfree(hvs);

	if (!chan)
		return;

	vmbus_hvsock_device_unregister(chan);
}

static void hv_transport_release(struct vsock_sock *vsk)
{
	vsock_remove_sock(vsk);
}

static int hv_transport_connect(struct vsock_sock *vsk)
{
	struct hv_vsock_sock *hvs = vsk->trans;

	hvs->vm_srv_id = hvs->host_srv_id = template;
	*((u32 *)&hvs->vm_srv_id.b[0]) = vsk->local_addr.svm_port;
	*((u32 *)&hvs->host_srv_id.b[0]) = vsk->remote_addr.svm_port;

	return vmbus_send_tl_connect_request(&hvs->vm_srv_id, &hvs->host_srv_id);
}

static int hv_transport_shutdown(struct vsock_sock *vsk, int mode)
{

	return 0;
}

static int hv_transport_dgram_bind(struct vsock_sock *vsk,
				struct sockaddr_vm *addr)
{
	return -EOPNOTSUPP;
}

static int hv_transport_dgram_dequeue(struct vsock_sock *vsk,
				   struct msghdr *msg,
				   size_t len, int flags)
{
	return -EOPNOTSUPP;
}

static int hv_transport_dgram_enqueue(struct vsock_sock *vsk,
			       struct sockaddr_vm *remote_addr,
			       struct msghdr *msg,
			       size_t dgram_len)
{
	return -EOPNOTSUPP;
}

static bool hv_transport_dgram_allow(u32 cid, u32 port)
{
	return false;
}

static int hvsock_pre_recv(struct vsock_sock *vsk)
{
	struct hv_vsock_sock *hvs = vsk->trans;
	bool need_refill = !hvs->recv || !(hvs->recv->data_offset < hvs->recv->data_len);
	struct vmbus_channel *chan = hvs->chan;
	size_t payload_len;

	if (!need_refill) {
		return 0;
	}

	BUG_ON(hvs->recv && hvs->recv->data_len != 0);

	if (hvsock_get_recv_buf(hvs) != 0 ||
	    hvsock_recv_data(chan, hvs, &payload_len) != 0 ||
	    payload_len > sizeof(hvs->recv->buf) ||
	    payload_len == 0) {
			return -1; //TODO: EAGAIN???
	}

	WARN_ON(payload_len == 0);
	hvs->recv->data_len = payload_len;
	hvs->recv->data_offset = 0;
	return 0;
}

static ssize_t hv_transport_stream_dequeue(struct vsock_sock *vsk,
				struct msghdr *msg,
				size_t len, int flags)
{
	struct hv_vsock_sock *hvs = vsk->trans;
	int ret;
	int to_read;

	if (flags & MSG_PEEK)
		return -EOPNOTSUPP;

	if (hvsock_pre_recv(vsk) != 0) {
		WARN_ON(1);
		return -EPROTO;
	}

	to_read = min_t(unsigned int, len, hvs->recv->data_len);

	ret = memcpy_to_msg(msg, hvs->recv->buf + hvs->recv->data_offset, to_read);
	if (ret != 0)
		return ret;

	hvs->recv->data_len -= to_read;

	if (hvs->recv->data_len == 0)
		hvsock_put_recv_buf(hvs);
	else
		hvs->recv->data_offset += to_read;

	return to_read;
}

static ssize_t hv_transport_stream_enqueue(struct vsock_sock *vsk,
				struct msghdr *msg,
				size_t len)
{
	struct hv_vsock_sock *hvs = vsk->trans;
	struct vmbus_channel *chan = hvs->chan;
	size_t to_write, max_writable;
	int ret;

	max_writable = get_ringbuffer_writable_bytes(chan);

	to_write = min_t(size_t, len, max_writable);
	to_write = min_t(size_t, to_write, sizeof(hvs->send->buf));

	ret = hvsock_get_send_buf(hvs);
	if (ret < 0)
		return ret;


	ret = memcpy_from_msg(hvs->send->buf, msg, to_write);
	if (ret != 0) {
		hvsock_put_send_buf(hvs);
		return ret;
	}

	ret = hvsock_send_data(chan, hvs, to_write);
	hvsock_put_send_buf(hvs);
	if (ret != 0)
		return ret;

	return to_write;
}

static s64 hv_transport_stream_has_data(struct vsock_sock *vsk)
{
	s64 ret;
	struct hv_vsock_sock *hvs = vsk->trans;

	if (hvsock_pre_recv(vsk) != 0)
		return 0;

	ret = hvs->recv->data_len - hvs->recv->data_offset;
	return ret;
}

static s64 hv_transport_stream_has_space(struct vsock_sock *vsk)
{
	u32 avl_write_bytes, dummy;
	s64 ret;
	struct hv_vsock_sock *hvs = vsk->trans;
	struct vmbus_channel *chan = hvs->chan;

	hv_get_ringbuffer_availbytes(&chan->outbound,
				     &dummy, &avl_write_bytes);

	if (avl_write_bytes <= HVSOCK_PKT_LEN(1)) //FIXME: check avl w for FIN
		return 0;

	ret = avl_write_bytes - HVSOCK_PKT_LEN(1); //FIXME

	ret = round_down(ret, 8);
	return ret;
}

static u64 hv_transport_stream_rcvhiwat(struct vsock_sock *vsk)
{
	struct hv_vsock_sock *hvs = vsk->trans;

	return sizeof(hvs->recv->buf) + 1;
}

static bool hv_transport_stream_is_active(struct vsock_sock *vsk)
{
	return true;
}

static bool hv_transport_stream_allow(u32 cid, u32 port)
{
	return true;
}

static int hv_transport_notify_poll_in(struct vsock_sock *vsk,
				size_t target,
				bool *data_ready_now)
{
	if (vsock_stream_has_data(vsk))
		*data_ready_now = true;
	else
		*data_ready_now = false;

	return 0;
}

static int hv_transport_notify_poll_out(struct vsock_sock *vsk,
				 size_t target,
				 bool *space_avail_now)
{
	s64 free_space;

	free_space = vsock_stream_has_space(vsk);

	/* We only write if there is enough space */
	if (free_space >= PAGE_SIZE_4K)
		*space_avail_now = true;
	else
		*space_avail_now = false;

	return 0;
}

static int hv_transport_notify_recv_init(struct vsock_sock *vsk,
	size_t target, struct vsock_transport_recv_notify_data *data)
{
	return 0;
}

static int hv_transport_notify_recv_pre_block(struct vsock_sock *vsk,
	size_t target, struct vsock_transport_recv_notify_data *data)
{
	return 0;
}

static int hv_transport_notify_recv_pre_dequeue(struct vsock_sock *vsk,
	size_t target, struct vsock_transport_recv_notify_data *data)
{
	return 0;
}

static int hv_transport_notify_recv_post_dequeue(struct vsock_sock *vsk,
	size_t target, ssize_t copied, bool data_read,
	struct vsock_transport_recv_notify_data *data)
{
	return 0;
}

static int hv_transport_notify_send_init(struct vsock_sock *vsk,
	struct vsock_transport_send_notify_data *data)
{
	return 0;
}

static int hv_transport_notify_send_pre_block(struct vsock_sock *vsk,
	struct vsock_transport_send_notify_data *data)
{
	return 0;
}

static int hv_transport_notify_send_pre_enqueue(struct vsock_sock *vsk,
	struct vsock_transport_send_notify_data *data)
{
	return 0;
}

static int hv_transport_notify_send_post_enqueue(struct vsock_sock *vsk,
	ssize_t written, struct vsock_transport_send_notify_data *data)
{
	return 0;
}

static void hv_transport_set_buffer_size(struct vsock_sock *vsk, u64 val)
{
	return;
}

static void hv_transport_set_min_buffer_size(struct vsock_sock *vsk, u64 val)
{
	return;
}

static void hv_transport_set_max_buffer_size(struct vsock_sock *vsk, u64 val)
{
	return;
}

static u64 hv_transport_get_buffer_size(struct vsock_sock *vsk)
{
	return -ENOPROTOOPT;
}

static u64 hv_transport_get_min_buffer_size(struct vsock_sock *vsk)
{
	return -ENOPROTOOPT;
}


static u64 hv_transport_get_max_buffer_size(struct vsock_sock *vsk)
{
	return -ENOPROTOOPT;
}

static struct vsock_transport hyperv_transport = {
	.get_local_cid            = hv_transport_get_local_cid,

	.init                     = hv_transport_do_socket_init,
	.destruct                 = hv_transport_destruct,
	.release                  = hv_transport_release,
	.connect                  = hv_transport_connect,
	.shutdown                 = hv_transport_shutdown,

	.dgram_bind               = hv_transport_dgram_bind,
	.dgram_dequeue            = hv_transport_dgram_dequeue,
	.dgram_enqueue            = hv_transport_dgram_enqueue,
	.dgram_allow              = hv_transport_dgram_allow,

	.stream_dequeue           = hv_transport_stream_dequeue,
	.stream_enqueue           = hv_transport_stream_enqueue,
	.stream_has_data          = hv_transport_stream_has_data,
	.stream_has_space         = hv_transport_stream_has_space,
	.stream_rcvhiwat          = hv_transport_stream_rcvhiwat,
	.stream_is_active         = hv_transport_stream_is_active,
	.stream_allow             = hv_transport_stream_allow,

	.notify_poll_in           = hv_transport_notify_poll_in,
	.notify_poll_out          = hv_transport_notify_poll_out,
	.notify_recv_init         = hv_transport_notify_recv_init,
	.notify_recv_pre_block    = hv_transport_notify_recv_pre_block,
	.notify_recv_pre_dequeue  = hv_transport_notify_recv_pre_dequeue,
	.notify_recv_post_dequeue = hv_transport_notify_recv_post_dequeue,
	.notify_send_init         = hv_transport_notify_send_init,
	.notify_send_pre_block    = hv_transport_notify_send_pre_block,
	.notify_send_pre_enqueue  = hv_transport_notify_send_pre_enqueue,
	.notify_send_post_enqueue = hv_transport_notify_send_post_enqueue,

	.set_buffer_size          = hv_transport_set_buffer_size,
	.set_min_buffer_size      = hv_transport_set_min_buffer_size,
	.set_max_buffer_size      = hv_transport_set_max_buffer_size,
	.get_buffer_size          = hv_transport_get_buffer_size,
	.get_min_buffer_size      = hv_transport_get_min_buffer_size,
	.get_max_buffer_size      = hv_transport_get_max_buffer_size,
};


static int __init hyperv_vsock_init(void)
{
	int ret;

	if (vmbus_proto_version < VERSION_WIN10)
		return -ENODEV;

	ret = vmbus_driver_register(&hvsock_drv);
	if (ret) {
		pr_err("failed to register hv_sock driver\n");
		return ret;
	}

	ret = vsock_core_init(&hyperv_transport);
	if (ret) {
		pr_err("failed in vsock_core_init\n");
		goto err;
	}

	return 0;
err:
	vmbus_driver_unregister(&hvsock_drv);
	return ret;

}

static void __exit hyperv_vsock_exit(void)
{
	vmbus_driver_unregister(&hvsock_drv);
	vsock_core_exit();
}

module_init(hyperv_vsock_init);
module_exit(hyperv_vsock_exit);

MODULE_LICENSE("GPL v2");
