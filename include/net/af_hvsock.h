#ifndef __AF_HVSOCK_H__
#define __AF_HVSOCK_H__

#include <linux/kernel.h>
#include <linux/hyperv.h>
#include <net/sock.h>

/* The host side's design of the feature requires 5 exact pages for recv/send
 * rings respectively -- this is suboptimal considering memory consumption,
 * however unluckily we have to live with it, before the host comes up with
 * a better new design in the future.
 */
#define RINGBUFFER_HVSOCK_RCV_SIZE (PAGE_SIZE * 5)
#define RINGBUFFER_HVSOCK_SND_SIZE (PAGE_SIZE * 5)

#define sk_to_hvsock(__sk)   ((struct hvsock_sock *)(__sk))
#define hvsock_to_sk(__hvsk) ((struct sock *)(__hvsk))

/* The MTU is 16KB per the host side's design. */
struct hvsock_recv_buf {
	unsigned int data_len;
	unsigned int data_offset;

	struct vmpipe_proto_header hdr;
	u8 buf[PAGE_SIZE * 4];
};

/* We send at most 4KB payload per VMBus packet. */
struct hvsock_send_buf {
	struct vmpipe_proto_header hdr;
	u8 buf[PAGE_SIZE];
};

struct hvsock_sock {
	/* sk must be the first member. */
	struct sock sk;

	struct sockaddr_hv local_addr;
	struct sockaddr_hv remote_addr;

	/* protected by the global hvsock_mutex */
	struct list_head bound_list;
	struct list_head connected_list;

	struct list_head accept_queue;
	/* used by enqueue and dequeue */
	struct mutex accept_queue_mutex;

	struct delayed_work dwork;

	u32 peer_shutdown;

	struct vmbus_channel *channel;

	struct hvsock_send_buf *send;
	struct hvsock_recv_buf *recv;
};

#endif /* __AF_HVSOCK_H__ */
