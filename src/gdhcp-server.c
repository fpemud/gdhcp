/*
 *
 *  DHCP library with GLib integration
 *
 *  Copyright (C) 2009-2012  Intel Corporation. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include "config.h"

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if_arp.h>

#include <linux/if.h>
#include <linux/filter.h>

#include <glib.h>

#include "gdhcp.h"
#include "gdhcp-common.h"
#include "gdhcp-unaligned.h"

/* 8 hours */
#define DEFAULT_DHCP_LEASE_SEC (8*60*60)

/* 5 minutes  */
#define OFFER_TIME (5*60)

typedef struct {
	GDHCPType type;
	bool started;
	int ifindex;
	char *interface;
	uint32_t start_ip;
	uint32_t end_ip;
	uint32_t server_nip;	/* our address in network byte order */
	uint32_t lease_seconds;
	int listener_sockfd;
	guint listener_watch;
	GIOChannel *listener_channel;
	GList *lease_list;
	GHashTable *nip_lease_hash;
	GHashTable *option_hash; /* Options send to client */
	GDHCPSaveLeaseFunc save_lease_func;
} GDHCPServerPrivate;

G_DEFINE_TYPE_WITH_PRIVATE (GDHCPServer, gdhcp_server, G_TYPE_OBJECT)

struct dhcp_lease {
	time_t expire;
	uint32_t lease_nip;
	uint8_t lease_mac[ETH_ALEN];
};

enum {
	SIG_LEASE_ADDED,
	N_SIGNALS,
};

static guint signals[N_SIGNALS];

static void gdhcp_server_dispose(GObject *object);
static void destroy_lease_table(GDHCPServer *dhcp_server);

static void gdhcp_server_class_init(GDHCPServerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->dispose = gdhcp_server_dispose;

	/**
	 * GDHCPServer::lease_added:
	 *
	 * The "lease_added" signal is called when FIXME.
	 */
	signals[SIG_LEASE_ADDED] = g_signal_new("lease_added",
											G_TYPE_FROM_CLASS(klass),
											G_SIGNAL_RUN_LAST,
											G_STRUCT_OFFSET(GDHCPServerClass, lease_added),
											NULL, NULL,
											g_cclosure_marshal_VOID__VOID,
											G_TYPE_NONE, 0);
	g_signal_set_va_marshaller(signals[SIG_LEASE_ADDED],
							   G_TYPE_FROM_CLASS(klass),
							   g_cclosure_marshal_VOID__VOIDv);
}

static void gdhcp_server_init(GDHCPServer *dhcp_server)
{
}

static void gdhcp_server_dispose(GObject *object)
{
	GDHCPServer *dhcp_server = (GDHCPServer *)object;
	GDHCPServerPrivate *priv = gdhcp_server_get_instance_private(dhcp_server);

	gdhcp_server_stop(dhcp_server);

	g_hash_table_destroy(priv->option_hash);

	destroy_lease_table(dhcp_server);

	g_free(priv->interface);

	G_OBJECT_CLASS (gdhcp_server_parent_class)->dispose(object);
}

static inline void debug(GDHCPServer *server, const char *format, ...)
{
#if 0
	char str[256];
	va_list ap;

	va_start(ap, format);

	if (vsnprintf(str, sizeof(str), format, ap) > 0)
		printf(str);

	va_end(ap);
#endif
}

static struct dhcp_lease *find_lease_by_mac(GDHCPServer *dhcp_server, const uint8_t *mac)
{
	GDHCPServerPrivate *priv = gdhcp_server_get_instance_private(dhcp_server);
	GList *list;

	for (list = priv->lease_list; list; list = list->next) {
		struct dhcp_lease *lease = list->data;

		if (memcmp(lease->lease_mac, mac, ETH_ALEN) == 0)
			return lease;
	}

	return NULL;
}

static void remove_lease(GDHCPServer *dhcp_server, struct dhcp_lease *lease)
{
	GDHCPServerPrivate *priv = gdhcp_server_get_instance_private(dhcp_server);

	priv->lease_list = g_list_remove(priv->lease_list, lease);

	g_hash_table_remove(priv->nip_lease_hash, GINT_TO_POINTER((int) lease->lease_nip));
	g_free(lease);
}

/* Clear the old lease and create the new one */
static int get_lease(GDHCPServer *dhcp_server, uint32_t yiaddr,
				const uint8_t *mac, struct dhcp_lease **lease)
{
	GDHCPServerPrivate *priv = gdhcp_server_get_instance_private(dhcp_server);
	struct dhcp_lease *lease_nip, *lease_mac;

	if (yiaddr == 0)
		return -ENXIO;

	if (ntohl(yiaddr) < priv->start_ip)
		return -ENXIO;

	if (ntohl(yiaddr) > priv->end_ip)
		return -ENXIO;

	if (memcmp(mac, MAC_BCAST_ADDR, ETH_ALEN) == 0)
		return -ENXIO;

	if (memcmp(mac, MAC_ANY_ADDR, ETH_ALEN) == 0)
		return -ENXIO;

	lease_mac = find_lease_by_mac(dhcp_server, mac);

	lease_nip = g_hash_table_lookup(priv->nip_lease_hash, GINT_TO_POINTER((int) ntohl(yiaddr)));
	debug(dhcp_server, "lease_mac %p lease_nip %p", lease_mac, lease_nip);

	if (lease_nip) {
		priv->lease_list = g_list_remove(priv->lease_list, lease_nip);
		g_hash_table_remove(priv->nip_lease_hash, GINT_TO_POINTER((int) ntohl(yiaddr)));

		if (!lease_mac)
			*lease = lease_nip;
		else if (lease_nip != lease_mac) {
			remove_lease(dhcp_server, lease_mac);
			*lease = lease_nip;
		} else
			*lease = lease_nip;

		return 0;
	}

	if (lease_mac) {
		priv->lease_list = g_list_remove(priv->lease_list, lease_mac);
		g_hash_table_remove(priv->nip_lease_hash, GINT_TO_POINTER((int) lease_mac->lease_nip));
		*lease = lease_mac;

		return 0;
	}

	*lease = g_try_new0(struct dhcp_lease, 1);
	if (!*lease)
		return -ENOMEM;

	return 0;
}

static gint compare_expire(gconstpointer a, gconstpointer b)
{
	const struct dhcp_lease *lease1 = a;
	const struct dhcp_lease *lease2 = b;

	return lease2->expire - lease1->expire;
}

static struct dhcp_lease *add_lease(GDHCPServer *dhcp_server, uint32_t expire,
					const uint8_t *chaddr, uint32_t yiaddr)
{
	GDHCPServerPrivate *priv = gdhcp_server_get_instance_private(dhcp_server);
	struct dhcp_lease *lease = NULL;
	int ret;

	ret = get_lease(dhcp_server, yiaddr, chaddr, &lease);
	if (ret != 0)
		return NULL;

	memset(lease, 0, sizeof(*lease));

	memcpy(lease->lease_mac, chaddr, ETH_ALEN);
	lease->lease_nip = ntohl(yiaddr);

	if (expire == 0)
		lease->expire = time(NULL) + priv->lease_seconds;
	else
		lease->expire = expire;

	priv->lease_list = g_list_insert_sorted(priv->lease_list, lease, compare_expire);

	g_hash_table_insert(priv->nip_lease_hash, GINT_TO_POINTER((int) lease->lease_nip), lease);

	return lease;
}

static struct dhcp_lease *find_lease_by_nip(GDHCPServer *dhcp_server, uint32_t nip)
{
	GDHCPServerPrivate *priv = gdhcp_server_get_instance_private(dhcp_server);
	return g_hash_table_lookup(priv->nip_lease_hash, GINT_TO_POINTER((int) nip));
}

/* Check if the IP is taken; if it is, add it to the lease table */
static bool arp_check(uint32_t nip, const uint8_t *safe_mac)
{
	/* TODO: Add ARP checking */
	return true;
}

static bool is_expired_lease(struct dhcp_lease *lease)
{
	if (lease->expire < time(NULL))
		return true;

	return false;
}

static uint32_t find_free_or_expired_nip(GDHCPServer *dhcp_server,
					const uint8_t *safe_mac)
{
	GDHCPServerPrivate *priv = gdhcp_server_get_instance_private(dhcp_server);
	uint32_t ip_addr;
	struct dhcp_lease *lease;
	GList *list;

	ip_addr = priv->start_ip;
	for (; ip_addr <= priv->end_ip; ip_addr++) {
		/* e.g. 192.168.55.0 */
		if ((ip_addr & 0xff) == 0)
			continue;

		/* e.g. 192.168.55.255 */
		if ((ip_addr & 0xff) == 0xff)
			continue;

		lease = find_lease_by_nip(dhcp_server, ip_addr);
		if (lease)
			continue;

		if (arp_check(htonl(ip_addr), safe_mac))
			return ip_addr;
	}

	/* The last lease is the oldest one */
	list = g_list_last(priv->lease_list);
	if (!list)
		return 0;

	lease = list->data;
	if (!lease)
		return 0;

	 if (!is_expired_lease(lease))
		return 0;

	 if (!arp_check(lease->lease_nip, safe_mac))
		return 0;

	return lease->lease_nip;
}

static void lease_set_expire(GDHCPServer *dhcp_server, struct dhcp_lease *lease, uint32_t expire)
{
	GDHCPServerPrivate *priv = gdhcp_server_get_instance_private(dhcp_server);

	priv->lease_list = g_list_remove(priv->lease_list, lease);

	lease->expire = expire;

	priv->lease_list = g_list_insert_sorted(priv->lease_list, lease, compare_expire);
}

static void destroy_lease_table(GDHCPServer *dhcp_server)
{
	GDHCPServerPrivate *priv = gdhcp_server_get_instance_private(dhcp_server);
	GList *list;

	g_hash_table_destroy(priv->nip_lease_hash);

	priv->nip_lease_hash = NULL;

	for (list = priv->lease_list; list; list = list->next) {
		struct dhcp_lease *lease = list->data;
		g_free(lease);
	}

	g_list_free(priv->lease_list);

	priv->lease_list = NULL;
}

static uint32_t get_interface_address(int index)
{
	struct ifreq ifr;
	int sk, err;
	struct sockaddr_in *server_ip;
	uint32_t ret = 0;

	sk = socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (sk < 0) {
		perror("Open socket error");
		return 0;
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = index;

	err = ioctl(sk, SIOCGIFNAME, &ifr);
	if (err < 0) {
		perror("Get interface name error");
		goto done;
	}

	err = ioctl(sk, SIOCGIFADDR, &ifr);
	if (err < 0) {
		perror("Get ip address error");
		goto done;
	}

	server_ip = (struct sockaddr_in *) &ifr.ifr_addr;
	ret = server_ip->sin_addr.s_addr;

done:
	close(sk);

	return ret;
}

/**
 * gdhcp_server_new:
 * @type:
 * @ifindex:
 *
 * Creates a new #GDHCPServer instance.
 *
 * Returns: (transfer full): A newly created #GDHCPServer
 */
GDHCPServer *gdhcp_server_new(GDHCPType type, int ifindex, GError **error)
{
	GDHCPServer *dhcp_server = NULL;
	GDHCPServerPrivate *priv;

	g_assert(ifindex > 0);

	dhcp_server = g_object_new(GDHCP_TYPE_SERVER, NULL);
	if (!dhcp_server) {
		return NULL;
	}

	priv = gdhcp_server_get_instance_private(dhcp_server);

	priv->interface = get_interface_name(ifindex);
	if (!priv->interface) {
		g_object_unref(dhcp_server);
		g_set_error_literal(error,
							g_quark_from_string("fixme"),
							1,
							"Interface unavailable");
		return NULL;
	}

	if (!interface_is_up(ifindex)) {
		g_free(priv->interface);
		g_object_unref(dhcp_server);
		g_set_error_literal(error,
							g_quark_from_string("fixme"),
							1,
							"Interface down");
		return NULL;
	}

	priv->server_nip = get_interface_address(ifindex);
	if (priv->server_nip == 0) {
		g_free(priv->interface);
		g_object_unref(dhcp_server);
		g_set_error_literal(error,
							g_quark_from_string("fixme"),
							1,
							"IP address invalid");
		return NULL;
	}

	priv->nip_lease_hash = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);
	priv->option_hash = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);

	priv->started = FALSE;

	/* All the leases have the same fixed lease time,
	 * do not support DHCP_LEASE_TIME option from client.
	 */
	priv->lease_seconds = DEFAULT_DHCP_LEASE_SEC;

	priv->type = type;
	priv->ifindex = ifindex;
	priv->listener_sockfd = -1;
	priv->listener_watch = -1;
	priv->listener_channel = NULL;
	priv->save_lease_func = NULL;

	return dhcp_server;
}

static uint8_t check_packet_type(struct dhcp_packet *packet)
{
	uint8_t *type;

	if (packet->hlen != ETH_ALEN)
		return 0;

	if (packet->op != BOOTREQUEST)
		return 0;

	type = dhcp_get_option(packet, DHCP_MESSAGE_TYPE);

	if (!type)
		return 0;

	if (*type < DHCP_MINTYPE)
		return 0;

	if (*type > DHCP_MAXTYPE)
		return 0;

	return *type;
}

static void init_packet(GDHCPServer *dhcp_server, struct dhcp_packet *packet,
				struct dhcp_packet *client_packet, char type)
{
	GDHCPServerPrivate *priv = gdhcp_server_get_instance_private(dhcp_server);

	/* Sets op, htype, hlen, cookie fields
	 * and adds DHCP_MESSAGE_TYPE option */
	dhcp_init_header(packet, type);

	packet->xid = client_packet->xid;
	memcpy(packet->chaddr, client_packet->chaddr,
				sizeof(client_packet->chaddr));
	packet->flags = client_packet->flags;
	packet->gateway_nip = client_packet->gateway_nip;
	packet->ciaddr = client_packet->ciaddr;
	dhcp_add_option_uint32(packet, DHCP_SERVER_ID, ntohl(priv->server_nip));
}

static void add_option(gpointer key, gpointer value, gpointer user_data)
{
	const char *option_value = value;
	uint8_t option_code = GPOINTER_TO_INT(key);
	struct in_addr nip;
	struct dhcp_packet *packet = user_data;

	if (!option_value)
		return;

	switch (option_code) {
	case G_DHCP_SUBNET:
	case G_DHCP_ROUTER:
	case G_DHCP_DNS_SERVER:
		if (inet_aton(option_value, &nip) == 0)
			return;

		dhcp_add_option_uint32(packet, (uint8_t) option_code,
							ntohl(nip.s_addr));
		break;
	default:
		return;
	}
}

static void add_server_options(GDHCPServer *dhcp_server,
				struct dhcp_packet *packet)
{
	GDHCPServerPrivate *priv = gdhcp_server_get_instance_private(dhcp_server);
	g_hash_table_foreach(priv->option_hash, add_option, packet);
}

static bool check_requested_nip(GDHCPServer *dhcp_server, uint32_t requested_nip)
{
	GDHCPServerPrivate *priv = gdhcp_server_get_instance_private(dhcp_server);
	struct dhcp_lease *lease;

	if (requested_nip == 0)
		return false;

	if (requested_nip < priv->start_ip)
		return false;

	if (requested_nip > priv->end_ip)
		return false;

	lease = find_lease_by_nip(dhcp_server, requested_nip);
	if (!lease)
		return true;

	if (!is_expired_lease(lease))
		return false;

	return true;
}

static void send_packet_to_client(GDHCPServer *dhcp_server, struct dhcp_packet *dhcp_pkt)
{
	GDHCPServerPrivate *priv = gdhcp_server_get_instance_private(dhcp_server);
	const uint8_t *chaddr;
	uint32_t ciaddr;

	if ((dhcp_pkt->flags & htons(BROADCAST_FLAG))
				|| dhcp_pkt->ciaddr == 0) {
		debug(dhcp_server, "Broadcasting packet to client");
		ciaddr = INADDR_BROADCAST;
		chaddr = MAC_BCAST_ADDR;
	} else {
		debug(dhcp_server, "Unicasting packet to client ciaddr");
		ciaddr = dhcp_pkt->ciaddr;
		chaddr = dhcp_pkt->chaddr;
	}

	dhcp_send_raw_packet(dhcp_pkt,
		priv->server_nip, SERVER_PORT,
		ciaddr, CLIENT_PORT, chaddr,
		priv->ifindex, false);
}

static void send_offer(GDHCPServer *dhcp_server,
			struct dhcp_packet *client_packet,
				struct dhcp_lease *lease,
					uint32_t requested_nip)
{
	GDHCPServerPrivate *priv = gdhcp_server_get_instance_private(dhcp_server);
	struct dhcp_packet packet;
	struct in_addr addr;

	init_packet(dhcp_server, &packet, client_packet, DHCPOFFER);

	if (lease)
		packet.yiaddr = htonl(lease->lease_nip);
	else if (check_requested_nip(dhcp_server, requested_nip))
		packet.yiaddr = htonl(requested_nip);
	else
		packet.yiaddr = htonl(find_free_or_expired_nip(dhcp_server, client_packet->chaddr));

	debug(dhcp_server, "find yiaddr %u", packet.yiaddr);

	if (!packet.yiaddr) {
		debug(dhcp_server, "Err: Can not found lease and send offer");
		return;
	}

	lease = add_lease(dhcp_server, OFFER_TIME, packet.chaddr, packet.yiaddr);
	if (!lease) {
		debug(dhcp_server,
				"Err: No free IP addresses. OFFER abandoned");
		return;
	}

	dhcp_add_option_uint32(&packet, DHCP_LEASE_TIME, priv->lease_seconds);
	add_server_options(dhcp_server, &packet);

	addr.s_addr = packet.yiaddr;

	debug(dhcp_server, "Sending OFFER of %s", inet_ntoa(addr));
	send_packet_to_client(dhcp_server, &packet);
}

static void save_lease(GDHCPServer *dhcp_server)
{
	GDHCPServerPrivate *priv = gdhcp_server_get_instance_private(dhcp_server);
	GList *list;

	if (!priv->save_lease_func)
		return;

	for (list = priv->lease_list; list; list = list->next) {
		struct dhcp_lease *lease = list->data;
		priv->save_lease_func(lease->lease_mac, lease->lease_nip, lease->expire);
	}
}

static void send_ACK(GDHCPServer *dhcp_server,
		struct dhcp_packet *client_packet, uint32_t dest)
{
	GDHCPServerPrivate *priv = gdhcp_server_get_instance_private(dhcp_server);
	struct dhcp_packet packet;
	uint32_t lease_time_sec;
	struct in_addr addr;

	init_packet(dhcp_server, &packet, client_packet, DHCPACK);
	packet.yiaddr = htonl(dest);

	lease_time_sec = priv->lease_seconds;

	dhcp_add_option_uint32(&packet, DHCP_LEASE_TIME, lease_time_sec);

	add_server_options(dhcp_server, &packet);

	addr.s_addr = htonl(dest);

	debug(dhcp_server, "Sending ACK to %s", inet_ntoa(addr));

	send_packet_to_client(dhcp_server, &packet);

	add_lease(dhcp_server, 0, packet.chaddr, packet.yiaddr);

	g_signal_emit(dhcp_server, signals[SIG_LEASE_ADDED], packet.chaddr, packet.yiaddr);
}

static void send_NAK(GDHCPServer *dhcp_server,
			struct dhcp_packet *client_packet)
{
	GDHCPServerPrivate *priv = gdhcp_server_get_instance_private(dhcp_server);
	struct dhcp_packet packet;

	init_packet(dhcp_server, &packet, client_packet, DHCPNAK);

	debug(dhcp_server, "Sending NAK");

	dhcp_send_raw_packet(&packet,
			priv->server_nip, SERVER_PORT,
			INADDR_BROADCAST, CLIENT_PORT, MAC_BCAST_ADDR,
			priv->ifindex, false);
}

static void send_inform(GDHCPServer *dhcp_server,
				struct dhcp_packet *client_packet)
{
	struct dhcp_packet packet;

	init_packet(dhcp_server, &packet, client_packet, DHCPACK);
	add_server_options(dhcp_server, &packet);
	send_packet_to_client(dhcp_server, &packet);
}

static gboolean listener_event(GIOChannel *channel, GIOCondition condition,
							gpointer user_data)
{
	GDHCPServer *dhcp_server = user_data;
	GDHCPServerPrivate *priv = gdhcp_server_get_instance_private(dhcp_server);
	struct dhcp_packet packet;
	struct dhcp_lease *lease;
	uint32_t requested_nip = 0;
	uint8_t type, *server_id_option, *request_ip_option;
	int re;

	if (condition & (G_IO_NVAL | G_IO_ERR | G_IO_HUP)) {
		priv->listener_watch = 0;
		return FALSE;
	}

	re = dhcp_recv_l3_packet(&packet, priv->listener_sockfd);
	if (re < 0)
		return TRUE;

	type = check_packet_type(&packet);
	if (type == 0)
		return TRUE;

	server_id_option = dhcp_get_option(&packet, DHCP_SERVER_ID);
	if (server_id_option) {
		uint32_t server_nid =
			get_unaligned((const uint32_t *) server_id_option);

		if (server_nid != priv->server_nip)
			return TRUE;
	}

	request_ip_option = dhcp_get_option(&packet, DHCP_REQUESTED_IP);
	if (request_ip_option)
		requested_nip = get_be32(request_ip_option);

	lease = find_lease_by_mac(dhcp_server, packet.chaddr);

	switch (type) {
	case DHCPDISCOVER:
		debug(dhcp_server, "Received DISCOVER");

		send_offer(dhcp_server, &packet, lease, requested_nip);
		break;
	case DHCPREQUEST:
		debug(dhcp_server, "Received REQUEST NIP %d",
							requested_nip);
		if (requested_nip == 0) {
			requested_nip = ntohl(packet.ciaddr);
			if (requested_nip == 0)
				break;
		}

		if (lease && requested_nip == lease->lease_nip) {
			debug(dhcp_server, "Sending ACK");
			send_ACK(dhcp_server, &packet,
				lease->lease_nip);
			break;
		}

		if (server_id_option || !lease) {
			debug(dhcp_server, "Sending NAK");
			send_NAK(dhcp_server, &packet);
		}

		break;
	case DHCPDECLINE:
		debug(dhcp_server, "Received DECLINE");

		if (!server_id_option)
			break;

		if (!request_ip_option)
			break;

		if (!lease)
			break;

		if (requested_nip == lease->lease_nip)
			remove_lease(dhcp_server, lease);

		break;
	case DHCPRELEASE:
		debug(dhcp_server, "Received RELEASE");

		if (!server_id_option)
			break;

		if (!lease)
			break;

		if (packet.ciaddr == lease->lease_nip)
			lease_set_expire(dhcp_server, lease,
					time(NULL));
		break;
	case DHCPINFORM:
		debug(dhcp_server, "Received INFORM");
		send_inform(dhcp_server, &packet);
		break;
	}

	return TRUE;
}

/* Caller need to load leases before call it */
int gdhcp_server_start(GDHCPServer *dhcp_server)
{
	GDHCPServerPrivate *priv = gdhcp_server_get_instance_private(dhcp_server);
	GIOChannel *listener_channel;
	int listener_sockfd;

	if (priv->started)
		return 0;

	listener_sockfd = dhcp_l3_socket(SERVER_PORT,
					priv->interface, AF_INET);
	if (listener_sockfd < 0)
		return -EIO;

	listener_channel = g_io_channel_unix_new(listener_sockfd);
	if (!listener_channel) {
		close(listener_sockfd);
		return -EIO;
	}

	priv->listener_sockfd = listener_sockfd;
	priv->listener_channel = listener_channel;

	g_io_channel_set_close_on_unref(listener_channel, TRUE);
	priv->listener_watch =
			g_io_add_watch_full(listener_channel, G_PRIORITY_HIGH,
				G_IO_IN | G_IO_NVAL | G_IO_ERR | G_IO_HUP,
						listener_event, dhcp_server,
								NULL);
	g_io_channel_unref(priv->listener_channel);

	priv->started = TRUE;

	return 0;
}

int gdhcp_server_set_option(GDHCPServer *dhcp_server, unsigned char option_code, const char *option_value)
{
	GDHCPServerPrivate *priv = gdhcp_server_get_instance_private(dhcp_server);
	struct in_addr nip;

	if (!option_value)
		return -EINVAL;

	debug(dhcp_server, "option_code %d option_value %s", option_code, option_value);

	switch (option_code) {
		case G_DHCP_SUBNET:
		case G_DHCP_ROUTER:
		case G_DHCP_DNS_SERVER:
			if (inet_aton(option_value, &nip) == 0)
				return -ENXIO;
			break;
		default:
			return -EINVAL;
	}

	g_hash_table_replace(priv->option_hash, GINT_TO_POINTER((int) option_code), (gpointer) option_value);
	return 0;
}

void gdhcp_server_set_save_lease(GDHCPServer *dhcp_server,
				GDHCPSaveLeaseFunc func, gpointer user_data)
{
	GDHCPServerPrivate *priv = gdhcp_server_get_instance_private(dhcp_server);
	priv->save_lease_func = func;
}

void gdhcp_server_stop(GDHCPServer *dhcp_server)
{
	GDHCPServerPrivate *priv = gdhcp_server_get_instance_private(dhcp_server);

	/* Save leases, before stop; load them before start */
	save_lease(dhcp_server);

	if (priv->listener_watch > 0) {
		g_source_remove(priv->listener_watch);
		priv->listener_watch = 0;
	}

	priv->listener_channel = NULL;

	priv->started = FALSE;
}

int gdhcp_server_set_ip_range(GDHCPServer *dhcp_server, const char *start_ip, const char *end_ip)
{
	GDHCPServerPrivate *priv = gdhcp_server_get_instance_private(dhcp_server);
	struct in_addr _host_addr;

	if (inet_aton(start_ip, &_host_addr) == 0)
		return -ENXIO;

	priv->start_ip = ntohl(_host_addr.s_addr);

	if (inet_aton(end_ip, &_host_addr) == 0)
		return -ENXIO;

	priv->end_ip = ntohl(_host_addr.s_addr);

	return 0;
}

void gdhcp_server_set_lease_time(GDHCPServer *dhcp_server,
					unsigned int lease_time)
{
	GDHCPServerPrivate *priv = gdhcp_server_get_instance_private(dhcp_server);
	priv->lease_seconds = lease_time;
}
