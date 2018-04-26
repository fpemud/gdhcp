/*
 *
 *  DHCP library with GLib integration
 *
 *  Copyright (C) 2009-2013  Intel Corporation. All rights reserved.
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

#ifndef __G_DHCP_H
#define __G_DHCP_H

#include <stdbool.h>
#include <stdint.h>
#include <arpa/inet.h>

#include <glib.h>

#define GDHCP_INSIDE
# include "gdhcp-version.h"
#undef GDHCP_INSIDE

G_BEGIN_DECLS

#ifndef GDHCP_EXTERN
#define GDHCP_EXTERN
#endif

/* DHCP Client part*/
#define GDHCP_TYPE_CLIENT  (gdhcp_client_get_type())
#define GDHCP_CLIENT_ERROR (gdhcp_client_error_quark())

typedef enum {
	G_DHCP_CLIENT_ERROR_NONE,
	G_DHCP_CLIENT_ERROR_INTERFACE_UNAVAILABLE,
	G_DHCP_CLIENT_ERROR_INTERFACE_IN_USE,
	G_DHCP_CLIENT_ERROR_INTERFACE_DOWN,
	G_DHCP_CLIENT_ERROR_NOMEM,
	G_DHCP_CLIENT_ERROR_INVALID_INDEX,
	G_DHCP_CLIENT_ERROR_INVALID_OPTION
} GDHCPClientError;

GDHCP_EXTERN
G_DECLARE_DERIVABLE_TYPE (GDHCPClient, gdhcp_client, GDHCP, CLIENT, GObject)

struct _GDHCPClientClass
{
  GObjectClass parent_class;

  void     (*notification) (GDHCPClient *self,
                            const gchar   *method_name,
                            GVariant      *params);
  gboolean (*handle_call)  (GDHCPClient *self,
                            const gchar   *method,
                            GVariant      *id,
                            GVariant      *params);
  void     (*failed)       (GDHCPClient *self);

  gpointer _reserved2;
  gpointer _reserved3;
  gpointer _reserved4;
  gpointer _reserved5;
  gpointer _reserved6;
  gpointer _reserved7;
  gpointer _reserved8;
};

typedef enum {
	G_DHCP_CLIENT_EVENT_LEASE_AVAILABLE,
	G_DHCP_CLIENT_EVENT_IPV4LL_AVAILABLE,
	G_DHCP_CLIENT_EVENT_NO_LEASE,
	G_DHCP_CLIENT_EVENT_LEASE_LOST,
	G_DHCP_CLIENT_EVENT_IPV4LL_LOST,
	G_DHCP_CLIENT_EVENT_ADDRESS_CONFLICT,
	G_DHCP_CLIENT_EVENT_INFORMATION_REQ,
	G_DHCP_CLIENT_EVENT_SOLICITATION,
	G_DHCP_CLIENT_EVENT_ADVERTISE,
	G_DHCP_CLIENT_EVENT_REQUEST,
	G_DHCP_CLIENT_EVENT_RENEW,
	G_DHCP_CLIENT_EVENT_REBIND,
	G_DHCP_CLIENT_EVENT_RELEASE,
	G_DHCP_CLIENT_EVENT_CONFIRM,
	G_DHCP_CLIENT_EVENT_DECLINE,
} GDHCPClientEvent;

typedef enum {
	G_DHCP_IPV4,
	G_DHCP_IPV6,
	G_DHCP_IPV4LL,
} GDHCPType;

#define G_DHCP_SUBNET		0x01
#define G_DHCP_ROUTER		0x03
#define G_DHCP_TIME_SERVER	0x04
#define G_DHCP_DNS_SERVER	0x06
#define G_DHCP_DOMAIN_NAME	0x0f
#define G_DHCP_HOST_NAME	0x0c
#define G_DHCP_MTU		0x1a
#define G_DHCP_NTP_SERVER	0x2a
#define G_DHCP_VENDOR_CLASS_ID	0x3c
#define G_DHCP_CLIENT_ID	0x3d

#define G_DHCPV6_CLIENTID	1
#define G_DHCPV6_SERVERID	2
#define G_DHCPV6_IA_NA		3
#define G_DHCPV6_IA_TA		4
#define G_DHCPV6_IAADDR		5
#define G_DHCPV6_ORO		6
#define G_DHCPV6_PREFERENCE     7
#define G_DHCPV6_ELAPSED_TIME   8
#define G_DHCPV6_STATUS_CODE	13
#define G_DHCPV6_RAPID_COMMIT	14
#define G_DHCPV6_DNS_SERVERS	23
#define G_DHCPV6_DOMAIN_LIST	24
#define G_DHCPV6_IA_PD		25
#define G_DHCPV6_IA_PREFIX	26
#define G_DHCPV6_SNTP_SERVERS	31

#define G_DHCPV6_ERROR_SUCCESS	0
#define G_DHCPV6_ERROR_FAILURE	1
#define G_DHCPV6_ERROR_NO_ADDR	2
#define G_DHCPV6_ERROR_BINDING	3
#define G_DHCPV6_ERROR_LINK	4
#define G_DHCPV6_ERROR_MCAST	5
#define G_DHCPV6_ERROR_NO_PREFIX 6

typedef enum {
	G_DHCPV6_DUID_LLT = 1,
	G_DHCPV6_DUID_EN  = 2,
	G_DHCPV6_DUID_LL  = 3,
} GDHCPDuidType;

typedef struct {
	/*
	 * Note that no field in this struct can be allocated
	 * from heap or there will be a memory leak when the
	 * struct is freed by client.c:remove_option_value()
	 */
	struct in6_addr prefix;
	unsigned char prefixlen;
	uint32_t preferred;
	uint32_t valid;
	time_t expire;
} GDHCPIAPrefix;

typedef void (*GDHCPClientEventFunc) (GDHCPClient *client, gpointer user_data);

typedef void (*GDHCPDebugFunc)(const char *str, gpointer user_data);

GDHCP_EXTERN
GQuark g_dhcp_client_error_quark(void);

GDHCP_EXTERN
GDHCPClient *g_dhcp_client_new(GDHCPType type, int index, GDHCPClientError *error);

GDHCP_EXTERN
int g_dhcp_client_start(GDHCPClient *client, const char *last_address);

GDHCP_EXTERN
void g_dhcp_client_stop(GDHCPClient *client);

GDHCP_EXTERN
GDHCPClient *g_dhcp_client_ref(GDHCPClient *client);

GDHCP_EXTERN
void g_dhcp_client_unref(GDHCPClient *client);

GDHCP_EXTERN
void g_dhcp_client_register_event(GDHCPClient *client,
					GDHCPClientEvent event,
					GDHCPClientEventFunc func,
					gpointer user_data);

GDHCP_EXTERN
GDHCPClientError g_dhcp_client_set_request(GDHCPClient *client, unsigned int option_code);

GDHCP_EXTERN
void g_dhcp_client_clear_requests(GDHCPClient *dhcp_client);

GDHCP_EXTERN
void g_dhcp_client_clear_values(GDHCPClient *dhcp_client);

GDHCP_EXTERN
GDHCPClientError g_dhcp_client_set_id(GDHCPClient *client);

GDHCP_EXTERN
GDHCPClientError g_dhcp_client_set_send(GDHCPClient *client, unsigned char option_code, const char *option_value);

GDHCP_EXTERN
char *g_dhcp_client_get_server_address(GDHCPClient *client);

GDHCP_EXTERN
char *g_dhcp_client_get_address(GDHCPClient *client);

GDHCP_EXTERN
char *g_dhcp_client_get_netmask(GDHCPClient *client);

GDHCP_EXTERN
GList *g_dhcp_client_get_option(GDHCPClient *client, unsigned char option_code);

GDHCP_EXTERN
int g_dhcp_client_get_index(GDHCPClient *client);

GDHCP_EXTERN
void g_dhcp_client_set_debug(GDHCPClient *client, GDHCPDebugFunc func, gpointer user_data);

GDHCP_EXTERN
int g_dhcp_v6_create_duid(GDHCPDuidType duid_type, int index, int type, unsigned char **duid, int *duid_len);

GDHCP_EXTERN
int g_dhcp_v6_client_set_duid(GDHCPClient *dhcp_client, unsigned char *duid, int duid_len);

GDHCP_EXTERN
int g_dhcp_v6_client_set_pd(GDHCPClient *dhcp_client, uint32_t *T1, uint32_t *T2, GSList *prefixes);

GDHCP_EXTERN
GSList *g_dhcp_v6_copy_prefixes(GSList *prefixes);

GDHCP_EXTERN
gboolean g_dhcp_v6_client_clear_send(GDHCPClient *dhcp_client, uint16_t code);

GDHCP_EXTERN
void g_dhcp_v6_client_set_send(GDHCPClient *dhcp_client, uint16_t option_code, uint8_t *option_value, uint16_t option_len);

GDHCP_EXTERN
uint16_t g_dhcp_v6_client_get_status(GDHCPClient *dhcp_client);

GDHCP_EXTERN
int g_dhcp_v6_client_set_oro(GDHCPClient *dhcp_client, int args, ...);

GDHCP_EXTERN
void g_dhcp_v6_client_create_iaid(GDHCPClient *dhcp_client, int index, unsigned char *iaid);

GDHCP_EXTERN
int g_dhcp_v6_client_get_timeouts(GDHCPClient *dhcp_client, uint32_t *T1, uint32_t *T2, time_t *started, time_t *expire);

GDHCP_EXTERN
uint32_t g_dhcp_v6_client_get_iaid(GDHCPClient *dhcp_client);

GDHCP_EXTERN
void g_dhcp_v6_client_set_iaid(GDHCPClient *dhcp_client, uint32_t iaid);

GDHCP_EXTERN
int g_dhcp_v6_client_set_ia(GDHCPClient *dhcp_client, int index,
			int code, uint32_t *T1, uint32_t *T2,
			bool add_addresses, const char *address);

GDHCP_EXTERN
int g_dhcp_v6_client_set_ias(GDHCPClient *dhcp_client, int index,
			int code, uint32_t *T1, uint32_t *T2,
			GSList *addresses);

GDHCP_EXTERN
void g_dhcp_v6_client_reset_request(GDHCPClient *dhcp_client);

GDHCP_EXTERN
void g_dhcp_v6_client_set_retransmit(GDHCPClient *dhcp_client);

GDHCP_EXTERN
void g_dhcp_v6_client_clear_retransmit(GDHCPClient *dhcp_client);

/* DHCP Server */
typedef enum {
	G_DHCP_SERVER_ERROR_NONE,
	G_DHCP_SERVER_ERROR_INTERFACE_UNAVAILABLE,
	G_DHCP_SERVER_ERROR_INTERFACE_IN_USE,
	G_DHCP_SERVER_ERROR_INTERFACE_DOWN,
	G_DHCP_SERVER_ERROR_NOMEM,
	G_DHCP_SERVER_ERROR_INVALID_INDEX,
	G_DHCP_SERVER_ERROR_INVALID_OPTION,
	G_DHCP_SERVER_ERROR_IP_ADDRESS_INVALID
} GDHCPServerError;

typedef void (*GDHCPSaveLeaseFunc) (unsigned char *mac,
			unsigned int nip, unsigned int expire);

typedef void (*GDHCPLeaseAddedCb) (unsigned char *mac, uint32_t ip);

struct _GDHCPServer;

typedef struct _GDHCPServer GDHCPServer;

GDHCP_EXTERN
GDHCPServer *g_dhcp_server_new(GDHCPType type, int ifindex, GDHCPServerError *error);

GDHCP_EXTERN
int g_dhcp_server_start(GDHCPServer *server);

GDHCP_EXTERN
void g_dhcp_server_stop(GDHCPServer *server);

GDHCP_EXTERN
GDHCPServer *g_dhcp_server_ref(GDHCPServer *server);

GDHCP_EXTERN
void g_dhcp_server_unref(GDHCPServer *server);

GDHCP_EXTERN
int g_dhcp_server_set_option(GDHCPServer *server, unsigned char option_code, const char *option_value);

GDHCP_EXTERN
int g_dhcp_server_set_ip_range(GDHCPServer *server, const char *start_ip, const char *end_ip);

GDHCP_EXTERN
void g_dhcp_server_set_debug(GDHCPServer *server, GDHCPDebugFunc func, gpointer user_data);

GDHCP_EXTERN
void g_dhcp_server_set_lease_time(GDHCPServer *dhcp_server, unsigned int lease_time);

GDHCP_EXTERN
void g_dhcp_server_set_save_lease(GDHCPServer *dhcp_server, GDHCPSaveLeaseFunc func, gpointer user_data);

GDHCP_EXTERN
void g_dhcp_server_set_lease_added_cb(GDHCPServer *dhcp_server, GDHCPLeaseAddedCb cb);

int dhcp_get_random(uint64_t *val);
void dhcp_cleanup_random(void);

G_END_DECLS

#endif /* __G_DHCP_H */
