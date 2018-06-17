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
#include <glib-object.h>

#define GDHCP_INSIDE
# include "gdhcp-version.h"
#undef GDHCP_INSIDE

G_BEGIN_DECLS

#ifndef GDHCP_EXTERN
#define GDHCP_EXTERN
#endif

/* common */

typedef enum {
	G_DHCP_IPV4,
	G_DHCP_IPV6,
	G_DHCP_IPV4LL,
} GDHCPType;



/* DHCP client part */

#define GDHCP_TYPE_CLIENT  (gdhcp_client_get_type())
#define GDHCP_CLIENT_ERROR (gdhcp_client_error_quark())

G_DECLARE_DERIVABLE_TYPE (GDHCPClient, gdhcp_client, GDHCP, CLIENT, GObject)

struct _GDHCPClientClass
{
  GObjectClass parent_class;

  void (*lease_available)  (GDHCPClient *self, gpointer lease_available_data);
  void (*ipv4ll_available) (GDHCPClient *self, gpointer lease_available_data);
  void (*no_lease)         (GDHCPClient *self, gpointer no_lease_data);
  void (*lease_lost)       (GDHCPClient *self, gpointer lease_lost_data);
  void (*ipv4ll_lost)      (GDHCPClient *self, gpointer ipv4ll_lost_data);
  void (*address_conflict) (GDHCPClient *self, gpointer address_conflict_data);
  void (*information_req)  (GDHCPClient *self, gpointer information_req_data);
  void (*solicitation)     (GDHCPClient *self, gpointer solicitation_data);
  void (*advertise)        (GDHCPClient *self, gpointer advertise_data);
  void (*request)          (GDHCPClient *self, gpointer request_data);
  void (*renew)            (GDHCPClient *self, gpointer renew_data);
  void (*rebind)           (GDHCPClient *self, gpointer rebind_data);
  void (*release)          (GDHCPClient *self, gpointer release_data);
  void (*confirm)          (GDHCPClient *self, gpointer confirm_data);
  void (*decline)          (GDHCPClient *self, gpointer decline_data);

  gpointer _reserved2;
  gpointer _reserved3;
  gpointer _reserved4;
  gpointer _reserved5;
  gpointer _reserved6;
  gpointer _reserved7;
  gpointer _reserved8;
};

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

GDHCP_EXTERN
GDHCPClient *gdhcp_client_new(GDHCPType type, int index, GError **error);

GDHCP_EXTERN
int gdhcp_client_start(GDHCPClient *client, const char *last_address);

GDHCP_EXTERN
void gdhcp_client_stop(GDHCPClient *client);

GDHCP_EXTERN
void gdhcp_client_set_request(GDHCPClient *client, unsigned int option_code);

GDHCP_EXTERN
void gdhcp_client_clear_requests(GDHCPClient *dhcp_client);

GDHCP_EXTERN
void gdhcp_client_clear_values(GDHCPClient *dhcp_client);

GDHCP_EXTERN
void gdhcp_client_set_id(GDHCPClient *client, GError **error);

GDHCP_EXTERN
void gdhcp_client_set_send(GDHCPClient *client, unsigned char option_code, const char *option_value, GError **error);

GDHCP_EXTERN
char *gdhcp_client_get_server_address(GDHCPClient *client);

GDHCP_EXTERN
char *gdhcp_client_get_address(GDHCPClient *client);

GDHCP_EXTERN
char *gdhcp_client_get_netmask(GDHCPClient *client);

GDHCP_EXTERN
GList *gdhcp_client_get_option(GDHCPClient *client, unsigned char option_code);

GDHCP_EXTERN
int gdhcp_client_get_index(GDHCPClient *client);

GDHCP_EXTERN
int gdhcp_v6_create_duid(GDHCPDuidType duid_type, int index, int type, unsigned char **duid, int *duid_len);

GDHCP_EXTERN
int gdhcp_v6_client_set_duid(GDHCPClient *dhcp_client, unsigned char *duid, int duid_len);

GDHCP_EXTERN
int gdhcp_v6_client_set_pd(GDHCPClient *dhcp_client, uint32_t *T1, uint32_t *T2, GSList *prefixes);

GDHCP_EXTERN
GSList *gdhcp_v6_copy_prefixes(GSList *prefixes);

GDHCP_EXTERN
gboolean gdhcp_v6_client_clear_send(GDHCPClient *dhcp_client, uint16_t code);

GDHCP_EXTERN
void gdhcp_v6_client_set_send(GDHCPClient *dhcp_client, uint16_t option_code, uint8_t *option_value, uint16_t option_len);

GDHCP_EXTERN
uint16_t gdhcp_v6_client_get_status(GDHCPClient *dhcp_client);

GDHCP_EXTERN
int gdhcp_v6_client_set_oro(GDHCPClient *dhcp_client, int args, ...);

GDHCP_EXTERN
void gdhcp_v6_client_create_iaid(GDHCPClient *dhcp_client, int index, unsigned char *iaid);

GDHCP_EXTERN
int gdhcp_v6_client_get_timeouts(GDHCPClient *dhcp_client, uint32_t *T1, uint32_t *T2, time_t *started, time_t *expire);

GDHCP_EXTERN
uint32_t gdhcp_v6_client_get_iaid(GDHCPClient *dhcp_client);

GDHCP_EXTERN
void gdhcp_v6_client_set_iaid(GDHCPClient *dhcp_client, uint32_t iaid);

GDHCP_EXTERN
int gdhcp_v6_client_set_ia(GDHCPClient *dhcp_client, int index,
			int code, uint32_t *T1, uint32_t *T2,
			bool add_addresses, const char *address);

GDHCP_EXTERN
int gdhcp_v6_client_set_ias(GDHCPClient *dhcp_client, int index,
			int code, uint32_t *T1, uint32_t *T2,
			GSList *addresses);

GDHCP_EXTERN
void gdhcp_v6_client_reset_request(GDHCPClient *dhcp_client);

GDHCP_EXTERN
void gdhcp_v6_client_set_retransmit(GDHCPClient *dhcp_client);

GDHCP_EXTERN
void gdhcp_v6_client_clear_retransmit(GDHCPClient *dhcp_client);



/* DHCP server part */

#define GDHCP_TYPE_SERVER  (gdhcp_server_get_type())
#define GDHCP_SERVER_ERROR (gdhcp_server_error_quark())

G_DECLARE_DERIVABLE_TYPE (GDHCPServer, gdhcp_server, GDHCP, SERVER, GObject)

struct _GDHCPServerClass
{
  GObjectClass parent_class;
  void (*lease_added)  (GDHCPClient *self, gpointer lease_added_data);
};

typedef void (*GDHCPSaveLeaseFunc) (unsigned char *mac,
			unsigned int nip, unsigned int expire);

GDHCP_EXTERN
GDHCPServer *gdhcp_server_new(GDHCPType type, int ifindex, GError **error);

GDHCP_EXTERN
int gdhcp_server_start(GDHCPServer *server);

GDHCP_EXTERN
void gdhcp_server_stop(GDHCPServer *server);

GDHCP_EXTERN
int gdhcp_server_set_option(GDHCPServer *server, unsigned char option_code, const char *option_value);

GDHCP_EXTERN
int gdhcp_server_set_ip_range(GDHCPServer *server, const char *start_ip, const char *end_ip);

GDHCP_EXTERN
void gdhcp_server_set_lease_time(GDHCPServer *dhcp_server, unsigned int lease_time);

GDHCP_EXTERN
void gdhcp_server_set_save_lease(GDHCPServer *dhcp_server, GDHCPSaveLeaseFunc func, gpointer user_data);

int dhcp_get_random(uint64_t *val);
void dhcp_cleanup_random(void);

G_END_DECLS

#endif /* __G_DHCP_H */
