/* build with:
 *   gcc `pkg-config --cflags --libs gdhcp-1.0` dhcp-server-test.c -o dhcp-server-test
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gdhcp.h>

static GMainLoop *main_loop;

static void sig_term(int sig)
{
	g_main_loop_quit(main_loop);
}

static void handle_error(GDHCPServerError error)
{
	switch (error) {
	case G_DHCP_SERVER_ERROR_NONE:
		printf("dhcp server ok\n");
		break;
	case G_DHCP_SERVER_ERROR_INTERFACE_UNAVAILABLE:
		printf("Interface unavailable\n");
		break;
	case G_DHCP_SERVER_ERROR_INTERFACE_IN_USE:
		printf("Interface in use\n");
		break;
	case G_DHCP_SERVER_ERROR_INTERFACE_DOWN:
		printf("Interface down\n");
		break;
	case G_DHCP_SERVER_ERROR_NOMEM:
		printf("No memory\n");
		break;
	case G_DHCP_SERVER_ERROR_INVALID_INDEX:
		printf("Invalid index\n");
		break;
	case G_DHCP_SERVER_ERROR_INVALID_OPTION:
		printf("Invalid option\n");
		break;
	case G_DHCP_SERVER_ERROR_IP_ADDRESS_INVALID:
		printf("Invalid address\n");
		break;
	}
}

static void dhcp_debug(const char *str, void *data)
{
	printf("%s: %s\n", (const char *) data, str);
}


int main(int argc, char *argv[])
{
	struct sigaction sa;
	GDHCPServerError error;
	GDHCPServer *dhcp_server;
	int index;

	if (argc < 2) {
		printf("Usage: dhcp-server-test <interface index>\n");
		exit(0);
	}

	index = atoi(argv[1]);

	printf("Create DHCP server for interface %d\n", index);

	dhcp_server = gdhcp_server_new(G_DHCP_IPV4, index, &error);
	if (!dhcp_server) {
		handle_error(error);
		exit(0);
	}

	gdhcp_server_set_debug(dhcp_server, dhcp_debug, "DHCP");

	gdhcp_server_set_lease_time(dhcp_server, 3600);
	gdhcp_server_set_option(dhcp_server, G_DHCP_SUBNET, "255.255.0.0");
	gdhcp_server_set_option(dhcp_server, G_DHCP_ROUTER, "192.168.0.2");
	gdhcp_server_set_option(dhcp_server, G_DHCP_DNS_SERVER, "192.168.0.3");
	gdhcp_server_set_ip_range(dhcp_server, "192.168.0.101", "192.168.0.102");
	main_loop = g_main_loop_new(NULL, FALSE);

	printf("Start DHCP Server operation\n");

	gdhcp_server_start(dhcp_server);

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_term;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	g_main_loop_run(main_loop);

	gdhcp_server_unref(dhcp_server);

	g_main_loop_unref(main_loop);

	return 0;
}
