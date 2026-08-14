#include <arpa/inet.h>
#include <glib.h>
#include <gio/gio.h>
#include <libqmi-glib.h>
#include <stdio.h>
#include <string.h>

typedef struct { GMainLoop *loop; QmiDevice *device; QmiClientWds *client; guint32 handle; } Context;

static void fail(Context *c, const char *stage, GError *error) {
    g_printerr("qmi-ims-helper: %s: %s\n", stage, error ? error->message : "unknown error");
    if (error) g_error_free(error);
    g_main_loop_quit(c->loop);
}

static void settings_done(GObject *source, GAsyncResult *res, gpointer data) {
    Context *c = data; GError *error = NULL;
    QmiMessageWdsGetCurrentSettingsOutput *out = qmi_client_wds_get_current_settings_finish(c->client, res, &error);
    if (!out || !qmi_message_wds_get_current_settings_output_get_result(out, &error)) { fail(c, "get settings", error); return; }
    GArray *addr = NULL, *gw = NULL, *pcscf = NULL, *pco = NULL; guint8 prefix = 0, gw_prefix = 0; guint32 mtu = 0; guint16 pco_mcc = 0, pco_mnc = 0, pco_id = 0; gboolean pco_pcs = FALSE;
    if (!qmi_message_wds_get_current_settings_output_get_ipv6_address(out, &addr, &prefix, NULL) ||
        !qmi_message_wds_get_current_settings_output_get_ipv6_gateway_address(out, &gw, &gw_prefix, NULL)) {
        fail(c, "IPv6 settings missing", NULL); qmi_message_wds_get_current_settings_output_unref(out); return;
    }
    qmi_message_wds_get_current_settings_output_get_mtu(out, &mtu, NULL);
    qmi_message_wds_get_current_settings_output_get_pcscf_server_address_list(out, &pcscf, NULL);
    qmi_message_wds_get_current_settings_output_get_operator_reserved_pco(out, &pco_mcc, &pco_mnc, &pco_pcs, &pco, &pco_id, NULL);
    struct in6_addr a = {0}, g = {0}; char abuf[INET6_ADDRSTRLEN] = {0}, gbuf[INET6_ADDRSTRLEN] = {0};
    for (guint i = 0; i < 8; i++) { ((guint16 *)a.s6_addr)[i] = htons(g_array_index(addr, guint16, i)); ((guint16 *)g.s6_addr)[i] = htons(g_array_index(gw, guint16, i)); }
    inet_ntop(AF_INET6, &a, abuf, sizeof(abuf)); inet_ntop(AF_INET6, &g, gbuf, sizeof(gbuf));
    printf("{\"phase\":\"bearer_up\",\"cid\":%u,\"handle\":%u,\"ipv6\":\"%s\",\"prefix\":%u,\"gateway\":\"%s\",\"gateway_prefix\":%u,\"mtu\":%u,\"pcscf_count\":%u,\"pcscf0\":%u,\"pco_mcc\":%u,\"pco_mnc\":%u,\"pco_id\":%u,\"pco_len\":%u}\n", qmi_client_get_cid(QMI_CLIENT(c->client)), c->handle, abuf, prefix, gbuf, gw_prefix, mtu, pcscf ? pcscf->len : 0, (pcscf && pcscf->len) ? g_array_index(pcscf, guint32, 0) : 0, pco_mcc, pco_mnc, pco_id, pco ? pco->len : 0);
    fflush(stdout); g_printerr("qmi-ims-helper: WDS client held alive\n"); qmi_message_wds_get_current_settings_output_unref(out);
}

static void start_done(GObject *source, GAsyncResult *res, gpointer data) {
    Context *c = data; GError *error = NULL; QmiMessageWdsStartNetworkOutput *out = qmi_client_wds_start_network_finish(c->client, res, &error);
    guint32 handle = 0;
    if (!out || !qmi_message_wds_start_network_output_get_result(out, &error) || !qmi_message_wds_start_network_output_get_packet_data_handle(out, &handle, NULL)) { fail(c, "start network", error); return; }
    c->handle = handle; qmi_message_wds_start_network_output_unref(out);
    QmiMessageWdsGetCurrentSettingsInput *in = qmi_message_wds_get_current_settings_input_new();
    qmi_message_wds_get_current_settings_input_set_requested_settings(in, QMI_WDS_REQUESTED_SETTINGS_IP_ADDRESS | QMI_WDS_REQUESTED_SETTINGS_GATEWAY_INFO | QMI_WDS_REQUESTED_SETTINGS_PCSCF_ADDRESS | QMI_WDS_REQUESTED_SETTINGS_PCSCF_SERVER_ADDRESS_LIST | QMI_WDS_REQUESTED_SETTINGS_PCSCF_DOMAIN_NAME_LIST | QMI_WDS_REQUESTED_SETTINGS_OPERATOR_RESERVED_PCO | QMI_WDS_REQUESTED_SETTINGS_MTU | QMI_WDS_REQUESTED_SETTINGS_IP_FAMILY, NULL);
    qmi_client_wds_get_current_settings(c->client, in, 30, NULL, settings_done, c); qmi_message_wds_get_current_settings_input_unref(in);
}

static void family_done(GObject *source, GAsyncResult *res, gpointer data) {
    Context *c = data; GError *error = NULL; QmiMessageWdsSetIpFamilyOutput *out = qmi_client_wds_set_ip_family_finish(c->client, res, &error);
    if (!out || !qmi_message_wds_set_ip_family_output_get_result(out, &error)) { fail(c, "set IPv6 family", error); return; }
    qmi_message_wds_set_ip_family_output_unref(out); QmiMessageWdsStartNetworkInput *in = qmi_message_wds_start_network_input_new();
    qmi_message_wds_start_network_input_set_apn(in, "ims", NULL); qmi_message_wds_start_network_input_set_profile_index_3gpp(in, 4, NULL); qmi_message_wds_start_network_input_set_ip_family_preference(in, QMI_WDS_IP_FAMILY_IPV6, NULL);
    qmi_client_wds_start_network(c->client, in, 60, NULL, start_done, c); qmi_message_wds_start_network_input_unref(in);
}

static void client_done(GObject *source, GAsyncResult *res, gpointer data) {
    Context *c = data; GError *error = NULL; QmiClient *client = qmi_device_allocate_client_finish(c->device, res, &error);
    if (!client) { fail(c, "allocate WDS client", error); return; } c->client = QMI_CLIENT_WDS(client);
    QmiMessageWdsSetIpFamilyInput *in = qmi_message_wds_set_ip_family_input_new(); qmi_message_wds_set_ip_family_input_set_preference(in, QMI_WDS_IP_FAMILY_IPV6, NULL); qmi_client_wds_set_ip_family(c->client, in, 30, NULL, family_done, c); qmi_message_wds_set_ip_family_input_unref(in);
}
static void open_done(GObject *source, GAsyncResult *res, gpointer data) { Context *c = data; GError *error = NULL; if (!qmi_device_open_finish(c->device, res, &error)) { fail(c, "open device", error); return; } qmi_device_allocate_client(c->device, QMI_SERVICE_WDS, QMI_CID_NONE, 30, NULL, client_done, c); }
static void device_done(GObject *source, GAsyncResult *res, gpointer data) { Context *c = data; GError *error = NULL; c->device = qmi_device_new_finish(res, &error); if (!c->device) { fail(c, "create device", error); return; } qmi_device_open(c->device, QMI_DEVICE_OPEN_FLAGS_PROXY | QMI_DEVICE_OPEN_FLAGS_NET_RAW_IP | QMI_DEVICE_OPEN_FLAGS_NET_NO_QOS_HEADER, 30, NULL, open_done, c); }
int main(int argc, char **argv) { Context c = {0}; c.loop = g_main_loop_new(NULL, FALSE); GFile *f = g_file_new_for_path(argc > 1 ? argv[1] : "/dev/wwan0at2"); qmi_device_new(f, NULL, device_done, &c); g_object_unref(f); g_main_loop_run(c.loop); if (c.client) qmi_device_release_client(c.device, QMI_CLIENT(c.client), QMI_DEVICE_RELEASE_CLIENT_FLAGS_NONE, 5, NULL, NULL, NULL); if (c.device) g_object_unref(c.device); g_main_loop_unref(c.loop); return 0; }
