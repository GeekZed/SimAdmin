#include <glib.h>
#include <libqmi-glib.h>
#include <libqmi-glib/qmi-uim.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    GMainLoop *loop;
    QmiDevice *device;
    QmiClientUim *client;
    GError *error;
    guint8 slot;
    guint8 channel;
    GArray *aid;
    GArray *apdu;
    gboolean send_apdu;
} App;

static void fail(App *app, GError *error) {
    if (error) app->error = error;
    g_main_loop_quit(app->loop);
}

static GArray *hex_array(const char *text, GError **error) {
    GArray *array = g_array_new(FALSE, FALSE, sizeof(guint8));
    size_t length = strlen(text);
    if ((length & 1) != 0) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "odd hexadecimal length");
        g_array_unref(array);
        return NULL;
    }
    for (size_t i = 0; i < length; i += 2) {
        char byte_text[3] = {text[i], text[i + 1], 0};
        char *end = NULL;
        unsigned long value = strtoul(byte_text, &end, 16);
        if (!end || *end != 0 || value > 255) {
            g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "invalid hexadecimal APDU");
            g_array_unref(array);
            return NULL;
        }
        guint8 byte = (guint8)value;
        g_array_append_val(array, byte);
    }
    return array;
}

static void print_array(const GArray *array) {
    for (guint i = 0; array && i < array->len; ++i) printf("%02X", g_array_index(array, guint8, i));
    putchar('\n');
}

static void close_channel(App *app);

static void close_done(QmiClientUim *client, GAsyncResult *result, gpointer user_data) {
    App *app = user_data;
    GError *error = NULL;
    QmiMessageUimLogicalChannelOutput *output = qmi_client_uim_logical_channel_finish(client, result, &error);
    if (output) qmi_message_uim_logical_channel_output_unref(output);
    g_clear_error(&error);
    g_main_loop_quit(app->loop);
}

static void close_channel(App *app) {
    QmiMessageUimLogicalChannelInput *input = qmi_message_uim_logical_channel_input_new();
    GError *error = NULL;
    if (!qmi_message_uim_logical_channel_input_set_slot(input, app->slot, &error) ||
        !qmi_message_uim_logical_channel_input_set_channel_id(input, app->channel, &error)) {
        qmi_message_uim_logical_channel_input_unref(input);
        fail(app, error);
        return;
    }
    qmi_client_uim_logical_channel(app->client, input, 30, NULL, (GAsyncReadyCallback)close_done, app);
    qmi_message_uim_logical_channel_input_unref(input);
}

static void send_done(QmiClientUim *client, GAsyncResult *result, gpointer user_data) {
    App *app = user_data;
    GError *error = NULL;
    QmiMessageUimSendApduOutput *output = qmi_client_uim_send_apdu_finish(client, result, &error);
    if (!output || !qmi_message_uim_send_apdu_output_get_result(output, &error)) {
        if (output) qmi_message_uim_send_apdu_output_unref(output);
        fail(app, error);
        return;
    }
    GArray *response = NULL;
    if (!qmi_message_uim_send_apdu_output_get_apdu_response(output, &response, &error)) {
        qmi_message_uim_send_apdu_output_unref(output);
        fail(app, error);
        return;
    }
    print_array(response);
    qmi_message_uim_send_apdu_output_unref(output);
    close_channel(app);
}

static void open_done(QmiClientUim *client, GAsyncResult *result, gpointer user_data) {
    App *app = user_data;
    GError *error = NULL;
    QmiMessageUimOpenLogicalChannelOutput *output = qmi_client_uim_open_logical_channel_finish(client, result, &error);
    if (!output || !qmi_message_uim_open_logical_channel_output_get_result(output, &error) ||
        !qmi_message_uim_open_logical_channel_output_get_channel_id(output, &app->channel, &error)) {
        if (output) qmi_message_uim_open_logical_channel_output_unref(output);
        fail(app, error);
        return;
    }
    GArray *select_response = NULL;
    if (!qmi_message_uim_open_logical_channel_output_get_select_response(output, &select_response, &error)) {
        qmi_message_uim_open_logical_channel_output_unref(output);
        fail(app, error);
        return;
    }
    if (!app->send_apdu) {
        print_array(select_response);
        qmi_message_uim_open_logical_channel_output_unref(output);
        close_channel(app);
        return;
    }
    qmi_message_uim_open_logical_channel_output_unref(output);
    QmiMessageUimSendApduInput *input = qmi_message_uim_send_apdu_input_new();
    if (!qmi_message_uim_send_apdu_input_set_slot(input, app->slot, &error) ||
        !qmi_message_uim_send_apdu_input_set_channel_id(input, app->channel, &error) ||
        !qmi_message_uim_send_apdu_input_set_apdu(input, app->apdu, &error)) {
        qmi_message_uim_send_apdu_input_unref(input);
        fail(app, error);
        return;
    }
    qmi_client_uim_send_apdu(client, input, 30, NULL, (GAsyncReadyCallback)send_done, app);
    qmi_message_uim_send_apdu_input_unref(input);
}

static void client_done(QmiDevice *device, GAsyncResult *result, gpointer user_data) {
    App *app = user_data;
    GError *error = NULL;
    QmiClient *client = qmi_device_allocate_client_finish(device, result, &error);
    if (!client) { fail(app, error); return; }
    app->client = QMI_CLIENT_UIM(client);
    QmiMessageUimOpenLogicalChannelInput *input = qmi_message_uim_open_logical_channel_input_new();
    if (!qmi_message_uim_open_logical_channel_input_set_slot(input, app->slot, &error) ||
        !qmi_message_uim_open_logical_channel_input_set_aid(input, app->aid, &error)) {
        qmi_message_uim_open_logical_channel_input_unref(input);
        fail(app, error);
        return;
    }
    qmi_client_uim_open_logical_channel(app->client, input, 30, NULL, (GAsyncReadyCallback)open_done, app);
    qmi_message_uim_open_logical_channel_input_unref(input);
}

static void device_open_done(QmiDevice *device, GAsyncResult *result, gpointer user_data) {
    App *app = user_data;
    GError *error = NULL;
    if (!qmi_device_open_finish(device, result, &error)) { fail(app, error); return; }
    qmi_device_allocate_client(device, QMI_SERVICE_UIM, QMI_CID_NONE, 30, NULL, (GAsyncReadyCallback)client_done, app);
}

static void device_new_done(GObject *source, GAsyncResult *result, gpointer user_data) {
    App *app = user_data;
    GError *error = NULL;
    app->device = qmi_device_new_finish(result, &error);
    if (!app->device) { fail(app, error); return; }
    qmi_device_open(app->device, QMI_DEVICE_OPEN_FLAGS_PROXY, 30, NULL, (GAsyncReadyCallback)device_open_done, app);
}

int main(int argc, char **argv) {
    if (argc != 4 && argc != 5) {
        fprintf(stderr, "usage: %s /dev/qmi aid apdu [send]\n", argv[0]);
        return 2;
    }
    App app = {0};
    app.loop = g_main_loop_new(NULL, FALSE);
    app.slot = 1;
    app.aid = hex_array(argv[2], &app.error);
    app.apdu = hex_array(argv[3], &app.error);
    if (!app.aid || !app.apdu) {
        fprintf(stderr, "%s\n", app.error ? app.error->message : "invalid APDU");
        return 2;
    }
    app.send_apdu = argc == 5;
    GFile *file = g_file_new_for_path(argv[1]);
    qmi_device_new(file, NULL, device_new_done, &app);
    g_object_unref(file);
    g_main_loop_run(app.loop);
    if (app.error) fprintf(stderr, "%s\n", app.error->message);
    if (app.client) g_object_unref(app.client);
    if (app.device) g_object_unref(app.device);
    g_array_unref(app.aid);
    g_array_unref(app.apdu);
    g_main_loop_unref(app.loop);
    return app.error ? 1 : 0;
}
