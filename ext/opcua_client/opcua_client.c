#include <ruby.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <mbedtls/pem.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#include <mbedtls/base64.h>
#include "open62541.h"

VALUE cClient;
VALUE cError;
VALUE cConnectionError;
VALUE cNodeError;
VALUE cTypeMismatchError;
VALUE cProtocolError;
VALUE cArgumentError;
VALUE mOPCUAClient;

/* Diagnostic logging is silent unless OPCUA_CLIENT_DEBUG is set in the
   environment (read once in Init_opcua_client). Use DBG() instead of DBG(). */
static int g_debug = 0;
#define DBG(...) do { if (g_debug) { printf(__VA_ARGS__); fflush(stdout); } } while (0)

struct UninitializedClient {
    UA_Client *client;
};

struct OpcuaClientContext {
    VALUE rubyClientInstance;
};

UA_ByteString loadFile(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        DBG("Failed to open file: %s\n", path);
        return UA_STRING_NULL;
    }

    // Seek to the end of the file to determine its size
    fseek(fp, 0, SEEK_END);
    size_t fileSize = ftell(fp);
    rewind(fp);

    // Allocate memory for the file contents
    UA_ByteString fileContents;
    fileContents.data = (uint8_t *)malloc(fileSize);
    if (!fileContents.data) {
        DBG("Failed to allocate memory for file: %s\n", path);
        fclose(fp);
        return UA_STRING_NULL;
    }

    // Set the length of the ByteString
    fileContents.length = fileSize;

    // Read the file into the allocated memory
    size_t bytesRead = fread(fileContents.data, 1, fileSize, fp);
    if (bytesRead != fileSize) {
        DBG("Failed to read file: %s\n", path);
        free(fileContents.data);
        fileContents.data = NULL;
        fileContents.length = 0;
        fclose(fp);
        return UA_STRING_NULL;
    }

    fclose(fp);
    return fileContents;
}

UA_ByteString convertPemToDer(const char *pem_data, int is_private_key) {
    UA_ByteString der_data = UA_STRING_NULL;
    int ret = 0;

    DBG("Converting PEM to DER using mbedtls library...\n");

    if (is_private_key) {
        // Handle private key conversion
        mbedtls_pk_context pk;
        mbedtls_pk_init(&pk);

        // Parse PEM private key
        ret = mbedtls_pk_parse_key(&pk, (const unsigned char *)pem_data, strlen(pem_data) + 1, NULL, 0);
        if (ret != 0) {
            DBG("Failed to parse PEM private key, mbedtls error: -0x%04x\n", -ret);
            mbedtls_pk_free(&pk);
            return UA_STRING_NULL;
        }

        // Allocate buffer with a reasonable size for DER private key (typically < 2KB)
        size_t der_len = 2048;
        unsigned char *der_buffer = malloc(der_len);
        if (!der_buffer) {
            DBG("Failed to allocate memory for DER private key\n");
            mbedtls_pk_free(&pk);
            return UA_STRING_NULL;
        }

        // Write DER data - the function writes from the end of buffer backwards
        ret = mbedtls_pk_write_key_der(&pk, der_buffer, der_len);
        if (ret <= 0) {
            DBG("Failed to write DER private key, mbedtls error: -0x%04x\n", -ret);
            free(der_buffer);
            mbedtls_pk_free(&pk);
            return UA_STRING_NULL;
        }

        // The actual DER data starts at (der_buffer + der_len - ret) and has length ret
        size_t actual_der_len = ret;
        unsigned char *actual_der_start = der_buffer + der_len - ret;

        // Allocate the exact amount needed and copy
        der_data.data = (uint8_t *)malloc(actual_der_len);
        if (!der_data.data) {
            DBG("Failed to allocate final DER buffer\n");
            free(der_buffer);
            mbedtls_pk_free(&pk);
            return UA_STRING_NULL;
        }

        memcpy(der_data.data, actual_der_start, actual_der_len);
        der_data.length = actual_der_len;

        free(der_buffer);
        mbedtls_pk_free(&pk);

        DBG("Successfully converted private key from PEM to DER, size: %lu bytes\n", der_data.length);
    } else {
        // Handle certificate conversion
        mbedtls_x509_crt crt;
        mbedtls_x509_crt_init(&crt);

        // Parse PEM certificate
        ret = mbedtls_x509_crt_parse(&crt, (const unsigned char *)pem_data, strlen(pem_data) + 1);
        if (ret != 0) {
            DBG("Failed to parse PEM certificate, mbedtls error: -0x%04x\n", -ret);
            mbedtls_x509_crt_free(&crt);
            return UA_STRING_NULL;
        }

        // The certificate's DER data is already available in the parsed structure
        der_data.data = (uint8_t *)malloc(crt.raw.len);
        if (!der_data.data) {
            DBG("Failed to allocate memory for DER certificate\n");
            mbedtls_x509_crt_free(&crt);
            return UA_STRING_NULL;
        }

        memcpy(der_data.data, crt.raw.p, crt.raw.len);
        der_data.length = crt.raw.len;
        mbedtls_x509_crt_free(&crt);

        DBG("Successfully converted certificate from PEM to DER, size: %lu bytes\n", der_data.length);
    }

    return der_data;
}

static VALUE toRubyTime(UA_DateTime raw_date) {
    UA_DateTimeStruct dts = UA_DateTime_toStruct(raw_date);
    VALUE year = UINT2NUM(dts.year);
    VALUE month = UINT2NUM(dts.month);
    VALUE day = UINT2NUM(dts.day);
    VALUE hour = UINT2NUM(dts.hour);
    VALUE min = UINT2NUM(dts.min);
    VALUE sec = UINT2NUM(dts.sec);
    VALUE millis = UINT2NUM(dts.milliSec);
    VALUE cDate = rb_const_get(rb_cObject, rb_intern("Time"));
    VALUE rb_date = rb_funcall(cDate, rb_intern("gm"), 7, year, month, day, hour, min, sec, millis);
    return rb_date;
}

static UA_DateTime fromRubyTime(VALUE ruby_time) {
    // Handle both Time objects and numeric values (milliseconds)
    if (RB_TYPE_P(ruby_time, T_FIXNUM) || RB_TYPE_P(ruby_time, T_BIGNUM)) {
        // Treat as milliseconds and convert to UA_DateTime
        long long milliseconds = NUM2LL(ruby_time);
        return milliseconds * UA_DATETIME_MSEC;
    } else if (rb_obj_is_kind_of(ruby_time, rb_cTime)) {
        // Ruby Time object - extract components
        VALUE year = rb_funcall(ruby_time, rb_intern("year"), 0);
        VALUE month = rb_funcall(ruby_time, rb_intern("month"), 0);
        VALUE day = rb_funcall(ruby_time, rb_intern("day"), 0);
        VALUE hour = rb_funcall(ruby_time, rb_intern("hour"), 0);
        VALUE min = rb_funcall(ruby_time, rb_intern("min"), 0);
        VALUE sec = rb_funcall(ruby_time, rb_intern("sec"), 0);
        VALUE usec = rb_funcall(ruby_time, rb_intern("usec"), 0);

        // Convert to UA_DateTime using Unix timestamp approach
        VALUE unix_time = rb_funcall(ruby_time, rb_intern("to_i"), 0);
        long long unix_seconds = NUM2LL(unix_time);
        long long microseconds = NUM2LL(usec);

        // Convert Unix timestamp to OPC UA DateTime
        // OPC UA DateTime is 100-nanosecond intervals since January 1, 1601 UTC
        UA_DateTime ua_time = (unix_seconds * UA_DATETIME_SEC) + UA_DATETIME_UNIX_EPOCH;
        ua_time += microseconds * UA_DATETIME_USEC;

        return ua_time;
    } else {
        // Fallback: treat as numeric milliseconds
        double ms = NUM2DBL(ruby_time);
        return (UA_DateTime)(ms * UA_DATETIME_MSEC);
    }
}

static void
handler_dataChanged(UA_Client *client, UA_UInt32 subId, void *subContext,
                           UA_UInt32 monId, void *monContext, UA_DataValue *value) {

    struct OpcuaClientContext *ctx = UA_Client_getContext(client);
    VALUE self = ctx->rubyClientInstance;
    VALUE callback = rb_ivar_get(self, rb_intern("@callback_after_data_changed"));

    if (NIL_P(callback)) {
        return;
    }

    VALUE v_serverTime = Qnil;
    if (value->hasServerTimestamp) {
        v_serverTime = toRubyTime(value->serverTimestamp);
    }

    VALUE v_sourceTime = Qnil;
    if (value->hasSourceTimestamp) {
        v_sourceTime = toRubyTime(value->sourceTimestamp);
    }

    VALUE params = rb_ary_new();
    rb_ary_push(params, UINT2NUM(subId));
    rb_ary_push(params, UINT2NUM(monId));
    rb_ary_push(params, v_serverTime);
    rb_ary_push(params, v_sourceTime);

    VALUE v_newValue = Qnil;

    if(UA_Variant_hasScalarType(&value->value, &UA_TYPES[UA_TYPES_DATETIME])) {
        UA_DateTime raw_date = *(UA_DateTime *) value->value.data;
        v_newValue = toRubyTime(raw_date);
    } else if (UA_Variant_hasScalarType(&value->value, &UA_TYPES[UA_TYPES_INT32])) {
        UA_Int32 number = *(UA_Int32 *) value->value.data;
        v_newValue = INT2NUM(number);
    } else if (UA_Variant_hasScalarType(&value->value, &UA_TYPES[UA_TYPES_INT16])) {
        UA_Int16 number = *(UA_Int16 *) value->value.data;
        v_newValue = INT2NUM(number);
    } else if (UA_Variant_hasScalarType(&value->value, &UA_TYPES[UA_TYPES_BOOLEAN])) {
        UA_Boolean b = *(UA_Boolean *) value->value.data;
        v_newValue = b ? Qtrue : Qfalse;
    } else if (UA_Variant_hasScalarType(&value->value, &UA_TYPES[UA_TYPES_FLOAT])) {
        UA_Float dbl = *(UA_Float *) value->value.data;
        v_newValue = DBL2NUM(dbl);
    }

    rb_ary_push(params, v_newValue);
    rb_proc_call(callback, params);
}

static void
deleteSubscriptionCallback(UA_Client *client, UA_UInt32 subscriptionId, void *subscriptionContext) {
    // DBG("Subscription Id %u was deleted\n", subscriptionId);
}

static void
subscriptionInactivityCallback(UA_Client *client, UA_UInt32 subscriptionId, void *subContext) {
    // DBG("Inactivity for subscription %u", subscriptionId);
}

static void
stateCallback (UA_Client *client, UA_ClientState clientState) {
    struct OpcuaClientContext *ctx = UA_Client_getContext(client);

    switch(clientState) {
        case UA_CLIENTSTATE_DISCONNECTED:
            ; // DBG("%s\n", "The client is disconnected");
            break;
        case UA_CLIENTSTATE_CONNECTED:
            ; // DBG("%s\n", "A TCP connection to the server is open");
            break;
        case UA_CLIENTSTATE_SECURECHANNEL:
            ; // DBG("%s\n", "A SecureChannel to the server is open");
            break;
        case UA_CLIENTSTATE_SESSION:
            ; // DBG("%s\n", "A new session was created!");
            VALUE self = ctx->rubyClientInstance;

            VALUE callback = rb_ivar_get(self, rb_intern("@callback_after_session_created"));
            if (!NIL_P(callback)) {
                VALUE params = rb_ary_new();
                rb_ary_push(params, self);
                rb_proc_call(callback, params); // rescue?
            }

            break;
        case UA_CLIENTSTATE_SESSION_RENEWED:
            /* The session was renewed. We don't need to recreate the subscription. */
            break;
    }
    return;
}

/* Single source of truth mapping a UA_StatusCode to an operational category.
   open62541 1.0.x ships the constants but no severity/category helper, so we
   enumerate the families the robot realistically returns. Anything unlisted
   falls through to CAT_PROTOCOL (a safe default: never mis-typed as a link
   failure). */
typedef enum { CAT_CONNECTION, CAT_NODE, CAT_TYPE, CAT_PROTOCOL } StatusCategory;

static StatusCategory status_category(UA_StatusCode s) {
    switch (s) {
        /* ---- connection / session / channel / transport ---- */
        case UA_STATUSCODE_BADCOMMUNICATIONERROR:
        case UA_STATUSCODE_BADTIMEOUT:
        case UA_STATUSCODE_BADSHUTDOWN:
        case UA_STATUSCODE_BADSERVERNOTCONNECTED:
        case UA_STATUSCODE_BADSERVERHALTED:
        case UA_STATUSCODE_BADSECURECHANNELIDINVALID:
        case UA_STATUSCODE_BADSESSIONIDINVALID:
        case UA_STATUSCODE_BADSESSIONCLOSED:
        case UA_STATUSCODE_BADSESSIONNOTACTIVATED:
        case UA_STATUSCODE_BADSECURECHANNELCLOSED:
        case UA_STATUSCODE_BADSECURECHANNELTOKENUNKNOWN:
        case UA_STATUSCODE_BADNOTCONNECTED:
        case UA_STATUSCODE_BADCONNECTIONREJECTED:
        case UA_STATUSCODE_BADDISCONNECT:
        case UA_STATUSCODE_BADCONNECTIONCLOSED:
            return CAT_CONNECTION;
        /* ---- node / addressing ---- */
        case UA_STATUSCODE_BADNODEIDINVALID:
        case UA_STATUSCODE_BADNODEIDUNKNOWN:
        case UA_STATUSCODE_BADATTRIBUTEIDINVALID:
        case UA_STATUSCODE_BADINDEXRANGEINVALID:
        case UA_STATUSCODE_BADINDEXRANGENODATA:
        case UA_STATUSCODE_BADNOTFOUND:
            return CAT_NODE;
        /* ---- type / value ---- */
        case UA_STATUSCODE_BADTYPEMISMATCH:
        case UA_STATUSCODE_BADOUTOFRANGE:
        case UA_STATUSCODE_BADDATATYPEIDUNKNOWN:
            return CAT_TYPE;
        /* ---- everything else (BadUnexpectedError, BadInternalError, ...) ---- */
        default:
            return CAT_PROTOCOL;
    }
}

static VALUE class_for_category(StatusCategory c) {
    switch (c) {
        case CAT_CONNECTION: return cConnectionError;
        case CAT_NODE:       return cNodeError;
        case CAT_TYPE:       return cTypeMismatchError;
        default:             return cProtocolError;
    }
}

/* Build a classified exception carrying structured data, then raise it.
   rb_raise() can't attach ivars, so we construct the object first. The message
   string is kept byte-identical to the previous "%u: %s" format so any existing
   string matching keeps working. node_index is the failing slot in a multi_*
   call, or -1 (-> nil) for single-node / service-level failures. */
static VALUE raise_ua_status(UA_StatusCode status, long node_index) {
    VALUE klass = class_for_category(status_category(status));
    const char *name = UA_StatusCode_name(status);
    VALUE exc = rb_exc_new_str(klass, rb_sprintf("%u: %s", status, name));
    rb_iv_set(exc, "@status_code", UINT2NUM(status));
    rb_iv_set(exc, "@status_name", rb_str_new_cstr(name));
    rb_iv_set(exc, "@node_index", node_index >= 0 ? LONG2NUM(node_index) : Qnil);
    rb_exc_raise(exc);
    return Qnil; /* unreached */
}

/* Client-side errors that have no UA status code (caller misuse, undecodable
   type). status_code is nil; status_name carries the message. */
static VALUE raise_client_error(VALUE klass, const char *msg) {
    VALUE exc = rb_exc_new_str(klass, rb_str_new_cstr(msg));
    rb_iv_set(exc, "@status_code", Qnil);
    rb_iv_set(exc, "@status_name", rb_str_new_cstr(msg));
    rb_iv_set(exc, "@node_index", Qnil);
    rb_exc_raise(exc);
    return Qnil; /* unreached */
}

static VALUE raise_invalid_arguments_error() {
    return raise_client_error(cArgumentError, "Invalid arguments");
}

/* Thin wrapper so existing single-node call sites compile unchanged; the
   status code drives classification, node_index is nil. */
static VALUE raise_ua_status_error(UA_StatusCode status) {
    return raise_ua_status(status, -1);
}

static void UA_Client_free(void *self) {
    // DBG("free client\n");
    struct UninitializedClient *uclient = self;

    if (uclient->client) {
        struct OpcuaClientContext *ctx = UA_Client_getContext(uclient->client);
        xfree(ctx);
        UA_Client_delete(uclient->client);
    }

    xfree(self);
}

static const rb_data_type_t UA_Client_Type = {
    "UA_Uninitialized_Client",
    { 0, UA_Client_free, 0 },
    0, 0, RUBY_TYPED_FREE_IMMEDIATELY,
};

static VALUE allocate(VALUE klass) {
    // DBG("allocate client\n");
    struct UninitializedClient *uclient = ALLOC(struct UninitializedClient);
    *uclient = (const struct UninitializedClient){ 0 };

    return TypedData_Wrap_Struct(klass, &UA_Client_Type, uclient);
}

static VALUE rb_initialize(VALUE self) {
    struct UninitializedClient *uclient;
    TypedData_Get_Struct(self, struct UninitializedClient, &UA_Client_Type, uclient);

    uclient->client = UA_Client_new();

    UA_ClientConfig *config = UA_Client_getConfig(uclient->client);

    config->stateCallback = stateCallback;

    config->subscriptionInactivityCallback = subscriptionInactivityCallback;

    struct OpcuaClientContext *ctx = ALLOC(struct OpcuaClientContext);
    *ctx = (const struct OpcuaClientContext){ 0 };

    ctx->rubyClientInstance = self;
    config->clientContext = ctx;

    return Qnil;
}

// Helper function to check if a string value is nil or empty
static bool is_empty_or_nil(VALUE val) {
    return NIL_P(val) || (RB_TYPE_P(val, T_STRING) && RSTRING_LEN(val) == 0);
}

// Type predicates for write-value validation. Used to reject non-numeric Ruby
// args with a rescuable OPCUAClient::ArgumentError instead of a bare ::TypeError
// from NUM2LL/NUM2DBL. value_is_numeric accepts whatever those accept (Integer
// or Float), so accepted-input behaviour is unchanged.
static bool value_is_integer(VALUE val) {
    return RB_TYPE_P(val, T_FIXNUM) == 1 || RB_TYPE_P(val, T_BIGNUM) == 1;
}

static bool value_is_numeric(VALUE val) {
    return rb_obj_is_kind_of(val, rb_cNumeric) == Qtrue;
}

static VALUE rb_connect(int argc, VALUE *argv, VALUE self) {
    VALUE v_connectionString, v_username, v_password, v_client_cert, v_private_key;

    // Require 1 arg (url), allow up to 5 (url, username, password, client_cert, private_key)
    rb_scan_args(argc, argv, "14", &v_connectionString, &v_username, &v_password, &v_client_cert, &v_private_key);

    if (RB_TYPE_P(v_connectionString, T_STRING) != 1) {
        DBG("Invalid connection string provided.\n");
        return raise_invalid_arguments_error();
    }

    char *connectionString = StringValueCStr(v_connectionString);

    struct UninitializedClient *uclient;
    TypedData_Get_Struct(self, struct UninitializedClient, &UA_Client_Type, uclient);
    UA_Client *client = uclient->client;

    UA_StatusCode status;
    UA_ClientConfig *config = UA_Client_getConfig(client);

    struct OpcuaClientContext *existing_ctx = (struct OpcuaClientContext *)config->clientContext;

    // Check if we need to avoid reconfiguring security policies for reconnection
    bool hasExistingSecurityPolicies = (config->securityPoliciesSize > 0);

    // Check client state - only proceed with connection if not already in session
    UA_ClientState clientState = UA_Client_getState(client);
    bool isDisconnected = (clientState == UA_CLIENTSTATE_DISCONNECTED);

    // If we're already connected/in session, return success immediately
    if (clientState == UA_CLIENTSTATE_SESSION || clientState == UA_CLIENTSTATE_SESSION_RENEWED) {
        DBG("Client already has active session (state: %d), skipping connection...\n", clientState);
        return Qnil;
    }

    // Only clear cached endpoint info if we're actually disconnected
    // This prevents disrupting active sessions
    if (isDisconnected) {
        DBG("Client is disconnected, clearing endpoint cache for fresh discovery...\n");
        UA_EndpointDescription_clear(&config->endpoint);
        UA_UserTokenPolicy_clear(&config->userTokenPolicy);
        UA_String_clear(&config->securityPolicyUri);
    } else {
        DBG("Client is connecting, preserving endpoint configuration...\n");
    }

    bool useEncryption = !is_empty_or_nil(v_username) && !is_empty_or_nil(v_password) &&
                         !is_empty_or_nil(v_client_cert) && !is_empty_or_nil(v_private_key);

    if (useEncryption) {
        DBG("Setting up encrypted connection...\n");
        DBG("***CONNECTING***\n");
        if (hasExistingSecurityPolicies) {
            DBG("Security policies already configured, skipping encryption setup...\n");

            config->stateCallback = stateCallback;
            config->subscriptionInactivityCallback = subscriptionInactivityCallback;
            config->clientContext = existing_ctx;
        } else {
            // First-time encryption setup
            // Validate certificate and private key parameters
            if (RB_TYPE_P(v_client_cert, T_STRING) != 1 || RB_TYPE_P(v_private_key, T_STRING) != 1) {
                DBG("Invalid certificate or private key provided.\n");
                return raise_invalid_arguments_error();
            }

            // Convert PEM certificates to DER format
            char *cert_pem = StringValueCStr(v_client_cert);
            char *key_pem = StringValueCStr(v_private_key);

            DBG("Converting PEM certificates to DER format...\n");
            UA_ByteString certificate = convertPemToDer(cert_pem, 0); // 0 = certificate
            UA_ByteString privateKey = convertPemToDer(key_pem, 1);   // 1 = private key

            if (certificate.data == NULL || privateKey.data == NULL) {
                DBG("Failed to convert certificates to DER format.\n");
                if (certificate.data) UA_ByteString_clear(&certificate);
                if (privateKey.data) UA_ByteString_clear(&privateKey);
                return raise_invalid_arguments_error();
            }

            DBG("Configuring encryption...\n");
            status = UA_ClientConfig_setDefaultEncryption(config, certificate, privateKey,
                                                          NULL, 0, NULL, 0);

            UA_ByteString_clear(&certificate);
            UA_ByteString_clear(&privateKey);

            if (status != UA_STATUSCODE_GOOD) {
                DBG("Failed to set encryption configuration: %s\n", UA_StatusCode_name(status));
                return raise_ua_status_error(status);
            }

            config->stateCallback = stateCallback;
            config->subscriptionInactivityCallback = subscriptionInactivityCallback;
            config->clientContext = existing_ctx;

            DBG("Encryption configuration successful.\n");
        }
    } else {
        DBG("Setting up non-encrypted connection...\n");

        if (!hasExistingSecurityPolicies) {
            status = UA_ClientConfig_setDefault(config);
            if (status != UA_STATUSCODE_GOOD) {
                DBG("Failed to set default configuration: %s\n", UA_StatusCode_name(status));
                return raise_ua_status_error(status);
            }
        } else {
            DBG("Security policies already exist, skipping default config setup...\n");
        }

        config->stateCallback = stateCallback;
        config->subscriptionInactivityCallback = subscriptionInactivityCallback;
        config->clientContext = existing_ctx;
    }

    UA_String_deleteMembers(&config->clientDescription.applicationUri);
    config->clientDescription.applicationUri = UA_STRING_NULL;

    if (!is_empty_or_nil(v_username) && !is_empty_or_nil(v_password)) {
        // Username/password authentication
        const char *username = StringValueCStr(v_username);
        const char *password = StringValueCStr(v_password);

        DBG("Connecting with username/password authentication%s...\n", useEncryption ? " and encryption" : "");

        // Connect with username and password
        status = UA_Client_connect_username(client, connectionString, username, password);
    } else {
        // Anonymous authentication
        DBG("Connecting anonymously%s...\n", useEncryption ? " with encryption" : "");

        // Connect anonymously
        status = UA_Client_connect(client, connectionString);
    }

    if (status == UA_STATUSCODE_GOOD) {
        DBG("Connection successful!\n");
        return Qnil;
    } else {
        DBG("Connection failed: %s\n", UA_StatusCode_name(status));
        return raise_ua_status_error(status);
    }
}

static VALUE rb_createSubscription(VALUE self) {
    struct UninitializedClient * uclient;
    TypedData_Get_Struct(self, struct UninitializedClient, &UA_Client_Type, uclient);
    UA_Client *client = uclient->client;

    UA_CreateSubscriptionRequest request = UA_CreateSubscriptionRequest_default();
    UA_CreateSubscriptionResponse response = UA_Client_Subscriptions_create(client, request, NULL, NULL, deleteSubscriptionCallback);

    if (response.responseHeader.serviceResult == UA_STATUSCODE_GOOD) {
        UA_UInt32 subscriptionId = response.subscriptionId;
        return UINT2NUM(subscriptionId);
    } else {
        return Qnil;
    }
}

static VALUE rb_addMonitoredItem(VALUE self, VALUE v_subscriptionId, VALUE v_monNsIndex, VALUE v_monNsName) {
    struct UninitializedClient * uclient;
    TypedData_Get_Struct(self, struct UninitializedClient, &UA_Client_Type, uclient);
    UA_Client *client = uclient->client;

    UA_UInt32 subscriptionId = NUM2UINT(v_subscriptionId); // TODO: check type
    UA_UInt16 monNsIndex = NUM2USHORT(v_monNsIndex); // TODO: check type
    char* monNsName = StringValueCStr(v_monNsName); // TODO: check type

    UA_MonitoredItemCreateRequest monRequest = UA_MonitoredItemCreateRequest_default(UA_NODEID_STRING(monNsIndex, monNsName));

    UA_MonitoredItemCreateResult monResponse =
    UA_Client_MonitoredItems_createDataChange(client, subscriptionId,
                                              UA_TIMESTAMPSTORETURN_BOTH,
                                              monRequest, NULL, handler_dataChanged, NULL);
    if (monResponse.statusCode == UA_STATUSCODE_GOOD) {
        // DBG("Request to monitor field %hu:%s successful, id %u\n", monNsIndex, monNsName, monResponse.monitoredItemId);
        UA_UInt32 monitoredItemId = monResponse.monitoredItemId;
        return UINT2NUM(monitoredItemId);
    } else {
        // DBG("Request to monitor field failed: %s\n", UA_StatusCode_name(monResponse.statusCode));
        return Qnil;
    }
}

static VALUE rb_deleteMonitoredItem(VALUE self, VALUE v_subscriptionId, VALUE v_monitoredItemId) {
    struct UninitializedClient * uclient;
    TypedData_Get_Struct(self, struct UninitializedClient, &UA_Client_Type, uclient);
    UA_Client *client = uclient->client;

    UA_UInt32 subscriptionId = NUM2UINT(v_subscriptionId);
    UA_UInt32 monitoredItemId = NUM2UINT(v_monitoredItemId);

    UA_DeleteMonitoredItemsRequest deleteRequest;
    UA_DeleteMonitoredItemsRequest_init(&deleteRequest);
    deleteRequest.subscriptionId = subscriptionId;
    deleteRequest.monitoredItemIds = &monitoredItemId;
    deleteRequest.monitoredItemIdsSize = 1;

    UA_DeleteMonitoredItemsResponse deleteResponse =
        UA_Client_MonitoredItems_delete(client, deleteRequest);

    if (deleteResponse.responseHeader.serviceResult == UA_STATUSCODE_GOOD &&
        deleteResponse.resultsSize > 0 &&
        deleteResponse.results[0] == UA_STATUSCODE_GOOD) {
        DBG("Successfully deleted monitored item %u from subscription %u\n", monitoredItemId, subscriptionId);
        UA_DeleteMonitoredItemsResponse_clear(&deleteResponse);
        return Qtrue;
    } else {
        DBG("Failed to delete monitored item %u from subscription %u\n", monitoredItemId, subscriptionId);
        UA_DeleteMonitoredItemsResponse_clear(&deleteResponse);
        return Qfalse;
    }
}

static VALUE rb_deleteSubscription(VALUE self, VALUE v_subscriptionId) {
    struct UninitializedClient * uclient;
    TypedData_Get_Struct(self, struct UninitializedClient, &UA_Client_Type, uclient);
    UA_Client *client = uclient->client;

    UA_UInt32 subscriptionId = NUM2UINT(v_subscriptionId);

    UA_DeleteSubscriptionsRequest deleteRequest;
    UA_DeleteSubscriptionsRequest_init(&deleteRequest);
    deleteRequest.subscriptionIds = &subscriptionId;
    deleteRequest.subscriptionIdsSize = 1;

    UA_DeleteSubscriptionsResponse deleteResponse =
        UA_Client_Subscriptions_delete(client, deleteRequest);

    if (deleteResponse.responseHeader.serviceResult == UA_STATUSCODE_GOOD &&
        deleteResponse.resultsSize > 0 &&
        deleteResponse.results[0] == UA_STATUSCODE_GOOD) {
        DBG("Successfully deleted subscription %u\n", subscriptionId);
        UA_DeleteSubscriptionsResponse_clear(&deleteResponse);
        return Qtrue;
    } else {
        DBG("Failed to delete subscription %u\n", subscriptionId);
        UA_DeleteSubscriptionsResponse_clear(&deleteResponse);
        return Qfalse;
    }
}

static VALUE rb_deleteAllSubscriptions(VALUE self) {
    struct UninitializedClient * uclient;
    TypedData_Get_Struct(self, struct UninitializedClient, &UA_Client_Type, uclient);
    UA_Client *client = uclient->client;

    // This will delete all subscriptions for the client session
    UA_StatusCode status = UA_Client_Subscriptions_deleteSingle(client, 0);

    if (status == UA_STATUSCODE_GOOD || status == UA_STATUSCODE_BADSUBSCRIPTIONIDINVALID) {
        // BADSUBSCRIPTIONIDINVALID means no subscriptions exist, which is also success for our purpose
        DBG("Successfully deleted all subscriptions\n");
        return Qtrue;
    } else {
        DBG("Failed to delete all subscriptions: %s\n", UA_StatusCode_name(status));
        return Qfalse;
    }
}

static VALUE rb_disconnect(VALUE self) {
    struct UninitializedClient * uclient;
    TypedData_Get_Struct(self, struct UninitializedClient, &UA_Client_Type, uclient);
    UA_Client *client = uclient->client;

    UA_StatusCode status = UA_Client_disconnect(client);
    DBG("***DISCONNECTING***\n");
    return RB_UINT2NUM(status);
}

/* On failure, *failedIndex is set to the index of the offending node for a
   per-node error, or left at -1 for a service/connection-level failure (so the
   caller classifies it as a link problem rather than a node problem). The real
   UA status code is returned instead of a synthesized BADUNEXPECTEDERROR. */
static UA_StatusCode multiRead(UA_Client *client, const UA_NodeId *nodeId, UA_Variant *out, const long varsCount, long *failedIndex) {
    *failedIndex = -1;

    UA_UInt16 rvSize = UA_TYPES[UA_TYPES_READVALUEID].memSize;
    UA_ReadValueId *rValues = UA_calloc(varsCount, rvSize);

    for (int i = 0; i < varsCount; i++) {
        UA_ReadValueId *readItem = &rValues[i];
        readItem->nodeId = nodeId[i];
        readItem->attributeId = UA_ATTRIBUTEID_VALUE;
    }

    UA_ReadRequest request;
    UA_ReadRequest_init(&request);
    request.nodesToRead = rValues;
    request.nodesToReadSize = varsCount;

    UA_ReadResponse response = UA_Client_Service_read(client, request);

    /* Service/connection-level failure: no per-node index. */
    UA_StatusCode service = response.responseHeader.serviceResult;
    if (service != UA_STATUSCODE_GOOD) {
        UA_ReadResponse_deleteMembers(&response);
        UA_free(rValues);
        return service;
    }

    if (response.resultsSize != (size_t)varsCount) {
        UA_ReadResponse_deleteMembers(&response);
        UA_free(rValues);
        return UA_STATUSCODE_BADUNEXPECTEDERROR;
    }

    UA_DataValue *results = response.results;

    /* Per-node check: report which node failed and its real status code. */
    for (long i = 0; i < varsCount; i++) {
        if ((results[i].hasStatus && results[i].status != UA_STATUSCODE_GOOD) || !results[i].hasValue) {
            *failedIndex = i;
            UA_StatusCode node = results[i].hasStatus ? results[i].status : UA_STATUSCODE_BADUNEXPECTEDERROR;
            UA_ReadResponse_deleteMembers(&response);
            UA_free(rValues);
            return node;
        }
    }

    for (long i = 0; i < varsCount; i++) {
        out[i] = results[i].value;
        UA_Variant_init(&results[i].value);
    }

    UA_ReadResponse_deleteMembers(&response);
    UA_free(rValues);
    return UA_STATUSCODE_GOOD;
}

/* On a per-node write failure, *failedIndex is set to the offending node and
   its real status code is returned. Service-level failures leave it at -1. */
static UA_StatusCode multiWrite(UA_Client *client, const UA_NodeId *nodeId, const UA_Variant *in, const long varsSize, long *failedIndex) {
    *failedIndex = -1;
    UA_AttributeId attributeId = UA_ATTRIBUTEID_VALUE;

    UA_UInt16 wvSize = UA_TYPES[UA_TYPES_WRITEVALUE].memSize;

    UA_WriteValue *wValues = UA_calloc(varsSize, wvSize);

    for (int i = 0; i < varsSize; i++) {
        UA_WriteValue *wValue = &wValues[i];
        wValue->attributeId = attributeId;
        wValue->nodeId = nodeId[i];
        wValue->value.value = in[i];
        wValue->value.hasValue = true;
    }

    UA_WriteRequest wReq;
    UA_WriteRequest_init(&wReq);
    wReq.nodesToWrite = wValues;
    wReq.nodesToWriteSize = varsSize;

    UA_WriteResponse wResp = UA_Client_Service_write(client, wReq);

    UA_StatusCode retval = wResp.responseHeader.serviceResult;
    if (retval == UA_STATUSCODE_GOOD) {
        if (wResp.resultsSize == (size_t)varsSize) {
            retval = wResp.results[0];

            for (size_t i = 0; i < wResp.resultsSize; i++) {
                if (wResp.results[i] != UA_STATUSCODE_GOOD) {
                    retval = wResp.results[i];
                    *failedIndex = (long)i;
                    break;
                }
            }
        } else {
            retval = UA_STATUSCODE_BADUNEXPECTEDERROR;
        }
    }

    UA_WriteResponse_deleteMembers(&wResp);
    UA_free(wValues);

    return retval;
}

static VALUE rb_readUaValues(VALUE self, VALUE v_nsIndex, VALUE v_aryNames) {
    if (RB_TYPE_P(v_nsIndex, T_FIXNUM) != 1) {
        return raise_invalid_arguments_error();
    }

    if (RB_TYPE_P(v_aryNames, T_ARRAY) != 1) {
        return raise_invalid_arguments_error();
    }
    const long namesCount = RARRAY_LEN(v_aryNames);

    int nsIndex = FIX2INT(v_nsIndex);

    struct UninitializedClient * uclient;
    TypedData_Get_Struct(self, struct UninitializedClient, &UA_Client_Type, uclient);
    UA_Client *client = uclient->client;

    UA_UInt16 nidSize = UA_TYPES[UA_TYPES_NODEID].memSize;
    UA_UInt16 variantSize = UA_TYPES[UA_TYPES_VARIANT].memSize;

    UA_NodeId *nodes = UA_calloc(namesCount, nidSize);
    UA_Variant *readValues = UA_calloc(namesCount, variantSize);

    for (int i=0; i<namesCount; i++) {
        VALUE v_name = rb_ary_entry(v_aryNames, i);

        if (RB_TYPE_P(v_name, T_STRING) != 1) {
            UA_free(nodes);
            UA_free(readValues);
            return raise_invalid_arguments_error();
        }

        char *name = StringValueCStr(v_name);
        nodes[i] = UA_NODEID_STRING(nsIndex, name);
    }

    long failedIndex = -1;
    UA_StatusCode status = multiRead(client, nodes, readValues, namesCount, &failedIndex);

    VALUE resultArray = Qnil;

    if (status == UA_STATUSCODE_GOOD) {
        resultArray = rb_ary_new2(namesCount);

        for (int i=0; i<namesCount; i++) {
            VALUE rubyVal = Qnil;

            if (UA_Variant_hasScalarType(&readValues[i], &UA_TYPES[UA_TYPES_INT16])) {
                UA_Int16 val = *(UA_Int16*)readValues[i].data;
                rubyVal = INT2FIX(val);
            } else if (UA_Variant_hasScalarType(&readValues[i], &UA_TYPES[UA_TYPES_UINT16])) {
                UA_UInt16 val = *(UA_UInt16*)readValues[i].data;
                rubyVal = INT2FIX(val);
            } else if (UA_Variant_hasScalarType(&readValues[i], &UA_TYPES[UA_TYPES_INT32])) {
                UA_Int32 val = *(UA_Int32*)readValues[i].data;
                rubyVal = INT2FIX(val);
            } else if (UA_Variant_hasScalarType(&readValues[i], &UA_TYPES[UA_TYPES_UINT32])) {
                UA_UInt32 val = *(UA_UInt32*)readValues[i].data;
                rubyVal = INT2FIX(val);
            } else if (UA_Variant_hasScalarType(&readValues[i], &UA_TYPES[UA_TYPES_INT64])) {
                UA_Int64 val = *(UA_Int64*)readValues[i].data;
                rubyVal = LL2NUM(val);
            } else if (UA_Variant_hasScalarType(&readValues[i], &UA_TYPES[UA_TYPES_BOOLEAN])) {
                UA_Boolean val = *(UA_Boolean*)readValues[i].data;
                rubyVal = val ? Qtrue : Qfalse;
            } else if (UA_Variant_hasScalarType(&readValues[i], &UA_TYPES[UA_TYPES_FLOAT])) {
                UA_Float val = *(UA_Float*)readValues[i].data;
                rubyVal = DBL2NUM(val);
            } else if (UA_Variant_hasScalarType(&readValues[i], &UA_TYPES[UA_TYPES_DOUBLE])) {
                UA_Float val = *(UA_Double*)readValues[i].data;
                rubyVal = DBL2NUM(val);
            } else if (UA_Variant_hasScalarType(&readValues[i], &UA_TYPES[UA_TYPES_STRING])) {
                UA_String val = *(UA_String*)readValues[i].data;
                rubyVal = rb_utf8_str_new((const char *)val.data, val.length);
            } else if (UA_Variant_hasScalarType(&readValues[i], &UA_TYPES[UA_TYPES_DATETIME])) {
                UA_DateTime val = *(UA_DateTime*)readValues[i].data;
                rubyVal = toRubyTime(val);
            } else if (UA_Variant_hasScalarType(&readValues[i], &UA_TYPES[UA_TYPES_UTCTIME])) {
                UA_UtcTime val = *(UA_UtcTime*)readValues[i].data;
                rubyVal = toRubyTime(val);  // UA_UtcTime is same as UA_DateTime
            } else {
                rubyVal = Qnil; // unsupported
            }

            rb_ary_push(resultArray, rubyVal);
        }
    } else {
        /* Clean up */
        for (int i=0; i<namesCount; i++) {
            UA_Variant_deleteMembers(&readValues[i]);
        }
        UA_free(nodes);
        UA_free(readValues);

        return raise_ua_status(status, failedIndex);
    }

    /* Clean up */
    for (int i=0; i<namesCount; i++) {
        UA_Variant_deleteMembers(&readValues[i]);
    }
    UA_free(nodes);
    UA_free(readValues);

    return resultArray;
}

static VALUE rb_readUaValuesNumeric(VALUE self, VALUE v_nsIndex, VALUE v_aryNodeIds) {
    if (RB_TYPE_P(v_nsIndex, T_FIXNUM) != 1) {
        return raise_invalid_arguments_error();
    }

    if (RB_TYPE_P(v_aryNodeIds, T_ARRAY) != 1) {
        return raise_invalid_arguments_error();
    }
    const long nodeIdsCount = RARRAY_LEN(v_aryNodeIds);

    int nsIndex = FIX2INT(v_nsIndex);

    struct UninitializedClient * uclient;
    TypedData_Get_Struct(self, struct UninitializedClient, &UA_Client_Type, uclient);
    UA_Client *client = uclient->client;

    UA_UInt16 nidSize = UA_TYPES[UA_TYPES_NODEID].memSize;
    UA_UInt16 variantSize = UA_TYPES[UA_TYPES_VARIANT].memSize;

    UA_NodeId *nodes = UA_calloc(nodeIdsCount, nidSize);
    UA_Variant *readValues = UA_calloc(nodeIdsCount, variantSize);

    for (int i=0; i<nodeIdsCount; i++) {
        VALUE v_nodeId = rb_ary_entry(v_aryNodeIds, i);

        if (RB_TYPE_P(v_nodeId, T_FIXNUM) != 1) {
            UA_free(nodes);
            UA_free(readValues);
            return raise_invalid_arguments_error();
        }

        UA_UInt32 numericId = NUM2UINT(v_nodeId);
        nodes[i] = UA_NODEID_NUMERIC(nsIndex, numericId);
    }

    long failedIndex = -1;
    UA_StatusCode status = multiRead(client, nodes, readValues, nodeIdsCount, &failedIndex);

    VALUE resultArray = Qnil;

    if (status == UA_STATUSCODE_GOOD) {
        resultArray = rb_ary_new2(nodeIdsCount);

        for (int i=0; i<nodeIdsCount; i++) {
            VALUE rubyVal = Qnil;

            if (UA_Variant_hasScalarType(&readValues[i], &UA_TYPES[UA_TYPES_INT16])) {
                UA_Int16 val = *(UA_Int16*)readValues[i].data;
                rubyVal = INT2FIX(val);
            } else if (UA_Variant_hasScalarType(&readValues[i], &UA_TYPES[UA_TYPES_UINT16])) {
                UA_UInt16 val = *(UA_UInt16*)readValues[i].data;
                rubyVal = INT2FIX(val);
            } else if (UA_Variant_hasScalarType(&readValues[i], &UA_TYPES[UA_TYPES_INT32])) {
                UA_Int32 val = *(UA_Int32*)readValues[i].data;
                rubyVal = INT2FIX(val);
            } else if (UA_Variant_hasScalarType(&readValues[i], &UA_TYPES[UA_TYPES_UINT32])) {
                UA_UInt32 val = *(UA_UInt32*)readValues[i].data;
                rubyVal = INT2FIX(val);
            } else if (UA_Variant_hasScalarType(&readValues[i], &UA_TYPES[UA_TYPES_INT64])) {
                UA_Int64 val = *(UA_Int64*)readValues[i].data;
                rubyVal = LL2NUM(val);
            } else if (UA_Variant_hasScalarType(&readValues[i], &UA_TYPES[UA_TYPES_BOOLEAN])) {
                UA_Boolean val = *(UA_Boolean*)readValues[i].data;
                rubyVal = val ? Qtrue : Qfalse;
            } else if (UA_Variant_hasScalarType(&readValues[i], &UA_TYPES[UA_TYPES_FLOAT])) {
                UA_Float val = *(UA_Float*)readValues[i].data;
                rubyVal = DBL2NUM(val);
            } else if (UA_Variant_hasScalarType(&readValues[i], &UA_TYPES[UA_TYPES_DOUBLE])) {
                UA_Float val = *(UA_Double*)readValues[i].data;
                rubyVal = DBL2NUM(val);
            } else if (UA_Variant_hasScalarType(&readValues[i], &UA_TYPES[UA_TYPES_STRING])) {
                UA_String val = *(UA_String*)readValues[i].data;
                rubyVal = rb_utf8_str_new((const char *)val.data, val.length);
            } else if (UA_Variant_hasScalarType(&readValues[i], &UA_TYPES[UA_TYPES_DATETIME])) {
                UA_DateTime val = *(UA_DateTime*)readValues[i].data;
                rubyVal = toRubyTime(val);
            } else if (UA_Variant_hasScalarType(&readValues[i], &UA_TYPES[UA_TYPES_UTCTIME])) {
                UA_UtcTime val = *(UA_UtcTime*)readValues[i].data;
                rubyVal = toRubyTime(val);  // UA_UtcTime is same as UA_DateTime
            } else {
                rubyVal = Qnil; // unsupported
            }

            rb_ary_push(resultArray, rubyVal);
        }
    } else {
        /* Clean up */
        for (int i=0; i<nodeIdsCount; i++) {
            UA_Variant_deleteMembers(&readValues[i]);
        }
        UA_free(nodes);
        UA_free(readValues);

        return raise_ua_status(status, failedIndex);
    }

    /* Clean up */
    for (int i=0; i<nodeIdsCount; i++) {
        UA_Variant_deleteMembers(&readValues[i]);
    }
    UA_free(nodes);
    UA_free(readValues);

    return resultArray;
}

/* Free the parallel nodes/values buffers built by rb_writeUaValues before a
   raise. Deleting members of yet-unbuilt (zeroed) variants is a safe no-op,
   so the full count can always be passed. */
static void free_write_buffers(UA_NodeId *nodes, UA_Variant *values, long count) {
    if (values) {
        for (long i = 0; i < count; i++) {
            UA_Variant_deleteMembers(&values[i]);
        }
        UA_free(values);
    }
    if (nodes) {
        UA_free(nodes);
    }
}

static VALUE rb_writeUaValues(VALUE self, VALUE v_nsIndex, VALUE v_aryNames, VALUE v_aryNewValues, int uaType) {
    if (RB_TYPE_P(v_nsIndex, T_FIXNUM) != 1) {
        return raise_invalid_arguments_error();
    }

    if (RB_TYPE_P(v_aryNames, T_ARRAY) != 1) {
        return raise_invalid_arguments_error();
    }
    if (RB_TYPE_P(v_aryNewValues, T_ARRAY) != 1) {
        return raise_invalid_arguments_error();
    }

    const long namesCount = RARRAY_LEN(v_aryNames);
    const long valuesCount = RARRAY_LEN(v_aryNewValues);

    if (namesCount != valuesCount) {
        return raise_invalid_arguments_error();
    }

    int nsIndex = FIX2INT(v_nsIndex);

    struct UninitializedClient * uclient;
    TypedData_Get_Struct(self, struct UninitializedClient, &UA_Client_Type, uclient);
    UA_Client *client = uclient->client;

    UA_UInt16 nidSize = UA_TYPES[UA_TYPES_NODEID].memSize;
    UA_UInt16 variantSize = UA_TYPES[UA_TYPES_VARIANT].memSize;

    UA_NodeId *nodes = UA_calloc(namesCount, nidSize);
    UA_Variant *values = UA_calloc(namesCount, variantSize);

    for (int i=0; i<namesCount; i++) {
        VALUE v_name = rb_ary_entry(v_aryNames, i);
        VALUE v_newValue = rb_ary_entry(v_aryNewValues, i);

        if (RB_TYPE_P(v_name, T_STRING) != 1) {
            free_write_buffers(nodes, values, namesCount);
            return raise_invalid_arguments_error();
        }

        char *name = StringValueCStr(v_name);
        nodes[i] = UA_NODEID_STRING(nsIndex, name);

        if (uaType == UA_TYPES_UINT16) {
            if (RB_TYPE_P(v_newValue, T_FIXNUM) != 1) {
                free_write_buffers(nodes, values, namesCount);
                return raise_invalid_arguments_error();
            }
            UA_UInt16 newValue = NUM2USHORT(v_newValue);
            values[i].data = UA_malloc(sizeof(UA_UInt16));
            *(UA_UInt16*)values[i].data = newValue;
            values[i].type = &UA_TYPES[uaType];
        } else if (uaType == UA_TYPES_INT16) {
            if (RB_TYPE_P(v_newValue, T_FIXNUM) != 1) {
                free_write_buffers(nodes, values, namesCount);
                return raise_invalid_arguments_error();
            }
            UA_Int16 newValue = NUM2SHORT(v_newValue);
            values[i].data = UA_malloc(sizeof(UA_Int16));
            *(UA_Int16*)values[i].data = newValue;
            values[i].type = &UA_TYPES[uaType];
        } else if (uaType == UA_TYPES_UINT32) {
            if (RB_TYPE_P(v_newValue, T_FIXNUM) != 1) {
                free_write_buffers(nodes, values, namesCount);
                return raise_invalid_arguments_error();
            }
            UA_UInt32 newValue = NUM2UINT(v_newValue);
            values[i].data = UA_malloc(sizeof(UA_UInt32));
            *(UA_UInt32*)values[i].data = newValue;
            values[i].type = &UA_TYPES[uaType];
        } else if (uaType == UA_TYPES_INT32 && RB_TYPE_P(v_newValue, T_ARRAY)) {
            size_t arrayLength = RARRAY_LEN(v_newValue);
            UA_Int32 *arrayData = UA_malloc(sizeof(UA_Int32) * arrayLength);

            for (size_t j = 0; j < arrayLength; j++) {
                VALUE element = rb_ary_entry(v_newValue, j);
                if (RB_TYPE_P(element, T_FIXNUM) != 1) {
                    UA_free(arrayData);
                    free_write_buffers(nodes, values, namesCount);
                    return raise_invalid_arguments_error();
                }
                arrayData[j] = NUM2INT(element);
            }

            values[i].data = arrayData;
            values[i].arrayLength = arrayLength;
            values[i].type = &UA_TYPES[UA_TYPES_INT32];
        } else if (uaType == UA_TYPES_INT32) {
            if (RB_TYPE_P(v_newValue, T_FIXNUM) != 1) {
                free_write_buffers(nodes, values, namesCount);
                return raise_invalid_arguments_error();
            }
            UA_Int32 newValue = NUM2INT(v_newValue);
            values[i].data = UA_malloc(sizeof(UA_Int32));
            *(UA_Int32*)values[i].data = newValue;
            values[i].type = &UA_TYPES[uaType];
        } else if (uaType == UA_TYPES_INT64 && RB_TYPE_P(v_newValue, T_ARRAY)) {
            size_t arrayLength = RARRAY_LEN(v_newValue);
            UA_Int64 *arrayData = UA_malloc(sizeof(UA_Int64) * arrayLength);

            for (size_t j = 0; j < arrayLength; j++) {
                VALUE element = rb_ary_entry(v_newValue, j);
                if (!value_is_numeric(element)) {
                    UA_free(arrayData);
                    free_write_buffers(nodes, values, namesCount);
                    return raise_invalid_arguments_error();
                }
                arrayData[j] = NUM2LL(element);
            }

            values[i].data = arrayData;
            values[i].arrayLength = arrayLength;
            values[i].type = &UA_TYPES[UA_TYPES_INT64];
        } else if (uaType == UA_TYPES_INT64) {
            if (!value_is_numeric(v_newValue)) {
                free_write_buffers(nodes, values, namesCount);
                return raise_invalid_arguments_error();
            }
            UA_Int64 newValue = NUM2LL(v_newValue);
            values[i].data = UA_malloc(sizeof(UA_Int64));
            *(UA_Int64*)values[i].data = newValue;
            values[i].type = &UA_TYPES[uaType];
        } else if (uaType == UA_TYPES_FLOAT) {
            if (!value_is_numeric(v_newValue)) {
                free_write_buffers(nodes, values, namesCount);
                return raise_invalid_arguments_error();
            }
            UA_Float newValue = NUM2DBL(v_newValue);
            values[i].data = UA_malloc(sizeof(UA_Float));
            *(UA_Float*)values[i].data = newValue;
            values[i].type = &UA_TYPES[uaType];
        } else if (uaType == UA_TYPES_DOUBLE) {
            if (!value_is_numeric(v_newValue)) {
                free_write_buffers(nodes, values, namesCount);
                return raise_invalid_arguments_error();
            }
            UA_Double newValue = NUM2DBL(v_newValue);
            values[i].data = UA_malloc(sizeof(UA_Double));
            *(UA_Double*)values[i].data = newValue;
            values[i].type = &UA_TYPES[uaType];
        } else if (uaType == UA_TYPES_BOOLEAN) {
            if (RB_TYPE_P(v_newValue, T_TRUE) != 1 && RB_TYPE_P(v_newValue, T_FALSE) != 1) {
                free_write_buffers(nodes, values, namesCount);
                return raise_invalid_arguments_error();
            }
            UA_Boolean newValue = RTEST(v_newValue);
            values[i].data = UA_malloc(sizeof(UA_Boolean));
            *(UA_Boolean*)values[i].data = newValue;
            values[i].type = &UA_TYPES[UA_TYPES_BOOLEAN];
        } else if (uaType == UA_TYPES_STRING) {
            if (RB_TYPE_P(v_newValue, T_STRING) != 1) {
                free_write_buffers(nodes, values, namesCount);
                return raise_invalid_arguments_error();
            }
            UA_String newValue = UA_STRING(StringValueCStr(v_newValue));
            values[i].data = UA_malloc(sizeof(UA_String));
            UA_String_copy(&newValue, (UA_String*)values[i].data);
            values[i].type = &UA_TYPES[uaType];
        } else if (uaType == UA_TYPES_BYTE) {
            if (RB_TYPE_P(v_newValue, T_FIXNUM) != 1) {
                free_write_buffers(nodes, values, namesCount);
                return raise_invalid_arguments_error();
            }
            UA_Byte newValue = (UA_Byte)NUM2UINT(v_newValue);
            values[i].data = UA_malloc(sizeof(UA_Byte));
            *(UA_Byte*)values[i].data = newValue;
            values[i].type = &UA_TYPES[uaType];
        } else {
            free_write_buffers(nodes, values, namesCount);
            return raise_client_error(cArgumentError, "Unsupported type");
        }
    }

    long failedIndex = -1;
    UA_StatusCode status = multiWrite(client, nodes, values, namesCount, &failedIndex);

    if (status != UA_STATUSCODE_GOOD) {
        free_write_buffers(nodes, values, namesCount);
        return raise_ua_status(status, failedIndex);
    }

    free_write_buffers(nodes, values, namesCount);
    return Qnil;
}

static VALUE rb_writeUaValue(VALUE self, VALUE v_nsIndex, VALUE v_name, VALUE v_newValue, int uaType) {
    if (RB_TYPE_P(v_name, T_STRING) != 1) {
        return raise_invalid_arguments_error();
    }

    if (RB_TYPE_P(v_nsIndex, T_FIXNUM) != 1) {
        return raise_invalid_arguments_error();
    }

    if (uaType == UA_TYPES_INT16 && RB_TYPE_P(v_newValue, T_FIXNUM) != 1) {
        return raise_invalid_arguments_error();
    }

    char *name = StringValueCStr(v_name);
    int nsIndex = FIX2INT(v_nsIndex);

    struct UninitializedClient * uclient;
    TypedData_Get_Struct(self, struct UninitializedClient, &UA_Client_Type, uclient);
    UA_Client *client = uclient->client;

    UA_Variant value;
    UA_Variant_init(&value);

    if (uaType == UA_TYPES_INT16) {
        UA_Int16 newValue = NUM2SHORT(v_newValue);
        value.data = UA_malloc(sizeof(UA_Int16));
        *(UA_Int16*)value.data = newValue;
        value.type = &UA_TYPES[UA_TYPES_INT16];
    } else if (uaType == UA_TYPES_UINT16) {
        UA_UInt16 newValue = NUM2USHORT(v_newValue);
        value.data = UA_malloc(sizeof(UA_UInt16));
        *(UA_UInt16*)value.data = newValue;
        value.type = &UA_TYPES[UA_TYPES_UINT16];
    } else if (uaType == UA_TYPES_INT32 && RB_TYPE_P(v_newValue, T_ARRAY)) {
        size_t arrayLength = RARRAY_LEN(v_newValue);
        UA_Int32 *arrayData = UA_malloc(sizeof(UA_Int32) * arrayLength);

        for (size_t i = 0; i < arrayLength; i++) {
            VALUE element = rb_ary_entry(v_newValue, i);
            if (RB_TYPE_P(element, T_FIXNUM) != 1) {
                UA_free(arrayData);
                return raise_invalid_arguments_error();
            }
            arrayData[i] = NUM2INT(element);
        }

        value.data = arrayData;
        value.arrayLength = arrayLength;
        value.type = &UA_TYPES[UA_TYPES_INT32];
    } else if (uaType == UA_TYPES_INT32) {
        UA_Int32 newValue = NUM2INT(v_newValue);
        value.data = UA_malloc(sizeof(UA_Int32));
        *(UA_Int32*)value.data = newValue;
        value.type = &UA_TYPES[UA_TYPES_INT32];
    } else if (uaType == UA_TYPES_UINT32 && RB_TYPE_P(v_newValue, T_ARRAY)) {
        size_t arrayLength = RARRAY_LEN(v_newValue);
        UA_UInt32 *arrayData = UA_malloc(sizeof(UA_UInt32) * arrayLength);

        for (size_t i = 0; i < arrayLength; i++) {
            VALUE element = rb_ary_entry(v_newValue, i);
            if (RB_TYPE_P(element, T_FIXNUM) != 1) {
                UA_free(arrayData);
                return raise_invalid_arguments_error();
            }
            arrayData[i] = NUM2UINT(element);
        }

        value.data = arrayData;
        value.arrayLength = arrayLength;
        value.type = &UA_TYPES[UA_TYPES_UINT32];
    } else if (uaType == UA_TYPES_UINT32) {
        UA_UInt32 newValue = NUM2UINT(v_newValue);
        value.data = UA_malloc(sizeof(UA_UInt32));
        *(UA_UInt32*)value.data = newValue;
        value.type = &UA_TYPES[UA_TYPES_UINT32];
    } else if (uaType == UA_TYPES_INT64 && RB_TYPE_P(v_newValue, T_ARRAY)) {
        size_t arrayLength = RARRAY_LEN(v_newValue);
        UA_Int64 *arrayData = UA_malloc(sizeof(UA_Int64) * arrayLength);

        for (size_t i = 0; i < arrayLength; i++) {
            VALUE element = rb_ary_entry(v_newValue, i);
            if (!value_is_numeric(element)) {
                UA_free(arrayData);
                return raise_invalid_arguments_error();
            }
            arrayData[i] = NUM2LL(element);
        }

        value.data = arrayData;
        value.arrayLength = arrayLength;
        value.type = &UA_TYPES[UA_TYPES_INT64];
    } else if (uaType == UA_TYPES_INT64) {
        if (!value_is_numeric(v_newValue)) {
            return raise_invalid_arguments_error();
        }
        UA_Int64 newValue = NUM2LL(v_newValue);
        value.data = UA_malloc(sizeof(UA_Int64));
        *(UA_Int64*)value.data = newValue;
        value.type = &UA_TYPES[UA_TYPES_INT64];
    } else if (uaType == UA_TYPES_FLOAT) {
        if (!value_is_numeric(v_newValue)) {
            return raise_invalid_arguments_error();
        }
        UA_Float newValue = NUM2DBL(v_newValue);
        value.data = UA_malloc(sizeof(UA_Float));
        *(UA_Float*)value.data = newValue;
        value.type = &UA_TYPES[UA_TYPES_FLOAT];
    } else if (uaType == UA_TYPES_DOUBLE) {
        if (!value_is_numeric(v_newValue)) {
            return raise_invalid_arguments_error();
        }
        UA_Double newValue = NUM2DBL(v_newValue);
        value.data = UA_malloc(sizeof(UA_Double));
        *(UA_Double*)value.data = newValue;
        value.type = &UA_TYPES[UA_TYPES_DOUBLE];
    } else if (uaType == UA_TYPES_BOOLEAN) {
        UA_Boolean newValue = RTEST(v_newValue);
        value.data = UA_malloc(sizeof(UA_Boolean));
        *(UA_Boolean*)value.data = newValue;
        value.type = &UA_TYPES[UA_TYPES_BOOLEAN];
    } else if (uaType == UA_TYPES_STRING) {
        UA_String newValue = UA_STRING(StringValueCStr(v_newValue));
        value.data = UA_malloc(sizeof(UA_String));
        UA_String_copy(&newValue, (UA_String*)value.data);
        value.type = &UA_TYPES[UA_TYPES_STRING];
    } else if (uaType == UA_TYPES_BYTE) {
        if (RB_TYPE_P(v_newValue, T_FIXNUM) != 1) {
            return raise_invalid_arguments_error();
        }
        UA_Byte newValue = (UA_Byte)NUM2UINT(v_newValue);
        value.data = UA_malloc(sizeof(UA_Byte));
        *(UA_Byte*)value.data = newValue;
        value.type = &UA_TYPES[UA_TYPES_BYTE];
    } else if (uaType == UA_TYPES_DATETIME) {
        UA_DateTime newValue = fromRubyTime(v_newValue);
        value.data = UA_malloc(sizeof(UA_DateTime));
        *(UA_DateTime*)value.data = newValue;
        value.type = &UA_TYPES[UA_TYPES_DATETIME];
    }
    else {
        UA_Variant_deleteMembers(&value);
        return raise_client_error(cArgumentError, "Unsupported type");
    }

    UA_StatusCode status = UA_Client_writeValueAttribute(client, UA_NODEID_STRING(nsIndex, name), &value);

    if (status == UA_STATUSCODE_GOOD) {
        // DBG("%s\n", "value write successful");
    } else {
        /* Clean up */
        UA_Variant_deleteMembers(&value);
        return raise_ua_status_error(status);
    }

    /* Clean up */
    UA_Variant_deleteMembers(&value);

    return Qnil;
}

static VALUE rb_writeUInt16Value(VALUE self, VALUE v_nsIndex, VALUE v_name, VALUE v_newValue) {
    return rb_writeUaValue(self, v_nsIndex, v_name, v_newValue, UA_TYPES_UINT16);
}

static VALUE rb_writeUInt16Values(VALUE self, VALUE v_nsIndex, VALUE v_aryNames, VALUE v_aryNewValues) {
    return rb_writeUaValues(self, v_nsIndex, v_aryNames, v_aryNewValues, UA_TYPES_UINT16);
}

static VALUE rb_writeInt16Value(VALUE self, VALUE v_nsIndex, VALUE v_name, VALUE v_newValue) {
    return rb_writeUaValue(self, v_nsIndex, v_name, v_newValue, UA_TYPES_INT16);
}

static VALUE rb_writeInt16Values(VALUE self, VALUE v_nsIndex, VALUE v_aryNames, VALUE v_aryNewValues) {
    return rb_writeUaValues(self, v_nsIndex, v_aryNames, v_aryNewValues, UA_TYPES_INT16);
}

static VALUE rb_writeInt32Value(VALUE self, VALUE v_nsIndex, VALUE v_name, VALUE v_newValue) {
    return rb_writeUaValue(self, v_nsIndex, v_name, v_newValue, UA_TYPES_INT32);
}

static VALUE rb_writeInt32Values(VALUE self, VALUE v_nsIndex, VALUE v_aryNames, VALUE v_aryNewValues) {
    return rb_writeUaValues(self, v_nsIndex, v_aryNames, v_aryNewValues, UA_TYPES_INT32);
}

static VALUE rb_writeInt32List(VALUE self, VALUE v_nsIndex, VALUE v_name, VALUE v_newValue) {
    return rb_writeUaValue(self, v_nsIndex, v_name, v_newValue, UA_TYPES_INT32);
}

static VALUE rb_writeUInt32Value(VALUE self, VALUE v_nsIndex, VALUE v_name, VALUE v_newValue) {
    return rb_writeUaValue(self, v_nsIndex, v_name, v_newValue, UA_TYPES_UINT32);
}

static VALUE rb_writeUInt32Values(VALUE self, VALUE v_nsIndex, VALUE v_aryNames, VALUE v_aryNewValues) {
    return rb_writeUaValues(self, v_nsIndex, v_aryNames, v_aryNewValues, UA_TYPES_UINT32);
}

static VALUE rb_writeUint32List(VALUE self, VALUE v_nsIndex, VALUE v_name, VALUE v_newValue) {
    return rb_writeUaValue(self, v_nsIndex, v_name, v_newValue, UA_TYPES_UINT32);
}

static VALUE rb_writeInt32ListValues(VALUE self, VALUE v_nsIndex, VALUE v_aryNames, VALUE v_aryNewValues) {
    return rb_writeUaValues(self, v_nsIndex, v_aryNames, v_aryNewValues, UA_TYPES_INT32);
}

static VALUE rb_writeBooleanValue(VALUE self, VALUE v_nsIndex, VALUE v_name, VALUE v_newValue) {
    return rb_writeUaValue(self, v_nsIndex, v_name, v_newValue, UA_TYPES_BOOLEAN);
}

static VALUE rb_writeBooleanValues(VALUE self, VALUE v_nsIndex, VALUE v_aryNames, VALUE v_aryNewValues) {
    return rb_writeUaValues(self, v_nsIndex, v_aryNames, v_aryNewValues, UA_TYPES_BOOLEAN);
}

static VALUE rb_writeFloatValue(VALUE self, VALUE v_nsIndex, VALUE v_name, VALUE v_newValue) {
    return rb_writeUaValue(self, v_nsIndex, v_name, v_newValue, UA_TYPES_FLOAT);
}

static VALUE rb_writeFloatValues(VALUE self, VALUE v_nsIndex, VALUE v_aryNames, VALUE v_aryNewValues) {
    return rb_writeUaValues(self, v_nsIndex, v_aryNames, v_aryNewValues, UA_TYPES_FLOAT);
}

static VALUE rb_writeDoubleValue(VALUE self, VALUE v_nsIndex, VALUE v_name, VALUE v_newValue) {
    return rb_writeUaValue(self, v_nsIndex, v_name, v_newValue, UA_TYPES_DOUBLE);
}

static VALUE rb_writeDoubleValues(VALUE self, VALUE v_nsIndex, VALUE v_aryNames, VALUE v_aryNewValues) {
    return rb_writeUaValues(self, v_nsIndex, v_aryNames, v_aryNewValues, UA_TYPES_DOUBLE);
}

static VALUE rb_writeStringValue(VALUE self, VALUE v_nsIndex, VALUE v_name, VALUE v_newValue) {
    return rb_writeUaValue(self, v_nsIndex, v_name, v_newValue, UA_TYPES_STRING);
}

static VALUE rb_writeStringValues(VALUE self, VALUE v_nsIndex, VALUE v_aryNames, VALUE v_aryNewValues) {
    return rb_writeUaValues(self, v_nsIndex, v_aryNames, v_aryNewValues, UA_TYPES_STRING);
}

static VALUE rb_writeByteValue(VALUE self, VALUE v_nsIndex, VALUE v_name, VALUE v_newValue) {
    return rb_writeUaValue(self, v_nsIndex, v_name, v_newValue, UA_TYPES_BYTE);
}

static VALUE rb_writeByteValues(VALUE self, VALUE v_nsIndex, VALUE v_aryNames, VALUE v_aryNewValues) {
    return rb_writeUaValues(self, v_nsIndex, v_aryNames, v_aryNewValues, UA_TYPES_BYTE);
}

static VALUE rb_writeTimeValue(VALUE self, VALUE v_nsIndex, VALUE v_name, VALUE v_newValue) {
    return rb_writeUaValue(self, v_nsIndex, v_name, v_newValue, UA_TYPES_DATETIME);
}

static VALUE rb_writeInt64Value(VALUE self, VALUE v_nsIndex, VALUE v_name, VALUE v_newValue) {
    return rb_writeUaValue(self, v_nsIndex, v_name, v_newValue, UA_TYPES_INT64);
}

static VALUE rb_writeInt64Values(VALUE self, VALUE v_nsIndex, VALUE v_aryNames, VALUE v_aryNewValues) {
    return rb_writeUaValues(self, v_nsIndex, v_aryNames, v_aryNewValues, UA_TYPES_INT64);
}

static VALUE rb_writeInt64List(VALUE self, VALUE v_nsIndex, VALUE v_name, VALUE v_newValue) {
    return rb_writeUaValue(self, v_nsIndex, v_name, v_newValue, UA_TYPES_INT64);
}

static VALUE rb_writeInt64ListValues(VALUE self, VALUE v_nsIndex, VALUE v_aryNames, VALUE v_aryNewValues) {
    return rb_writeUaValues(self, v_nsIndex, v_aryNames, v_aryNewValues, UA_TYPES_INT64);
}

static VALUE rb_readUaValue(VALUE self, VALUE v_nsIndex, VALUE v_name, int type) {
    if (RB_TYPE_P(v_name, T_STRING) != 1) {
        return raise_invalid_arguments_error();
    }

    if (RB_TYPE_P(v_nsIndex, T_FIXNUM) != 1) {
        return raise_invalid_arguments_error();
    }

    char *name = StringValueCStr(v_name);
    int nsIndex = FIX2INT(v_nsIndex);

    struct UninitializedClient * uclient;
    TypedData_Get_Struct(self, struct UninitializedClient, &UA_Client_Type, uclient);
    UA_Client *client = uclient->client;

    UA_Variant value;
    UA_Variant_init(&value);
    UA_StatusCode status = UA_Client_readValueAttribute(client, UA_NODEID_STRING(nsIndex, name), &value);

    if (status == UA_STATUSCODE_GOOD) {
        // DBG("%s\n", "value read successful");
    } else {
        /* Clean up */
        UA_Variant_deleteMembers(&value);
        return raise_ua_status_error(status);
    }

    VALUE result = Qnil;

    if (type == UA_TYPES_INT16 && UA_Variant_hasScalarType(&value, &UA_TYPES[UA_TYPES_INT16])) {
        UA_Int16 val =*(UA_Int16*)value.data;
        // DBG("the value is: %i\n", val);
        result = INT2FIX(val);
    } else if (type == UA_TYPES_UINT16 && UA_Variant_hasScalarType(&value, &UA_TYPES[UA_TYPES_UINT16])) {
        UA_UInt16 val =*(UA_UInt16*)value.data;
        // DBG("the value is: %i\n", val);
        result = INT2FIX(val);
    } else if (type == UA_TYPES_INT32 && UA_Variant_hasArrayType(&value, &UA_TYPES[UA_TYPES_INT32])) {
        size_t arrayLength = value.arrayLength;
        UA_Int32 *arrayData = (UA_Int32 *)value.data;

        result = rb_ary_new();
        for (size_t i = 0; i < arrayLength; i++) {
            rb_ary_push(result, INT2FIX(arrayData[i]));
        }
    } else if (type == UA_TYPES_INT32 && UA_Variant_hasScalarType(&value, &UA_TYPES[UA_TYPES_INT32])) {
        UA_Int32 val =*(UA_Int32*)value.data;
        result = INT2FIX(val);
    } else if (type == UA_TYPES_UINT32 && UA_Variant_hasArrayType(&value, &UA_TYPES[UA_TYPES_UINT32])) {
        size_t arrayLength = value.arrayLength;
        UA_UInt32 *arrayData = (UA_UInt32 *)value.data;

        result = rb_ary_new();
        for (size_t i = 0; i < arrayLength; i++) {
            rb_ary_push(result, INT2FIX(arrayData[i]));
        }
    } else if (type == UA_TYPES_UINT32 && UA_Variant_hasScalarType(&value, &UA_TYPES[UA_TYPES_UINT32])) {
        UA_UInt32 val =*(UA_UInt32*)value.data;
        result = INT2FIX(val);
    } else if (type == UA_TYPES_INT64 && UA_Variant_hasArrayType(&value, &UA_TYPES[UA_TYPES_INT64])) {
        size_t arrayLength = value.arrayLength;
        UA_Int64 *arrayData = (UA_Int64 *)value.data;

        result = rb_ary_new();
        for (size_t i = 0; i < arrayLength; i++) {
            rb_ary_push(result, LL2NUM(arrayData[i]));
        }
    } else if (type == UA_TYPES_INT64 && UA_Variant_hasScalarType(&value, &UA_TYPES[UA_TYPES_INT64])) {
        UA_Int64 val = *(UA_Int64*)value.data;
        result = LL2NUM(val);
    } else if (type == UA_TYPES_BOOLEAN && UA_Variant_hasArrayType(&value, &UA_TYPES[UA_TYPES_BOOLEAN])) {
        size_t arrayLength = value.arrayLength;
        UA_Boolean *arrayData = (UA_Boolean *)value.data;

        result = rb_ary_new();
        for (size_t i = 0; i < arrayLength; i++) {
            rb_ary_push(result, arrayData[i] ? Qtrue : Qfalse);
        }
    } else if (type == UA_TYPES_BOOLEAN && UA_Variant_hasScalarType(&value, &UA_TYPES[UA_TYPES_BOOLEAN])) {
        UA_Boolean val =*(UA_Boolean*)value.data;
        result = val ? Qtrue : Qfalse;
    } else if (type == UA_TYPES_FLOAT && UA_Variant_hasScalarType(&value, &UA_TYPES[UA_TYPES_FLOAT])) {
        UA_Float val =*(UA_Float*)value.data;
        result = DBL2NUM(val);
    } else if (type == UA_TYPES_DOUBLE && UA_Variant_hasScalarType(&value, &UA_TYPES[UA_TYPES_DOUBLE])) {
        UA_Double val =*(UA_Double*)value.data;
        result = DBL2NUM(val);
    } else if (type == UA_TYPES_STRING && UA_Variant_hasScalarType(&value, &UA_TYPES[UA_TYPES_STRING])) {
        UA_String val =*(UA_String*)value.data;
        result = rb_utf8_str_new((const char *)val.data, val.length);
    } else if (type == UA_TYPES_BYTE && UA_Variant_hasScalarType(&value, &UA_TYPES[UA_TYPES_BYTE])) {
        UA_Byte val = *(UA_Byte*)value.data;
        result = INT2FIX(val);
    } else if (type == UA_TYPES_DATETIME && UA_Variant_hasScalarType(&value, &UA_TYPES[UA_TYPES_DATETIME])) {
        UA_DateTime val = *(UA_DateTime*)value.data;
        result = toRubyTime(val);
    } else {
        UA_Variant_deleteMembers(&value);
        return raise_client_error(cTypeMismatchError, "UA type mismatch");
    }

    /* Clean up */
    UA_Variant_deleteMembers(&value);

    return result;
}

static VALUE rb_readInt16Value(VALUE self, VALUE v_nsIndex, VALUE v_name) {
    return rb_readUaValue(self, v_nsIndex, v_name, UA_TYPES_INT16);
}

static VALUE rb_readUInt16Value(VALUE self, VALUE v_nsIndex, VALUE v_name) {
    return rb_readUaValue(self, v_nsIndex, v_name, UA_TYPES_UINT16);
}

static VALUE rb_readInt32Value(VALUE self, VALUE v_nsIndex, VALUE v_name) {
    return rb_readUaValue(self, v_nsIndex, v_name, UA_TYPES_INT32);
}

static VALUE rb_readInt32List(VALUE self, VALUE v_nsIndex, VALUE v_name) {
    return rb_readUaValue(self, v_nsIndex, v_name, UA_TYPES_INT32);
}

static VALUE rb_readUInt32Value(VALUE self, VALUE v_nsIndex, VALUE v_name) {
    return rb_readUaValue(self, v_nsIndex, v_name, UA_TYPES_UINT32);
}

static VALUE rb_readUint32List(VALUE self, VALUE v_nsIndex, VALUE v_name) {
    return rb_readUaValue(self, v_nsIndex, v_name, UA_TYPES_UINT32);
}

static VALUE rb_readBooleanValue(VALUE self, VALUE v_nsIndex, VALUE v_name) {
    return rb_readUaValue(self, v_nsIndex, v_name, UA_TYPES_BOOLEAN);
}

static VALUE rb_readFloatValue(VALUE self, VALUE v_nsIndex, VALUE v_name) {
    return rb_readUaValue(self, v_nsIndex, v_name, UA_TYPES_FLOAT);
}

static VALUE rb_readDoubleValue(VALUE self, VALUE v_nsIndex, VALUE v_name) {
    return rb_readUaValue(self, v_nsIndex, v_name, UA_TYPES_DOUBLE);
}

static VALUE rb_readStringValue(VALUE self, VALUE v_nsIndex, VALUE v_name) {
    return rb_readUaValue(self, v_nsIndex, v_name, UA_TYPES_STRING);
}

static VALUE rb_readByteValue(VALUE self, VALUE v_nsIndex, VALUE v_name) {
    return rb_readUaValue(self, v_nsIndex, v_name, UA_TYPES_BYTE);
}

static VALUE rb_readTimeValue(VALUE self, VALUE v_nsIndex, VALUE v_name) {
    return rb_readUaValue(self, v_nsIndex, v_name, UA_TYPES_DATETIME);
}

static VALUE rb_readInt64Value(VALUE self, VALUE v_nsIndex, VALUE v_name) {
    return rb_readUaValue(self, v_nsIndex, v_name, UA_TYPES_INT64);
}

static VALUE rb_readInt64List(VALUE self, VALUE v_nsIndex, VALUE v_name) {
    return rb_readUaValue(self, v_nsIndex, v_name, UA_TYPES_INT64);
}

static VALUE rb_readInt64Values(VALUE self, VALUE v_nsIndex, VALUE v_aryNames) {
    if (RB_TYPE_P(v_nsIndex, T_FIXNUM) != 1) {
        return raise_invalid_arguments_error();
    }

    if (RB_TYPE_P(v_aryNames, T_ARRAY) != 1) {
        return raise_invalid_arguments_error();
    }
    const long namesCount = RARRAY_LEN(v_aryNames);

    int nsIndex = FIX2INT(v_nsIndex);

    struct UninitializedClient * uclient;
    TypedData_Get_Struct(self, struct UninitializedClient, &UA_Client_Type, uclient);
    UA_Client *client = uclient->client;

    UA_UInt16 nidSize = UA_TYPES[UA_TYPES_NODEID].memSize;
    UA_UInt16 variantSize = UA_TYPES[UA_TYPES_VARIANT].memSize;

    UA_NodeId *nodes = UA_calloc(namesCount, nidSize);
    UA_Variant *readValues = UA_calloc(namesCount, variantSize);

    for (int i=0; i<namesCount; i++) {
        VALUE v_name = rb_ary_entry(v_aryNames, i);

        if (RB_TYPE_P(v_name, T_STRING) != 1) {
            UA_free(nodes);
            UA_free(readValues);
            return raise_invalid_arguments_error();
        }

        char *name = StringValueCStr(v_name);
        nodes[i] = UA_NODEID_STRING(nsIndex, name);
    }

    long failedIndex = -1;
    UA_StatusCode status = multiRead(client, nodes, readValues, namesCount, &failedIndex);

    VALUE resultArray = Qnil;

    if (status == UA_STATUSCODE_GOOD) {
        resultArray = rb_ary_new2(namesCount);

        for (int i=0; i<namesCount; i++) {
            VALUE rubyVal = Qnil;

            if (UA_Variant_hasScalarType(&readValues[i], &UA_TYPES[UA_TYPES_INT64])) {
                UA_Int64 val = *(UA_Int64*)readValues[i].data;
                rubyVal = LL2NUM(val);
            } else {
                for (int k=0; k<namesCount; k++) {
                    UA_Variant_deleteMembers(&readValues[k]);
                }
                UA_free(nodes);
                UA_free(readValues);
                return raise_client_error(cTypeMismatchError, "UA type mismatch - expected INT64");
            }

            rb_ary_push(resultArray, rubyVal);
        }
    } else {
        /* Clean up */
        for (int i=0; i<namesCount; i++) {
            UA_Variant_deleteMembers(&readValues[i]);
        }
        UA_free(nodes);
        UA_free(readValues);

        return raise_ua_status(status, failedIndex);
    }

    /* Clean up */
    for (int i=0; i<namesCount; i++) {
        UA_Variant_deleteMembers(&readValues[i]);
    }
    UA_free(nodes);
    UA_free(readValues);

    return resultArray;
}

static VALUE rb_readBooleanList(VALUE self, VALUE v_nsIndex, VALUE v_name) {
    return rb_readUaValue(self, v_nsIndex, v_name, UA_TYPES_BOOLEAN);
}

static VALUE rb_get_human_UA_StatusCode(VALUE self, VALUE v_code) {
    if (RB_TYPE_P(v_code, T_FIXNUM) == 1) {
        unsigned int code = FIX2UINT(v_code);
        const char* name = UA_StatusCode_name(code);
        return rb_str_export_locale(rb_str_new_cstr(name));
    } else {
        return raise_invalid_arguments_error();
    }
}

/* OPCUAClient.classify_status_code(code) ->
   :good | :uncertain | :connection | :node | :type | :protocol
   Exposes the same categorizer used to pick exception subclasses, so a
   consumer can map raw status codes before adopting the subclasses. The top
   two severity bits cover Good/Uncertain; Bad codes go through status_category. */
static VALUE rb_classify_status_code(VALUE self, VALUE v_code) {
    if (!value_is_integer(v_code)) {
        return raise_invalid_arguments_error();
    }
    UA_StatusCode s = NUM2UINT(v_code);
    UA_UInt32 severity = s & 0xC0000000;       /* 0x0=Good, 0x40=Uncertain, 0x80=Bad */
    if (severity == 0x00000000) return ID2SYM(rb_intern("good"));
    if (severity == 0x40000000) return ID2SYM(rb_intern("uncertain"));
    switch (status_category(s)) {
        case CAT_CONNECTION: return ID2SYM(rb_intern("connection"));
        case CAT_NODE:       return ID2SYM(rb_intern("node"));
        case CAT_TYPE:       return ID2SYM(rb_intern("type"));
        default:             return ID2SYM(rb_intern("protocol"));
    }
}

static VALUE rb_run_single_monitoring_cycle(VALUE self) {
    struct UninitializedClient * uclient;
    TypedData_Get_Struct(self, struct UninitializedClient, &UA_Client_Type, uclient);
    UA_Client *client = uclient->client;

    UA_StatusCode status = UA_Client_runAsync(client, 1000);
    return UINT2NUM(status);
}

static VALUE rb_run_single_monitoring_cycle_bang(VALUE self) {
    struct UninitializedClient * uclient;
    TypedData_Get_Struct(self, struct UninitializedClient, &UA_Client_Type, uclient);
    UA_Client *client = uclient->client;

    UA_StatusCode status = UA_Client_runAsync(client, 1000);

    if (status != UA_STATUSCODE_GOOD) {
        return raise_ua_status_error(status);
    }

    return Qnil;
}

static VALUE rb_state(VALUE self) {
    struct UninitializedClient * uclient;
    TypedData_Get_Struct(self, struct UninitializedClient, &UA_Client_Type, uclient);
    UA_Client *client = uclient->client;

    UA_ClientState state = UA_Client_getState(client);
    return INT2NUM(state);
}

static void defineStateContants(VALUE mOPCUAClient) {
    rb_define_const(mOPCUAClient, "UA_CLIENTSTATE_DISCONNECTED", INT2NUM(UA_CLIENTSTATE_DISCONNECTED));
    rb_define_const(mOPCUAClient, "UA_CLIENTSTATE_CONNECTED", INT2NUM(UA_CLIENTSTATE_CONNECTED));
    rb_define_const(mOPCUAClient, "UA_CLIENTSTATE_SECURECHANNEL", INT2NUM(UA_CLIENTSTATE_SECURECHANNEL));
    rb_define_const(mOPCUAClient, "UA_CLIENTSTATE_SESSION", INT2NUM(UA_CLIENTSTATE_SESSION));
    rb_define_const(mOPCUAClient, "UA_CLIENTSTATE_SESSION_RENEWED", INT2NUM(UA_CLIENTSTATE_SESSION_RENEWED));
}

void Init_opcua_client()
{
#ifdef UA_ENABLE_SUBSCRIPTIONS
    // DBG("%s\n", "ok! opcua-client-ruby built with subscriptions enabled.");
#endif

    g_debug = getenv("OPCUA_CLIENT_DEBUG") != NULL;

    mOPCUAClient = rb_const_get(rb_cObject, rb_intern("OPCUAClient"));
    rb_global_variable(&mOPCUAClient);
    defineStateContants(mOPCUAClient);

    cError = rb_define_class_under(mOPCUAClient, "Error", rb_eStandardError);
    rb_global_variable(&cError);

    /* Classified subclasses of Error (every existing `rescue OPCUAClient::Error`
       still catches them all). See status_category() for the mapping. */
    cConnectionError = rb_define_class_under(mOPCUAClient, "ConnectionError", cError);
    rb_global_variable(&cConnectionError);
    cNodeError = rb_define_class_under(mOPCUAClient, "NodeError", cError);
    rb_global_variable(&cNodeError);
    cTypeMismatchError = rb_define_class_under(mOPCUAClient, "TypeMismatchError", cError);
    rb_global_variable(&cTypeMismatchError);
    cProtocolError = rb_define_class_under(mOPCUAClient, "ProtocolError", cError);
    rb_global_variable(&cProtocolError);
    cArgumentError = rb_define_class_under(mOPCUAClient, "ArgumentError", cError);
    rb_global_variable(&cArgumentError);

    /* Structured data carried on every raised error (readers on the base class,
       inherited by all subclasses). */
    rb_define_attr(cError, "status_code", 1, 0);  /* Integer UA status, or nil for client-side errors */
    rb_define_attr(cError, "status_name", 1, 0);  /* e.g. "BadConnectionClosed", or a client message */
    rb_define_attr(cError, "node_index", 1, 0);   /* Integer index of failing node in a multi_* call, else nil */

    cClient = rb_define_class_under(mOPCUAClient, "Client", rb_cObject);
    rb_global_variable(&cClient);

    rb_define_alloc_func(cClient, allocate);

    rb_define_method(cClient, "initialize", rb_initialize, 0);

    rb_define_method(cClient, "run_single_monitoring_cycle", rb_run_single_monitoring_cycle, 0);
    rb_define_method(cClient, "run_mon_cycle", rb_run_single_monitoring_cycle, 0);
    rb_define_method(cClient, "do_mon_cycle", rb_run_single_monitoring_cycle, 0);

    rb_define_method(cClient, "run_single_monitoring_cycle!", rb_run_single_monitoring_cycle_bang, 0);
    rb_define_method(cClient, "run_mon_cycle!", rb_run_single_monitoring_cycle_bang, 0);
    rb_define_method(cClient, "do_mon_cycle!", rb_run_single_monitoring_cycle_bang, 0);

    rb_define_method(cClient, "connect", rb_connect, -1);
    rb_define_method(cClient, "disconnect", rb_disconnect, 0);
    rb_define_method(cClient, "state", rb_state, 0);

    rb_define_method(cClient, "read_int16", rb_readInt16Value, 2);
    rb_define_method(cClient, "read_uint16", rb_readUInt16Value, 2);
    rb_define_method(cClient, "read_int32", rb_readInt32Value, 2);
    rb_define_method(cClient, "read_uint32", rb_readUInt32Value, 2);
    rb_define_method(cClient, "read_float", rb_readFloatValue, 2);
    rb_define_method(cClient, "read_double", rb_readDoubleValue, 2);
    rb_define_method(cClient, "read_boolean", rb_readBooleanValue, 2);
    rb_define_method(cClient, "read_bool", rb_readBooleanValue, 2);
    rb_define_method(cClient, "read_string", rb_readStringValue, 2);
    rb_define_method(cClient, "read_byte", rb_readByteValue, 2);
    rb_define_method(cClient, "read_time", rb_readTimeValue, 2);
    rb_define_method(cClient, "read_int64", rb_readInt64Value, 2);
    rb_define_method(cClient, "read_int64_list", rb_readInt64List, 2);
    rb_define_method(cClient, "read_uint32_list", rb_readUint32List, 2);
    rb_define_method(cClient, "read_int32_list", rb_readInt32List, 2);
    rb_define_method(cClient, "read_boolean_list", rb_readBooleanList, 2);

    rb_define_method(cClient, "write_int16", rb_writeInt16Value, 3);
    rb_define_method(cClient, "write_uint16", rb_writeUInt16Value, 3);
    rb_define_method(cClient, "write_int32", rb_writeInt32Value, 3);
    rb_define_method(cClient, "write_uint32", rb_writeUInt32Value, 3);
    rb_define_method(cClient, "write_float", rb_writeFloatValue, 3);
    rb_define_method(cClient, "write_double", rb_writeDoubleValue, 3);
    rb_define_method(cClient, "write_boolean", rb_writeBooleanValue, 3);
    rb_define_method(cClient, "write_bool", rb_writeBooleanValue, 3);
    rb_define_method(cClient, "write_string", rb_writeStringValue, 3);
    rb_define_method(cClient, "write_byte", rb_writeByteValue, 3);
    rb_define_method(cClient, "write_time", rb_writeTimeValue, 3);
    rb_define_method(cClient, "write_int64", rb_writeInt64Value, 3);
    rb_define_method(cClient, "write_int64_list", rb_writeInt64List, 3);
    rb_define_method(cClient, "write_uint32_list", rb_writeUint32List, 3);
    rb_define_method(cClient, "write_int32_list", rb_writeInt32List, 3);

    rb_define_method(cClient, "multi_write_int16", rb_writeInt16Values, 3);
    rb_define_method(cClient, "multi_write_uint16", rb_writeUInt16Values, 3);
    rb_define_method(cClient, "multi_write_int32", rb_writeInt32Values, 3);
    rb_define_method(cClient, "multi_write_uint32", rb_writeUInt32Values, 3);
    rb_define_method(cClient, "multi_write_float", rb_writeFloatValues, 3);
    rb_define_method(cClient, "multi_write_double", rb_writeDoubleValues, 3);
    rb_define_method(cClient, "multi_write_boolean", rb_writeBooleanValues, 3);
    rb_define_method(cClient, "multi_write_bool", rb_writeBooleanValues, 3);
    rb_define_method(cClient, "multi_write_string", rb_writeStringValues, 3);
    rb_define_method(cClient, "multi_write_byte", rb_writeByteValues, 3);
    rb_define_method(cClient, "multi_write_int64", rb_writeInt64Values, 3);
    rb_define_method(cClient, "multi_write_int64_list", rb_writeInt64ListValues, 3);
    rb_define_method(cClient, "multi_write_int32_list", rb_writeInt32ListValues, 3);

    rb_define_method(cClient, "multi_read", rb_readUaValues, 2);
    rb_define_method(cClient, "multi_read_numeric", rb_readUaValuesNumeric, 2);
    rb_define_method(cClient, "multi_read_int64", rb_readInt64Values, 2);

    rb_define_method(cClient, "create_subscription", rb_createSubscription, 0);
    rb_define_method(cClient, "add_monitored_item", rb_addMonitoredItem, 3);
    rb_define_method(cClient, "delete_monitored_item", rb_deleteMonitoredItem, 2);
    rb_define_method(cClient, "delete_subscription", rb_deleteSubscription, 1);
    rb_define_method(cClient, "delete_all_subscriptions", rb_deleteAllSubscriptions, 0);

    rb_define_singleton_method(mOPCUAClient, "human_status_code", rb_get_human_UA_StatusCode, 1);
    rb_define_singleton_method(mOPCUAClient, "classify_status_code", rb_classify_status_code, 1);
}
