#include <signal.h>
#include <stdio.h>
#include "open62541.h"

static char* newString() {
    // TODO: memory management
    return new char [100];
}

static UA_NodeId addVariableUnder(UA_Server *server, UA_Int16 nsId, int type, const char *desc, const char *name, const char *nodeIdString, const char *qnString, UA_NodeId parentNodeId, void *defaultValue) {

    UA_NodeId referenceTypeId = UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES);
    UA_NodeId typeDefinition = UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE);

    UA_VariableAttributes attr = UA_VariableAttributes_default;

    if (type == UA_TYPES_INT32) {
        UA_Int32 initialValue = *(UA_Int32*)defaultValue;
        UA_Variant_setScalar(&attr.value, &initialValue, &UA_TYPES[type]);
    } else if (type == UA_TYPES_INT16) {
        UA_Int16 initialValue = *(UA_Int16*)defaultValue;
        UA_Variant_setScalar(&attr.value, &initialValue, &UA_TYPES[type]);
    } else if (type == UA_TYPES_UINT16) {
        UA_UInt16 initialValue = *(UA_UInt16*)defaultValue;
        UA_Variant_setScalar(&attr.value, &initialValue, &UA_TYPES[type]);
    } else if (type == UA_TYPES_UINT32) {
        UA_UInt32 initialValue = *(UA_UInt32*)defaultValue;
        UA_Variant_setScalar(&attr.value, &initialValue, &UA_TYPES[type]);
    } else if (type == UA_TYPES_BOOLEAN) {
        UA_Boolean initialValue = *(UA_Boolean*)defaultValue;
        UA_Variant_setScalar(&attr.value, &initialValue, &UA_TYPES[type]);
    } else if (type == UA_TYPES_FLOAT) {
        UA_Float initialValue = *(UA_Float*)defaultValue;
        UA_Variant_setScalar(&attr.value, &initialValue, &UA_TYPES[type]);
    } else if (type == UA_TYPES_STRING) {
        UA_String *initialValue = (UA_String*)defaultValue;
        UA_Variant_setScalar(&attr.value, initialValue, &UA_TYPES[type]);
    } else if (type == UA_TYPES_INT64) {
        UA_Int64 initialValue = *(UA_Int64*)defaultValue;
        UA_Variant_setScalar(&attr.value, &initialValue, &UA_TYPES[type]);
    } else if (type == UA_TYPES_DOUBLE) {
        UA_Double initialValue = *(UA_Double*)defaultValue;
        UA_Variant_setScalar(&attr.value, &initialValue, &UA_TYPES[type]);
    } else if (type == UA_TYPES_BYTE) {
        UA_Byte initialValue = *(UA_Byte*)defaultValue;
        UA_Variant_setScalar(&attr.value, &initialValue, &UA_TYPES[type]);
    } else if (type == UA_TYPES_DATETIME) {
        UA_DateTime initialValue = *(UA_DateTime*)defaultValue;
        UA_Variant_setScalar(&attr.value, &initialValue, &UA_TYPES[type]);
    } else {
        throw "type not supported";
    }

    attr.description = UA_LOCALIZEDTEXT((char*) "en-US", (char*) desc);
    attr.displayName = UA_LOCALIZEDTEXT((char*) "en-US", (char*) name);
    attr.dataType = UA_TYPES[type].typeId;
    attr.accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;

    UA_NodeId nodeId = UA_NODEID_STRING(nsId, (char*) nodeIdString); // node id
    UA_QualifiedName qualifiedName = UA_QUALIFIEDNAME(nsId, (char*) qnString); // browse name
    UA_Server_addVariableNode(server, nodeId, parentNodeId,
                              referenceTypeId, qualifiedName,
                              typeDefinition, attr, NULL, NULL);

    return nodeId;
}

static UA_NodeId addVariable(UA_Server *server, UA_Int16 nsId, int type, const char *desc, const char *name, const char *nodeIdString, const char *qnString, void *defaultValue) {
    UA_NodeId parentNodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER);
    return addVariableUnder(server, nsId, type, desc, name, nodeIdString, qnString, parentNodeId, defaultValue);
}

static void addVariableV2(UA_Server *server, UA_Int16 nsId, int type, const char *variable, void *defaultValue) {
    char* varName = newString();
    sprintf(varName, "%s", variable);

    char* desc = newString();
    char* displayName = newString();
    const char* qn = varName;

    sprintf(desc, "%s.desc", varName);
    sprintf(displayName, "%s.dn", varName);

    char* nodeId = newString();
    sprintf(nodeId, "%s", varName);

    UA_NodeId parentNode = addVariable(server, nsId, type, desc, displayName, nodeId, varName, defaultValue);
}

static void addVariableInt(UA_Server *server, UA_Int16 nsId, int type, const char *variable, UA_Int32 defaultValue) {
    addVariableV2(server, nsId, type, variable, &defaultValue);
}

static void addVariableBool(UA_Server *server, UA_Int16 nsId, int type, const char *variable, UA_Boolean defaultValue) {
    addVariableV2(server, nsId, type, variable, &defaultValue);
}

static void addVariableFloat(UA_Server *server, UA_Int16 nsId, int type, const char *variable, UA_Float defaultValue = 0) {
    addVariableV2(server, nsId, type, variable, &defaultValue);
}

static void addVariableString(UA_Server *server, UA_Int16 nsId, int type, const char *variable, UA_String defaultValue = UA_STRING("")) {
    addVariableV2(server, nsId, type, variable, &defaultValue);
}

static void addVariableInt64(UA_Server *server, UA_Int16 nsId, const char *variable, UA_Int64 defaultValue) {
    addVariableV2(server, nsId, UA_TYPES_INT64, variable, &defaultValue);
}

static void addVariableDouble(UA_Server *server, UA_Int16 nsId, const char *variable, UA_Double defaultValue) {
    addVariableV2(server, nsId, UA_TYPES_DOUBLE, variable, &defaultValue);
}

static void addVariableByte(UA_Server *server, UA_Int16 nsId, const char *variable, UA_Byte defaultValue) {
    addVariableV2(server, nsId, UA_TYPES_BYTE, variable, &defaultValue);
}

static void addVariableTime(UA_Server *server, UA_Int16 nsId, const char *variable, UA_DateTime defaultValue) {
    addVariableV2(server, nsId, UA_TYPES_DATETIME, variable, &defaultValue);
}

// Array-valued node (valueRank ANY so the client can write a scalar or an array).
static void addArrayVariable(UA_Server *server, UA_Int16 nsId, int type, const char *variable, void *data, size_t len) {
    UA_VariableAttributes attr = UA_VariableAttributes_default;
    UA_Variant_setArray(&attr.value, data, len, &UA_TYPES[type]);
    attr.valueRank = UA_VALUERANK_ANY;
    attr.dataType = UA_TYPES[type].typeId;
    attr.accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
    attr.displayName = UA_LOCALIZEDTEXT((char*) "en-US", (char*) variable);

    UA_NodeId nodeId = UA_NODEID_STRING(nsId, (char*) variable);
    UA_QualifiedName qn = UA_QUALIFIEDNAME(nsId, (char*) variable);
    UA_NodeId parentNodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER);
    UA_NodeId referenceTypeId = UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES);
    UA_NodeId typeDefinition = UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE);
    UA_Server_addVariableNode(server, nodeId, parentNodeId, referenceTypeId, qn,
                              typeDefinition, attr, NULL, NULL);
}

// Numeric-id node (for multi_read_numeric coverage).
static void addNumericInt32(UA_Server *server, UA_Int16 nsId, UA_UInt32 numericId, UA_Int32 defaultValue) {
    UA_VariableAttributes attr = UA_VariableAttributes_default;
    UA_Variant_setScalar(&attr.value, &defaultValue, &UA_TYPES[UA_TYPES_INT32]);
    attr.dataType = UA_TYPES[UA_TYPES_INT32].typeId;
    attr.accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
    char nm[32];
    sprintf(nm, "num_%u", numericId);
    attr.displayName = UA_LOCALIZEDTEXT((char*) "en-US", nm);

    UA_NodeId nodeId = UA_NODEID_NUMERIC(nsId, numericId);
    UA_QualifiedName qn = UA_QUALIFIEDNAME(nsId, nm);
    UA_NodeId parentNodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER);
    UA_NodeId referenceTypeId = UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES);
    UA_NodeId typeDefinition = UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE);
    UA_Server_addVariableNode(server, nodeId, parentNodeId, referenceTypeId, qn,
                              typeDefinition, attr, NULL, NULL);
}

UA_Boolean running = true;
static void signalHandler(int signum) {
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_SERVER, "Signal received: %i", signum);
    running = false;
}

static void addVariables(UA_Server *server) {
    UA_Int16 ns2Id = UA_Server_addNamespace(server, "ns2"); // id=2
    UA_Int16 ns3Id = UA_Server_addNamespace(server, "ns3"); // id=3
    UA_Int16 ns4Id = UA_Server_addNamespace(server, "ns4"); // id=4
    UA_Int16 ns5Id = UA_Server_addNamespace(server, "ns5"); // id=5

    addVariableInt(server, ns5Id, UA_TYPES_INT16, "int16_a", 0);
    addVariableInt(server, ns5Id, UA_TYPES_INT16, "int16_b", -100);
    addVariableInt(server, ns5Id, UA_TYPES_INT16, "int16_c", 100);
    addVariableInt(server, ns5Id, UA_TYPES_INT32, "int32_a", 0);
    addVariableInt(server, ns5Id, UA_TYPES_INT32, "int32_b", -1000);
    addVariableInt(server, ns5Id, UA_TYPES_INT32, "int32_c", 1000);
    addVariableInt(server, ns5Id, UA_TYPES_UINT16, "uint16_a", 0);
    addVariableInt(server, ns5Id, UA_TYPES_UINT16, "uint16_b", 100);
    addVariableInt(server, ns5Id, UA_TYPES_UINT16, "uint16_c", 200);
    addVariableInt(server, ns5Id, UA_TYPES_UINT32, "uint32_a", 0);
    addVariableInt(server, ns5Id, UA_TYPES_UINT32, "uint32_b", 1000);
    addVariableInt(server, ns5Id, UA_TYPES_UINT32, "uint32_c", 2000);
    addVariableBool(server, ns5Id, UA_TYPES_BOOLEAN, "bool_a", true);
    addVariableBool(server, ns5Id, UA_TYPES_BOOLEAN, "bool_b", false);
    addVariableFloat(server, ns5Id, UA_TYPES_FLOAT, "float_a", 0);
    addVariableFloat(server, ns5Id, UA_TYPES_FLOAT, "float_b", -123.222);
    addVariableFloat(server, ns5Id, UA_TYPES_FLOAT, "float_c", 123.222);
    addVariableString(server, ns5Id, UA_TYPES_STRING, "string_a", UA_STRING(""));
    addVariableString(server, ns5Id, UA_TYPES_STRING, "string_b", UA_STRING("Example text"));

    // 64-bit ints (values intentionally beyond the int32 range), doubles, bytes, time
    addVariableInt64(server, ns5Id, "int64_a", 0);
    addVariableInt64(server, ns5Id, "int64_b", -5000000000LL);
    addVariableInt64(server, ns5Id, "int64_c", 5000000000LL);
    addVariableDouble(server, ns5Id, "double_a", 0);
    addVariableDouble(server, ns5Id, "double_b", -123456.789);
    addVariableDouble(server, ns5Id, "double_c", 123456.789);
    addVariableByte(server, ns5Id, "byte_a", 0);
    addVariableByte(server, ns5Id, "byte_b", 255);
    addVariableTime(server, ns5Id, "time_a", 0);

    // Array/list nodes (valueRank ANY)
    static UA_Int32 int32list_init[3] = {0, 0, 0};
    addArrayVariable(server, ns5Id, UA_TYPES_INT32, "int32list_a", int32list_init, 3);
    static UA_UInt32 uint32list_init[3] = {0, 0, 0};
    addArrayVariable(server, ns5Id, UA_TYPES_UINT32, "uint32list_a", uint32list_init, 3);
    static UA_Int64 int64list_init[4] = {0, 0, 0, 0};
    addArrayVariable(server, ns5Id, UA_TYPES_INT64, "int64list_a", int64list_init, 4);

    // Numeric node id (for multi_read_numeric)
    addNumericInt32(server, ns5Id, 5001, 4242);
}

int main(void) {
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    // open62541 1.0 server bootstrap (the server owns its config).
    UA_Server *server = UA_Server_new();
    UA_ServerConfig_setDefault(UA_Server_getConfig(server));
    addVariables(server);

    UA_StatusCode retval = UA_Server_run(server, &running);

    UA_Server_delete(server);
    return (int)retval;
}
