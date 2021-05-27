#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include <mosquitto_broker.h>
#include <mosquitto_plugin.h>
#include <mosquitto.h>


#if MOSQ_AUTH_PLUGIN_VERSION >= 3
# define mosquitto_auth_opt mosquitto_opt
#endif

#include "go-auth.h"

// Same constant as one in go-auth.go.
#define AuthRejected 0
#define AuthGranted 1
#define AuthError 2

int mosquitto_auth_plugin_version(void) {
  #ifdef MOSQ_AUTH_PLUGIN_VERSION
    #if MOSQ_AUTH_PLUGIN_VERSION == 5
      return 4; // This is v2.0, use the backwards compatibility
    #else
      return MOSQ_AUTH_PLUGIN_VERSION;
    #endif
  #else
    return 4;
  #endif
}

int mosquitto_auth_plugin_init(void **user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count) {
  /*
    Pass auth_opts hash as keys and values char* arrays to Go in order to initialize them there.
  */

  GoInt32 opts_count = auth_opt_count;
  
  GoString keys[auth_opt_count];
  GoString values[auth_opt_count];
  int i;
  struct mosquitto_auth_opt *o;
  for (i = 0, o = auth_opts; i < auth_opt_count; i++, o++) {
    GoString opt_key = {o->key, strlen(o->key)};
    GoString opt_value = {o->value, strlen(o->value)};
    keys[i] = opt_key;
    values[i] = opt_value;
  }

  GoSlice keysSlice = {keys, auth_opt_count, auth_opt_count};
  GoSlice valuesSlice = {values, auth_opt_count, auth_opt_count};

  char versionArray[10];
  sprintf(versionArray, "%i.%i.%i", LIBMOSQUITTO_MAJOR, LIBMOSQUITTO_MINOR, LIBMOSQUITTO_REVISION);

  GoString version = {versionArray, strlen(versionArray)};

  AuthPluginInit(keysSlice, valuesSlice, opts_count, version);
  return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_plugin_cleanup(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count) {
  AuthPluginCleanup();
  return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_init(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count, bool reload) {
  return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_cleanup(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count, bool reload) {
  return MOSQ_ERR_SUCCESS;
}

#if MOSQ_AUTH_PLUGIN_VERSION >= 4
int mosquitto_auth_unpwd_check(void *user_data, struct mosquitto *client, const char *username, const char *password)
#elif MOSQ_AUTH_PLUGIN_VERSION >=3
int mosquitto_auth_unpwd_check(void *userdata, const struct mosquitto *client, const char *username, const char *password)
#else
int mosquitto_auth_unpwd_check(void *userdata, const char *username, const char *password)
#endif
{
  #if MOSQ_AUTH_PLUGIN_VERSION >= 3
    const char* clientid = mosquitto_client_id(client);
  #else
    const char* clientid = "";
  #endif
  if (username == NULL || password == NULL) {
    printf("error: received null username or password for unpwd check\n");
    fflush(stdout);
    return MOSQ_ERR_AUTH;
  }

  GoString go_username = {username, strlen(username)};
  GoString go_password = {password, strlen(password)};
  GoString go_clientid = {clientid, strlen(clientid)};

  GoUint8 ret = AuthUnpwdCheck(go_username, go_password, go_clientid);

  switch (ret)
  {
  case AuthGranted:
    return MOSQ_ERR_SUCCESS;
    break;
  case AuthRejected:
    return MOSQ_ERR_AUTH;
    break;
  case AuthError:
    return MOSQ_ERR_UNKNOWN;
    break;
  default:
    fprintf(stderr, "unknown plugin error: %d\n", ret);
    return MOSQ_ERR_UNKNOWN;
  }
}

#if MOSQ_AUTH_PLUGIN_VERSION >= 4
int mosquitto_auth_acl_check(void *user_data, int access, struct mosquitto *client, const struct mosquitto_acl_msg *msg)
#elif MOSQ_AUTH_PLUGIN_VERSION >= 3
int mosquitto_auth_acl_check(void *userdata, int access, const struct mosquitto *client, const struct mosquitto_acl_msg *msg)
#else
int mosquitto_auth_acl_check(void *userdata, const char *clientid, const char *username, const char *topic, int access)
#endif
{
  #if MOSQ_AUTH_PLUGIN_VERSION >= 3
    const char* clientid = mosquitto_client_id(client);
    const char* username = mosquitto_client_username(client);
    const char* topic = msg->topic;
  #endif
  if (clientid == NULL || username == NULL || topic == NULL || access < 1) {
    printf("error: received null username, clientid or topic, or access is equal or less than 0 for acl check\n");
    fflush(stdout);
    return MOSQ_ERR_ACL_DENIED;
  }

  GoString go_clientid = {clientid, strlen(clientid)};
  GoString go_username = {username, strlen(username)};
  GoString go_topic = {topic, strlen(topic)};
  GoInt32 go_access = access;

  GoUint8 ret = AuthAclCheck(go_clientid, go_username, go_topic, go_access);

  switch (ret)
  {
  case AuthGranted:
    return MOSQ_ERR_SUCCESS;
    break;
  case AuthRejected:
    return MOSQ_ERR_ACL_DENIED;
    break;
  case AuthError:
    return MOSQ_ERR_UNKNOWN;
    break;
  default:
    fprintf(stderr, "unknown plugin error: %d\n", ret);
    return MOSQ_ERR_UNKNOWN;
  }
}

#if MOSQ_AUTH_PLUGIN_VERSION >= 4
int mosquitto_auth_psk_key_get(void *user_data, struct mosquitto *client, const char *hint, const char *identity, char *key, int max_key_len)
#elif MOSQ_AUTH_PLUGIN_VERSION >= 3
int mosquitto_auth_psk_key_get(void *userdata, const struct mosquitto *client, const char *hint, const char *identity, char *key, int max_key_len)
#else
int mosquitto_auth_psk_key_get(void *userdata, const char *hint, const char *identity, char *key, int max_key_len)
#endif
{
  return MOSQ_ERR_AUTH;
}
