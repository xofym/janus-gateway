/*! \file   janus_hls.c
 * \author Axel Etcheverry <axel.etcheverry@getmyfox.com>
 * \copyright GNU General Public License v3
 * \brief  Janus HLS plugin
 * \details Check the \ref hls for more details.
 *
 * \ingroup plugins
 * \ref plugins
 *
 * \page hls HLS plugin documentation
 *
 */

#include "plugin.h"

#include "janus_hls_recorder.h"

#include <dirent.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <jansson.h>

#include "../debug.h"
#include "../apierror.h"
#include "../config.h"
#include "../mutex.h"
#include "../record.h"
#include "../sdp-utils.h"
#include "../rtp.h"
#include "../rtcp.h"
#include "../utils.h"


/* Plugin information */
#define JANUS_HLS_VERSION			1
#define JANUS_HLS_VERSION_STRING	"0.0.1"
#define JANUS_HLS_DESCRIPTION		"This is a HLS plugin for Janus, to record WebRTC sessions in HLS."
#define JANUS_HLS_NAME				"JANUS HLS plugin"
#define JANUS_HLS_AUTHOR			"Somfy Protect by Myfox"
#define JANUS_HLS_PACKAGE			"janus.plugin.hls"

/* Plugin methods */
janus_plugin *create(void);
int janus_hls_init(janus_callbacks *callback, const char *onfig_path);
void janus_hls_destroy(void);
int janus_hls_get_api_compatibility(void);
int janus_hls_get_version(void);
const char *janus_hls_get_version_string(void);
const char *janus_hls_get_description(void);
const char *janus_hls_get_name(void);
const char *janus_hls_get_author(void);
const char *janus_hls_get_package(void);
void janus_hls_create_session(janus_plugin_session *handle, int *error);
struct janus_plugin_result *janus_hls_handle_message(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep);
void janus_hls_setup_media(janus_plugin_session *handle);
void janus_hls_incoming_rtp(janus_plugin_session *handle, int video, char *buf, int len);
void janus_hls_incoming_rtcp(janus_plugin_session *handle, int video, char *buf, int len);
void janus_hls_slow_link(janus_plugin_session *handle, int uplink, int video);
void janus_hls_hangup_media(janus_plugin_session *handle);
void janus_hls_destroy_session(janus_plugin_session *handle, int *error);
json_t *janus_hls_query_session(janus_plugin_session *handle);

/* Plugin setup */
static janus_plugin janus_hls_plugin =
	JANUS_PLUGIN_INIT (
		.init = janus_hls_init,
		.destroy = janus_hls_destroy,

		.get_api_compatibility = janus_hls_get_api_compatibility,
		.get_version = janus_hls_get_version,
		.get_version_string = janus_hls_get_version_string,
		.get_description = janus_hls_get_description,
		.get_name = janus_hls_get_name,
		.get_author = janus_hls_get_author,
		.get_package = janus_hls_get_package,

		.create_session = janus_hls_create_session,
		.handle_message = janus_hls_handle_message,
		.setup_media = janus_hls_setup_media,
		.incoming_rtp = janus_hls_incoming_rtp,
		.incoming_rtcp = janus_hls_incoming_rtcp,
		.slow_link = janus_hls_slow_link,
		.hangup_media = janus_hls_hangup_media,
		.destroy_session = janus_hls_destroy_session,
		.query_session = janus_hls_query_session,
	);

/* Plugin creator */
janus_plugin *create(void) {
	JANUS_LOG(LOG_VERB, "%s created!\n", JANUS_HLS_NAME);

	return &janus_hls_plugin;
}

/* Parameter validation */
static struct janus_json_parameter request_parameters[] = {
	{"request", JSON_STRING, JANUS_JSON_PARAM_REQUIRED}
};
static struct janus_json_parameter configure_parameters[] = {
	{"video-bitrate-max", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"video-keyframe-interval", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE}
};
static struct janus_json_parameter record_parameters[] = {
	{"name", JSON_STRING, JANUS_JSON_PARAM_REQUIRED | JANUS_JSON_PARAM_NONEMPTY},
	{"id", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"update", JANUS_JSON_BOOL, 0}
};

/* Useful stuff */
static volatile gint initialized = 0, stopping = 0;
static gboolean notify_events = TRUE;
static janus_callbacks *gateway = NULL;
static GThread *handler_thread;
static void *janus_hls_handler(void *data);
static void janus_hls_hangup_media_internal(janus_plugin_session *handle);

typedef struct janus_hls_message {
	janus_plugin_session *handle;
	char *transaction;
	json_t *message;
	json_t *jsep;
} janus_hls_message;
static GAsyncQueue *messages = NULL;
static janus_hls_message exit_message;

typedef struct janus_hls_rtp_header_extension {
	uint16_t type;
	uint16_t length;
} janus_hls_rtp_header_extension;

typedef struct janus_hls_frame_packet {
	uint16_t seq;	/* RTP Sequence number */
	uint64_t ts;	/* RTP Timestamp */
	int len;		/* Length of the data */
	long offset;	/* Offset of the data in the file */
	struct janus_hls_frame_packet *next;
	struct janus_hls_frame_packet *prev;
} janus_hls_frame_packet;

typedef struct janus_hls_recording {
	guint64 id;					/* Recording unique ID */
	char *name;					/* Name of the recording */
	char *date;					/* Time of the recording */
	char *arc_file;				/* Audio file name */
	janus_audiocodec acodec;	/* Codec used for audio, if available */
	char *vrc_file;				/* Video file name */
	janus_videocodec vcodec;	/* Codec used for video, if available */
	volatile gint completed;	/* Whether this recording was completed or still going on */
	volatile gint destroyed;	/* Whether this recording has been marked as destroyed */
	janus_refcount ref;			/* Reference counter */
	janus_mutex mutex;			/* Mutex for this recording */

	uint8_t *received_frame; 	/* frame buffer */
} janus_hls_recording;

static GHashTable *recordings = NULL;
static janus_mutex recordings_mutex = JANUS_MUTEX_INITIALIZER;

typedef struct janus_hls_session {
	janus_plugin_session *handle;
	gint64 sdp_sessid;
	gint64 sdp_version;
	gboolean active;
	gboolean recorder;		/* Whether this session is used to record or to replay a WebRTC session */
	janus_hls_recording *recording;
	janus_hls_recorder *rc; /* HLS recorder */
	janus_recorder *arc;	/* Audio recorder */
	janus_recorder *vrc;	/* Video recorder */
	janus_mutex rec_mutex;	/* Mutex to protect the recorders from race conditions */
	guint video_remb_startup;
	gint64 video_remb_last;
	guint32 video_bitrate;
	guint video_keyframe_interval;			/* Keyframe request interval (ms) */
	guint64 video_keyframe_request_last;	/* Timestamp of last keyframe request sent */
	gint video_fir_seq;
	janus_rtp_switching_context context;
	uint32_t ssrc[3];		/* Only needed in case VP8 (or H.264) simulcasting is involved */
	char *rid[3];			/* Only needed if simulcasting is rid-based */
	uint32_t rec_vssrc;		/* SSRC we'll put in the recording for video, in case simulcasting is involved) */
	janus_rtp_simulcasting_context sim_context;
	janus_vp8_simulcast_context vp8_context;
	volatile gint hangingup;
	volatile gint destroyed;
	janus_refcount ref;
} janus_hls_session;

static GHashTable *sessions;
static janus_mutex sessions_mutex = JANUS_MUTEX_INITIALIZER;

static void janus_hls_session_destroy(janus_hls_session *session) {
	if (session && g_atomic_int_compare_and_exchange(&session->destroyed, 0, 1)) {
		janus_refcount_decrease(&session->ref);
	}
}

static void janus_hls_session_free(const janus_refcount *session_ref) {
	janus_hls_session *session = janus_refcount_containerof(session_ref, janus_hls_session, ref);
	/* Remove the reference to the core plugin session */
	janus_refcount_decrease(&session->handle->ref);
	/* This session can be destroyed, free all the resources */
	g_free(session);
}


static void janus_hls_recording_destroy(janus_hls_recording *recording) {
	if (recording && g_atomic_int_compare_and_exchange(&recording->destroyed, 0, 1)) {
		janus_refcount_decrease(&recording->ref);
	}
}

static void janus_hls_recording_free(const janus_refcount *recording_ref) {
	janus_hls_recording *recording = janus_refcount_containerof(recording_ref, janus_hls_recording, ref);
	/* This recording can be destroyed, free all the resources */
	g_free(recording->name);
	g_free(recording->date);
	g_free(recording->arc_file);
	g_free(recording->vrc_file);
	g_free(recording);
}


static char *recordings_path = NULL;

/* Helper to send RTCP feedback back to recorders, if needed */
void janus_hls_send_rtcp_feedback(janus_plugin_session *handle, int video, char *buf, int len);

static void janus_hls_message_free(janus_hls_message *msg) {
	if (!msg || msg == &exit_message) {
		return;
	}

	if (msg->handle && msg->handle->plugin_handle) {
		janus_hls_session *session = (janus_hls_session *)msg->handle->plugin_handle;
		janus_refcount_decrease(&session->ref);
	}
	msg->handle = NULL;

	g_free(msg->transaction);
	msg->transaction = NULL;
	if (msg->message) {
		json_decref(msg->message);
	}
	msg->message = NULL;
	if (msg->jsep) {
		json_decref(msg->jsep);
	}
	msg->jsep = NULL;

	g_free(msg);
}


/* Error codes */
#define JANUS_HLS_ERROR_NO_MESSAGE			411
#define JANUS_HLS_ERROR_INVALID_JSON		412
#define JANUS_HLS_ERROR_INVALID_REQUEST		413
#define JANUS_HLS_ERROR_INVALID_ELEMENT		414
#define JANUS_HLS_ERROR_MISSING_ELEMENT		415
#define JANUS_HLS_ERROR_NOT_FOUND			416
#define JANUS_HLS_ERROR_INVALID_RECORDING	417
#define JANUS_HLS_ERROR_INVALID_STATE		418
#define JANUS_HLS_ERROR_INVALID_SDP			419
#define JANUS_HLS_ERROR_RECORDING_EXISTS	420
#define JANUS_HLS_ERROR_UNKNOWN_ERROR		499


/* Plugin implementation */
int janus_hls_init(janus_callbacks *callback, const char *config_path) {
	if (g_atomic_int_get(&stopping)) {
		/* Still stopping from before */
		return -1;
	}

	if (callback == NULL || config_path == NULL) {
		/* Invalid arguments */
		return -1;
	}

	/* Read configuration */
	char filename[255];
	g_snprintf(filename, 255, "%s/%s.jcfg", config_path, JANUS_HLS_PACKAGE);
	JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
	janus_config *config = janus_config_parse(filename);

	if (config == NULL) {
		JANUS_LOG(LOG_WARN, "Couldn't find .jcfg configuration file (%s), trying .cfg\n", JANUS_HLS_PACKAGE);
		g_snprintf(filename, 255, "%s/%s.cfg", config_path, JANUS_HLS_PACKAGE);
		JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
		config = janus_config_parse(filename);
	}

	if (config != NULL) {
		janus_config_print(config);
	}

	/* Parse configuration */
	if (config != NULL) {
		janus_config_category *config_general = janus_config_get_create(config, NULL, janus_config_type_category, "general");
		janus_config_item *path = janus_config_get(config, config_general, janus_config_type_item, "path");
		if (path && path->value) {
			recordings_path = g_strdup(path->value);
		}

		janus_config_item *events = janus_config_get(config, config_general, janus_config_type_item, "events");
		if (events != NULL && events->value != NULL) {
			notify_events = janus_is_true(events->value);
		}

		if (!notify_events && callback->events_is_enabled()) {
			JANUS_LOG(LOG_WARN, "Notification of events to handlers disabled for %s\n", JANUS_HLS_NAME);
		}

		/* Done */
		janus_config_destroy(config);
		config = NULL;
	}

	if (recordings_path == NULL) {
		JANUS_LOG(LOG_FATAL, "No recordings path specified, giving up...\n");
		return -1;
	}

	/* Create the folder, if needed */
	struct stat st = {0};
	if (stat(recordings_path, &st) == -1) {
		int res = janus_mkdir(recordings_path, 0755);
		JANUS_LOG(LOG_VERB, "Creating folder: %d\n", res);

		if (res != 0) {
			JANUS_LOG(LOG_ERR, "%s", strerror(errno));
			return -1;	/* No point going on... */
		}
	}

	recordings = g_hash_table_new_full(g_int64_hash, g_int64_equal, (GDestroyNotify)g_free, (GDestroyNotify)janus_hls_recording_destroy);

	sessions = g_hash_table_new_full(NULL, NULL, NULL, (GDestroyNotify)janus_hls_session_destroy);
	messages = g_async_queue_new_full((GDestroyNotify) janus_hls_message_free);
	/* This is the callback we'll need to invoke to contact the Janus core */
	gateway = callback;

	g_atomic_int_set(&initialized, 1);

	/* Launch the thread that will handle incoming messages */
	GError *error = NULL;
	handler_thread = g_thread_try_new("hls handler", janus_hls_handler, NULL, &error);
	if (error != NULL) {
		g_atomic_int_set(&initialized, 0);
		JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the HLS handler thread...\n", error->code, error->message ? error->message : "??");

		return -1;
	}

	/* init recorder */
	janus_hls_recorder_init();

	JANUS_LOG(LOG_INFO, "%s initialized!\n", JANUS_HLS_NAME);

	return 0;
}

void janus_hls_destroy(void) {
	if (!g_atomic_int_get(&initialized)) {
		return;
	}
	g_atomic_int_set(&stopping, 1);

	g_async_queue_push(messages, &exit_message);
	if (handler_thread != NULL) {
		g_thread_join(handler_thread);
		handler_thread = NULL;
	}
	/* FIXME We should destroy the sessions cleanly */
	janus_mutex_lock(&sessions_mutex);
	g_hash_table_destroy(sessions);
	sessions = NULL;
	g_hash_table_destroy(recordings);
	recordings = NULL;
	janus_mutex_unlock(&sessions_mutex);
	g_async_queue_unref(messages);
	messages = NULL;
	g_atomic_int_set(&initialized, 0);
	g_atomic_int_set(&stopping, 0);
	JANUS_LOG(LOG_INFO, "%s destroyed!\n", JANUS_HLS_NAME);
}

int janus_hls_get_api_compatibility(void) {
	/* Important! This is what your plugin MUST always return: don't lie here or bad things will happen */
	return JANUS_PLUGIN_API_VERSION;
}

int janus_hls_get_version(void) {
	return JANUS_HLS_VERSION;
}

const char *janus_hls_get_version_string(void) {
	return JANUS_HLS_VERSION_STRING;
}

const char *janus_hls_get_description(void) {
	return JANUS_HLS_DESCRIPTION;
}

const char *janus_hls_get_name(void) {
	return JANUS_HLS_NAME;
}

const char *janus_hls_get_author(void) {
	return JANUS_HLS_AUTHOR;
}

const char *janus_hls_get_package(void) {
	return JANUS_HLS_PACKAGE;
}

static janus_hls_session *janus_hls_lookup_session(janus_plugin_session *handle) {
	janus_hls_session *session = NULL;
	if (g_hash_table_contains(sessions, handle)) {
		session = (janus_hls_session *)handle->plugin_handle;
	}

	return session;
}

void janus_hls_create_session(janus_plugin_session *handle, int *error) {
	if (g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		*error = -1;

		return;
	}

	janus_hls_session *session = g_malloc0(sizeof(janus_hls_session));
	session->handle = handle;
	session->active = FALSE;
	session->recorder = FALSE;
	session->arc = NULL;
	session->vrc = NULL;
	janus_mutex_init(&session->rec_mutex);
	g_atomic_int_set(&session->hangingup, 0);
	g_atomic_int_set(&session->destroyed, 0);
	session->video_remb_startup = 4;
	session->video_remb_last = janus_get_monotonic_time();
	session->video_bitrate = 1024 * 1024; 		/* This is 1mbps by default */
	session->video_keyframe_request_last = 0;
	session->video_keyframe_interval = 10000; 	/* 10 seconds by default */
	session->video_fir_seq = 0;
	janus_rtp_switching_context_reset(&session->context);
	janus_rtp_simulcasting_context_reset(&session->sim_context);
	janus_vp8_simulcast_context_reset(&session->vp8_context);
	janus_refcount_init(&session->ref, janus_hls_session_free);
	handle->plugin_handle = session;

	janus_mutex_lock(&sessions_mutex);
	g_hash_table_insert(sessions, handle, session);
	janus_mutex_unlock(&sessions_mutex);

	return;
}

void janus_hls_destroy_session(janus_plugin_session *handle, int *error) {
	if (g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		*error = -1;

		return;
	}

	janus_mutex_lock(&sessions_mutex);
	janus_hls_session *session = janus_hls_lookup_session(handle);
	if (!session) {
		janus_mutex_unlock(&sessions_mutex);
		JANUS_LOG(LOG_ERR, "No HLS session associated with this handle...\n");
		*error = -2;

		return;
	}

	/* close hls recorder */
	janus_hls_recorder_destroy(session->rc);

	JANUS_LOG(LOG_VERB, "Removing HLS session...\n");
	janus_hls_hangup_media_internal(handle);
	g_hash_table_remove(sessions, handle);
	janus_mutex_unlock(&sessions_mutex);

	return;
}

json_t *janus_hls_query_session(janus_plugin_session *handle) {
	if (g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		return NULL;
	}

	janus_mutex_lock(&sessions_mutex);
	janus_hls_session *session = janus_hls_lookup_session(handle);
	if (!session) {
		janus_mutex_unlock(&sessions_mutex);
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");

		return NULL;
	}

	janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&sessions_mutex);
	/* In the echo test, every session is the same: we just provide some configure info */
	json_t *info = json_object();
	json_object_set_new(info, "type", json_string(session->recorder ? "recorder" : (session->recording ? "player" : "none")));
	if (session->recording) {
		janus_refcount_increase(&session->recording->ref);
		json_object_set_new(info, "recording_id", json_integer(session->recording->id));
		json_object_set_new(info, "recording_name", json_string(session->recording->name));
		janus_refcount_decrease(&session->recording->ref);
	}

	json_object_set_new(info, "hangingup", json_integer(g_atomic_int_get(&session->hangingup)));
	json_object_set_new(info, "destroyed", json_integer(g_atomic_int_get(&session->destroyed)));
	janus_refcount_decrease(&session->ref);

	return info;
}

struct janus_plugin_result *janus_hls_handle_message(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep) {
	if (g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		return janus_plugin_result_new(JANUS_PLUGIN_ERROR, g_atomic_int_get(&stopping) ? "Shutting down" : "Plugin not initialized", NULL);
	}

	/* Pre-parse the message */
	int error_code = 0;
	char error_cause[512];
	json_t *root = message;
	json_t *response = NULL;

	janus_mutex_lock(&sessions_mutex);
	janus_hls_session *session = janus_hls_lookup_session(handle);
	if (!session) {
		janus_mutex_unlock(&sessions_mutex);
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		error_code = JANUS_HLS_ERROR_UNKNOWN_ERROR;
		g_snprintf(error_cause, 512, "%s", "No session associated with this handle...");

		goto plugin_response;
	}

	/* Increase the reference counter for this session: we'll decrease it after we handle the message */
	janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&sessions_mutex);
	if (g_atomic_int_get(&session->destroyed)) {
		JANUS_LOG(LOG_ERR, "Session has already been destroyed...\n");
		error_code = JANUS_HLS_ERROR_UNKNOWN_ERROR;
		g_snprintf(error_cause, 512, "%s", "Session has already been destroyed...");

		goto plugin_response;
	}

	if (message == NULL) {
		JANUS_LOG(LOG_ERR, "No message??\n");
		error_code = JANUS_HLS_ERROR_NO_MESSAGE;
		g_snprintf(error_cause, 512, "%s", "No message??");

		goto plugin_response;
	}

	if (!json_is_object(root)) {
		JANUS_LOG(LOG_ERR, "JSON error: not an object\n");
		error_code = JANUS_HLS_ERROR_INVALID_JSON;
		g_snprintf(error_cause, 512, "JSON error: not an object");

		goto plugin_response;
	}

	/* Get the request first */
	JANUS_VALIDATE_JSON_OBJECT(
		root,
		request_parameters,
		error_code,
		error_cause,
		TRUE,
		JANUS_HLS_ERROR_MISSING_ELEMENT,
		JANUS_HLS_ERROR_INVALID_ELEMENT
	);

	if (error_code != 0) {
		goto plugin_response;
	}

	json_t *request = json_object_get(root, "request");
	/* Some requests ('create' and 'destroy') can be handled synchronously */
	const char *request_text = json_string_value(request);

	if (!strcasecmp(request_text, "configure")) {
		JANUS_VALIDATE_JSON_OBJECT(
			root,
			configure_parameters,
			error_code,
			error_cause,
			TRUE,
			JANUS_HLS_ERROR_MISSING_ELEMENT,
			JANUS_HLS_ERROR_INVALID_ELEMENT
		);
		if (error_code != 0) {
			goto plugin_response;
		}

		json_t *video_bitrate_max = json_object_get(root, "video-bitrate-max");
		if (video_bitrate_max) {
			session->video_bitrate = json_integer_value(video_bitrate_max);
			JANUS_LOG(LOG_VERB, "Video bitrate has been set to %"SCNu32"\n", session->video_bitrate);
		}

		json_t *video_keyframe_interval = json_object_get(root, "video-keyframe-interval");
		if (video_keyframe_interval) {
			session->video_keyframe_interval = json_integer_value(video_keyframe_interval);
			JANUS_LOG(LOG_VERB, "Video keyframe interval has been set to %u\n", session->video_keyframe_interval);
		}

		response = json_object();
		json_object_set_new(response, "hls", json_string("configure"));
		json_object_set_new(response, "status", json_string("ok"));
		/* Return a success, and also let the client be aware of what changed, to allow crosschecks */
		json_t *settings = json_object();
		json_object_set_new(settings, "video-keyframe-interval", json_integer(session->video_keyframe_interval));
		json_object_set_new(settings, "video-bitrate-max", json_integer(session->video_bitrate));
		json_object_set_new(response, "settings", settings);

		goto plugin_response;
	} else if (!strcasecmp(request_text, "record") || !strcasecmp(request_text, "stop")) {
		/* These messages are handled asynchronously */
		janus_hls_message *msg = g_malloc(sizeof(janus_hls_message));
		msg->handle = handle;
		msg->transaction = transaction;
		msg->message = root;
		msg->jsep = jsep;

		g_async_queue_push(messages, msg);

		return janus_plugin_result_new(JANUS_PLUGIN_OK_WAIT, NULL, NULL);
	} else {
		JANUS_LOG(LOG_VERB, "Unknown request '%s'\n", request_text);
		error_code = JANUS_HLS_ERROR_INVALID_REQUEST;
		g_snprintf(error_cause, 512, "Unknown request '%s'", request_text);
	}

plugin_response:
	{
		if (error_code == 0 && !response) {
			error_code = JANUS_HLS_ERROR_UNKNOWN_ERROR;
			g_snprintf(error_cause, 512, "Invalid response");
		}

		if (error_code != 0) {
			/* Prepare JSON error event */
			json_t *event = json_object();
			json_object_set_new(event, "hls", json_string("event"));
			json_object_set_new(event, "error_code", json_integer(error_code));
			json_object_set_new(event, "error", json_string(error_cause));
			response = event;
		}

		if (root != NULL) {
			json_decref(root);
		}

		if (jsep != NULL) {
			json_decref(jsep);
		}

		g_free(transaction);

		if (session != NULL) {
			janus_refcount_decrease(&session->ref);
		}

		return janus_plugin_result_new(JANUS_PLUGIN_OK, NULL, response);
	}
}

void janus_hls_setup_media(janus_plugin_session *handle) {
	JANUS_LOG(LOG_INFO, "[%s-%p] WebRTC media is now available\n", JANUS_HLS_PACKAGE, handle);

	if (g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		return;
	}

	janus_mutex_lock(&sessions_mutex);
	janus_hls_session *session = janus_hls_lookup_session(handle);
	if (!session) {
		janus_mutex_unlock(&sessions_mutex);
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");

		return;
	}

	if (g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&sessions_mutex);

		return;
	}

	janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&sessions_mutex);
	g_atomic_int_set(&session->hangingup, 0);
	/* Take note of the fact that the session is now active */
	session->active = TRUE;

	janus_refcount_decrease(&session->ref);
}

void janus_hls_send_rtcp_feedback(janus_plugin_session *handle, int video, char *buf, int len) {
	if (video != 1) {
		return;	/* We just do this for video, for now */
	}

	janus_hls_session *session = (janus_hls_session *)handle->plugin_handle;
	char rtcpbuf[24];

	/* Send a RR+SDES+REMB every five seconds, or ASAP while we are still
	 * ramping up (first 4 RTP packets) */
	gint64 now = janus_get_monotonic_time();
	gint64 elapsed = now - session->video_remb_last;
	gboolean remb_rampup = session->video_remb_startup > 0;

	if (remb_rampup || (elapsed >= 5*G_USEC_PER_SEC)) {
		guint32 bitrate = session->video_bitrate;

		if (remb_rampup) {
			bitrate = bitrate / session->video_remb_startup;
			session->video_remb_startup--;
		}

		/* Send a new REMB back */
		char rtcpbuf[24];
		janus_rtcp_remb((char *)(&rtcpbuf), 24, bitrate);
		gateway->relay_rtcp(handle, video, rtcpbuf, 24);

		session->video_remb_last = now;
	}

	/* Request a keyframe on a regular basis (every session->video_keyframe_interval ms) */
	elapsed = now - session->video_keyframe_request_last;
	gint64 interval = (gint64)(session->video_keyframe_interval / 1000) * G_USEC_PER_SEC;

	if (elapsed >= interval) {
		/* Send both a FIR and a PLI, just to be sure */
		janus_rtcp_fir((char *)&rtcpbuf, 20, &session->video_fir_seq);
		gateway->relay_rtcp(handle, video, rtcpbuf, 20);
		janus_rtcp_pli((char *)&rtcpbuf, 12);
		gateway->relay_rtcp(handle, video, rtcpbuf, 12);
		session->video_keyframe_request_last = now;
	}
}

#define uint32s_in_rtp_header 3

void janus_hls_incoming_rtp(janus_plugin_session *handle, int video, char *buf, int len) {
	if (handle == NULL || g_atomic_int_get(&handle->stopped) || g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		return;
	}

	janus_hls_session *session = (janus_hls_session *)handle->plugin_handle;
	if (!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");

		return;
	}

	if (g_atomic_int_get(&session->destroyed)) {
		return;
	}

	if (!session->recorder || !session->recording) {
		return;
	}

	if (video) {
		janus_rtp_header *header = (janus_rtp_header *)buf;

		if (header) {
			int profile_len = 0;

			if (header->extension == 1) {
				janus_rtp_header_extension *xtn_hdr = (janus_rtp_header_extension *)((uint32_t *)header + uint32s_in_rtp_header + header->csrccount);

				profile_len = ntohs(xtn_hdr->length);
			}

			JANUS_LOG(
				LOG_HUGE,
				"[%s-%p] RTP Header: \n\tSeq=%"SCNu16", \n\tType=%"SCNu16", \n\tSsrc=%"SCNu32", \n\tTs=%"SCNu32", \n\tExt=%"SCNu16", \n\tProfile=%lu\n",
				JANUS_HLS_PACKAGE,
				handle,
				ntohs(header->seq_number),
				header->type,
				ntohl(header->ssrc),
				ntohl(header->timestamp),
				header->extension,
				profile_len
			);
		} else {
			JANUS_LOG(LOG_HUGE, "[%s-%p] RTP Header empty\n", JANUS_HLS_PACKAGE, handle);
		}


		int plen = 0;
		char *payload = janus_rtp_payload(buf, len, &plen);

		JANUS_LOG(LOG_HUGE, "[%s-%p] Payload len=%d (%lu)\n", JANUS_HLS_PACKAGE, handle, plen, strlen(payload));

		if (payload) {

			gboolean kf = janus_h264_is_keyframe(payload, plen);
			if (kf) {
				JANUS_LOG(LOG_HUGE, "[%s-%p] New keyframe received! ts=%"SCNu32"\n", JANUS_HLS_PACKAGE, handle, header->timestamp);
			}

			char newname[1024];
			memset(newname, 0, 1024);
			g_snprintf(newname, 1024, "%s/%s.h264", recordings_path, session->recording->name);

			// JANUS_LOG(LOG_HUGE, "[%s-%p] Write file %s\n", JANUS_HLS_PACKAGE, handle, newname);

			FILE *file = fopen(newname, "ab");

			int temp = 0, tot = plen;
			while (tot > 0) {
				temp = fwrite(payload+plen-tot, sizeof(char), tot, file);
				if (temp <= 0) {
					JANUS_LOG(LOG_ERR, "Error saving frame...\n");

					return;
				}

				tot -= temp;
			}

			fclose(file);

		}
	}
/*
	janus_hls_frame *frame = g_malloc(sizeof(janus_hls_frame));
	frame->buffer = g_strdup(buf);
	frame->len = len;

	if (video) {
		frame->type = AVMEDIA_TYPE_VIDEO;
	} else {
		frame->type = AVMEDIA_TYPE_AUDIO;
	}

	janus_hls_recorder_save_frame(session->rc, frame);
*/


	/* Save the frame if we're recording */
	//janus_recorder_save_frame(video ? session->vrc : session->arc, buf, len);

	//JANUS_LOG(LOG_VERB, "[%s-%p] Save frame len: %d\n", JANUS_HLS_PACKAGE, handle, len);

	janus_hls_send_rtcp_feedback(handle, video, buf, len);

	//g_free(frame);
}

void janus_hls_incoming_rtcp(janus_plugin_session *handle, int video, char *buf, int len) {
	if (handle == NULL || g_atomic_int_get(&handle->stopped) || g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		return;
	}
}

void janus_hls_slow_link(janus_plugin_session *handle, int uplink, int video) {
	if (handle == NULL || g_atomic_int_get(&handle->stopped) || g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized) || !gateway) {
		return;
	}

	janus_mutex_lock(&sessions_mutex);
	janus_hls_session *session = janus_hls_lookup_session(handle);
	if (!session || g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&sessions_mutex);

		return;
	}

	janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&sessions_mutex);

	json_t *event = json_object();
	json_object_set_new(event, "hls", json_string("event"));
	json_t *result = json_object();
	json_object_set_new(result, "status", json_string("slow_link"));
	/* What is uplink for the server is downlink for the client, so turn the tables */
	json_object_set_new(result, "current-bitrate", json_integer(session->video_bitrate));
	json_object_set_new(result, "uplink", json_integer(uplink ? 0 : 1));
	json_object_set_new(event, "result", result);
	gateway->push_event(session->handle, &janus_hls_plugin, NULL, event, NULL);
	json_decref(event);
	janus_refcount_decrease(&session->ref);
}

void janus_hls_hangup_media(janus_plugin_session *handle) {
	JANUS_LOG(LOG_INFO, "[%s-%p] No WebRTC media anymore\n", JANUS_HLS_PACKAGE, handle);
	janus_mutex_lock(&sessions_mutex);
	janus_hls_hangup_media_internal(handle);
	janus_mutex_unlock(&sessions_mutex);
}

static void janus_hls_hangup_media_internal(janus_plugin_session *handle) {
	if (g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		return;
	}

	janus_hls_session *session = janus_hls_lookup_session(handle);
	if (!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}

	session->active = FALSE;
	if (g_atomic_int_get(&session->destroyed)) {
		return;
	}

	if (!g_atomic_int_compare_and_exchange(&session->hangingup, 0, 1)) {
		return;
	}

	janus_rtp_switching_context_reset(&session->context);
	janus_rtp_simulcasting_context_reset(&session->sim_context);
	janus_vp8_simulcast_context_reset(&session->vp8_context);

	/* Send an event to the browser and tell it's over */
	json_t *event = json_object();
	json_object_set_new(event, "hls", json_string("event"));
	json_object_set_new(event, "result", json_string("done"));
	int ret = gateway->push_event(handle, &janus_hls_plugin, NULL, event, NULL);
	JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (%s)\n", ret, janus_get_api_error(ret));
	json_decref(event);

	session->active = FALSE;
	janus_mutex_lock(&session->rec_mutex);
	if (session->arc) {
		janus_recorder *rc = session->arc;
		session->arc = NULL;
		janus_recorder_close(rc);
		JANUS_LOG(LOG_INFO, "Closed audio recording %s\n", rc->filename ? rc->filename : "??");
		janus_recorder_destroy(rc);
	}

	if (session->vrc) {
		janus_recorder *rc = session->vrc;
		session->vrc = NULL;
		janus_recorder_close(rc);
		JANUS_LOG(LOG_INFO, "Closed video recording %s\n", rc->filename ? rc->filename : "??");
		janus_recorder_destroy(rc);
	}
	janus_mutex_unlock(&session->rec_mutex);

	if (session->recording) {
		janus_refcount_decrease(&session->recording->ref);
		session->recording = NULL;
	}

	int i = 0;
	for (i = 0; i<3; i++) {
		session->ssrc[i] = 0;
		g_free(session->rid[i]);
		session->rid[i] = NULL;
	}

	g_atomic_int_set(&session->hangingup, 0);
}

/* Thread to handle incoming messages */
static void *janus_hls_handler(void *data) {
	JANUS_LOG(LOG_VERB, "Joining HLS handler thread\n");

	janus_hls_message *msg = NULL;
	int error_code = 0;
	char error_cause[512];
	json_t *root = NULL;

	while (g_atomic_int_get(&initialized) && !g_atomic_int_get(&stopping)) {
		msg = g_async_queue_pop(messages);
		if (msg == &exit_message) {
			break;
		}

		if (msg->handle == NULL) {
			janus_hls_message_free(msg);

			continue;
		}

		janus_mutex_lock(&sessions_mutex);
		janus_hls_session *session = janus_hls_lookup_session(msg->handle);
		if (!session) {
			janus_mutex_unlock(&sessions_mutex);
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			janus_hls_message_free(msg);

			continue;
		}

		if (g_atomic_int_get(&session->destroyed)) {
			janus_mutex_unlock(&sessions_mutex);
			janus_hls_message_free(msg);

			continue;
		}

		janus_mutex_unlock(&sessions_mutex);

		/* Handle request */
		error_code = 0;
		root = NULL;

		if (msg->message == NULL) {
			JANUS_LOG(LOG_ERR, "No message??\n");
			error_code = JANUS_HLS_ERROR_NO_MESSAGE;
			g_snprintf(error_cause, 512, "%s", "No message??");

			goto error;
		}

		root = msg->message;
		/* Get the request first */
		JANUS_VALIDATE_JSON_OBJECT(
			root,
			request_parameters,
			error_code,
			error_cause,
			TRUE,
			JANUS_HLS_ERROR_MISSING_ELEMENT,
			JANUS_HLS_ERROR_INVALID_ELEMENT
		);
		if (error_code != 0) {
			goto error;
		}

		const char *msg_sdp_type = json_string_value(json_object_get(msg->jsep, "type"));
		const char *msg_sdp = json_string_value(json_object_get(msg->jsep, "sdp"));
		json_t *request = json_object_get(root, "request");
		const char *request_text = json_string_value(request);
		json_t *event = NULL;
		json_t *result = NULL;
		char *sdp = NULL;
		gboolean sdp_update = FALSE;

		if (json_object_get(msg->jsep, "update") != NULL) {
			sdp_update = json_is_true(json_object_get(msg->jsep, "update"));
		}

		if (!strcasecmp(request_text, "record")) {
			if (!msg_sdp || !msg_sdp_type || strcasecmp(msg_sdp_type, "offer")) {
				JANUS_LOG(LOG_ERR, "Missing SDP offer\n");
				error_code = JANUS_HLS_ERROR_MISSING_ELEMENT;
				g_snprintf(error_cause, 512, "Missing SDP offer");

				goto error;
			}

			JANUS_VALIDATE_JSON_OBJECT(
				root,
				record_parameters,
				error_code,
				error_cause,
				TRUE,
				JANUS_HLS_ERROR_MISSING_ELEMENT,
				JANUS_HLS_ERROR_INVALID_ELEMENT
			);
			if (error_code != 0) {
				goto error;
			}

			char error_str[512];
			janus_sdp *offer = janus_sdp_parse(msg_sdp, error_str, sizeof(error_str)), *answer = NULL;
			if (offer == NULL) {
				json_decref(event);
				JANUS_LOG(LOG_ERR, "Error parsing offer: %s\n", error_str);
				error_code = JANUS_HLS_ERROR_INVALID_SDP;
				g_snprintf(error_cause, 512, "Error parsing offer: %s", error_str);

				goto error;
			}

			json_t *name = json_object_get(root, "name");
			const char *name_text = json_string_value(name);

			json_t *update = json_object_get(root, "update");
			gboolean do_update = update ? json_is_true(update) : FALSE;
			if (do_update && !sdp_update) {
				JANUS_LOG(LOG_WARN, "Got a 'update' request, but no SDP update? Ignoring...\n");
			}
			/* Check if this is a new recorder, or if an update is taking place (i.e., ICE restart) */
			guint64 id = 0;
			janus_hls_recording *rec = NULL;
			gboolean audio = FALSE, video = FALSE;
			if (sdp_update) {
				/* Renegotiation: make sure the user provided an offer, and send answer */
				JANUS_LOG(LOG_VERB, "Request to update existing recorder\n");
				if (!session->recorder || !session->recording) {
					JANUS_LOG(LOG_ERR, "Not a recording session, can't update\n");
					error_code = JANUS_HLS_ERROR_INVALID_STATE;
					g_snprintf(error_cause, 512, "Not a recording session, can't update");

					goto error;
				}

				id = session->recording->id;
				rec = session->recording;
				session->sdp_version++;		/* This needs to be increased when it changes */
				audio = (session->arc != NULL);
				video = (session->vrc != NULL);
				sdp_update = do_update;

				goto recdone;
			}

			/* If we're here, we're doing a new recording */
			janus_mutex_lock(&recordings_mutex);

			json_t *rec_id = json_object_get(root, "id");
			if (rec_id) {
				id = json_integer_value(rec_id);
				if (id > 0) {
					/* Let's make sure the ID doesn't exist already */
					if (g_hash_table_lookup(recordings, &id) != NULL) {
						/* It does... */
						janus_mutex_unlock(&recordings_mutex);
						JANUS_LOG(LOG_ERR, "Recording %"SCNu64" already exists!\n", id);
						error_code = JANUS_HLS_ERROR_RECORDING_EXISTS;
						g_snprintf(error_cause, 512, "Recording %"SCNu64" already exists", id);

						goto error;
					}
				}
			}

			if (id == 0) {
				while (id == 0) {
					id = janus_random_uint64();
					if (g_hash_table_lookup(recordings, &id) != NULL) {
						/* Recording ID already taken, try another one */
						id = 0;
					}
				}
			}

			JANUS_LOG(LOG_VERB, "Starting new recording with ID %"SCNu64"\n", id);

			rec = g_malloc0(sizeof(janus_hls_recording));
			rec->id = id;
			rec->name = g_strdup(name_text);
			rec->acodec = JANUS_AUDIOCODEC_NONE;
			rec->vcodec = JANUS_VIDEOCODEC_NONE;

			g_atomic_int_set(&rec->destroyed, 0);
			g_atomic_int_set(&rec->completed, 0);

			janus_refcount_init(&rec->ref, janus_hls_recording_free);
			janus_refcount_increase(&rec->ref);	/* This is for the user writing the recording */
			janus_mutex_init(&rec->mutex);
			/* Check which codec we should record for audio and/or video */
			const char *acodec = NULL, *vcodec = NULL;
			janus_sdp_find_preferred_codecs(offer, &acodec, &vcodec);
			rec->acodec = janus_audiocodec_from_name(acodec);
			rec->vcodec = janus_videocodec_from_name(vcodec);

			/* We found preferred codecs: let's just make sure the direction is what we need */
			janus_sdp_mline *m = janus_sdp_mline_find(offer, JANUS_SDP_AUDIO);
			if (m != NULL && m->direction == JANUS_SDP_RECVONLY) {
				rec->acodec = JANUS_AUDIOCODEC_NONE;
			}

			audio = (rec->acodec != JANUS_AUDIOCODEC_NONE);
			if (audio) {
				JANUS_LOG(LOG_VERB, "Audio codec: %s\n", janus_audiocodec_name(rec->acodec));
			}

			m = janus_sdp_mline_find(offer, JANUS_SDP_VIDEO);
			if (m != NULL && m->direction == JANUS_SDP_RECVONLY) {
				rec->vcodec = JANUS_VIDEOCODEC_NONE;
			}

			video = (rec->vcodec != JANUS_VIDEOCODEC_NONE);
			if (video) {
				JANUS_LOG(LOG_VERB, "Video codec: %s\n", janus_videocodec_name(rec->vcodec));
			}

			/* Create a date string */
			time_t t = time(NULL);
			struct tm *tmv = localtime(&t);
			char outstr[200];
			strftime(outstr, sizeof(outstr), "%Y-%m-%d %H:%M:%S", tmv);
			rec->date = g_strdup(outstr);

			if (audio) {
				char filename[256];
				g_snprintf(filename, 256, "%s-%"SCNu64"-audio", name_text, id);

				rec->arc_file = g_strdup(filename);
				session->arc = janus_recorder_create(recordings_path, janus_audiocodec_name(rec->acodec), rec->arc_file);
			}

			if (video) {
				char filename[256];
				g_snprintf(filename, 256, "%s-%"SCNu64"-video", name_text, id);

				rec->vrc_file = g_strdup(filename);
				session->vrc = janus_recorder_create(recordings_path, janus_videocodec_name(rec->vcodec), rec->vrc_file);

				rec->received_frame = g_malloc0(1920 * 1080 * 3);
			}

			session->recorder = TRUE;
			session->recording = rec;

			session->rc = janus_hls_recorder_create(recordings_path, name_text, 60);

			session->sdp_version = 1;	/* This needs to be increased when it changes */
			session->sdp_sessid = janus_get_real_time();
			g_hash_table_insert(recordings, janus_uint64_dup(rec->id), rec);
			janus_mutex_unlock(&recordings_mutex);
			/* We need to prepare an answer */
recdone:
			answer = janus_sdp_generate_answer(offer,
				JANUS_SDP_OA_AUDIO, audio,
				JANUS_SDP_OA_AUDIO_CODEC, janus_audiocodec_name(rec->acodec),
				JANUS_SDP_OA_AUDIO_DIRECTION, JANUS_SDP_RECVONLY,
				JANUS_SDP_OA_VIDEO, video,
				JANUS_SDP_OA_VIDEO_CODEC, janus_videocodec_name(rec->vcodec),
				JANUS_SDP_OA_VIDEO_DIRECTION, JANUS_SDP_RECVONLY,
				JANUS_SDP_OA_DATA, FALSE,
				JANUS_SDP_OA_ACCEPT_EXTMAP, JANUS_RTP_EXTMAP_MID,
				JANUS_SDP_OA_ACCEPT_EXTMAP, JANUS_RTP_EXTMAP_RID,
				JANUS_SDP_OA_ACCEPT_EXTMAP, JANUS_RTP_EXTMAP_REPAIRED_RID,
				JANUS_SDP_OA_ACCEPT_EXTMAP, JANUS_RTP_EXTMAP_TRANSPORT_WIDE_CC,
				JANUS_SDP_OA_DONE
			);
			g_free(answer->s_name);
			char s_name[100];
			g_snprintf(s_name, sizeof(s_name), "Recording %"SCNu64, rec->id);
			answer->s_name = g_strdup(s_name);
			/* Let's overwrite a couple o= fields, in case this is a renegotiation */
			answer->o_sessid = session->sdp_sessid;
			answer->o_version = session->sdp_version;
			/* Generate the SDP string */
			sdp = janus_sdp_write(answer);
			janus_sdp_destroy(offer);
			janus_sdp_destroy(answer);
			JANUS_LOG(LOG_VERB, "Going to answer this SDP:\n%s\n", sdp);
			/* If the user negotiated simulcasting, prepare it accordingly */
			json_t *msg_simulcast = json_object_get(msg->jsep, "simulcast");
			if (msg_simulcast) {
				JANUS_LOG(LOG_VERB, "Recording client negotiated simulcasting\n");
				int rid_ext_id = -1;
				janus_rtp_simulcasting_prepare(msg_simulcast, &rid_ext_id, session->ssrc, session->rid);
				session->sim_context.rid_ext_id = rid_ext_id;
				session->sim_context.substream_target = 2;	/* Let's aim for the highest quality */
				session->sim_context.templayer_target = 2;	/* Let's aim for all temporal layers */
				if (rec->vcodec != JANUS_VIDEOCODEC_VP8 && rec->vcodec != JANUS_VIDEOCODEC_H264) {
					/* VP8 r H.264 were not negotiated, if simulcasting was enabled then disable it here */
					int i = 0;
					for (i = 0; i<3; i++) {
						session->ssrc[i] = 0;
						g_free(session->rid[i]);
						session->rid[i] = NULL;
					}
				}
			}
			/* Done! */
			result = json_object();
			json_object_set_new(result, "status", json_string("recording"));
			json_object_set_new(result, "id", json_integer(id));
			/* Also notify event handlers */
			if (!sdp_update && notify_events && gateway->events_is_enabled()) {
				json_t *info = json_object();
				json_object_set_new(info, "event", json_string("recording"));
				json_object_set_new(info, "id", json_integer(id));
				json_object_set_new(info, "audio", session->arc ? json_true() : json_false());
				json_object_set_new(info, "video", session->vrc ? json_true() : json_false());
				gateway->notify_event(&janus_hls_plugin, session->handle, info);
			}
		} else if (!strcasecmp(request_text, "stop")) {
			/* Done! */
			result = json_object();
			json_object_set_new(result, "status", json_string("stopped"));
			if (session->recording) {
				json_object_set_new(result, "id", json_integer(session->recording->id));
				/* Also notify event handlers */
				if (notify_events && gateway->events_is_enabled()) {
					json_t *info = json_object();
					json_object_set_new(info, "event", json_string("stopped"));
					if (session->recording) {
						json_object_set_new(info, "id", json_integer(session->recording->id));
					}
					gateway->notify_event(&janus_hls_plugin, session->handle, info);
				}
			}
			/* Tell the core to tear down the PeerConnection, hangup_media will do the rest */
			gateway->close_pc(session->handle);
		} else {
			JANUS_LOG(LOG_ERR, "Unknown request '%s'\n", request_text);
			error_code = JANUS_HLS_ERROR_INVALID_REQUEST;
			g_snprintf(error_cause, 512, "Unknown request '%s'", request_text);

			goto error;
		}

		/* Prepare JSON event */
		event = json_object();
		json_object_set_new(event, "hls", json_string("event"));
		if (result != NULL) {
			json_object_set_new(event, "result", result);
		}
		if (!sdp) {
			int ret = gateway->push_event(msg->handle, &janus_hls_plugin, msg->transaction, event, NULL);
			JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (%s)\n", ret, janus_get_api_error(ret));
			json_decref(event);
		} else {
			const char *type = session->recorder ? "answer" : "offer";
			json_t *jsep = json_pack("{ssss}", "type", type, "sdp", sdp);
			if (sdp_update) {
				json_object_set_new(jsep, "restart", json_true());
			}
			/* How long will the gateway take to push the event? */
			g_atomic_int_set(&session->hangingup, 0);
			gint64 start = janus_get_monotonic_time();
			int res = gateway->push_event(msg->handle, &janus_hls_plugin, msg->transaction, event, jsep);
			JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (took %"SCNu64" us)\n", res, janus_get_monotonic_time()-start);
			g_free(sdp);
			json_decref(event);
			json_decref(jsep);
		}
		janus_hls_message_free(msg);
		continue;

error:
		{
			/* Prepare JSON error event */
			json_t *event = json_object();
			json_object_set_new(event, "hls", json_string("event"));
			json_object_set_new(event, "error_code", json_integer(error_code));
			json_object_set_new(event, "error", json_string(error_cause));
			int ret = gateway->push_event(msg->handle, &janus_hls_plugin, msg->transaction, event, NULL);
			JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (%s)\n", ret, janus_get_api_error(ret));
			json_decref(event);
			janus_hls_message_free(msg);
		}
	}

	JANUS_LOG(LOG_VERB, "Leaving HLS handler thread\n");

	return NULL;
}
