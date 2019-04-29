/*! \file   janus_hls_recorder.c
 * \author Axel Etcheverry <axel.etcheverry@getmyfox.com>
 * \copyright GNU General Public License v3
 * \brief  Janus HLS recorder
 *
 * \ingroup hlsapi
 * \ref hlsapi
 */


#include <arpa/inet.h>
#include <sys/stat.h>
#include <errno.h>
#include <libgen.h>

#include <glib.h>
#include <jansson.h>

#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>

#include "janus_hls_recorder.h"

#include "../debug.h"
#include "../utils.h"

static void janus_hls_recorder_free(const janus_refcount *recorder_ref) {
	janus_hls_recorder *recorder = janus_refcount_containerof(recorder_ref, janus_hls_recorder, ref);
	/* This recorder can be destroyed, free all the resources */
	janus_hls_recorder_close(recorder);

	g_free(recorder->dir);
	recorder->dir = NULL;

	g_free(recorder->filename);
	recorder->filename = NULL;

	g_free(recorder);
}

janus_hls_recorder *janus_hls_recorder_create(const char *dir, const char *filename, const uint16_t segment_length) {
	/* Create the recorder */
	janus_hls_recorder *rc = g_malloc0(sizeof(janus_hls_recorder));
	rc->dir = NULL;
	rc->filename = NULL;

	const char *rec_dir = NULL;
	const char *rec_file = NULL;
	char *copy_for_parent = NULL;
	char *copy_for_base = NULL;

	/* Check dir and filename values */
	if (filename != NULL) {
		/* Helper copies to avoid overwriting */
		copy_for_parent = g_strdup(filename);
		copy_for_base = g_strdup(filename);
		/* Get filename parent folder */
		const char *filename_parent = dirname(copy_for_parent);
		/* Get filename base file */
		const char *filename_base = basename(copy_for_base);
		if (!dir) {
			/* If dir is NULL we have to create filename_parent and filename_base */
			rec_dir = filename_parent;
			rec_file = filename_base;
		} else {
			/* If dir is valid we have to create dir and filename*/
			rec_dir = dir;
			rec_file = filename;

			if (strcasecmp(filename_parent, ".") || strcasecmp(filename_base, filename)) {
				JANUS_LOG(LOG_WARN, "Unsupported combination of dir and filename %s %s\n", dir, filename);
			}
		}
	}

	if (rec_dir != NULL) {
		/* Check if this directory exists, and create it if needed */
		struct stat s;
		int err = stat(rec_dir, &s);

		if (err == -1) {
			if (ENOENT == errno) {
				/* Directory does not exist, try creating it */
				if (janus_mkdir(rec_dir, 0755) < 0) {
					JANUS_LOG(LOG_ERR, "mkdir error: %d\n", errno);
					return NULL;
				}
			} else {
				JANUS_LOG(LOG_ERR, "stat error: %d\n", errno);
				return NULL;
			}
		} else {
			if (S_ISDIR(s.st_mode)) {
				/* Directory exists */
				JANUS_LOG(LOG_VERB, "Directory exists: %s\n", rec_dir);
			} else {
				/* File exists but it's not a directory? */
				JANUS_LOG(LOG_ERR, "Not a directory? %s\n", rec_dir);
				return NULL;
			}
		}
	}

	if (rec_dir) {
		rc->dir = g_strdup(rec_dir);
	}

	if (rec_file) {
		rc->filename = g_strdup(rec_file);
	}

	janus_mutex_init(&rc->mutex);
	g_atomic_int_set(&rc->destroyed, 0);

	janus_refcount_init(&rc->ref, janus_hls_recorder_free);

	g_free(copy_for_parent);
	g_free(copy_for_base);

	return rc;
}

int janus_hls_recorder_save_frame(janus_hls_recorder *recorder, char *buffer, uint length) {
	if (!recorder) {
		return -1;
	}

	janus_mutex_lock_nodebug(&recorder->mutex);

	if (!buffer || length < 1) {
		janus_mutex_unlock_nodebug(&recorder->mutex);

		return -2;
	}

	/* Done */
	janus_mutex_unlock_nodebug(&recorder->mutex);

	return 0;
}

int janus_hls_recorder_close(janus_hls_recorder *recorder) {
	janus_mutex_lock_nodebug(&recorder->mutex);

	janus_mutex_unlock_nodebug(&recorder->mutex);

	return 0;
}