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

#include "janus_hls_recorder.h"

#include "../debug.h"
#include "../utils.h"

static int max_width = 0, max_height = 0, fps = 0;

void janus_hls_recorder_init() {
	/* Setup FFmpeg */
	av_register_all();

	/* Adjust logging to match the hls recorder */
	av_log_set_level(janus_log_level <= LOG_NONE ? AV_LOG_QUIET :
		(janus_log_level == LOG_FATAL ? AV_LOG_FATAL :
			(janus_log_level == LOG_ERR ? AV_LOG_ERROR :
				(janus_log_level == LOG_WARN ? AV_LOG_WARNING :
					(janus_log_level == LOG_INFO ? AV_LOG_INFO :
						(janus_log_level == LOG_VERB ? AV_LOG_VERBOSE : AV_LOG_DEBUG))))));
}


static void janus_hls_recorder_free(const janus_refcount *recorder_ref) {
	janus_hls_recorder *recorder = janus_refcount_containerof(recorder_ref, janus_hls_recorder, ref);
	/* This recorder can be destroyed, free all the resources */
	janus_hls_recorder_destroy(recorder);

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

	janus_hls_recorder_create_chunk(rc);

	return rc;
}

void janus_hls_recorder_close_chunk(janus_hls_recorder *recorder) {
	if (!recorder) {
		return;
	}

#ifdef USE_CODECPAR
	if (recorder->vEncoder != NULL) {
		avcodec_close(recorder->vEncoder);
	}
#else
	if (recorder->vStream != NULL && recorder->vStream->codec != NULL) {
		avcodec_close(recorder->vStream->codec);
	}
#endif

	if (recorder->aStream != NULL && recorder->aStream->codec != NULL) {
		avcodec_close(recorder->aStream->codec);
	}

	if (recorder->fctx == NULL) {
		return;
	}

	av_write_trailer(recorder->fctx);

	if (recorder->fctx->streams[0] != NULL) {
#ifndef USE_CODECPAR
		av_free(recorder->fctx->streams[0]->codec);
#endif
		av_free(recorder->fctx->streams[0]);
	}

	avio_flush(recorder->fctx->pb);
	avio_close(recorder->fctx->pb);
	av_free(recorder->fctx);
}

int janus_hls_recorder_create_chunk(janus_hls_recorder *recorder) {
	if (!recorder) {
		return -1;
	}

	janus_mutex_lock_nodebug(&recorder->mutex);

	// close previous chunk
	janus_hls_recorder_close_chunk(recorder);

	/* MP4 output */
	recorder->fctx = avformat_alloc_context();
	if (recorder->fctx == NULL) {
		JANUS_LOG(LOG_ERR, "Error allocating context\n");

		janus_mutex_unlock_nodebug(&recorder->mutex);

		return -1;
	}

	recorder->fctx->oformat = av_guess_format("mpegts", NULL, NULL);
	if (recorder->fctx->oformat == NULL) {
		JANUS_LOG(LOG_ERR, "Error guessing format\n");

		janus_mutex_unlock_nodebug(&recorder->mutex);

		return -1;
	}

	gint64 now = janus_get_real_time();

	snprintf(
		recorder->fctx->filename,
		sizeof(recorder->fctx->filename),
		"%s/%s-%d.ts",
		recorder->dir,
		recorder->filename,
		now
	);

#ifdef USE_CODECPAR
	AVCodec *codec = avcodec_find_encoder(AV_CODEC_ID_H264);
	if (!codec) {
		/* Error opening video codec */
		JANUS_LOG(LOG_ERR, "Encoder not available\n");

		janus_mutex_unlock_nodebug(&recorder->mutex);

		return -1;
	}

	recorder->fctx->video_codec = codec;
	recorder->fctx->oformat->video_codec = codec->id;
	recorder->vStream = avformat_new_stream(recorder->fctx, codec);
	recorder->vStream->id = recorder->fctx->nb_streams-1;
	recorder->vEncoder = avcodec_alloc_context3(codec);
	recorder->vEncoder->width = max_width;
	recorder->vEncoder->height = max_height;
	recorder->vEncoder->time_base = (AVRational){ 1, fps };
	recorder->vEncoder->pix_fmt = AV_PIX_FMT_YUV420P;
	recorder->vEncoder->flags |= CODEC_FLAG_GLOBAL_HEADER;
	if (avcodec_open2(recorder->vEncoder, codec, NULL) < 0) {
		/* Error opening video codec */
		JANUS_LOG(LOG_ERR, "Encoder error\n");

		janus_mutex_unlock_nodebug(&recorder->mutex);

		return -1;
	}

	avcodec_parameters_from_context(recorder->vStream->codecpar, recorder->vEncoder);
#else
	recorder->vStream = avformat_new_stream(recorder->fctx, 0);
	if (recorder->vStream == NULL) {
		JANUS_LOG(LOG_ERR, "Error adding stream\n");

		janus_mutex_unlock_nodebug(&recorder->mutex);

		return -1;
	}

#if LIBAVCODEC_VER_AT_LEAST(53, 21)
	avcodec_get_context_defaults3(recorder->vStream->codec, AVMEDIA_TYPE_VIDEO);
#else
	avcodec_get_context_defaults2(recorder->vStream->codec, AVMEDIA_TYPE_VIDEO);
#endif

#if LIBAVCODEC_VER_AT_LEAST(54, 25)
	recorder->vStream->codec->codec_id = AV_CODEC_ID_H264;
#else
	recorder->vStream->codec->codec_id = CODEC_ID_H264;
#endif
	recorder->vStream->codec->codec_type = AVMEDIA_TYPE_VIDEO;
	recorder->vStream->codec->time_base = (AVRational){1, fps};
	recorder->vStream->time_base = (AVRational){1, 90000};
	recorder->vStream->codec->width = max_width;
	recorder->vStream->codec->height = max_height;
	recorder->vStream->codec->pix_fmt = PIX_FMT_YUV420P;
	//~ if (fctx->flags & AVFMT_GLOBALHEADER)
		recorder->vStream->codec->flags |= CODEC_FLAG_GLOBAL_HEADER;
#endif

	if (avio_open(&recorder->fctx->pb, recorder->fctx->filename, AVIO_FLAG_WRITE) < 0) {
		JANUS_LOG(LOG_ERR, "Error opening file for output\n");

		janus_mutex_unlock_nodebug(&recorder->mutex);

		return -1;
	}

	if (avformat_write_header(recorder->fctx, NULL) < 0) {
		JANUS_LOG(LOG_ERR, "Could not write mpegts header to first output file.\n");

		janus_mutex_unlock_nodebug(&recorder->mutex);

		return -1;
	}

	JANUS_LOG(LOG_DBG, "Starting segment '%s'", recorder->fctx->filename);


	/* Done */
	janus_mutex_unlock_nodebug(&recorder->mutex);

	return 0;
}

int janus_hls_recorder_save_frame(janus_hls_recorder *recorder, janus_hls_frame *frame) {
	if (!recorder) {
		return -1;
	}

	AVPacket *packet = g_malloc(sizeof(AVPacket));
	av_init_packet(packet);
	av_packet_from_data(packet, frame->buffer, frame->len);

	janus_mutex_lock_nodebug(&recorder->mutex);

	if (!frame->buffer || frame->len < 1) {
		janus_mutex_unlock_nodebug(&recorder->mutex);

		return -2;
	}

	int ret = av_write_frame(recorder->fctx, packet);
	if (ret < 0) {
		JANUS_LOG(LOG_ERR, "Warning: Could not write frame of stream.");
	} else if (ret > 0) {
		JANUS_LOG(LOG_ERR, "End of stream requested.");
		av_packet_unref(packet);

		return -3;
	}

	av_packet_unref(packet);

	/* Done */
	janus_mutex_unlock_nodebug(&recorder->mutex);

	return 0;
}

int janus_hls_recorder_destroy(janus_hls_recorder *recorder) {
	janus_mutex_lock_nodebug(&recorder->mutex);

	janus_hls_recorder_close_chunk(recorder);

	janus_mutex_unlock_nodebug(&recorder->mutex);

	return 0;
}