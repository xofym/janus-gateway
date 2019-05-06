/*! \file   janus_hls_recorder.h
 * \author Axel Etcheverry <axel.etcheverry@getmyfox.com>
 * \copyright GNU General Public License v3
 * \brief  Janus HLS recorder definition (headers)
 *
 * \ingroup hlsapi
 * \ref hlsapi
 */

#ifndef _JANUS_HLS_RECORDER_H
#define _JANUS_HLS_RECORDER_H

#include <inttypes.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>

#include "../mutex.h"
#include "../refcount.h"


#define LIBAVCODEC_VER_AT_LEAST(major, minor) \
	(LIBAVCODEC_VERSION_MAJOR > major || \
	 (LIBAVCODEC_VERSION_MAJOR == major && \
	  LIBAVCODEC_VERSION_MINOR >= minor))

#if LIBAVCODEC_VER_AT_LEAST(51, 42)
#define PIX_FMT_YUV420P AV_PIX_FMT_YUV420P
#endif

#if LIBAVCODEC_VER_AT_LEAST(56, 56)
#ifndef CODEC_FLAG_GLOBAL_HEADER
#define CODEC_FLAG_GLOBAL_HEADER AV_CODEC_FLAG_GLOBAL_HEADER
#endif
#ifndef FF_INPUT_BUFFER_PADDING_SIZE
#define FF_INPUT_BUFFER_PADDING_SIZE AV_INPUT_BUFFER_PADDING_SIZE
#endif
#endif

#if LIBAVCODEC_VER_AT_LEAST(57, 14)
#define USE_CODECPAR
#endif

/*! \brief Structure that represents a HLS recorder */
typedef struct janus_hls_recorder {
	/*! \brief Absolute path to the directory where the recorder file is stored */
	char *dir;
	/*! \brief Filename of this recorder file */
	char *filename;
	/*! \brief Segment length */
	uint16_t segment_length;
	/*! \brief Mutex to lock/unlock this recorder instance */
	janus_mutex mutex;
	/*! \brief Atomic flag to check if this instance has been destroyed */
	volatile gint destroyed;
	/*! \brief Reference counter for this instance */
	janus_refcount ref;

	AVFormatContext *fctx;
	AVStream *vStream;
	AVStream *aStream;

#ifdef USE_CODECPAR
	AVCodecContext *vEncoder;
#endif

} janus_hls_recorder;

typedef enum AVMediaType AVMediaType;

typedef struct janus_hls_frame {
	AVMediaType type;
	char *buffer;
	int len;
} janus_hls_frame;

void janus_hls_recorder_init();

/*! \brief Create a new HLS recorder
 * \note If no target directory is provided, the current directory will be used. If no filename
 * is passed, a random filename will be used.
 * @param[in] dir Path of the directory to save the recording into (will try to create it if it doesn't exist)
 * @param[in] codec Codec the packets to record are encoded in ("vp8", "opus", "h264", "g711", "vp9")
 * @param[in] filename Filename to use for the recording
 * @returns A valid janus_hls_recorder instance in case of success, NULL otherwise */
janus_hls_recorder *janus_hls_recorder_create(const char *dir, const char *filename, const uint16_t segment_length);

int janus_hls_recorder_create_chunk(janus_hls_recorder *recorder);

void janus_hls_recorder_close_chunk(janus_hls_recorder *recorder);

/*! \brief Save an RTP frame in the recorder
 * @param[in] recorder The janus_hls_recorder instance to save the frame to
 * @param[in] buffer The frame data to save
 * @param[in] length The frame data length
 * @returns 0 in case of success, a negative integer otherwise */
int janus_hls_recorder_save_frame(janus_hls_recorder *recorder, janus_hls_frame *frame);

/*! \brief Close the recorder
 * @param[in] recorder The janus_hls_recorder instance to close
 * @returns 0 in case of success, a negative integer otherwise */
int janus_hls_recorder_destroy(janus_hls_recorder *recorder);

#endif