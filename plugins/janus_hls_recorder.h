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

#include "../mutex.h"
#include "../refcount.h"

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
} janus_hls_recorder;


/*! \brief Create a new HLS recorder
 * \note If no target directory is provided, the current directory will be used. If no filename
 * is passed, a random filename will be used.
 * @param[in] dir Path of the directory to save the recording into (will try to create it if it doesn't exist)
 * @param[in] codec Codec the packets to record are encoded in ("vp8", "opus", "h264", "g711", "vp9")
 * @param[in] filename Filename to use for the recording
 * @returns A valid janus_hls_recorder instance in case of success, NULL otherwise */
janus_hls_recorder *janus_hls_recorder_create(const char *dir, const char *filename, const uint16_t segment_length);

/*! \brief Save an RTP frame in the recorder
 * @param[in] recorder The janus_hls_recorder instance to save the frame to
 * @param[in] buffer The frame data to save
 * @param[in] length The frame data length
 * @returns 0 in case of success, a negative integer otherwise */
int janus_hls_recorder_save_frame(janus_hls_recorder *recorder, char *buffer, uint length);

/*! \brief Close the recorder
 * @param[in] recorder The janus_hls_recorder instance to close
 * @returns 0 in case of success, a negative integer otherwise */
int janus_hls_recorder_close(janus_hls_recorder *recorder);

#endif