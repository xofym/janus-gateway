// We make use of this 'server' variable to provide the address of the
// REST Janus API. By default, in this example we assume that Janus is
// co-located with the web server hosting the HTML pages but listening
// on a different port (8088, the default for HTTP in Janus), which is
// why we make use of the 'window.location.hostname' base address. Since
// Janus can also do HTTPS, and considering we don't really want to make
// use of HTTP for Janus if your demos are served on HTTPS, we also rely
// on the 'window.location.protocol' prefix to build the variable, in
// particular to also change the port used to contact Janus (8088 for
// HTTP and 8089 for HTTPS, if enabled).
// In case you place Janus behind an Apache frontend (as we did on the
// online demos at http://janus.conf.meetecho.com) you can just use a
// relative path for the variable, e.g.:
//
// 		var server = "/janus";
//
// which will take care of this on its own.
//
//
// If you want to use the WebSockets frontend to Janus, instead, you'll
// have to pass a different kind of address, e.g.:
//
// 		var server = "ws://" + window.location.hostname + ":8188";
//
// Of course this assumes that support for WebSockets has been built in
// when compiling the server. WebSockets support has not been tested
// as much as the REST API, so handle with care!
//
//
// If you have multiple options available, and want to let the library
// autodetect the best way to contact your server (or pool of servers),
// you can also pass an array of servers, e.g., to provide alternative
// means of access (e.g., try WebSockets first and, if that fails, fall
// back to plain HTTP) or just have failover servers:
//
//		var server = [
//			"ws://" + window.location.hostname + ":8188",
//			"/janus"
//		];
//
// This will tell the library to try connecting to each of the servers
// in the presented order. The first working server will be used for
// the whole session.
//
var server = null;
if (window.location.protocol === 'http:') {
	server = "http://" + window.location.hostname + ":8088/janus";
} else {
	server = "https://" + window.location.hostname + ":8089/janus";
}

var janus = null;
var hls = null;
var opaqueId = "hlstest-"+Janus.randomString(12);

var spinner = null;
var bandwidth = 1024 * 1024;

var myname = null;
var recording = false;
var playing = false;
var recordingId = null;
var selectedRecording = null;
var selectedRecordingInfo = null;

var doSimulcast = (getQueryStringValue("simulcast") === "yes" || getQueryStringValue("simulcast") === "true");

$(document).ready(function() {
	// Initialize the library (all console debuggers enabled)
	Janus.init({debug: "all", callback: function() {
		// Use a button to start the demo
		$('#start').one('click', function() {
			$(this).attr('disabled', true).unbind('click');
			// Make sure the browser supports WebRTC
			if (!Janus.isWebrtcSupported()) {
				bootbox.alert("No WebRTC support... ");
				return;
			}

			// Create session
			janus = new Janus(
				{
					server: server,
					success: function() {
						// Attach to echo test plugin
						janus.attach(
							{
								plugin: "janus.plugin.hls",
								opaqueId: opaqueId,
								success: function(pluginHandle) {
									$('#details').remove();
									hls = pluginHandle;
									Janus.log("Plugin attached! (" + hls.getPlugin() + ", id=" + hls.getId() + ")");
									// Prepare the name prompt
									$('#hls').removeClass('hide').show();

									$('#record').removeAttr('disabled').click(startRecording);
								},
								error: function(error) {
									Janus.error("  -- Error attaching plugin...", error);
									bootbox.alert("  -- Error attaching plugin... " + error);
								},
								consentDialog: function(on) {
									Janus.debug("Consent dialog should be " + (on ? "on" : "off") + " now");
									if (on) {
										// Darken screen and show hint
										$.blockUI({
											message: '<div><img src="up_arrow.png"/></div>',
											css: {
												border: 'none',
												padding: '15px',
												backgroundColor: 'transparent',
												color: '#aaa',
												top: '10px',
												left: (navigator.mozGetUserMedia ? '-100px' : '300px')
											}
										});
									} else {
										// Restore screen
										$.unblockUI();
									}
								},
								webrtcState: function(on) {
									Janus.log("Janus says our WebRTC PeerConnection is " + (on ? "up" : "down") + " now");
									$("#videobox").parent().unblock();
								},
								onmessage: function(msg, jsep) {
									Janus.debug(" ::: Got a message :::");
									Janus.debug(msg);
									var result = msg["result"];
									if (result !== null && result !== undefined) {
										if (result["status"] !== undefined && result["status"] !== null) {
											var event = result["status"];
											if (event === 'preparing' || event === 'refreshing') {
												Janus.log("Preparing the recording playout");
												hls.createAnswer(
													{
														jsep: jsep,
														media: { audioSend: false, videoSend: false },	// We want recvonly audio/video
														success: function(jsep) {
															Janus.debug("Got SDP!");
															Janus.debug(jsep);
															var body = { "request": "start" };
															hls.send({"message": body, "jsep": jsep});
														},
														error: function(error) {
															Janus.error("WebRTC error:", error);
															bootbox.alert("WebRTC error... " + JSON.stringify(error));
														}
													});
												if (result["warning"]) {
													bootbox.alert(result["warning"]);
												}
											} else if (event === 'recording') {
												// Got an ANSWER to our recording OFFER
												if (jsep !== null && jsep !== undefined) {
													hls.handleRemoteJsep({jsep: jsep});
												}

												var id = result["id"];
												if (id !== null && id !== undefined) {
													Janus.log("The ID of the current recording is " + id);
													recordingId = id;
												}
											} else if (event === 'slow_link') {
												var uplink = result["uplink"];
												if (uplink !== 0) {
													// Janus detected issues when receiving our media, let's slow down
													bandwidth = parseInt(bandwidth / 1.5);
													hls.send({
														'message': {
															'request': 'configure',
															'video-bitrate-max': bandwidth, // Reduce the bitrate
															'video-keyframe-interval': 15000 // Keep the 15 seconds key frame interval
														}
													});
												}
											} else if (event === 'stopped') {
												Janus.log("Session has stopped!");
												var id = result["id"];
												if (recordingId !== null && recordingId !== undefined) {
													if (recordingId !== id) {
														Janus.warn("Not a stop to our recording?");
														return;
													}
													//bootbox.alert("Recording completed! Check the list of recordings to replay it.");
												}
												if (selectedRecording !== null && selectedRecording !== undefined) {
													if (selectedRecording !== id) {
														Janus.warn("Not a stop to our playout?");
														return;
													}
												}
												// FIXME Reset status
												$('#videobox').empty();
												$('#video').hide();
												recordingId = null;
												recording = false;
												playing = false;
												hls.hangup();
												$('#record').removeAttr('disabled').click(startRecording);
											}
										}
									} else {
										// FIXME Error?
										var error = msg["error"];
										bootbox.alert(error);
										// FIXME Reset status
										$('#videobox').empty();
										$('#video').hide();
										recording = false;
										playing = false;
										hls.hangup();
										$('#record').removeAttr('disabled').click(startRecording);
									}
								},
								onlocalstream: function(stream) {
									if (playing === true)
										return;
									Janus.debug(" ::: Got a local stream :::");
									Janus.debug(stream);
									$('#videotitle').html("Recording...");
									$('#stop').unbind('click').click(stop);
									$('#video').removeClass('hide').show();
									if ($('#thevideo').length === 0)
										$('#videobox').append('<video class="rounded centered" id="thevideo" width=320 height=240 autoplay playsinline muted="muted"/>');
									Janus.attachMediaStream($('#thevideo').get(0), stream);
									$("#thevideo").get(0).muted = "muted";
									if (hls.webrtcStuff.pc.iceConnectionState !== "completed" &&
											hls.webrtcStuff.pc.iceConnectionState !== "connected") {
										$("#videobox").parent().block({
											message: '<b>Publishing...</b>',
											css: {
												border: 'none',
												backgroundColor: 'transparent',
												color: 'white'
											}
										});
									}
									var videoTracks = stream.getVideoTracks();
									if (videoTracks === null || videoTracks === undefined || videoTracks.length === 0) {
										// No remote video
										$('#thevideo').hide();
										if ($('#videobox .no-video-container').length === 0) {
											$('#videobox').append(
												'<div class="no-video-container">' +
													'<i class="fa fa-video-camera fa-5 no-video-icon"></i>' +
													'<span class="no-video-text">No remote video available</span>' +
												'</div>');
										}
									} else {
										$('#videobox .no-video-container').remove();
										$('#thevideo').removeClass('hide').show();
									}
								},
								onremotestream: function(stream) {
									if (playing === false)
										return;
									Janus.debug(" ::: Got a remote stream :::");
									Janus.debug(stream);
									if ($('#thevideo').length === 0) {
										$('#videotitle').html(selectedRecordingInfo);
										$('#stop').unbind('click').click(stop);
										$('#video').removeClass('hide').show();
										$('#videobox').append('<video class="rounded centered hide" id="thevideo" width=320 height=240 autoplay playsinline/>');
										// No remote video yet
										$('#videobox').append('<video class="rounded centered" id="waitingvideo" width=320 height=240 />');
										if (spinner == null) {
											var target = document.getElementById('videobox');
											spinner = new Spinner({top:100}).spin(target);
										} else {
											spinner.spin();
										}
										// Show the video, hide the spinner and show the resolution when we get a playing event
										$("#thevideo").bind("playing", function () {
											$('#waitingvideo').remove();
											$('#thevideo').removeClass('hide');
											if (spinner !== null && spinner !== undefined)
												spinner.stop();
											spinner = null;
										});
									}
									Janus.attachMediaStream($('#thevideo').get(0), stream);
									var videoTracks = stream.getVideoTracks();
									if (videoTracks === null || videoTracks === undefined || videoTracks.length === 0) {
										// No remote video
										$('#thevideo').hide();
										if ($('#videobox .no-video-container').length === 0) {
											$('#videobox').append(
												'<div class="no-video-container">' +
													'<i class="fa fa-video-camera fa-5 no-video-icon"></i>' +
													'<span class="no-video-text">No remote video available</span>' +
												'</div>');
										}
									} else {
										$('#videobox .no-video-container').remove();
										$('#thevideo').removeClass('hide').show();
									}
								},
								oncleanup: function() {
									Janus.log(" ::: Got a cleanup notification :::");
									// FIXME Reset status
									$('#waitingvideo').remove();
									if (spinner !== null && spinner !== undefined)
										spinner.stop();
									spinner = null;
									$('#videobox').empty();
									$("#videobox").parent().unblock();
									$('#video').hide();
									recording = false;
									playing = false;
									$('#record').removeAttr('disabled').click(startRecording);
								}
							});
					},
					error: function(error) {
						Janus.error(error);
						bootbox.alert(error, function() {
							window.location.reload();
						});
					},
					destroyed: function() {
						window.location.reload();
					}
				});
		});
	}});
});

function startRecording() {
	if (recording) {
		return;
	}
	// Start a recording
	recording = true;
	playing = false;
	bootbox.prompt("Insert a name for the recording (e.g., John Smith says hello)", function(result) {
		if (result === null || result === undefined) {
			recording = false;
			return;
		}
		myname = result;
		$('#record').unbind('click').attr('disabled', true);

		// bitrate and keyframe interval can be set at any time:
		// before, after, during recording
		hls.send({
			'message': {
				'request': 'configure',
				'video-bitrate-max': bandwidth, // a quarter megabit
				'video-keyframe-interval': 15000 // 15 seconds
			}
		});

		hls.createOffer(
			{
				// By default, it's sendrecv for audio and video... no datachannels
				// If you want to test simulcasting (Chrome and Firefox only), then
				// pass a ?simulcast=true when opening this demo page: it will turn
				// the following 'simulcast' property to pass to janus.js to true
				simulcast: doSimulcast,
				success: function(jsep) {
					Janus.debug("Got SDP!");
					Janus.debug(jsep);
					var body = { "request": "record", "name": myname };
					hls.send({"message": body, "jsep": jsep});
				},
				error: function(error) {
					Janus.error("WebRTC error...", error);
					bootbox.alert("WebRTC error... " + error);
					hls.hangup();
				}
			});
	});
}

function stop() {
	// Stop a recording/playout
	$('#stop').unbind('click');
	var stop = { "request": "stop" };

	hls.send({"message": stop});
	hls.hangup();
}

// Helper to parse query string
function getQueryStringValue(name) {
	name = name.replace(/[\[]/, "\\[").replace(/[\]]/, "\\]");

	var regex = new RegExp("[\\?&]" + name + "=([^&#]*)"),
		results = regex.exec(location.search);

	return results === null ? "" : decodeURIComponent(results[1].replace(/\+/g, " "));
}
