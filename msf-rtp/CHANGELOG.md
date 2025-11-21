# Changelog

## v0.4.0 (2025-11-21)

* Add Opus packetizer and depacketizer
* Add H.264 depacketizer
* Add detailed error messages

## v0.3.0 (2025-11-06)

* Add RTP and RTCP channels for automatic frame decoding/encoding
* Add a more advanced reordering buffer implementation for dealing with
  multiple SSRCs in a single channel
* Add support for SDES RTCP packet encoding
* Add RTP statistics collectors and RTCP context for RTP-RTCP interaction
* Add RTP transceiver abstraction for connecting RTP and RTCP channels
* Update the RTCP handler to use the new RTP transceiver abstraction
* Make the maximum packet size for the H.264 packetizer configurable
* Remove unnecessary Unpin requirements

## v0.2.1 (2025-07-23)

* Fix unaligned reads

## v0.2.0 (2022-05-02)

* Add automatic RTCP handler (the current version does not do anything)
* Add RTP (de)packetizer abstractions
* Add PCM depacketizer
* Add H.264 packetizer
* Update msf-sdp dependency

## v0.1.0 (2022-04-01)

* Initial release
