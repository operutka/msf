# Media Streaming Framework

This repository is a collection of Rust libraries for multimedia streaming
applications. The intention is to implement basic protocols such as RTP, STUN,
SDP and others to allow construction of more complex, high-level protocols like
WebRTC, SIP, RTSP, etc.

The main focus here is to implement these protocols with minimum external
dependencies in order to minimize footprint of the resulting binaries as it is
often the case that these protocols need to be implemented in memory-restricted
devices such as IP cameras and set-top boxes. For the same reason, we should
also allow removing unnecessary functionality using crate features.

The whole project is in early stage of development, so expect missing or
incomplete features. Pull requests are welcome.
