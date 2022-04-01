use std::collections::VecDeque;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use msf_rtp::{
    utils::{ReorderingBuffer, ReorderingError},
    CompoundRtcpPacket, InvalidInput, PacketMux, RtcpPacketType, RtpHeader, RtpPacket,
};
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Private},
    sign::Signer,
    ssl::SslRef,
};

use crate::{
    key_stream::{KeyStream, AES128CM},
    profile::{SrtpProfile, SrtpProfileId},
    Error, InternalError,
};

/// Packet decoding error.
pub enum DecodingError {
    InvalidInput,
    DuplicatePacket,
    Other(Error),
}

impl From<InvalidInput> for DecodingError {
    fn from(_: InvalidInput) -> Self {
        Self::InvalidInput
    }
}

impl From<Error> for DecodingError {
    fn from(err: Error) -> Self {
        Self::Other(err)
    }
}

/// SRTP agent role.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum AgentRole {
    Client,
    Server,
}

/// SRTP session.
pub struct SrtpSession {
    profile: SrtpProfile,
    master_key: MasterKeyPair,

    receiver_rtp_keys: SessionKeys,
    receiver_rtcp_keys: SessionKeys,
    sender_rtp_keys: SessionKeys,
    sender_rtcp_keys: SessionKeys,

    input_buffer: VecDeque<PacketMux>,
    input_rtp_buffer: ReorderingBuffer,
    input_rtcp_window: ReplayList,
    output_rtp_index: u64,
    output_rtcp_index: u32,
}

impl SrtpSession {
    /// Create a new SRTP client session.
    pub fn client(ssl: &SslRef) -> Result<Self, Error> {
        Self::new(AgentRole::Client, ssl)
    }

    /// Create a new SRTP server session.
    pub fn server(ssl: &SslRef) -> Result<Self, Error> {
        Self::new(AgentRole::Server, ssl)
    }

    /// Create a new SRTP session.
    fn new(agent_role: AgentRole, ssl: &SslRef) -> Result<Self, Error> {
        let profile = ssl
            .selected_srtp_profile()
            .ok_or(InternalError::MissingProfile)?;

        let profile = SrtpProfile::from_openssl(profile.id())?;

        let master_key = MasterKeyPair::from_ssl(agent_role, profile, ssl)?;

        let res = Self {
            profile,
            master_key,

            receiver_rtp_keys: SessionKeys::new(),
            receiver_rtcp_keys: SessionKeys::new(),
            sender_rtp_keys: SessionKeys::new(),
            sender_rtcp_keys: SessionKeys::new(),

            input_buffer: VecDeque::new(),
            input_rtp_buffer: ReorderingBuffer::new(64),
            input_rtcp_window: ReplayList::new(),
            output_rtp_index: 0,
            output_rtcp_index: 0,
        };

        Ok(res)
    }

    /// Decode a given frame and push the resulting packet (if any) into the
    /// internal reordering buffer.
    pub fn decode(&mut self, frame: Bytes) -> Result<(), DecodingError> {
        if frame.len() < 2 {
            return Err(DecodingError::InvalidInput);
        }

        let pt = frame[1];

        if pt == 200 || pt == 201 {
            self.decode_rtcp_packet(frame)
        } else {
            self.decode_rtp_packet(frame)
        }
    }

    /// Take the next available packet from the internal reordering buffer.
    pub fn next(&mut self) -> Option<PacketMux> {
        self.input_buffer.pop_front()
    }

    /// Decode an RTP packet from a given frame.
    fn decode_rtp_packet(&mut self, mut frame: Bytes) -> Result<(), DecodingError> {
        let auth_tag_len = (self.profile.rtp_auth_tag_len() >> 3) as usize;

        let frame_len = frame.len();

        if frame_len < auth_tag_len {
            return Err(DecodingError::InvalidInput);
        }

        let auth_tag = frame.split_off(frame_len - auth_tag_len);
        let auth_data = frame.clone();

        let header = RtpHeader::decode(&mut frame)?;

        let index = self
            .input_rtp_buffer
            .estimate_index(header.sequence_number());

        if self.input_rtp_buffer.is_duplicate(index) {
            return Err(DecodingError::DuplicatePacket);
        }

        let session_key = self.get_receiver_rtp_key(index)?;

        if auth_tag != session_key.authenticate_rtp_packet((index >> 16) as u32, &auth_data)? {
            return Err(DecodingError::InvalidInput);
        }

        let mut payload = BytesMut::new();

        payload.resize(frame.len(), 0);

        session_key.decrypt_rtp_payload(header.ssrc(), index, &frame, &mut payload)?;

        let mut packet = RtpPacket::from_parts(header, payload.freeze())?;

        while let Err(ReorderingError::BufferFull(tmp)) = self.input_rtp_buffer.push(packet) {
            if let Some(p) = self.input_rtp_buffer.take() {
                self.input_buffer.push_back(p.into());
            }

            packet = tmp;
        }

        while let Some(p) = self.input_rtp_buffer.next() {
            self.input_buffer.push_back(p.into());
        }

        Ok(())
    }

    /// Decode an RTCP packet from a given frame.
    fn decode_rtcp_packet(&mut self, mut frame: Bytes) -> Result<(), DecodingError> {
        let auth_tag_len = (self.profile.rtcp_auth_tag_len() >> 3) as usize;

        let frame_len = frame.len();

        if frame_len < (auth_tag_len + 12) {
            return Err(DecodingError::InvalidInput);
        }

        let auth_tag = frame.split_off(frame_len - auth_tag_len);
        let auth_data = frame.clone();

        let mut trailer = frame.split_off(frame.len() - 4);

        let e_index = trailer.get_u32();

        let index = e_index & ((1 << 31) - 1);

        if self.input_rtcp_window.is_duplicate(index) {
            return Err(DecodingError::DuplicatePacket);
        }

        let session_key = self.get_receiver_rtcp_key(index)?;

        if auth_tag != session_key.authenticate_rtcp_packet(&auth_data)? {
            return Err(DecodingError::InvalidInput);
        }

        let packet = if (e_index >> 31) == 1 {
            let mut tmp = BytesMut::with_capacity(frame.len());

            tmp.extend_from_slice(&frame[..8]);
            tmp.resize(frame.len(), 0);

            let mut ssrc = frame.slice(4..8);

            session_key.decrypt_rtcp_payload(ssrc.get_u32(), index, &frame[8..], &mut tmp[8..])?;

            CompoundRtcpPacket::decode(tmp.freeze())?
        } else {
            CompoundRtcpPacket::decode(frame)?
        };

        self.input_rtcp_window.update(index);
        self.input_buffer.push_back(packet.into());

        Ok(())
    }

    /// Encode a given RTP packet.
    pub fn encode_rtp_packet(&mut self, packet: RtpPacket) -> Result<Bytes, Error> {
        let index = self.output_rtp_index;

        self.output_rtp_index = self.output_rtp_index.wrapping_add(1);

        let header = packet.header().clone().with_sequence_number(index as u16);

        let payload = packet.payload();

        let len =
            header.raw_size() + payload.len() + (self.profile.rtp_auth_tag_len() >> 3) as usize;

        let mut buffer = BytesMut::with_capacity(len);

        header.encode(&mut buffer);

        let payload_offset = buffer.len();

        buffer.resize(payload_offset + payload.len(), 0);

        let session_key = self.get_sender_rtp_key(index)?;

        session_key.encrypt_rtp_payload(
            header.ssrc(),
            index,
            payload,
            &mut buffer[payload_offset..],
        )?;

        let auth_tag = session_key.authenticate_rtp_packet((index >> 16) as u32, &buffer)?;

        buffer.extend_from_slice(auth_tag);

        Ok(buffer.freeze())
    }

    /// Encode a given RTCP packet.
    pub fn encode_rtcp_packet(&mut self, packet: CompoundRtcpPacket) -> Result<Bytes, Error> {
        let pt = packet.first().unwrap().packet_type();

        debug_assert!(matches!(pt, RtcpPacketType::SR | RtcpPacketType::RR));

        let index = self.output_rtcp_index & ((1 << 31) - 1);

        self.output_rtcp_index = self.output_rtcp_index.wrapping_add(1);

        let mut tmp = BytesMut::new();

        packet.encode(&mut tmp);

        let tmp = tmp.freeze();

        let len = 4 + tmp.len() + (self.profile.rtcp_auth_tag_len() >> 3) as usize;

        let mut buffer = BytesMut::with_capacity(len);

        buffer.extend_from_slice(&tmp[..8]);
        buffer.resize(tmp.len(), 0);

        let mut ssrc = tmp.slice(4..8);

        let session_key = self.get_sender_rtcp_key(index)?;

        let e_index =
            session_key.encrypt_rtcp_payload(ssrc.get_u32(), index, &tmp[8..], &mut buffer[8..])?;

        buffer.put_u32(e_index);

        let auth_tag = session_key.authenticate_rtcp_packet(&buffer)?;

        buffer.extend_from_slice(auth_tag);

        Ok(buffer.freeze())
    }

    /// Get receiver RTP session key for a given packet index.
    fn get_receiver_rtp_key(&mut self, packet_index: u64) -> Result<&mut SessionKey, Error> {
        self.receiver_rtp_keys.get_or_create(packet_index, |idx| {
            self.master_key.derive_receiver_srtp_key(idx)
        })
    }

    /// Get receiver RTCP session key for a given packet index.
    fn get_receiver_rtcp_key(&mut self, packet_index: u32) -> Result<&mut SessionKey, Error> {
        self.receiver_rtcp_keys
            .get_or_create(packet_index as u64, |idx| {
                self.master_key.derive_receiver_srtcp_key(idx)
            })
    }

    /// Get sender RTP session key for a given packet index.
    fn get_sender_rtp_key(&mut self, packet_index: u64) -> Result<&mut SessionKey, Error> {
        self.sender_rtp_keys.get_or_create(packet_index, |idx| {
            self.master_key.derive_sender_srtp_key(idx)
        })
    }

    /// Get sender RTCP session key for a given packet index.
    fn get_sender_rtcp_key(&mut self, packet_index: u32) -> Result<&mut SessionKey, Error> {
        self.sender_rtcp_keys
            .get_or_create(packet_index as u64, |idx| {
                self.master_key.derive_sender_srtcp_key(idx)
            })
    }
}

/// Pair of master keys.
struct MasterKeyPair {
    sender: MasterKey,
    receiver: MasterKey,
}

impl MasterKeyPair {
    /// Extract a pair of master keys from a given SSL object.
    fn from_ssl(agent_role: AgentRole, profile: SrtpProfile, ssl: &SslRef) -> Result<Self, Error> {
        let master_key_len = ((profile.master_key_len() + 7) >> 3) as usize;
        let master_salt_len = ((profile.master_salt_len() + 7) >> 3) as usize;

        let mut buffer = BytesMut::new();

        buffer.resize((master_key_len + master_salt_len) << 1, 0);

        ssl.export_keying_material(&mut buffer, "EXTRACTOR-dtls_srtp", None)?;

        let mut buffer = buffer.freeze();

        let client_key = buffer.split_to(master_key_len);
        let server_key = buffer.split_to(master_key_len);
        let client_salt = buffer.split_to(master_salt_len);
        let server_salt = buffer.split_to(master_salt_len);

        let client = MasterKey::new(profile, client_key, client_salt);
        let server = MasterKey::new(profile, server_key, server_salt);

        let (sender, receiver) = if agent_role == AgentRole::Client {
            (client, server)
        } else {
            (server, client)
        };

        let res = Self { sender, receiver };

        Ok(res)
    }

    /// Derive a new SRTP key for a given packet index.
    fn derive_sender_srtp_key(&self, packet_index: u64) -> Result<SessionKey, Error> {
        self.sender.derive_srtp_key(packet_index)
    }

    /// Derive a new SRTCP key for a given packet index.
    fn derive_sender_srtcp_key(&self, packet_index: u64) -> Result<SessionKey, Error> {
        self.sender.derive_srtcp_key(packet_index)
    }

    /// Derive a new SRTP key for a given packet index.
    fn derive_receiver_srtp_key(&self, packet_index: u64) -> Result<SessionKey, Error> {
        self.receiver.derive_srtp_key(packet_index)
    }

    /// Derive a new SRTCP key for a given packet index.
    fn derive_receiver_srtcp_key(&self, packet_index: u64) -> Result<SessionKey, Error> {
        self.receiver.derive_srtcp_key(packet_index)
    }
}

/// Master key.
struct MasterKey {
    profile: SrtpProfile,
    key: Bytes,
    salt: Bytes,
}

impl MasterKey {
    /// Create a new master key.
    fn new(profile: SrtpProfile, key: Bytes, salt: Bytes) -> Self {
        Self { profile, key, salt }
    }

    /// Generate a given number of bits using the AES 128 CM based
    /// pseudo-random function as defined in RFC 3711.
    fn prf_aes_128_cm(&self, x: u128, len: u32) -> Result<Bytes, Error> {
        let iv = u128::to_be_bytes(x << 16);

        let bytes = ((len + 7) >> 3) as usize;

        let mut output = BytesMut::new();

        output.resize(bytes, 0);

        let mut ks = AES128CM::new(&self.key, &iv)?;

        ks.take(&mut output)?;

        Ok(output.freeze())
    }

    /// Derive a new key of a given length in bits.
    ///
    /// The key derivation is defined in RFC 3711.
    fn derive_key(&self, label: u8, packet_index: u64, len: u32) -> Result<Bytes, Error> {
        let key_derivation_rate = self.profile.key_derivation_rate();

        let x = u128::from_be_bytes(slice_to_right_array(&self.salt))
            ^ (get_key_id(label, packet_index, key_derivation_rate) as u128);

        self.prf_aes_128_cm(x, len)
    }

    /// Derive a new SRTP key for a given packet index.
    fn derive_srtp_key(&self, packet_index: u64) -> Result<SessionKey, Error> {
        let enc_key_len = self.profile.session_enc_key_len();
        let auth_key_len = self.profile.session_auth_key_len();
        let salt_len = self.profile.session_salt_len();

        let enc_key = self.derive_key(0x00, packet_index, enc_key_len)?;
        let auth_key = self.derive_key(0x01, packet_index, auth_key_len)?;
        let salt = self.derive_key(0x02, packet_index, salt_len)?;

        let key_derivation_rate = self.profile.key_derivation_rate();

        let min_packet_index = get_min_packet_index(packet_index, key_derivation_rate);
        let max_packet_index = get_max_packet_index(packet_index, key_derivation_rate);

        SessionKey::new(
            self.profile,
            enc_key,
            auth_key,
            salt,
            min_packet_index,
            max_packet_index,
        )
    }

    /// Derive a new SRTCP key for a given packet index.
    fn derive_srtcp_key(&self, packet_index: u64) -> Result<SessionKey, Error> {
        let enc_key_len = self.profile.session_enc_key_len();
        let auth_key_len = self.profile.session_auth_key_len();
        let salt_len = self.profile.session_salt_len();

        let enc_key = self.derive_key(0x03, packet_index, enc_key_len)?;
        let auth_key = self.derive_key(0x04, packet_index, auth_key_len)?;
        let salt = self.derive_key(0x05, packet_index, salt_len)?;

        let key_derivation_rate = self.profile.key_derivation_rate();

        let min_packet_index = get_min_packet_index(packet_index, key_derivation_rate);
        let max_packet_index = get_max_packet_index(packet_index, key_derivation_rate);

        SessionKey::new(
            self.profile,
            enc_key,
            auth_key,
            salt,
            min_packet_index,
            max_packet_index,
        )
    }
}

/// Session key.
struct SessionKey {
    profile: SrtpProfile,
    auth_algorithm: MessageDigest,
    enc_key: Bytes,
    auth_key: PKey<Private>,
    salt: Bytes,
    min_packet_index: u64,
    max_packet_index: u64,
    auth_buffer: Vec<u8>,
}

impl SessionKey {
    /// Create a new session key.
    fn new(
        profile: SrtpProfile,
        enc_key: Bytes,
        auth_key: Bytes,
        salt: Bytes,
        min_packet_index: u64,
        max_packet_index: u64,
    ) -> Result<Self, Error> {
        let auth_key = PKey::hmac(&auth_key)?;

        let auth_algorithm = match profile.id() {
            SrtpProfileId::SRTP_NULL_SHA1_32
            | SrtpProfileId::SRTP_NULL_SHA1_80
            | SrtpProfileId::SRTP_AES128_CM_SHA1_32
            | SrtpProfileId::SRTP_AES128_CM_SHA1_80 => MessageDigest::sha1(),
        };

        let auth_buffer_len = (profile.auth_output_len() >> 3) as usize;

        let res = Self {
            profile,
            auth_algorithm,
            enc_key,
            auth_key,
            salt,
            min_packet_index,
            max_packet_index,
            auth_buffer: vec![0u8; auth_buffer_len],
        };

        Ok(res)
    }

    /// Get the minimum acceptable packet index for this key.
    fn min_packet_index(&self) -> u64 {
        self.min_packet_index
    }

    /// Get the maximum acceptable packet index for this key.
    fn max_packet_index(&self) -> u64 {
        self.max_packet_index
    }

    /// Authenticate a given RTP packet and return the auth tag.
    fn authenticate_rtp_packet(&mut self, roc: u32, packet: &[u8]) -> Result<&[u8], Error> {
        let mut signer = Signer::new(self.auth_algorithm, &self.auth_key)?;

        signer.update(packet)?;
        signer.update(&roc.to_be_bytes())?;

        signer.sign(&mut self.auth_buffer)?;

        let len = (self.profile.rtp_auth_tag_len() >> 3) as usize;

        Ok(&self.auth_buffer[..len])
    }

    /// Authenticate a given RTCP packet and return the auth tag.
    fn authenticate_rtcp_packet(&mut self, packet: &[u8]) -> Result<&[u8], Error> {
        let mut signer = Signer::new(self.auth_algorithm, &self.auth_key)?;

        signer.sign_oneshot(&mut self.auth_buffer, packet)?;

        let len = (self.profile.rtcp_auth_tag_len() >> 3) as usize;

        Ok(&self.auth_buffer[..len])
    }

    /// Encrypt a given RTP payload.
    ///
    /// # Panics
    /// The method panics of the output buffer is shorter than the input
    /// buffer.
    fn encrypt_rtp_payload(
        &mut self,
        ssrc: u32,
        packet_index: u64,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), Error> {
        match self.profile.id() {
            SrtpProfileId::SRTP_NULL_SHA1_32 | SrtpProfileId::SRTP_NULL_SHA1_80 => {
                output.copy_from_slice(input);

                Ok(())
            }
            SrtpProfileId::SRTP_AES128_CM_SHA1_32 | SrtpProfileId::SRTP_AES128_CM_SHA1_80 => {
                let iv = (u128::from_be_bytes(slice_to_right_array(&self.salt)) << 16)
                    ^ ((ssrc as u128) << 64)
                    ^ ((packet_index as u128) << 16);

                let mut ks = AES128CM::new(&self.enc_key, &iv.to_be_bytes())?;

                ks.skip((self.profile.srtp_prefix_len() >> 3) as usize)?;

                ks.xor(input, output)
            }
        }
    }

    /// Encrypt a given RTCP "payload" (i.e. a portion of an RTCP packet that
    /// is supposed to be encrypted).
    ///
    /// The method will return the packet index with its MSB set if the packet
    /// was actually encrypted.
    ///
    /// # Panics
    /// The method panics of the output buffer is shorter than the input
    /// buffer.
    fn encrypt_rtcp_payload(
        &mut self,
        ssrc: u32,
        packet_index: u32,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<u32, Error> {
        match self.profile.id() {
            SrtpProfileId::SRTP_NULL_SHA1_32 | SrtpProfileId::SRTP_NULL_SHA1_80 => {
                output.copy_from_slice(input);

                Ok(packet_index)
            }
            SrtpProfileId::SRTP_AES128_CM_SHA1_32 | SrtpProfileId::SRTP_AES128_CM_SHA1_80 => {
                let iv = (u128::from_be_bytes(slice_to_right_array(&self.salt)) << 16)
                    ^ ((ssrc as u128) << 64)
                    ^ ((packet_index as u128) << 16);

                let mut ks = AES128CM::new(&self.enc_key, &iv.to_be_bytes())?;

                ks.skip((self.profile.srtp_prefix_len() >> 3) as usize)?;

                ks.xor(input, output)?;

                Ok(packet_index | (1 << 31))
            }
        }
    }

    /// Decrypt a given RTP payload.
    ///
    /// # Panics
    /// The method panics of the output buffer is shorter than the input
    /// buffer.
    fn decrypt_rtp_payload(
        &mut self,
        ssrc: u32,
        packet_index: u64,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), Error> {
        self.encrypt_rtp_payload(ssrc, packet_index, input, output)
    }

    /// Decrypt a given RTCP payload.
    ///
    /// # Panics
    /// The method panics of the output buffer is shorter than the input
    /// buffer.
    fn decrypt_rtcp_payload(
        &mut self,
        ssrc: u32,
        packet_index: u32,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<u32, Error> {
        self.encrypt_rtcp_payload(ssrc, packet_index, input, output)
    }
}

/// Collection of session keys.
///
/// The collection will store up to two session keys - the current key and the
/// previous key.
struct SessionKeys {
    inner: VecDeque<SessionKey>,
}

impl SessionKeys {
    /// Create a new session key collection.
    fn new() -> Self {
        Self {
            inner: VecDeque::with_capacity(2),
        }
    }

    /// Get or create a session for a given packet index.
    ///
    /// The derive function will be used for generating a new session key (if
    /// needed).
    fn get_or_create<F>(&mut self, packet_index: u64, derive: F) -> Result<&mut SessionKey, Error>
    where
        F: FnOnce(u64) -> Result<SessionKey, Error>,
    {
        let position = self.inner.iter().position(|key| {
            let min = key.min_packet_index();
            let max = key.max_packet_index();

            (min..=max).contains(&packet_index)
        });

        if let Some(index) = position {
            return Ok(&mut self.inner[index]);
        }

        if self.inner.len() > 1 {
            self.inner.pop_front();
        }

        self.inner.push_back(derive(packet_index)?);

        let key = self.inner.back_mut();

        Ok(key.unwrap())
    }
}

/// Replay list for SRTCP packets.
///
/// The depth of the replay list is fixed to 64.
struct ReplayList {
    start: Option<u32>,
    bitmap: u64,
}

impl ReplayList {
    /// Create a new replay list.
    fn new() -> Self {
        Self {
            start: None,
            bitmap: 0,
        }
    }

    /// Check if packet with a given index is a duplicate.
    fn is_duplicate(&self, index: u32) -> bool {
        let index = index & ((1 << 31) - 1);

        let start = self.start.unwrap_or(index);

        let offset = if index < start {
            (index | (1 << 31)) - start
        } else {
            index - start
        };

        if offset < 64 {
            ((self.bitmap >> (63 - offset)) & 1) == 1
        } else {
            offset >= (1 << 30)
        }
    }

    /// Update the list.
    fn update(&mut self, index: u32) {
        let index = index & ((1 << 31) - 1);

        if self.start.is_none() {
            self.start = Some(index);
        }

        let start = self.start.unwrap();

        let offset = if index < start {
            (index | (1 << 31)) - start
        } else {
            index - start
        };

        if offset < 64 {
            self.bitmap |= 1 << (63 - offset);

            let shift = self.bitmap.leading_ones();

            self.bitmap <<= shift;

            self.start = Some((start + shift) & ((1 << 31) - 1));
        } else {
            // if there was a big gap, there is really not much we can do
            // except resetting the replay list
            self.bitmap = 1 << 63;
            self.start = Some(index);
        }
    }
}

/// Get session key ID as defined in RFC 3711.
fn get_key_id(label: u8, packet_index: u64, key_derivation_rate: u64) -> u64 {
    let label = (label as u64) << 48;

    if key_derivation_rate == 0 {
        return label;
    }

    let packet_index = packet_index & ((1 << 48) - 1);

    let log2_kdr = key_derivation_rate.trailing_zeros();

    if (1 << log2_kdr) == key_derivation_rate {
        label | (packet_index >> log2_kdr)
    } else {
        label | (packet_index / key_derivation_rate)
    }
}

/// Get minimum packet index for a key derivation window that a given packet
/// index belongs to.
fn get_min_packet_index(packet_index: u64, key_derivation_rate: u64) -> u64 {
    if key_derivation_rate == 0 {
        return 0;
    }

    let log2_kdr = key_derivation_rate.trailing_zeros();

    if (1 << log2_kdr) == key_derivation_rate {
        (packet_index >> log2_kdr) << log2_kdr
    } else {
        packet_index - (packet_index % key_derivation_rate)
    }
}

/// Get maximum packet index for a key derivation window that a given packet
/// index belongs to.
fn get_max_packet_index(packet_index: u64, key_derivation_rate: u64) -> u64 {
    if key_derivation_rate == 0 {
        u64::MAX
    } else {
        get_min_packet_index(packet_index, key_derivation_rate) + key_derivation_rate - 1
    }
}

/// Create a right-aligned array from a given slice.
///
/// If the slice is shorter than the length of the target array, the data will
/// be right-aligned in the output. Otherwise, only the rightmost part of the
/// slice will be copied to fill the target array.
fn slice_to_right_array<const N: usize>(slice: &[u8]) -> [u8; N] {
    let mut res = [0u8; N];

    let src_len = slice.len();
    let copy = src_len.min(N);
    let src_start = src_len - copy;
    let dst_start = N - copy;

    let dst = &mut res[dst_start..];

    dst.copy_from_slice(&slice[src_start..]);

    res
}
