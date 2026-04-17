/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use aes::cipher::{BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use common::auth::{
    ACCOUNT_FLAG_ENCRYPT_ALGO_AES256, ACCOUNT_FLAG_ENCRYPT_METHOD_PGP,
    ACCOUNT_FLAG_ENCRYPT_TRAIN_SPAM_FILTER, EncryptionKeys,
};
use mail_builder::{encoders::base64::base64_encode_mime, mime::make_boundary};
use mail_parser::{Message, MimeHeaders, PartType};
use openpgp::{
    parse::Parse,
    serialize::stream,
    types::{KeyFlags, SymmetricAlgorithm},
};
use rand::{RngCore, SeedableRng, rngs::StdRng};
use rasn::types::{ObjectIdentifier, OctetString, SetOf};
use rasn_cms::{
    AlgorithmIdentifier, CONTENT_DATA, CONTENT_ENVELOPED_DATA, EncryptedContent,
    EncryptedContentInfo, EncryptedKey, EnvelopedData, IssuerAndSerialNumber,
    KeyTransRecipientInfo, RecipientIdentifier, RecipientInfo,
    algorithms::{AES128_CBC, AES256_CBC, RSA},
    pkcs7_compat::EncapsulatedContentInfo,
};
use rsa::{Pkcs1v15Encrypt, RsaPublicKey, pkcs1::DecodeRsaPublicKey};
use sequoia_openpgp as openpgp;
use std::io::Cursor;

#[derive(Debug)]
pub enum EncryptMessageError {
    AlreadyEncrypted,
    Error(String),
}

#[allow(async_fn_in_trait)]
pub trait EncryptMessage {
    async fn encrypt(
        &self,
        keys: &EncryptionKeys,
        flags: u64,
    ) -> Result<Vec<u8>, EncryptMessageError>;
    fn is_encrypted(&self) -> bool;
}

impl EncryptMessage for Message<'_> {
    async fn encrypt(
        &self,
        keys: &EncryptionKeys,
        flags: u64,
    ) -> Result<Vec<u8>, EncryptMessageError> {
        let root = self.root_part();
        let raw_message = self.raw_message();
        let mut outer_message = Vec::with_capacity((raw_message.len() as f64 * 1.5) as usize);
        let mut inner_message = Vec::with_capacity(raw_message.len());

        // Move MIME headers and body to inner message
        for header in root.headers() {
            (if header.name.is_mime_header() {
                &mut inner_message
            } else {
                &mut outer_message
            })
            .extend_from_slice(
                &raw_message[header.offset_field() as usize..header.offset_end() as usize],
            );
        }
        inner_message.extend_from_slice(b"\r\n");
        inner_message.extend_from_slice(&raw_message[root.raw_body_offset() as usize..]);

        // Encrypt inner message
        if flags & ACCOUNT_FLAG_ENCRYPT_METHOD_PGP != 0 {
            // Prepare encrypted message
            let boundary = make_boundary("_");
            outer_message.extend_from_slice(
                concat!(
                    "Content-Type: multipart/encrypted;\r\n\t",
                    "protocol=\"application/pgp-encrypted\";\r\n\t",
                    "boundary=\""
                )
                .as_bytes(),
            );
            outer_message.extend_from_slice(boundary.as_bytes());
            outer_message.extend_from_slice(
                concat!(
                    "\"\r\n\r\n",
                    "OpenPGP/MIME message (Automatically encrypted by Stalwart)\r\n\r\n",
                    "--"
                )
                .as_bytes(),
            );
            outer_message.extend_from_slice(boundary.as_bytes());
            outer_message.extend_from_slice(
                concat!(
                    "\r\nContent-Type: application/pgp-encrypted\r\n\r\n",
                    "Version: 1\r\n\r\n--"
                )
                .as_bytes(),
            );
            outer_message.extend_from_slice(boundary.as_bytes());
            outer_message.extend_from_slice(
                concat!(
                    "\r\nContent-Type: application/octet-stream; name=\"encrypted.asc\"\r\n",
                    "Content-Disposition: inline; filename=\"encrypted.asc\"\r\n\r\n"
                )
                .as_bytes(),
            );

            let certs = keys
                .iter()
                .map(openpgp::Cert::from_bytes)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|err| {
                    EncryptMessageError::Error(format!(
                        "Failed to parse OpenPGP public key: {}",
                        err
                    ))
                })?;

            // Encrypt contents (TODO: use rayon)
            let encrypted_contents = tokio::task::spawn_blocking(move || {
                // Parse public key
                let mut keys = Vec::with_capacity(certs.len());
                let policy = openpgp::policy::StandardPolicy::new();

                for cert in &certs {
                    for key in cert
                        .keys()
                        .with_policy(&policy, None)
                        .supported()
                        .alive()
                        .revoked(false)
                        .key_flags(KeyFlags::empty().set_transport_encryption())
                    {
                        keys.push(key);
                    }
                }

                // Compose a writer stack corresponding to the output format and
                // packet structure we want.
                let mut sink = Vec::with_capacity(inner_message.len());

                // Stream an OpenPGP message.
                let message = stream::Armorer::new(stream::Message::new(&mut sink))
                    .build()
                    .map_err(|err| {
                        EncryptMessageError::Error(format!("Failed to create armorer: {}", err))
                    })?;
                let message = stream::Encryptor::for_recipients(message, keys)
                    .symmetric_algo(flags.algo())
                    .build()
                    .map_err(|err| {
                        EncryptMessageError::Error(format!("Failed to build encryptor: {}", err))
                    })?;
                let mut message = stream::LiteralWriter::new(message).build().map_err(|err| {
                    EncryptMessageError::Error(format!("Failed to create literal writer: {}", err))
                })?;
                std::io::copy(&mut Cursor::new(inner_message), &mut message).map_err(|err| {
                    EncryptMessageError::Error(format!("Failed to encrypt message: {}", err))
                })?;
                message.finalize().map_err(|err| {
                    EncryptMessageError::Error(format!("Failed to finalize message: {}", err))
                })?;

                String::from_utf8(sink).map_err(|err| {
                    EncryptMessageError::Error(format!(
                        "Failed to convert encrypted message to UTF-8: {}",
                        err
                    ))
                })
            })
            .await
            .map_err(|err| {
                EncryptMessageError::Error(format!("Failed to encrypt message: {}", err))
            })??;
            outer_message.extend_from_slice(encrypted_contents.as_bytes());
            outer_message.extend_from_slice(b"\r\n--");
            outer_message.extend_from_slice(boundary.as_bytes());
            outer_message.extend_from_slice(b"--\r\n");
        } else {
            // Generate random IV
            let mut rng = StdRng::from_entropy();
            let mut iv = vec![0u8; 16];
            rng.fill_bytes(&mut iv);

            // Generate random key
            let mut key = vec![0u8; flags.key_size()];
            rng.fill_bytes(&mut key);

            // Encrypt contents (TODO: use rayon)
            let (encrypted_contents, key, iv) = tokio::task::spawn_blocking(move || {
                (flags.encrypt(&key, &iv, &inner_message), key, iv)
            })
            .await
            .map_err(|err| {
                EncryptMessageError::Error(format!("Failed to encrypt message: {}", err))
            })?;

            // Encrypt key using public keys
            let mut recipient_infos = SetOf::new();
            for cert in keys.iter() {
                let cert = rasn::der::decode::<rasn_pkix::Certificate>(cert).map_err(|err| {
                    EncryptMessageError::Error(format!("Failed to parse certificate: {}", err))
                })?;

                let public_key = RsaPublicKey::from_pkcs1_der(
                    cert.tbs_certificate
                        .subject_public_key_info
                        .subject_public_key
                        .as_raw_slice(),
                )
                .map_err(|err| {
                    EncryptMessageError::Error(format!("Failed to parse public key: {}", err))
                })?;
                let encrypted_key = public_key
                    .encrypt(&mut rng, Pkcs1v15Encrypt, &key[..])
                    .map_err(|err| {
                        EncryptMessageError::Error(format!("Failed to encrypt key: {}", err))
                    })
                    .unwrap();

                recipient_infos.insert(RecipientInfo::KeyTransRecipientInfo(
                    KeyTransRecipientInfo {
                        version: 0.into(),
                        rid: RecipientIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
                            issuer: cert.tbs_certificate.issuer,
                            serial_number: cert.tbs_certificate.serial_number,
                        }),
                        key_encryption_algorithm: AlgorithmIdentifier {
                            algorithm: RSA.into(),
                            parameters: Some(
                                rasn::der::encode(&())
                                    .map_err(|err| {
                                        EncryptMessageError::Error(format!(
                                            "Failed to encode RSA algorithm identifier: {}",
                                            err
                                        ))
                                    })?
                                    .into(),
                            ),
                        },
                        encrypted_key: EncryptedKey::from(encrypted_key),
                    },
                ));
            }

            let pkcs7 = rasn::der::encode(&EncapsulatedContentInfo {
                content_type: CONTENT_ENVELOPED_DATA.into(),
                content: Some(
                    rasn::der::encode(&EnvelopedData {
                        version: 0.into(),
                        originator_info: None,
                        recipient_infos,
                        encrypted_content_info: EncryptedContentInfo {
                            content_type: CONTENT_DATA.into(),
                            content_encryption_algorithm: AlgorithmIdentifier {
                                algorithm: flags.to_algorithm_identifier(),
                                parameters: Some(
                                    rasn::der::encode(&OctetString::from(iv))
                                        .map_err(|err| {
                                            EncryptMessageError::Error(format!(
                                                "Failed to encode IV: {}",
                                                err
                                            ))
                                        })?
                                        .into(),
                                ),
                            },
                            encrypted_content: Some(EncryptedContent::from(encrypted_contents)),
                        },
                        unprotected_attrs: None,
                    })
                    .map_err(|err| {
                        EncryptMessageError::Error(format!(
                            "Failed to encode EnvelopedData: {}",
                            err
                        ))
                    })?
                    .into(),
                ),
            })
            .map_err(|err| {
                EncryptMessageError::Error(format!("Failed to encode ContentInfo: {}", err))
            })?;

            // Generate message
            outer_message.extend_from_slice(
                concat!(
                    "Content-Type: application/pkcs7-mime;\r\n",
                    "\tname=\"smime.p7m\";\r\n",
                    "\tsmime-type=enveloped-data\r\n",
                    "Content-Disposition: attachment;\r\n",
                    "\tfilename=\"smime.p7m\"\r\n",
                    "Content-Transfer-Encoding: base64\r\n\r\n"
                )
                .as_bytes(),
            );
            base64_encode_mime(&pkcs7, &mut outer_message, false).map_err(|err| {
                EncryptMessageError::Error(format!("Failed to base64 encode PKCS7: {}", err))
            })?;
        }

        Ok(outer_message)
    }

    fn is_encrypted(&self) -> bool {
        if self.content_type().is_some_and(|ct| {
            let main_type = ct.c_type.as_ref();
            let sub_type = ct
                .c_subtype
                .as_ref()
                .map(|s| s.as_ref())
                .unwrap_or_default();

            (main_type.eq_ignore_ascii_case("application")
                && (sub_type.eq_ignore_ascii_case("pkcs7-mime")
                    || sub_type.eq_ignore_ascii_case("pkcs7-signature")
                    || (sub_type.eq_ignore_ascii_case("octet-stream")
                        && self.attachment_name().is_some_and(|name| {
                            name.rsplit_once('.')
                                .is_some_and(|(_, ext)| ["p7m", "p7s", "p7c", "p7z"].contains(&ext))
                        }))))
                || (main_type.eq_ignore_ascii_case("multipart")
                    && sub_type.eq_ignore_ascii_case("encrypted"))
        }) {
            return true;
        }

        if self.parts.len() <= 2 {
            let mut text_part = None;
            let mut is_multipart = false;

            for part in &self.parts {
                match &part.body {
                    PartType::Text(text) => {
                        text_part = Some(text.as_ref());
                    }
                    PartType::Multipart(_) => {
                        is_multipart = true;
                    }
                    _ => (),
                }
            }

            match text_part {
                Some(text)
                    if (self.parts.len() == 1 || is_multipart)
                        && text.trim_start().starts_with("-----BEGIN PGP MESSAGE-----") =>
                {
                    return true;
                }
                _ => (),
            }
        }

        false
    }
}

pub trait EncryptionFlags {
    fn key_size(&self) -> usize;
    fn to_algorithm_identifier(&self) -> ObjectIdentifier;
    fn can_train_spam_filter(&self) -> bool;
    fn encrypt(&self, key: &[u8], iv: &[u8], contents: &[u8]) -> Vec<u8>;
    fn algo(&self) -> SymmetricAlgorithm;
}

impl EncryptionFlags for u64 {
    fn key_size(&self) -> usize {
        if *self & ACCOUNT_FLAG_ENCRYPT_ALGO_AES256 != 0 {
            32
        } else {
            16
        }
    }

    fn to_algorithm_identifier(&self) -> ObjectIdentifier {
        if *self & ACCOUNT_FLAG_ENCRYPT_ALGO_AES256 != 0 {
            AES256_CBC.into()
        } else {
            AES128_CBC.into()
        }
    }

    fn can_train_spam_filter(&self) -> bool {
        *self & ACCOUNT_FLAG_ENCRYPT_TRAIN_SPAM_FILTER != 0
    }

    fn encrypt(&self, key: &[u8], iv: &[u8], contents: &[u8]) -> Vec<u8> {
        if *self & ACCOUNT_FLAG_ENCRYPT_ALGO_AES256 != 0 {
            cbc::Encryptor::<aes::Aes256>::new(key.into(), iv.into())
                .encrypt_padded_vec_mut::<Pkcs7>(contents)
        } else {
            cbc::Encryptor::<aes::Aes128>::new(key.into(), iv.into())
                .encrypt_padded_vec_mut::<Pkcs7>(contents)
        }
    }

    fn algo(&self) -> SymmetricAlgorithm {
        if *self & ACCOUNT_FLAG_ENCRYPT_ALGO_AES256 != 0 {
            SymmetricAlgorithm::AES256
        } else {
            SymmetricAlgorithm::AES128
        }
    }
}
