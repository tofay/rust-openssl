use std::{ffi::CString, ptr};

use ffi::{
    c_int, OSSL_HPKE_CTX_free, OSSL_HPKE_CTX_get_seq, OSSL_HPKE_CTX_new,
    OSSL_HPKE_CTX_set1_authpriv, OSSL_HPKE_CTX_set1_authpub, OSSL_HPKE_CTX_set1_ikme,
    OSSL_HPKE_CTX_set1_psk, OSSL_HPKE_CTX_set_seq, OSSL_HPKE_decap, OSSL_HPKE_encap,
    OSSL_HPKE_export, OSSL_HPKE_get_grease_value, OSSL_HPKE_get_public_encap_size,
    OSSL_HPKE_keygen, OSSL_HPKE_open, OSSL_HPKE_seal, OSSL_HPKE_str2suite, OSSL_HPKE_suite_check,
    OSSL_HPKE_SUITE, OSSL_HPKE_SUITE_DEFAULT,
};
use foreign_types::{ForeignType, ForeignTypeRef};
use openssl_macros::corresponds;

use crate::{
    cvt, cvt_p,
    error::ErrorStack,
    pkey::{self, PKey, PKeyRef, Private},
};

pub struct HpkeMode(c_int);

impl HpkeMode {
    pub const BASE: Self = HpkeMode(ffi::OSSL_HPKE_MODE_BASE);
    pub const PSK: Self = HpkeMode(ffi::OSSL_HPKE_MODE_PSK);
    pub const AUTH: Self = HpkeMode(ffi::OSSL_HPKE_MODE_AUTH);
    pub const PSKAUTH: Self = HpkeMode(ffi::OSSL_HPKE_MODE_PSKAUTH);
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct HpkeKem(u16);
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct HpkeKdf(u16);
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct HpkeAead(u16);

impl HpkeKem {
    pub const P256: Self = HpkeKem(ffi::OSSL_HPKE_KEM_ID_P256);
    pub const P384: Self = HpkeKem(ffi::OSSL_HPKE_KEM_ID_P384);
    pub const P521: Self = HpkeKem(ffi::OSSL_HPKE_KEM_ID_P521);
}

impl HpkeKdf {
    pub const HKDF_SHA256: Self = HpkeKdf(ffi::OSSL_HPKE_KDF_ID_HKDF_SHA256);
    pub const HKDF_SHA384: Self = HpkeKdf(ffi::OSSL_HPKE_KDF_ID_HKDF_SHA384);
    pub const HKDF_SHA512: Self = HpkeKdf(ffi::OSSL_HPKE_KDF_ID_HKDF_SHA512);
}

impl HpkeAead {
    pub const AES_GCM_128: Self = HpkeAead(ffi::OSSL_HPKE_AEAD_ID_AES_GCM_128);
    pub const AES_GCM_256: Self = HpkeAead(ffi::OSSL_HPKE_AEAD_ID_AES_GCM_256);
    pub const CHACHA_POLY1305: Self = HpkeAead(ffi::OSSL_HPKE_AEAD_ID_CHACHA_POLY1305);
    pub const EXPORTONLY: Self = HpkeAead(ffi::OSSL_HPKE_AEAD_ID_EXPORTONLY);
}

#[derive(Debug, Copy, Clone)]
pub struct HpkeSuite {
    pub kem_id: HpkeKem,
    pub kdf_id: HpkeKdf,
    pub aead_id: HpkeAead,
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::OSSL_HPKE_CTX;
    fn drop = OSSL_HPKE_CTX_free;

    pub struct HpkeSenderCtx;
    /// A reference to an [`HpkeCtx`].
    pub struct HpkeSenderCtxRef;
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::OSSL_HPKE_CTX;
    fn drop = OSSL_HPKE_CTX_free;

    pub struct HpkeReceiverCtx;
    /// A reference to an [`HpkeCtx`].
    pub struct HpkeReceiverCtxRef;
}

impl HpkeSenderCtxRef {
    #[corresponds(OSSL_HPKE_encap)]
    #[inline]
    pub fn encap(&self, enc: &mut [u8], pub_key: &[u8], info: &[u8]) -> Result<(), ErrorStack> {
        unsafe {
            let mut enclen = enc.len();
            cvt(OSSL_HPKE_encap(
                self.as_ptr(),
                enc.as_mut_ptr(),
                &mut enclen,
                pub_key.as_ptr(),
                pub_key.len(),
                info.as_ptr(),
                info.len(),
            ))?;
            Ok(())
        }
    }

    #[corresponds(OSSL_HPKE_seal)]
    #[inline]
    pub fn seal(&self, ct: &mut [u8], aad: &[u8], pt: &[u8]) -> Result<(), ErrorStack> {
        unsafe {
            let mut ctlen = ct.len();
            cvt(OSSL_HPKE_seal(
                self.as_ptr(),
                ct.as_mut_ptr(),
                &mut ctlen,
                aad.as_ptr(),
                aad.len(),
                pt.as_ptr(),
                pt.len(),
            ))?;
            Ok(())
        }
    }

    #[corresponds(OSSL_HPKE_CTX_set1_ikme)]
    #[inline]
    pub fn set1_ikme(&self, ikm: &[u8]) -> Result<(), ErrorStack> {
        unsafe {
            cvt(OSSL_HPKE_CTX_set1_ikme(
                self.as_ptr(),
                ikm.as_ptr(),
                ikm.len(),
            ))?;
            Ok(())
        }
    }

    #[corresponds(OSSL_HPKE_CTX_set1_authpriv)]
    #[inline]
    pub fn set1_authpriv(
        &self,
        pkey_key: &mut pkey::PKeyRef<pkey::Private>,
    ) -> Result<(), ErrorStack> {
        unsafe {
            cvt(OSSL_HPKE_CTX_set1_authpriv(
                self.as_ptr(),
                pkey_key.as_ptr(),
            ))?;
            Ok(())
        }
    }
}

impl HpkeReceiverCtx {
    /// Creates a new context.
    #[corresponds(OSSL_HPKE_CTX_new)]
    #[inline]
    pub fn new(mode: HpkeMode, suite: HpkeSuite) -> Result<Self, ErrorStack> {
        ffi::init();

        let suite = ffi::OSSL_HPKE_SUITE {
            kem_id: suite.kem_id.0,
            kdf_id: suite.kdf_id.0,
            aead_id: suite.aead_id.0,
        };

        unsafe {
            let ptr = cvt_p(OSSL_HPKE_CTX_new(
                mode.0,
                suite,
                ffi::OSSL_HPKE_ROLE_RECEIVER,
                ptr::null_mut(),
                ptr::null(),
            ))?;
            Ok(HpkeReceiverCtx::from_ptr(ptr))
        }
    }
}

impl HpkeReceiverCtxRef {
    #[corresponds(OSSL_HPKE_decap)]
    #[inline]
    pub fn decap(
        &self,
        enc: &[u8],
        private_key: &PKeyRef<Private>,
        info: &[u8],
    ) -> Result<(), ErrorStack> {
        unsafe {
            cvt(OSSL_HPKE_decap(
                self.as_ptr(),
                enc.as_ptr(),
                enc.len(),
                private_key.as_ptr(),
                info.as_ptr(),
                info.len(),
            ))?;
            Ok(())
        }
    }

    #[corresponds(OSSL_HPKE_open)]
    #[inline]
    pub fn open(&self, pt: &mut [u8], aad: &[u8], ct: &[u8]) -> Result<(), ErrorStack> {
        unsafe {
            let mut ptlen = pt.len();
            cvt(OSSL_HPKE_open(
                self.as_ptr(),
                pt.as_mut_ptr(),
                &mut ptlen,
                aad.as_ptr(),
                aad.len(),
                ct.as_ptr(),
                ct.len(),
            ))?;
            Ok(())
        }
    }

    #[corresponds(OSSL_HPKE_CTX_set1_authpub)]
    #[inline]
    pub fn set1_authpub(&self, public_key: &[u8]) -> Result<(), ErrorStack> {
        unsafe {
            cvt(OSSL_HPKE_CTX_set1_authpub(
                self.as_ptr(),
                public_key.as_ptr(),
                public_key.len(),
            ))?;
            Ok(())
        }
    }

    #[corresponds(OSSL_HPKE_CTX_set_seq)]
    #[inline]
    pub fn set_seq(&self, seq: u64) -> Result<(), ErrorStack> {
        unsafe {
            cvt(OSSL_HPKE_CTX_set_seq(self.as_ptr(), seq))?;
            Ok(())
        }
    }
}

macro_rules! common {
    ($t:ident) => {
        impl $t {
            #[corresponds(OSSL_HPKE_export)]
            #[inline]
            pub fn export(&self, secret: &mut [u8], label: &[u8]) -> Result<(), ErrorStack> {
                unsafe {
                    cvt(OSSL_HPKE_export(
                        self.as_ptr(),
                        secret.as_mut_ptr(),
                        secret.len(),
                        label.as_ptr(),
                        label.len(),
                    ))?;
                    Ok(())
                }
            }

            #[corresponds(OSSL_HPKE_CTX_set1_psk)]
            #[inline]
            pub fn set1_psk(&self, psk_id: &str, psk: &[u8]) -> Result<(), ErrorStack> {
                unsafe {
                    cvt(OSSL_HPKE_CTX_set1_psk(
                        self.as_ptr(),
                        psk_id.as_ptr() as *const _,
                        psk.as_ptr(),
                        psk.len(),
                    ))?;
                    Ok(())
                }
            }

            #[corresponds(OSSL_HPKE_CTX_get_seq)]
            #[inline]
            pub fn get_seq(&self) -> Result<u64, ErrorStack> {
                let mut seq = 0;
                unsafe {
                    cvt(OSSL_HPKE_CTX_get_seq(self.as_ptr(), &mut seq))?;
                }
                Ok(seq)
            }
        }
    };
}

common!(HpkeSenderCtxRef);
common!(HpkeReceiverCtxRef);

impl HpkeSuite {
    /// Creates a new sender context.
    #[corresponds(OSSL_HPKE_CTX_new)]
    #[inline]
    pub fn new_sender(&self, mode: HpkeMode) -> Result<HpkeSenderCtx, ErrorStack> {
        ffi::init();

        unsafe {
            let ptr = cvt_p(OSSL_HPKE_CTX_new(
                mode.0,
                self.ffi(),
                ffi::OSSL_HPKE_ROLE_SENDER,
                ptr::null_mut(),
                ptr::null(),
            ))?;
            Ok(HpkeSenderCtx::from_ptr(ptr))
        }
    }

    /// Creates a new receiver context.
    #[corresponds(OSSL_HPKE_CTX_new)]
    #[inline]
    pub fn new_receiver(&self, mode: HpkeMode) -> Result<HpkeReceiverCtx, ErrorStack> {
        ffi::init();

        unsafe {
            let ptr = cvt_p(OSSL_HPKE_CTX_new(
                mode.0,
                self.ffi(),
                ffi::OSSL_HPKE_ROLE_RECEIVER,
                ptr::null_mut(),
                ptr::null(),
            ))?;
            Ok(HpkeReceiverCtx::from_ptr(ptr))
        }
    }

    fn ffi(&self) -> OSSL_HPKE_SUITE {
        OSSL_HPKE_SUITE {
            kem_id: self.kem_id.0,
            kdf_id: self.kdf_id.0,
            aead_id: self.aead_id.0,
        }
    }

    #[corresponds(OSSL_HPKE_suite_check)]
    #[inline]
    pub fn check(&self) -> Result<(), ErrorStack> {
        unsafe {
            cvt(OSSL_HPKE_suite_check(self.ffi()))?;
            Ok(())
        }
    }

    #[corresponds(OSSL_HPKE_keygen)]
    #[inline]
    pub fn keygen(&self, ikm: Option<&[u8]>) -> Result<(PKey<Private>, Vec<u8>), ErrorStack> {
        ffi::init();
        let mut public_key = vec![0; self.public_encap_size()];
        let mut private_key = ptr::null_mut();

        unsafe {
            cvt(OSSL_HPKE_keygen(
                self.ffi(),
                public_key.as_mut_ptr(),
                &mut public_key.len(),
                &mut private_key,
                ikm.map(|ikm| ikm.as_ptr()).unwrap_or(ptr::null()),
                ikm.map(|ikm| ikm.len()).unwrap_or(0),
                ptr::null_mut(),
                ptr::null(),
            ))?;
            Ok((PKey::from_ptr(private_key), public_key))
        }
    }

    #[corresponds(OSSL_HPKE_get_public_encap_size)]
    #[inline]
    pub fn public_encap_size(&self) -> usize {
        unsafe {
            OSSL_HPKE_get_public_encap_size(ffi::OSSL_HPKE_SUITE {
                kem_id: self.kem_id.0,
                kdf_id: self.kdf_id.0,
                aead_id: self.aead_id.0,
            })
        }
    }

    #[corresponds(OSSL_HPKE_get_ciphertext_size)]
    #[inline]
    pub fn ciphertext_size(&self, clear_len: usize) -> usize {
        unsafe {
            ffi::OSSL_HPKE_get_ciphertext_size(
                ffi::OSSL_HPKE_SUITE {
                    kem_id: self.kem_id.0,
                    kdf_id: self.kdf_id.0,
                    aead_id: self.aead_id.0,
                },
                clear_len,
            )
        }
    }

    #[corresponds(OSSL_HPKE_get_recommended_ikmelen)]
    #[inline]
    pub fn recommended_ikmelen(&self) -> usize {
        unsafe {
            ffi::OSSL_HPKE_get_recommended_ikmelen(ffi::OSSL_HPKE_SUITE {
                kem_id: self.kem_id.0,
                kdf_id: self.kdf_id.0,
                aead_id: self.aead_id.0,
            })
        }
    }

    #[corresponds(OSSL_HPKE_get_grease_value)]
    #[inline]
    pub fn get_grease_value(
        &self,
        suite_in: Option<HpkeSuite>,
        clear_len: usize,
    ) -> Result<(Vec<u8>, Vec<u8>), ErrorStack> {
        let mut enc = vec![0; self.public_encap_size()];
        let mut ct = vec![0; self.ciphertext_size(clear_len)];

        unsafe {
            let mut enclen = enc.len();
            cvt(OSSL_HPKE_get_grease_value(
                suite_in.as_ref().map_or(ptr::null_mut(), |s| {
                    &s.ffi() as *const OSSL_HPKE_SUITE as *mut OSSL_HPKE_SUITE
                }),
                &self.ffi() as *const OSSL_HPKE_SUITE as *mut OSSL_HPKE_SUITE,
                enc.as_mut_ptr(),
                &mut enclen,
                ct.as_mut_ptr(),
                ct.len(),
                ptr::null_mut(),
                ptr::null(),
            ))?;
            Ok((enc, ct))
        }
    }
}

impl TryFrom<&str> for HpkeSuite {
    type Error = ErrorStack;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        unsafe {
            let s = CString::new(s).unwrap();
            let suite = ptr::null_mut();
            cvt(OSSL_HPKE_str2suite(s.as_ptr(), suite))?;
            Ok(HpkeSuite {
                kem_id: HpkeKem((*suite).kem_id),
                kdf_id: HpkeKdf((*suite).kdf_id),
                aead_id: HpkeAead((*suite).aead_id),
            })
        }
    }
}

impl Default for HpkeSuite {
    #[corresponds(OSSL_HPKE_SUITE_DEFAULT)]
    fn default() -> Self {
        let suite = OSSL_HPKE_SUITE_DEFAULT;
        HpkeSuite {
            kem_id: HpkeKem(suite.kem_id),
            kdf_id: HpkeKdf(suite.kdf_id),
            aead_id: HpkeAead(suite.aead_id),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{HpkeMode, HpkeSuite};

    // https://docs.openssl.org/master/man3/OSSL_HPKE_CTX_new/#examples
    #[test]
    fn roundtrip() {
        let suite = HpkeSuite::default();
        let pt = b"a message not in a bottle";
        let info = b"Some info";
        let aad: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
        let mut enc = vec![0; suite.public_encap_size()];
        let mut ct = vec![0; suite.ciphertext_size(pt.len())];

        // Generate receiver's key pair.
        let (private_key, public_key) = suite.keygen(None).unwrap();

        // Sender - encrypt the message with the receiver's public key.
        let sender = suite.new_sender(HpkeMode::BASE).unwrap();
        sender.encap(&mut enc, &public_key, info).unwrap();
        sender.seal(&mut ct, &aad, pt).unwrap();

        // Receiver - decrypt the message with the private key.
        let receiver = suite.new_receiver(HpkeMode::BASE).unwrap();
        receiver.decap(&enc, &private_key, info).unwrap();
        let mut pt2 = vec![0; pt.len()];
        receiver.open(&mut pt2, &aad, &ct).unwrap();

        assert_eq!(pt, &pt2[..]);
    }
}
