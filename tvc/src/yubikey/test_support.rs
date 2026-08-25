//! In-memory device fake shared by unit tests across the crate.

use super::{DeviceError, DeviceOps, DeviceStatus, Pin, QosSlot, SlotStatus};
use crate::config::turnkey::{QosOperatorPublicKey, YubiKeySerial};
use p256::PublicKey;
use p256::ecdh::diffie_hellman;
use qos_client::yubikey::YubiKeyError;
use qos_p256::P256Pair;
use zeroize::Zeroizing;

/// The PIN the fake accepts — the factory default, matching the hardware
/// tests.
pub(crate) const PIN: &[u8] = qos_client::yubikey::DEFAULT_PIN;

/// Serial of the device every [`FakeDevice`] holds.
pub(crate) fn serial() -> YubiKeySerial {
    YubiKeySerial::from(0x01c9_5c1f)
}

/// In-memory [`DeviceOps`] implementation: per-slot state and a software
/// P-256 pair standing in for the on-device keys, plus scriptable primitive
/// failures, recording every mutating call.
pub(crate) struct FakeDevice {
    status: DeviceStatus,
    pair: P256Pair,
    pub(crate) fail_provision: Option<QosSlot>,
    pub(crate) fail_delete: Option<QosSlot>,
    pub(crate) provision_calls: Vec<QosSlot>,
    pub(crate) delete_calls: Vec<QosSlot>,
}

impl FakeDevice {
    pub(crate) fn new(signing: SlotStatus, key_agreement: SlotStatus) -> Self {
        Self {
            status: DeviceStatus {
                signing,
                key_agreement,
            },
            pair: P256Pair::generate().expect("software key generation"),
            fail_provision: None,
            fail_delete: None,
            provision_calls: Vec::new(),
            delete_calls: Vec::new(),
        }
    }

    /// The composite operator key of the fake's on-device pair.
    pub(crate) fn operator_public_key(&self) -> QosOperatorPublicKey {
        QosOperatorPublicKey::try_from(self.pair.public_key().to_bytes().as_slice())
            .expect("software composite key is well-formed")
    }

    fn status_of(&mut self, serial: YubiKeySerial) -> Result<&mut DeviceStatus, DeviceError> {
        if serial == self::serial() {
            Ok(&mut self.status)
        } else {
            Err(DeviceError::NotFound { serial })
        }
    }

    fn slot_status(status: &mut DeviceStatus, slot: QosSlot) -> &mut SlotStatus {
        match slot {
            QosSlot::Signing => &mut status.signing,
            QosSlot::KeyAgreement => &mut status.key_agreement,
        }
    }

    fn checked_slot(
        &mut self,
        serial: YubiKeySerial,
        pin: &Pin,
        slot: QosSlot,
    ) -> Result<(), DeviceError> {
        let status = self.status_of(serial)?;

        if *Self::slot_status(status, slot) != SlotStatus::QosProvisioned {
            return Err(DeviceError::EmptySlot { slot });
        }

        if pin.as_bytes() != PIN {
            return Err(DeviceError::WrongPin { tries: 3 });
        }

        Ok(())
    }
}

impl DeviceOps for FakeDevice {
    fn connected_serials(&mut self) -> Result<Vec<YubiKeySerial>, DeviceError> {
        Ok(vec![serial()])
    }

    fn status(&mut self, serial: YubiKeySerial) -> Result<DeviceStatus, DeviceError> {
        self.status_of(serial).map(|status| status.clone())
    }

    fn provision_slot(
        &mut self,
        serial: YubiKeySerial,
        slot: QosSlot,
        _pin: &Pin,
    ) -> Result<(), DeviceError> {
        self.provision_calls.push(slot);

        if self.fail_provision == Some(slot) {
            return Err(DeviceError::Provision {
                slot,
                error: YubiKeyError::WillNotOverwriteSlot,
            });
        }

        let status = self.status_of(serial)?;
        *Self::slot_status(status, slot) = SlotStatus::QosProvisioned;
        Ok(())
    }

    fn pair_public_key(
        &mut self,
        serial: YubiKeySerial,
    ) -> Result<QosOperatorPublicKey, DeviceError> {
        let status = self.status_of(serial)?;

        if *status
            == (DeviceStatus {
                signing: SlotStatus::QosProvisioned,
                key_agreement: SlotStatus::QosProvisioned,
            })
        {
            Ok(self.operator_public_key())
        } else {
            Err(DeviceError::ReadPairPublicKey {
                error: YubiKeyError::CannotFindSigningKey,
            })
        }
    }

    fn delete_qos_certificate(
        &mut self,
        serial: YubiKeySerial,
        slot: QosSlot,
    ) -> Result<(), DeviceError> {
        self.delete_calls.push(slot);

        if self.fail_delete == Some(slot) {
            return Err(DeviceError::DeleteCertificate {
                slot,
                source: yubikey::Error::GenericError,
            });
        }

        let status = self.status_of(serial)?;
        *Self::slot_status(status, slot) = SlotStatus::Empty;
        Ok(())
    }

    fn sign(
        &mut self,
        serial: YubiKeySerial,
        pin: &Pin,
        message: &[u8],
    ) -> Result<Vec<u8>, DeviceError> {
        self.checked_slot(serial, pin, QosSlot::Signing)?;
        Ok(self.pair.sign(message).expect("software P-256 signing"))
    }

    fn key_agreement(
        &mut self,
        serial: YubiKeySerial,
        pin: &Pin,
        sender_public: PublicKey,
    ) -> Result<Zeroizing<Vec<u8>>, DeviceError> {
        self.checked_slot(serial, pin, QosSlot::KeyAgreement)?;

        let secret = diffie_hellman(
            self.pair.encryption_key().to_nonzero_scalar(),
            sender_public.as_affine(),
        );

        Ok(Zeroizing::new(secret.raw_secret_bytes().to_vec()))
    }
}
