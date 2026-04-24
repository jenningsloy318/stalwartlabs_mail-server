/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Server,
    ipc::{BroadcastEvent, RegistryChange},
    network::acme::{
        AcmeDnsParameters, AcmeError, AcmeResult, ParsedCert, directory::AcmeRequestBuilder,
    },
};
use registry::{
    schema::{
        enums::{AcmeChallengeType, AcmeRenewBefore, DnsRecordType},
        prelude::ObjectType,
        structs::{
            AcmeProvider, Certificate, CertificateManagement, DnsManagement, Domain, PublicText,
            PublicTextValue, SecretText, SecretTextValue, Task, TaskDnsManagement,
            TaskDomainManagement, TaskStatus,
        },
    },
    types::{datetime::UTCDateTime, id::ObjectId, map::Map},
};
use store::{
    registry::write::{RegistryWrite, RegistryWriteResult},
    write::now,
};
use types::id::Id;

impl Server {
    pub async fn acme_renew(&self, domain_id: Id) -> AcmeResult<Vec<Task>> {
        let Some(domain) = self.registry().object::<Domain>(domain_id).await? else {
            return Err(AcmeError::Invalid(format!(
                "Domain with ID {} not found",
                domain_id
            )));
        };
        let cert = match domain.certificate_management {
            CertificateManagement::Manual => {
                return Err(AcmeError::Invalid(
                    "ACME not configured for domain".to_string(),
                ));
            }
            CertificateManagement::Automatic(props) => props,
        };
        let Some(acme_provider) = self
            .registry()
            .object::<AcmeProvider>(cert.acme_provider_id)
            .await?
        else {
            return Err(AcmeError::Invalid(format!(
                "ACME provider with ID {} not found",
                cert.acme_provider_id
            )));
        };
        let dns_parameters = match &domain.dns_management {
            DnsManagement::Automatic(props)
                if acme_provider.challenge_type == AcmeChallengeType::Dns01 =>
            {
                match self.build_dns_updater(props.dns_server_id).await? {
                    Ok(updater) => Some(AcmeDnsParameters {
                        updater,
                        origin: props.origin.clone(),
                    }),
                    Err(err) => {
                        return Err(AcmeError::Invalid(format!(
                            "Failed to build DNS updater: {}",
                            err
                        )));
                    }
                }
            }
            _ => None,
        };
        if acme_provider.challenge_type == AcmeChallengeType::Dns01 && dns_parameters.is_none() {
            return Err(AcmeError::Invalid(
                "ACME provider requires DNS challenge but a DNS provider was not configured"
                    .to_string(),
            ));
        }
        let renew_before = acme_provider.renew_before;
        let pem_cert = AcmeRequestBuilder::new(acme_provider)
            .await?
            .renew(
                self,
                &domain.name,
                &cert.subject_alternative_names.into_inner(),
                dns_parameters,
            )
            .await?;
        let parsed_cert = ParsedCert::parse(&pem_cert.certificate)?;
        let certificate = Certificate {
            private_key: SecretText::Text(SecretTextValue {
                secret: pem_cert.private_key,
            }),
            certificate: PublicText::Text(PublicTextValue {
                value: pem_cert.certificate,
            }),
            issuer: parsed_cert.issuer,
            not_valid_after: UTCDateTime::from_timestamp(parsed_cert.valid_not_after.timestamp()),
            not_valid_before: UTCDateTime::from_timestamp(parsed_cert.valid_not_before.timestamp()),
            subject_alternative_names: Map::new(parsed_cert.sans),
        };
        let now = now();
        let expires_in = (parsed_cert.valid_not_after.timestamp() as u64).saturating_sub(now);
        if expires_in < 3600 {
            return Err(AcmeError::Invalid(format!(
                "Certificate expires in {} seconds, expected at least 3600 seconds",
                expires_in
            )));
        }

        match self
            .registry()
            .write(RegistryWrite::insert(&certificate.into()))
            .await?
        {
            RegistryWriteResult::Success(id) => {
                // Reload registry
                let change = RegistryChange::Insert(ObjectId::new(ObjectType::Certificate, id));
                Box::pin(self.reload_registry(change)).await?;
                self.cluster_broadcast(BroadcastEvent::RegistryChange(change))
                    .await;

                // Schedule next renewal
                let mut tasks = Vec::new();
                let renew_in = match renew_before {
                    AcmeRenewBefore::R12 => {
                        // 1/2 of the remaining time until expiration
                        expires_in / 2
                    }
                    AcmeRenewBefore::R23 => {
                        // 2/3 of the remaining time until expiration
                        expires_in * 2 / 3
                    }
                    AcmeRenewBefore::R34 => {
                        // 3/4 of the remaining time until expiration
                        expires_in * 3 / 4
                    }
                    AcmeRenewBefore::R45 => {
                        // 4/5 of the remaining time until expiration
                        expires_in * 4 / 5
                    }
                };
                tasks.push(Task::AcmeRenewal(TaskDomainManagement {
                    domain_id,
                    status: TaskStatus::at((now + renew_in) as i64),
                }));

                // Update TLSA records
                if let DnsManagement::Automatic(props) = &domain.dns_management
                    && props.publish_records.contains(&DnsRecordType::Tlsa)
                {
                    tasks.push(Task::DnsManagement(TaskDnsManagement {
                        domain_id,
                        on_success_renew_certificate: false,
                        status: TaskStatus::now(),
                        update_records: Map::new(vec![DnsRecordType::Tlsa]),
                    }));
                }

                Ok(tasks)
            }
            err => Err(AcmeError::Registry(err)),
        }
    }
}
