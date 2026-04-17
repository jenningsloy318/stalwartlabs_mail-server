/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::task_manager::TaskResult;
use common::Server;
use registry::schema::structs::{
    DnsManagement, Domain, Task, TaskDnsManagement, TaskDomainManagement, TaskStatus,
};
use std::fmt::Write;
use store::ahash::AHashSet;

pub(crate) trait DnsManagementTask: Sync + Send {
    fn dns_management(&self, task: &TaskDnsManagement) -> impl Future<Output = TaskResult> + Send;
}

impl DnsManagementTask for Server {
    async fn dns_management(&self, task: &TaskDnsManagement) -> TaskResult {
        match dns_management(self, task).await {
            Ok(result) => result,
            Err(err) => {
                let result = TaskResult::temporary(err.to_string());
                trc::error!(
                    err.caused_by(trc::location!())
                        .details("Failed to run DNS management task")
                );
                result
            }
        }
    }
}

async fn dns_management(server: &Server, task: &TaskDnsManagement) -> trc::Result<TaskResult> {
    if task.update_records.is_empty() {
        return Ok(TaskResult::permanent(
            "No DNS records to update".to_string(),
        ));
    }
    let Some(domain) = server.registry().object::<Domain>(task.domain_id).await? else {
        return Ok(TaskResult::permanent("Domain not found".to_string()));
    };
    let DnsManagement::Automatic(props) = &domain.dns_management else {
        return Ok(TaskResult::permanent(
            "Domain is not set to automatic DNS management".to_string(),
        ));
    };
    let dns_updater = match server.build_dns_updater(props.dns_server_id).await? {
        Ok(updater) => updater,
        Err(err) => {
            return Ok(TaskResult::permanent(format!(
                "Failed to build DNS updater: {}",
                err
            )));
        }
    };
    let origin = props.origin.as_deref().unwrap_or(&domain.name);
    let records = server
        .build_dns_records(task.domain_id, &domain, task.update_records.as_slice())
        .await?;

    // Delete any previous records
    let delete_records = records
        .iter()
        .map(|record| (&record.name, record.record.as_type()))
        .collect::<AHashSet<_>>();
    for (name, record_type) in delete_records {
        let _ = dns_updater.delete(origin, name, record_type).await;
    }

    // Add new records
    let mut errors = String::new();
    for record in records {
        if let Err(err) = dns_updater
            .create(origin, &record.name, record.record, false, false)
            .await
        {
            if !errors.is_empty() {
                errors.push_str("; ");
            }
            let _ = write!(
                &mut errors,
                "Failed to create DNS record for {}: {}",
                record.name, err
            );
        }
    }

    if errors.is_empty() {
        if task.on_success_renew_certificate {
            Ok(TaskResult::Success(vec![Task::AcmeRenewal(
                TaskDomainManagement {
                    domain_id: task.domain_id,
                    status: TaskStatus::now(),
                },
            )]))
        } else {
            Ok(TaskResult::Success(vec![]))
        }
    } else {
        Ok(TaskResult::permanent(errors))
    }
}
