/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::Server;
use jmap_proto::{
    method::query::{
        Comparator, Filter, QueryRequest, QueryResponse, RequestArguments, SortProperty,
    },
    types::{
        collection::{Collection, SyncCollection},
        property::Property,
    },
};
use std::future::Future;
use store::query::{self};

use crate::{JmapMethods, changes::state::StateManager};

pub trait SieveScriptQuery: Sync + Send {
    fn sieve_script_query(
        &self,
        request: QueryRequest<RequestArguments>,
    ) -> impl Future<Output = trc::Result<QueryResponse>> + Send;
}

impl SieveScriptQuery for Server {
    async fn sieve_script_query(
        &self,
        mut request: QueryRequest<RequestArguments>,
    ) -> trc::Result<QueryResponse> {
        let account_id = request.account_id.document_id();
        let mut filters = Vec::with_capacity(request.filter.len());

        for cond in std::mem::take(&mut request.filter) {
            match cond {
                Filter::Name(name) => filters.push(query::Filter::contains(Property::Name, &name)),
                Filter::IsActive(is_active) => {
                    filters.push(query::Filter::eq(Property::IsActive, vec![is_active as u8]))
                }
                Filter::And | Filter::Or | Filter::Not | Filter::Close => {
                    filters.push(cond.into());
                }
                other => {
                    return Err(trc::JmapEvent::UnsupportedFilter
                        .into_err()
                        .details(other.to_string()));
                }
            }
        }

        let result_set = self
            .filter(account_id, Collection::SieveScript, filters)
            .await?;

        let (response, paginate) = self
            .build_query_response(
                &result_set,
                self.get_state(account_id, SyncCollection::SieveScript)
                    .await?,
                &request,
            )
            .await?;

        if let Some(paginate) = paginate {
            // Parse sort criteria
            let mut comparators = Vec::with_capacity(request.sort.as_ref().map_or(1, |s| s.len()));
            for comparator in request
                .sort
                .and_then(|s| if !s.is_empty() { s.into() } else { None })
                .unwrap_or_else(|| vec![Comparator::descending(SortProperty::Name)])
            {
                comparators.push(match comparator.property {
                    SortProperty::Name => {
                        query::Comparator::field(Property::Name, comparator.is_ascending)
                    }
                    SortProperty::IsActive => {
                        query::Comparator::field(Property::IsActive, comparator.is_ascending)
                    }
                    other => {
                        return Err(trc::JmapEvent::UnsupportedSort
                            .into_err()
                            .details(other.to_string()));
                    }
                });
            }

            // Sort results
            self.sort(result_set, comparators, paginate, response).await
        } else {
            Ok(response)
        }
    }
}
