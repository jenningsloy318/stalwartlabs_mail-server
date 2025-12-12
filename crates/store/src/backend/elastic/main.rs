/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    backend::elastic::ElasticSearchStore,
    search::{
        CalendarSearchField, ContactSearchField, EmailSearchField, FileSearchField, SearchField,
        SearchableField, TracingSearchField,
    },
    write::SearchIndex,
};
use reqwest::{Error, Response, Url};
use serde_json::{Value, json};
use utils::config::{Config, http::build_http_client, utils::AsKey};

impl ElasticSearchStore {
    pub async fn open(config: &mut Config, prefix: impl AsKey) -> Option<Self> {
        let client = build_http_client(config, prefix.clone(), "application/json".into())?;
        let prefix = prefix.as_key();
        let url = config
            .value_require((&prefix, "url"))?
            .trim_end_matches("/")
            .to_string();
        Url::parse(&url)
            .map_err(|e| config.new_parse_error((&prefix, "url"), format!("Invalid URL: {e}",)))
            .ok()?;

        let es = Self { client, url };

        let shards = config
            .property_or_default((&prefix, "index.shards"), "3")
            .unwrap_or(3);
        let replicas = config
            .property_or_default((&prefix, "index.replicas"), "0")
            .unwrap_or(0);
        let with_source = config
            .property_or_default((&prefix, "index.include-source"), "false")
            .unwrap_or(false);

        #[cfg(feature = "test_mode")]
        let _ = es.drop_indexes().await;

        if let Err(err) = es.create_indexes(shards, replicas, with_source).await {
            config.new_build_error(prefix.as_str(), err.to_string());
        }

        Some(es)
    }

    pub async fn create_indexes(
        &self,
        shards: usize,
        replicas: usize,
        with_source: bool,
    ) -> trc::Result<()> {
        self.create_index::<EmailSearchField>(shards, replicas, with_source)
            .await?;
        self.create_index::<CalendarSearchField>(shards, replicas, with_source)
            .await?;
        self.create_index::<ContactSearchField>(shards, replicas, with_source)
            .await?;
        self.create_index::<TracingSearchField>(shards, replicas, with_source)
            .await?;
        Ok(())
    }

    async fn create_index<T: SearchableField>(
        &self,
        shards: usize,
        replicas: usize,
        with_source: bool,
    ) -> trc::Result<()> {
        let mut mappings = serde_json::Map::new();
        mappings.insert(
            "properties".to_string(),
            Value::Object(
                T::primary_keys()
                    .iter()
                    .chain(T::all_fields())
                    .map(|field| (field.es_field().to_string(), field.es_schema()))
                    .collect::<serde_json::Map<String, Value>>(),
            ),
        );
        if !with_source {
            mappings.insert("_source".to_string(), json!({ "enabled": false }));
        }
        let body = json!({
          "mappings": mappings,
          "settings": {
            "index.number_of_shards": shards,
            "index.number_of_replicas": replicas,
            "analysis": {
              "analyzer": {
                "default": {
                  "type": "custom",
                  "tokenizer": "standard",
                  "filter": ["lowercase", "stemmer"]
                }
              }
            }
          }
        });
        let body = serde_json::to_string(&body).unwrap_or_default();

        assert_success(
            self.client
                .put(format!("{}/{}", self.url, T::index().es_index_name()))
                .body(body)
                .send()
                .await,
        )
        .await
        .map(|_| ())
    }

    #[cfg(feature = "test_mode")]
    pub async fn drop_indexes(&self) -> trc::Result<()> {
        for index in &[
            SearchIndex::Email,
            SearchIndex::Calendar,
            SearchIndex::Contacts,
            SearchIndex::Tracing,
        ] {
            assert_success(
                self.client
                    .delete(format!("{}/{}", self.url, index.es_index_name()))
                    .send()
                    .await,
            )
            .await
            .map(|_| ())?;
        }

        Ok(())
    }
}

pub(crate) async fn assert_success(response: Result<Response, Error>) -> trc::Result<Response> {
    match response {
        Ok(response) => {
            let status = response.status();
            if status.is_success() {
                Ok(response)
            } else {
                Err(trc::StoreEvent::ElasticsearchError
                    .reason(response.text().await.unwrap_or_default())
                    .ctx(trc::Key::Code, status.as_u16()))
            }
        }
        Err(err) => Err(trc::StoreEvent::ElasticsearchError.reason(err)),
    }
}

impl SearchIndex {
    pub fn es_index_name(&self) -> &'static str {
        match self {
            SearchIndex::Email => "st_email",
            SearchIndex::Calendar => "st_calendar",
            SearchIndex::Contacts => "st_contact",
            SearchIndex::File => "st_file",
            SearchIndex::Tracing => "st_tracing",
            SearchIndex::InMemory => unreachable!(),
        }
    }
}

impl SearchField {
    pub fn es_field(&self) -> &'static str {
        match self {
            SearchField::AccountId => "acc_id",
            SearchField::DocumentId => "doc_id",
            SearchField::Id => "id",
            SearchField::Email(field) => match field {
                EmailSearchField::From => "from",
                EmailSearchField::To => "to",
                EmailSearchField::Cc => "cc",
                EmailSearchField::Bcc => "bcc",
                EmailSearchField::Subject => "subj",
                EmailSearchField::Body => "body",
                EmailSearchField::Attachment => "attach",
                EmailSearchField::ReceivedAt => "rcvd",
                EmailSearchField::SentAt => "sent",
                EmailSearchField::Size => "size",
                EmailSearchField::HasAttachment => "has_att",
                EmailSearchField::Headers => "headers",
            },
            SearchField::Calendar(field) => match field {
                CalendarSearchField::Title => "title",
                CalendarSearchField::Description => "desc",
                CalendarSearchField::Location => "loc",
                CalendarSearchField::Owner => "owner",
                CalendarSearchField::Attendee => "attendee",
                CalendarSearchField::Start => "start",
                CalendarSearchField::Uid => "uid",
            },
            SearchField::Contact(field) => match field {
                ContactSearchField::Member => "member",
                ContactSearchField::Kind => "kind",
                ContactSearchField::Name => "name",
                ContactSearchField::Nickname => "nick",
                ContactSearchField::Organization => "org",
                ContactSearchField::Email => "email",
                ContactSearchField::Phone => "phone",
                ContactSearchField::OnlineService => "online",
                ContactSearchField::Address => "addr",
                ContactSearchField::Note => "note",
                ContactSearchField::Uid => "uid",
            },
            SearchField::File(field) => match field {
                FileSearchField::Name => "name",
                FileSearchField::Content => "content",
            },
            SearchField::Tracing(field) => match field {
                TracingSearchField::EventType => "ev_type",
                TracingSearchField::QueueId => "queue_id",
                TracingSearchField::Keywords => "keywords",
            },
        }
    }

    pub fn es_schema(&self) -> Value {
        match self {
            SearchField::AccountId
            | SearchField::DocumentId
            | SearchField::Email(EmailSearchField::Size) => json!({
              "type": "integer"
            }),
            SearchField::Id
            | SearchField::Email(EmailSearchField::SentAt | EmailSearchField::ReceivedAt)
            | SearchField::Calendar(CalendarSearchField::Start)
            | SearchField::Tracing(TracingSearchField::QueueId | TracingSearchField::EventType) => {
                json!({
                  "type": "long"
                })
            }
            SearchField::Email(EmailSearchField::HasAttachment) => json!({
              "type": "boolean"
            }),
            SearchField::Calendar(CalendarSearchField::Uid)
            | SearchField::Contact(ContactSearchField::Uid) => json!({
              "type": "keyword",
            }),
            SearchField::Email(
                EmailSearchField::From | EmailSearchField::To | EmailSearchField::Subject,
            ) => json!({
              "type": "text",
              "fields": {
                "keyword": {
                  "type": "keyword"
                }
              }
            }),
            SearchField::Email(EmailSearchField::Headers) => {
                json!({
                  "type": "object",
                  "enabled": true
                })
            }
            #[cfg(feature = "test_mode")]
            SearchField::Email(EmailSearchField::Bcc | EmailSearchField::Cc) => {
                json!({
                  "type": "text",
                  "fields": {
                    "keyword": {
                      "type": "keyword"
                    }
                  }
                })
            }
            #[cfg(not(feature = "test_mode"))]
            SearchField::Email(EmailSearchField::Bcc | EmailSearchField::Cc) => {
                json!({
                  "type": "text"
                })
            }
            SearchField::Email(EmailSearchField::Body | EmailSearchField::Attachment)
            | SearchField::Calendar(
                CalendarSearchField::Title
                | CalendarSearchField::Description
                | CalendarSearchField::Location
                | CalendarSearchField::Owner
                | CalendarSearchField::Attendee,
            )
            | SearchField::Contact(
                ContactSearchField::Member
                | ContactSearchField::Kind
                | ContactSearchField::Name
                | ContactSearchField::Nickname
                | ContactSearchField::Organization
                | ContactSearchField::Email
                | ContactSearchField::Phone
                | ContactSearchField::OnlineService
                | ContactSearchField::Address
                | ContactSearchField::Note,
            )
            | SearchField::File(FileSearchField::Name | FileSearchField::Content)
            | SearchField::Tracing(TracingSearchField::Keywords) => json!({
              "type": "text"
            }),
        }
    }
}
