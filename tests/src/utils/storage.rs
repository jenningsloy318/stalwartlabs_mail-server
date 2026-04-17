/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::cleanup::{search_store_destroy, store_assert_is_empty};
use crate::utils::registry::UnwrapRegistryId;
use common::Server;
use registry::schema::structs::{Task, TaskStatus};
use registry::{
    schema::{
        enums::{BlobStoreType, DataStoreType, InMemoryStoreType, SearchStoreType},
        prelude::Object,
        structs::{
            BlobStore, DataStore, ElasticSearchStore, FileSystemStore, FoundationDbStore, HttpAuth,
            HttpAuthBasic, InMemoryStore, MeilisearchStore, MySqlStore, PostgreSqlStore,
            RedisStore, RocksDbStore, S3Store, S3StoreCustomRegion, S3StoreRegion, SearchStore,
            SecretKey, SecretKeyOptional, SecretKeyValue, SqliteStore,
        },
    },
    types::{EnumImpl, duration::Duration},
};
use store::write::now;
use store::{
    Deserialize, IterateParams, ValueKey,
    write::{TaskQueueClass, ValueClass},
};
use store::{RegistryStore, registry::write::RegistryWrite};

pub trait RegistryEnvStores {
    fn insert_stores_from_env(&self) -> impl Future<Output = ()>;
}

impl RegistryEnvStores for RegistryStore {
    async fn insert_stores_from_env(&self) {
        let path = self.path().as_os_str().to_str().unwrap();
        let search_store = std::env::var("SEARCH_STORE")
            .map(|store| SearchStoreType::parse(&store).expect("Invalid store type"))
            .map(|store| build_search_store(store, path))
            .map(Object::from)
            .ok();
        let blob_store = std::env::var("BLOB_STORE")
            .map(|store| BlobStoreType::parse(&store).expect("Invalid store type"))
            .map(|store| build_blob_store(store, path))
            .map(Object::from)
            .ok();
        let in_memory = std::env::var("MEMORY_STORE")
            .map(|store| InMemoryStoreType::parse(&store).expect("Invalid store type"))
            .map(|store| build_in_memory_store(store, path))
            .map(Object::from)
            .ok();

        for store in [search_store, blob_store, in_memory].into_iter().flatten() {
            self.write(RegistryWrite::insert(&store))
                .await
                .expect("Failed to insert store into registry")
                .unwrap_id(trc::location!());
        }
    }
}

pub fn build_data_store(typ: DataStoreType, path: &str) -> DataStore {
    match typ {
        DataStoreType::RocksDb => DataStore::RocksDb(RocksDbStore {
            path: format!("{path}/rocks.db"),
            ..Default::default()
        }),
        DataStoreType::Sqlite => DataStore::Sqlite(SqliteStore {
            path: format!("{path}/sqlite.db"),
            ..Default::default()
        }),
        DataStoreType::FoundationDb => DataStore::FoundationDb(FoundationDbStore::default()),
        DataStoreType::PostgreSql => DataStore::PostgreSql(PostgreSqlStore {
            host: "localhost".into(),
            port: 5432,
            auth_username: "stalwart".to_string().into(),
            auth_secret: SecretKeyOptional::Value(SecretKeyValue {
                secret: "stalwart".into(),
            }),
            database: "stalwart".into(),
            use_tls: false,
            allow_invalid_certs: true,
            ..Default::default()
        }),
        DataStoreType::MySql => DataStore::MySql(MySqlStore {
            host: "localhost".into(),
            port: 3307,
            auth_username: "root".to_string().into(),
            auth_secret: SecretKeyOptional::Value(SecretKeyValue {
                secret: "password".into(),
            }),
            database: "stalwart".into(),
            use_tls: false,
            allow_invalid_certs: true,
            ..Default::default()
        }),
    }
}

fn build_blob_store(typ: BlobStoreType, path: &str) -> BlobStore {
    match typ {
        BlobStoreType::S3 => BlobStore::S3(S3Store {
            access_key: "minioadmin".to_string().into(),
            bucket: "tmp".into(),
            region: S3StoreRegion::Custom(S3StoreCustomRegion {
                custom_endpoint: "http://localhost:9000".into(),
                custom_region: "eu-central-1".into(),
            }),
            secret_key: SecretKeyOptional::Value(SecretKeyValue {
                secret: "minioadmin".into(),
            }),
            allow_invalid_certs: true,
            ..Default::default()
        }),
        BlobStoreType::FileSystem => BlobStore::FileSystem(FileSystemStore {
            path: path.to_string(),
            ..Default::default()
        }),
        _ => unreachable!(),
    }
}

fn build_in_memory_store(typ: InMemoryStoreType, _path: &str) -> InMemoryStore {
    match typ {
        InMemoryStoreType::Redis => InMemoryStore::Redis(RedisStore {
            url: "redis://127.0.0.1".into(),
            ..Default::default()
        }),
        _ => unreachable!(),
    }
}

fn build_search_store(typ: SearchStoreType, _path: &str) -> SearchStore {
    match typ {
        SearchStoreType::ElasticSearch => SearchStore::ElasticSearch(ElasticSearchStore {
            url: "https://localhost:9200".into(),
            allow_invalid_certs: true,
            http_auth: HttpAuth::Basic(HttpAuthBasic {
                username: "elastic".into(),
                secret: SecretKey::Value(SecretKeyValue {
                    secret: "changeme".into(),
                }),
            }),
            ..Default::default()
        }),
        SearchStoreType::Meilisearch => SearchStore::Meilisearch(MeilisearchStore {
            url: "http://localhost:7700".into(),
            allow_invalid_certs: true,
            poll_interval: Duration::from_millis(100),
            ..Default::default()
        }),
        _ => unreachable!(),
    }
}

pub async fn wait_for_tasks(server: &Server, skip_not_due: bool, skip_permanent_failures: bool) {
    let mut count = 0;
    loop {
        let mut has_index_tasks = None;
        server
            .core
            .storage
            .data
            .iterate(
                IterateParams::new(
                    ValueKey::from(ValueClass::TaskQueue(TaskQueueClass::Task { id: 0 })),
                    ValueKey::from(ValueClass::TaskQueue(TaskQueueClass::Task { id: u64::MAX })),
                )
                .ascending(),
                |_, value| {
                    let task = Task::deserialize(value)?;
                    if (skip_permanent_failures && matches!(task.status(), TaskStatus::Failed(_)))
                        || (skip_not_due && task.due_timestamp() > now())
                    {
                        Ok(true)
                    } else {
                        has_index_tasks = Some(task);

                        Ok(false)
                    }
                },
            )
            .await
            .unwrap();

        if let Some(task) = has_index_tasks {
            count += 1;
            if count % 10 == 0 {
                println!("Waiting for pending task {:?}...", task);
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        } else {
            break;
        }
    }
}

pub async fn assert_is_empty(server: &Server, include_registry: bool) {
    // Wait for pending index tasks
    wait_for_tasks(server, false, false).await;

    // Assert is empty
    store_assert_is_empty(
        server.store(),
        server.core.storage.blob.clone(),
        include_registry,
    )
    .await;
    search_store_destroy(server.search_store()).await;

    // Clean caches
    for cache in [
        &server.inner.cache.events,
        &server.inner.cache.contacts,
        &server.inner.cache.files,
        &server.inner.cache.scheduling,
    ] {
        cache.clear();
    }
    server.inner.cache.messages.clear();
}
