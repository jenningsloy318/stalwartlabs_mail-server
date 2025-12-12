/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use reqwest::Client;

pub mod main;
pub mod search;

pub struct ElasticSearchStore {
    client: Client,
    url: String,
}
