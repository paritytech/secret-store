// Copyright 2015-2020 Parity Technologies (UK) Ltd.
// This file is part of Parity Secret Store.

// Parity Secret Store is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity Secret Store is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity Secret Store.  If not, see <http://www.gnu.org/licenses/>.

use std::collections::BTreeSet;
use hyper::Method;
use primitives::{service::ServiceTask, requester::Requester, serialization::SerializableAddress};
use crate::{DecomposedRequest, Error};

pub fn parse_http_request(request: &DecomposedRequest) -> Result<ServiceTask, Error> {
	let uri_path = request.uri.path().to_string();
	let uri_path = percent_encoding::percent_decode(uri_path.as_bytes())
		.decode_utf8()
		.map_err(|_| Error::InvalidRequest)?;

	let path: Vec<String> = uri_path.trim_start_matches('/').split('/').map(Into::into).collect();
	if path.len() == 0 {
		return Err(Error::InvalidRequest);
	}

	if path[0] == "admin" {
		return parse_admin_request(request, path);
	}

	let is_known_prefix = &path[0] == "shadow" || &path[0] == "schnorr" || &path[0] == "ecdsa" || &path[0] == "server";
	let (prefix, args_offset) = if is_known_prefix { (&*path[0], 1) } else { ("", 0) };
	let args_count = path.len() - args_offset;
	if args_count < 2 || path[args_offset].is_empty() || path[args_offset + 1].is_empty() {
		return Err(Error::InvalidRequest);
	}

	let document = match path[args_offset].parse() {
		Ok(document) => document,
		_ => return Err(Error::InvalidRequest),
	};
	let signature = match path[args_offset + 1].parse() {
		Ok(signature) => signature,
		_ => return Err(Error::InvalidRequest),
	};
	let signature = Requester::Signature(signature);

	let threshold = path.get(args_offset + 2).map(|v| v.parse());
	let message_hash = path.get(args_offset + 2).map(|v| v.parse());
	let common_point = path.get(args_offset + 2).map(|v| v.parse());
	let encrypted_key = path.get(args_offset + 3).map(|v| v.parse());
	match (prefix, args_count, &request.method, threshold, message_hash, common_point, encrypted_key) {
		("shadow", 3, &Method::POST, Some(Ok(threshold)), _, _, _) =>
			Ok(ServiceTask::GenerateServerKey(document, signature, threshold)),
		("shadow", 4, &Method::POST, _, _, Some(Ok(common_point)), Some(Ok(encrypted_key))) =>
			Ok(ServiceTask::StoreDocumentKey(document, signature, common_point, encrypted_key)),
		("", 3, &Method::POST, Some(Ok(threshold)), _, _, _) =>
			Ok(ServiceTask::GenerateDocumentKey(document, signature, threshold)),
		("server", 2, &Method::GET, _, _, _, _) =>
			Ok(ServiceTask::RetrieveServerKey(document, Some(signature))),
		("", 2, &Method::GET, _, _, _, _) =>
			Ok(ServiceTask::RetrieveDocumentKey(document, signature)),
		("shadow", 2, &Method::GET, _, _, _, _) =>
			Ok(ServiceTask::RetrieveShadowDocumentKey(document, signature)),
		("schnorr", 3, &Method::GET, _, Some(Ok(message_hash)), _, _) =>
			Ok(ServiceTask::SchnorrSignMessage(document, signature, message_hash)),
		("ecdsa", 3, &Method::GET, _, Some(Ok(message_hash)), _, _) =>
			Ok(ServiceTask::EcdsaSignMessage(document, signature, message_hash)),
		_ => Err(Error::InvalidRequest),
	}
}

fn parse_admin_request(request: &DecomposedRequest, path: Vec<String>) -> Result<ServiceTask, Error> {
	let args_count = path.len();
	if request.method != Method::POST || args_count != 4 || path[1] != "servers_set_change" {
		return Err(Error::InvalidRequest);
	}

	let old_set_signature = match path[2].parse() {
		Ok(signature) => signature,
		_ => return Err(Error::InvalidRequest),
	};

	let new_set_signature = match path[3].parse() {
		Ok(signature) => signature,
		_ => return Err(Error::InvalidRequest),
	};

	let new_servers_set: BTreeSet<SerializableAddress> = match serde_json::from_slice(&request.body) {
		Ok(new_servers_set) => new_servers_set,
		_ => return Err(Error::InvalidRequest),
	};

	Ok(ServiceTask::ChangeServersSet(old_set_signature, new_set_signature,
		new_servers_set.into_iter().map(Into::into).collect()))
}

#[cfg(test)]
mod tests {
	use std::str::FromStr;
	use assert_matches::assert_matches;
	use hyper::Uri;
	use primitives::ServerKeyId;
	use super::*;

	const KEY_ID_ENCODED: &'static str = "%30000000000000000000000000000000000000000000000000000000000000001";
	const KEY_ID: &'static str = "0000000000000000000000000000000000000000000000000000000000000001";
	const SIGNATURE: &'static str = "a199fb39e11eefb61c78a4074a53c0d4424600a3e74aad4fb9d93a26c30d067e\
		1d4d29936de0c73f19827394a1dd049480a0d581aee7ae7546968da7d3d1c2fd01";
	const THRESHOLD: &'static str = "2";
	const COMMON_POINT: &'static str = "b486d3840218837b035c66196ecb15e6b067ca20101e11bd5e626288ab6806\
		ecc70b8307012626bd512bad1559112d11d21025cef48cc7a1d2f3976da08f36c8";
	const ENCRYPTED_POINT: &'static str = "1395568277679f7f583ab7c0992da35f26cde57149ee70e524e49bdae62d\
		b3e18eb96122501e7cbb798b784395d7bb5a499edead0706638ad056d886e56cf8fb";
	const MESSAGE_HASH: &'static str = "281b6bf43cb86d0dc7b98e1b7def4a80f3ce16d28d2308f934f116767306f06c";
	const NODE1_ADDRESS: &'static str = "9aa83d4e5ae7a548e34f3b54a713a4f28d876bb8";
	const NODE2_ADDRESS: &'static str = "de925758b13aa7ea104d233888d970feb73b7dad";
	const OLD_SET_SIGNATURE: &'static str = "a199fb39e11eefb61c78a4074a53c0d4424600a3e74aad4fb9d93a26\
		c30d067e1d4d29936de0c73f19827394a1dd049480a0d581aee7ae7546968da7d3d1c2fd01";
	const NEW_SET_SIGNATURE: &'static str = "b199fb39e11eefb61c78a4074a53c0d4424600a3e74aad4fb9d93a26\
		c30d067e1d4d29936de0c73f19827394a1dd049480a0d581aee7ae7546968da7d3d1c2fd01";


	fn prepare_request(method: Method, uri_path: String) -> DecomposedRequest {
		DecomposedRequest {
			uri: Uri::builder().path_and_query(uri_path.as_str()).build().unwrap(),
			method,
			header_origin: None,
			header_host: None,
			body: Vec::new(),
		}
	}

	#[test]
	fn parse_http_request_successful() {
		assert_eq!(
			parse_http_request(&prepare_request(
				Method::POST,
				format!("/shadow/{}/{}/{}", KEY_ID, SIGNATURE, THRESHOLD),
			)).unwrap(),
			ServiceTask::GenerateServerKey(
				ServerKeyId::from_str(KEY_ID).unwrap(),
				Requester::Signature(SIGNATURE.parse().unwrap()),
				THRESHOLD.parse().unwrap(),
		));
		assert_eq!(
			parse_http_request(&prepare_request(
				Method::POST,
				format!("/shadow/{}/{}/{}/{}", KEY_ID, SIGNATURE, COMMON_POINT, ENCRYPTED_POINT),
			)).unwrap(),
			ServiceTask::StoreDocumentKey(
				ServerKeyId::from_str(KEY_ID).unwrap(),
				Requester::Signature(SIGNATURE.parse().unwrap()),
				COMMON_POINT.parse().unwrap(),
				ENCRYPTED_POINT.parse().unwrap(),
		));
		assert_eq!(
			parse_http_request(&prepare_request(
				Method::POST,
				format!("/{}/{}/{}", KEY_ID, SIGNATURE, THRESHOLD),
			)).unwrap(),
			ServiceTask::GenerateDocumentKey(
				ServerKeyId::from_str(KEY_ID).unwrap(),
				Requester::Signature(SIGNATURE.parse().unwrap()),
				THRESHOLD.parse().unwrap(),
		));
		assert_eq!(
			parse_http_request(&prepare_request(
				Method::GET,
				format!("/server/{}/{}", KEY_ID, SIGNATURE),
			)).unwrap(),
			ServiceTask::RetrieveServerKey(
				ServerKeyId::from_str(KEY_ID).unwrap(),
				Some(Requester::Signature(SIGNATURE.parse().unwrap())),
		));
		assert_eq!(
			parse_http_request(&prepare_request(
				Method::GET,
				format!("/{}/{}", KEY_ID, SIGNATURE),
			)).unwrap(),
			ServiceTask::RetrieveDocumentKey(
				ServerKeyId::from_str(KEY_ID).unwrap(),
				Requester::Signature(SIGNATURE.parse().unwrap()),
		));
		assert_eq!(
			parse_http_request(&prepare_request(
				Method::GET,
				format!("/{}/{}", KEY_ID_ENCODED, SIGNATURE),
			)).unwrap(),
			ServiceTask::RetrieveDocumentKey(
				ServerKeyId::from_str(KEY_ID).unwrap(),
				Requester::Signature(SIGNATURE.parse().unwrap()),
		));
		assert_eq!(
			parse_http_request(&prepare_request(
				Method::GET,
				format!("/shadow/{}/{}", KEY_ID, SIGNATURE),
			)).unwrap(),
			ServiceTask::RetrieveShadowDocumentKey(
				ServerKeyId::from_str(KEY_ID).unwrap(),
				Requester::Signature(SIGNATURE.parse().unwrap()),
		));
		assert_eq!(
			parse_http_request(&prepare_request(
				Method::GET,
				format!("/schnorr/{}/{}/{}", KEY_ID, SIGNATURE, MESSAGE_HASH),
			)).unwrap(),
			ServiceTask::SchnorrSignMessage(
				ServerKeyId::from_str(KEY_ID).unwrap(),
				Requester::Signature(SIGNATURE.parse().unwrap()),
				MESSAGE_HASH.parse().unwrap(),
		));
		assert_eq!(
			parse_http_request(&prepare_request(
				Method::GET,
				format!("/ecdsa/{}/{}/{}", KEY_ID, SIGNATURE, MESSAGE_HASH),
			)).unwrap(),
			ServiceTask::EcdsaSignMessage(
				ServerKeyId::from_str(KEY_ID).unwrap(),
				Requester::Signature(SIGNATURE.parse().unwrap()),
				MESSAGE_HASH.parse().unwrap(),
		));

		let mut servers_set_change_request = prepare_request(
			Method::POST,
			format!("/admin/servers_set_change/{}/{}", OLD_SET_SIGNATURE, NEW_SET_SIGNATURE),
		);
		servers_set_change_request.body = format!("[\"0x{}\",\"0x{}\"]", NODE1_ADDRESS, NODE2_ADDRESS).as_bytes().to_vec();
				assert_eq!(
			parse_http_request(&servers_set_change_request).unwrap(),
			ServiceTask::ChangeServersSet(
				OLD_SET_SIGNATURE.parse().unwrap(),
				NEW_SET_SIGNATURE.parse().unwrap(),
				vec![
					NODE1_ADDRESS.parse().unwrap(),
					NODE2_ADDRESS.parse().unwrap(),
				].into_iter().collect(),
		));
	}

	#[test]
	fn parse_request_failed() {
		assert_matches!(
			parse_http_request(&prepare_request(
				Method::GET,
				format!(""),
			)).unwrap_err(),
			Error::InvalidRequest
		);
		assert_matches!(
			parse_http_request(&prepare_request(
				Method::GET,
				format!("/shadow"),
			)).unwrap_err(),
			Error::InvalidRequest
		);
		assert_matches!(
			parse_http_request(&prepare_request(
				Method::GET,
				format!("///2"),
			)).unwrap_err(),
			Error::InvalidRequest
		);
		assert_matches!(
			parse_http_request(&prepare_request(
				Method::GET,
				format!("/shadow///2"),
			)).unwrap_err(),
			Error::InvalidRequest
		);
		assert_matches!(
			parse_http_request(&prepare_request(
				Method::GET,
				format!("/{}", KEY_ID),
			)).unwrap_err(),
			Error::InvalidRequest
		);
		assert_matches!(
			parse_http_request(&prepare_request(
				Method::GET,
				format!("/{}/", KEY_ID),
			)).unwrap_err(),
			Error::InvalidRequest
		);
		assert_matches!(
			parse_http_request(&prepare_request(
				Method::GET,
				format!("/a/b"),
			)).unwrap_err(),
			Error::InvalidRequest
		);
		assert_matches!(
			parse_http_request(&prepare_request(
				Method::GET,
				format!("/schnorr/{}/{}/{}/{}", KEY_ID, SIGNATURE, MESSAGE_HASH, THRESHOLD),
			)).unwrap_err(),
			Error::InvalidRequest
		);
		assert_matches!(
			parse_http_request(&prepare_request(
				Method::GET,
				format!("/ecdsa/{}/{}/{}/{}", KEY_ID, SIGNATURE, MESSAGE_HASH, THRESHOLD),
			)).unwrap_err(),
			Error::InvalidRequest
		);
		assert_matches!(
			parse_http_request(&prepare_request(
				Method::POST,
				format!("/admin/servers_set_change/{}/{}", OLD_SET_SIGNATURE, NEW_SET_SIGNATURE),
			)).unwrap_err(),
			Error::InvalidRequest
		);
	}
}
