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

use std::{future::Future, sync::Arc};
use futures::future::{FutureExt, TryFutureExt, ready};
use hyper::{
	Body, Method, Request, Response, Server, StatusCode, Uri,
	header::{self, HeaderValue},
	service::{make_service_fn, service_fn},
};
use jsonrpc_server_utils::cors::{self, AllowCors, AccessControlAllowOrigin};
use log::error;
use serde::Serialize;
use primitives::{
	Public, ecies_encrypt,
	error::Error as SecretStoreError,
	key_server::{DocumentKeyStoreArtifacts, DocumentKeyShadowRetrievalArtifacts, KeyServer},
	serialization::{SerializableBytes, SerializablePublic, SerializableEncryptedDocumentKeyShadow},
	service::ServiceTask,
};

mod parse;

type CorsDomains = Option<Vec<AccessControlAllowOrigin>>;

/// All possible errors.
#[derive(Debug)]
pub enum Error {
	/// Invalid listen address.
	InvalidListenAddress(String),
	/// Request has failed because of unauthorized Origin header.
	InvalidCors,
	/// Failed to parse HTTP request.
	InvalidRequest,
	/// Error from Hyper.
	Hyper(hyper::Error),
	/// Error from Secret Store.
	SecretStore(SecretStoreError),
}

/// Decomposed HTTP request.
#[derive(Debug, PartialEq)]
pub struct DecomposedRequest {
	/// Request URI.
	pub uri: Uri,
	/// Request method.
	pub method: Method,
	/// ORIGIN header field.
	pub header_origin: Option<String>,
	/// HOST header field.
	pub header_host: Option<String>,
	/// Request body.
	pub body: Vec<u8>,
}

/// Start listening HTTP requests on given address.
pub async fn start_service<KS: KeyServer>(
	listen_address: &str,
	listen_port: u16,
	key_server: Arc<KS>,
	cors: CorsDomains,
) -> Result<(), Error> {
	let cors = Arc::new(cors);
	let http_address = format!("{}:{}", listen_address, listen_port)
		.parse()
		.map_err(|err: std::net::AddrParseError| Error::InvalidListenAddress(format!("{}", err)))?;
	let http_server = Server::try_bind(&http_address)
		.map_err(|err| Error::InvalidListenAddress(format!("{}", err)))?;
	let http_service_fn = make_service_fn(move |_| {
		let key_server = key_server.clone();
		let cors = cors.clone();
		async move {
			Ok::<_, hyper::Error>(service_fn(
				move |http_request| serve_http_request(
					http_request,
					key_server.clone(),
					cors.clone(),
				)
			))
		}
	});
	let http_service = http_server.serve(http_service_fn);
	http_service.await.map_err(Error::Hyper)
}

/// Serve single HTTP request.
async fn serve_http_request<KS: KeyServer>(
	http_request: Request<Body>,
	key_server: Arc<KS>,
	cors_domains: Arc<CorsDomains>,
) -> Result<Response<Body>, hyper::Error> {
	match decompose_http_request(http_request).await {
		Ok(decomposed_request) => serve_decomposed_http_request(
			decomposed_request,
			key_server,
			cors_domains,
		).await,
		Err(error) => return Ok(return_error(error)),
	}
}

/// Serve single decomposed HTTP request.
async fn serve_decomposed_http_request<KS: KeyServer>(
	decomposed_request: DecomposedRequest,
	key_server: Arc<KS>,
	cors_domains: Arc<CorsDomains>,
) -> Result<Response<Body>, hyper::Error> {
	let allow_cors = match ensure_cors(&decomposed_request, cors_domains) {
		Ok(allow_cors) => allow_cors,
		Err(error) => return Ok(return_error(error)),
	};

	let service_task = match crate::parse::parse_http_request(&decomposed_request) {
		Ok(service_task) => service_task,
		Err(error) => return Ok(return_error(error)),
	};

	serve_service_task(
		decomposed_request,
		key_server,
		allow_cors,
		service_task,
	).await
}

/// Serve single service task.
async fn serve_service_task<KS: KeyServer>(
	decomposed_request: DecomposedRequest,
	key_server: Arc<KS>,
	allow_cors: AllowCors<AccessControlAllowOrigin>,
	service_task: ServiceTask,
) -> Result<Response<Body>, hyper::Error> {
	let log_secret_store_error = |error| {
		error!(
			target: "secretstore",
			"{} request {} has failed with: {}",
			decomposed_request.method,
			decomposed_request.uri,
			error,
		);

		Error::SecretStore(error)
	};

	match service_task {
		ServiceTask::GenerateServerKey(key_id, requester, threshold) =>
			Ok(return_unencrypted_server_key(
				&decomposed_request,
				allow_cors,
				key_server
					.generate_key(None, key_id, requester, threshold)
					.await
					.map(|artifacts| artifacts.key)
					.map_err(log_secret_store_error),
			)),
		ServiceTask::RetrieveServerKey(key_id, requester) =>
			Ok(return_unencrypted_server_key(
				&decomposed_request,
				allow_cors,
				key_server
					.restore_key_public(
						None,
						key_id,
						requester,
					)
					.await
					.map(|artifacts| artifacts.key)
					.map_err(log_secret_store_error),
			)),
		ServiceTask::GenerateDocumentKey(key_id, requester, threshold) =>
			Ok(return_encrypted_document_key(
				&decomposed_request,
				allow_cors,
				ready(requester.public(&key_id))
					.and_then(|requester_public|
						key_server
							.generate_document_key(None, key_id, requester, threshold)
							.map(Into::into)
							.and_then(move |artifacts| ready(ecies_encrypt(
								&requester_public,
								artifacts.document_key.as_bytes(),
							)))
					)
					.map_err(log_secret_store_error),
			).await),
		ServiceTask::StoreDocumentKey(key_id, requester, common_point, encrypted_point) =>
			Ok(return_empty(
				&decomposed_request,
				allow_cors,
				key_server
					.store_document_key(None, key_id, requester, common_point, encrypted_point)
					.await
					.map(Into::into)
					.map(|_: DocumentKeyStoreArtifacts| ())
					.map_err(log_secret_store_error),
			)),
		ServiceTask::RetrieveDocumentKey(key_id, requester) =>
			Ok(return_encrypted_document_key(
				&decomposed_request,
				allow_cors,
				ready(requester.public(&key_id))
					.and_then(|requester_public|
						key_server
							.restore_document_key(None, key_id, requester)
							.map(Into::into)
							.and_then(move |artifacts| ready(ecies_encrypt(
								&requester_public,
								artifacts.document_key.as_bytes(),
							)))
					)
					.map_err(log_secret_store_error)
			).await),
		ServiceTask::RetrieveShadowDocumentKey(key_id, requester) =>
			Ok(return_document_key_shadow(
				&decomposed_request,
				allow_cors,
				key_server
					.restore_document_key_shadow(None, key_id, requester)
					.await
					.map(Into::into)
					.map_err(log_secret_store_error),
			)),
		ServiceTask::SchnorrSignMessage(key_id, requester, message_hash) =>
			Ok(return_encrypted_message_signature(
				&decomposed_request,
				allow_cors,
				ready(requester.public(&key_id))
					.and_then(|requester_public|
						key_server
							.sign_message_schnorr(None, key_id, requester, message_hash)
							.map(Into::into)
							.and_then(|artifacts| {
								let mut combined_signature = [0; 64];
								combined_signature[..32].clone_from_slice(artifacts.signature_c.as_bytes());
								combined_signature[32..].clone_from_slice(artifacts.signature_s.as_bytes());
								ready(Ok(combined_signature))
							})
							.and_then(move |plain_signature| ready(ecies_encrypt(
								&requester_public,
								&plain_signature,
							)))
					)
					.map_err(log_secret_store_error)
			).await),
		ServiceTask::EcdsaSignMessage(key_id, requester, message_hash) =>
			Ok(return_encrypted_message_signature(
				&decomposed_request,
				allow_cors,
				ready(requester.public(&key_id))
					.and_then(|requester_public|
						key_server
							.sign_message_ecdsa(None, key_id, requester, message_hash)
							.map(Into::into)
							.and_then(move |artifacts| ready(ecies_encrypt(
								&requester_public,
								&*artifacts.signature,
							)))
					)
					.map_err(log_secret_store_error)
			).await),
		ServiceTask::ChangeServersSet(old_set_signature, new_set_signature, new_set) =>
			Ok(return_empty(
				&decomposed_request,
				allow_cors,
				key_server
					.change_servers_set(None, old_set_signature, new_set_signature, new_set)
					.await
					.map(Into::into)
					.map_err(log_secret_store_error),
			)),
	}
}

/// Decompose single HTTP request.
async fn decompose_http_request(
	http_request: Request<Body>,
) -> Result<DecomposedRequest, Error> {
	let uri = http_request.uri().clone();
	let method = http_request.method().clone();
	let header_origin = http_request
		.headers()
		.get(header::ORIGIN)
		.and_then(|value| value.to_str().ok())
		.map(Into::into);
	let header_host = http_request
		.headers()
		.get(header::HOST)
		.and_then(|value| value.to_str().ok())
		.map(Into::into);
	let body = hyper::body::to_bytes(http_request.into_body())
		.await
		.map_err(|error| {
			error!(
				target: "secretstore",
				"Failed to read body of {}-request {}: {}",
				method,
				uri,
				error,
			);

			Error::Hyper(error)
		})?.to_vec();

	Ok(DecomposedRequest {
		uri,
		method,
		header_origin,
		header_host,
		body,
	})
}

/// Check CORS rules.
fn ensure_cors(
	request: &DecomposedRequest,
	cors_domains: Arc<CorsDomains>,
) -> Result<AllowCors<AccessControlAllowOrigin>, Error> {
	let allow_cors = cors::get_cors_allow_origin(
		request.header_origin.as_ref().map(|s| s.as_ref()),
		request.header_host.as_ref().map(|s| s.as_ref()),
		&*cors_domains,
	);

	match allow_cors {
		AllowCors::Invalid => {
			error!(
				target: "secretstore",
				"Ignoring {}-request {} with unauthorized Origin header",
				request.method,
				request.uri,
			);

			Err(Error::InvalidCors)
		},
		_ => Ok(allow_cors),
	}
}

fn return_empty(
	request: &DecomposedRequest,
	allow_cors: AllowCors<AccessControlAllowOrigin>,
	empty: Result<(), Error>,
) -> Response<Body> {
	return_bytes::<i32>(request, allow_cors, empty.map(|_| None))
}

fn return_unencrypted_server_key(
	request: &DecomposedRequest,
	allow_cors: AllowCors<AccessControlAllowOrigin>,
	result: Result<Public, Error>,
) -> Response<Body> {
	return_bytes(request, allow_cors, result.map(|key| Some(SerializablePublic(key))))
}

async fn return_encrypted_document_key(
	request: &DecomposedRequest,
	allow_cors: AllowCors<AccessControlAllowOrigin>,
	encrypted_document_key: impl Future<Output=Result<Vec<u8>, Error>>,
) -> Response<Body> {
	return_bytes(
		request,
		allow_cors,
		encrypted_document_key
			.await
			.map(|key| Some(SerializableBytes(key))),
	)
}

fn return_document_key_shadow(
	request: &DecomposedRequest,
	allow_cors: AllowCors<AccessControlAllowOrigin>,
	document_key_shadow: Result<DocumentKeyShadowRetrievalArtifacts, Error>,
) -> Response<Body> {
	return_bytes(request, allow_cors, document_key_shadow.map(|k| Some(SerializableEncryptedDocumentKeyShadow {
		decrypted_secret: k.encrypted_document_key.into(),
		common_point: k.common_point.into(),
		decrypt_shadows: k
			.participants_coefficients
			.values()
			.cloned()
			.map(Into::into)
			.collect(),
	})))
}

async fn return_encrypted_message_signature(
	request: &DecomposedRequest,
	allow_cors: AllowCors<AccessControlAllowOrigin>,
	encrypted_signature: impl Future<Output=Result<Vec<u8>, Error>>,
) -> Response<Body> {
	return_bytes(
		request,
		allow_cors,
		encrypted_signature
			.await
			.map(|s| Some(SerializableBytes(s))),
	)
}

fn return_bytes<T: Serialize>(
	request: &DecomposedRequest,
	allow_cors: AllowCors<AccessControlAllowOrigin>,
	result: Result<Option<T>, Error>,
) -> Response<Body> {
	match result {
		Ok(Some(result)) => match serde_json::to_vec(&result) {
			Ok(result) => {
				let body: Body = result.into();
				let mut builder = Response::builder();
				builder = builder.header(
					header::CONTENT_TYPE,
					HeaderValue::from_static("application/json; charset=utf-8"),
				);
				if let AllowCors::Ok(AccessControlAllowOrigin::Value(origin)) = allow_cors {
					builder = builder.header(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin.to_string());
				}
				builder.body(body).expect("Error creating http response")
			},
			Err(err) => {
				error!(target: "secretstore", "Response to request {} has failed with: {}", request.uri, err);
				Response::builder()
					.status(StatusCode::INTERNAL_SERVER_ERROR)
					.body(Body::empty())
					.expect("Nothing to parse, cannot fail; qed")
			}
		},
		Ok(None) => {
			let mut builder = Response::builder();
			builder = builder.status(StatusCode::OK);
			if let AllowCors::Ok(AccessControlAllowOrigin::Value(origin)) = allow_cors {
				builder = builder.header(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin.to_string());
			}
			builder.body(Body::empty()).expect("Nothing to parse, cannot fail; qed")
		},
		Err(err) => return_error(err),
	}
}

fn return_error(err: Error) -> Response<Body> {
	let status = match err {
		Error::SecretStore(SecretStoreError::AccessDenied)
		| Error::SecretStore(SecretStoreError::ConsensusUnreachable)
		| Error::SecretStore(SecretStoreError::ConsensusTemporaryUnreachable) =>
			StatusCode::FORBIDDEN,
		| Error::SecretStore(SecretStoreError::ServerKeyIsNotFound)
		| Error::SecretStore(SecretStoreError::DocumentKeyIsNotFound) =>
			StatusCode::NOT_FOUND,
		Error::InvalidCors
		| Error::InvalidRequest
		| Error::SecretStore(SecretStoreError::InsufficientRequesterData(_))
		| Error::Hyper(_)
		| Error::SecretStore(SecretStoreError::Hyper(_))
		| Error::SecretStore(SecretStoreError::Serde(_))
		| Error::SecretStore(SecretStoreError::DocumentKeyAlreadyStored)
		| Error::SecretStore(SecretStoreError::ServerKeyAlreadyGenerated) =>
			StatusCode::BAD_REQUEST,
		_ => StatusCode::INTERNAL_SERVER_ERROR,
	};

	let mut res = Response::builder();
	res = res.status(status);

	// return error text. ignore errors when returning error
	let error_text = format!("\"{}\"", err);
	if let Ok(error_text) = serde_json::to_vec(&error_text) {
		res = res.header(header::CONTENT_TYPE, HeaderValue::from_static("application/json; charset=utf-8"));
		res.body(error_text.into())
			.expect("`error_text` is a formatted string, parsing cannot fail; qed")
	} else {
		res.body(Body::empty())
			.expect("Nothing to parse, cannot fail; qed")
	}
}

impl std::fmt::Display for Error {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
		match *self {
			Error::InvalidListenAddress(ref msg) => write!(f, "Invalid listen address: {}", msg),
			Error::InvalidCors => write!(f, "Request with unauthorized Origin header"),
			Error::InvalidRequest => write!(f, "Failed to parse request"),
			Error::Hyper(ref error) => write!(f, "Internal server error: {}", error),
			Error::SecretStore(ref error) => write!(f, "Secret store error: {}", error),
		}
	}
}

#[cfg(test)]
mod tests {
	use assert_matches::assert_matches;
	use primitives::{requester::Requester, key_server::AccumulatingKeyServer};
	use super::*;

	fn default_decomposed_request() -> DecomposedRequest {
		DecomposedRequest {
			uri: "http://some-uri/generate-server-key".parse().unwrap(),
			method: Method::POST,
			header_origin: Some("some-origin".into()),
			header_host: Some("some-host".into()),
			body: "Hello, world!".bytes().collect(),
		}
	}

	fn assert_access_denied_response(response: Response<Body>) {
		assert_eq!(response.status(), StatusCode::FORBIDDEN);
		assert_eq!(
			futures::executor::block_on(hyper::body::to_bytes(response.into_body())).unwrap(),
			serde_json::to_vec(&format!("\"{}\"", Error::SecretStore(SecretStoreError::AccessDenied))).unwrap(),
		);
	}

	#[test]
	fn decompose_http_request_works() {
		assert_eq!(
			futures::executor::block_on(decompose_http_request(
				Request::builder()
					.uri("http://some-uri/generate-server-key")
					.method(Method::POST)
					.header(header::ORIGIN, "some-origin")
					.header(header::HOST, "some-host")
					.body(Body::wrap_stream(
						futures::stream::iter(
							vec![Result::<_, std::io::Error>::Ok("Hello, world!")],
					)))
					.unwrap()
			)).unwrap(),
			default_decomposed_request(),
		);
	}

	#[test]
	fn decompose_http_request_fails() {
		assert_matches!(
			futures::executor::block_on(decompose_http_request(
				Request::builder()
					.body(Body::wrap_stream(
						futures::stream::iter(
							vec![Result::<&'static str, _>::Err(
								std::io::Error::new(std::io::ErrorKind::Other, "Test error"),
							)],
						)
					))
					.unwrap()
			)),
			Err(Error::Hyper(_))
		);
	}

	#[test]
	fn ensure_cors_works() {
		let mut request = default_decomposed_request();
		assert_matches!(ensure_cors(&request, Arc::new(None)), Ok(_));
		request.header_origin = None;
		assert_matches!(
			ensure_cors(&request, Arc::new(Some(vec![AccessControlAllowOrigin::Null]))),
			Ok(_)
		);
	}

	#[test]
	fn ensure_cors_fails() {
		assert_matches!(
			ensure_cors(
				&default_decomposed_request(),
				Arc::new(Some(vec![
					AccessControlAllowOrigin::Value("xxx".into()),
				])),
			),
			Err(Error::InvalidCors)
		);
	}

	#[test]
	fn return_empty_ok_works() {
		let response = return_empty(
			&default_decomposed_request(),
			AllowCors::NotRequired,
			Ok(()),
		);
		assert_eq!(response.status(), StatusCode::OK);
		assert_eq!(
			futures::executor::block_on(hyper::body::to_bytes(response.into_body())).unwrap(),
			Vec::new(),
		);
	}

	#[test]
	fn return_empty_err_works() {
		assert_access_denied_response(return_empty(
			&default_decomposed_request(),
			AllowCors::NotRequired,
			Err(Error::SecretStore(SecretStoreError::AccessDenied)),
		));
	}

	#[test]
	fn return_unencrypted_server_key_ok_works() {
		let response = return_unencrypted_server_key(
			&default_decomposed_request(),
			AllowCors::NotRequired,
			Ok([1u8; 64].into()),
		);
		assert_eq!(response.status(), StatusCode::OK);
		assert_eq!(
			futures::executor::block_on(hyper::body::to_bytes(response.into_body())).unwrap(),
			"\"0x01010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101\"",
		);
	}

	#[test]
	fn return_unencrypted_server_key_err_works() {
		assert_access_denied_response(return_unencrypted_server_key(
			&default_decomposed_request(),
			AllowCors::NotRequired,
			Err(Error::SecretStore(SecretStoreError::AccessDenied)),
		));
	}

	#[test]
	fn return_encrypted_document_key_ok_works() {
		let response = futures::executor::block_on(
			return_encrypted_document_key(
				&default_decomposed_request(),
				AllowCors::NotRequired,
				ready(Ok(vec![0x42])),
			)
		);
		assert_eq!(response.status(), StatusCode::OK);
		assert_eq!(
			futures::executor::block_on(hyper::body::to_bytes(response.into_body())).unwrap(),
			"\"0x42\"",
		);
	}

	#[test]
	fn return_encrypted_document_key_err_works() {
		assert_access_denied_response(futures::executor::block_on(
			return_encrypted_document_key(
				&default_decomposed_request(),
				AllowCors::NotRequired,
				ready(Err(Error::SecretStore(SecretStoreError::AccessDenied))),
			)
		));
	}

	#[test]
	fn return_document_key_shadow_ok_works() {
		let response = return_document_key_shadow(
			&default_decomposed_request(),
			AllowCors::NotRequired,
			Ok(DocumentKeyShadowRetrievalArtifacts {
				common_point: [1u8; 64].into(),
				threshold: 42,
				encrypted_document_key: [2u8; 64].into(),
				participants_coefficients: vec![
					([1u8; 20].into(), vec![0x42]),
					([2u8; 20].into(), vec![0x43]),
				].into_iter().collect(),
			}),
		);
		assert_eq!(response.status(), StatusCode::OK);
		assert_eq!(
			futures::executor::block_on(hyper::body::to_bytes(response.into_body())).unwrap(),
			"{\
				\"decrypted_secret\":\"0x02020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202\",\
				\"common_point\":\"0x01010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101\",\
				\"decrypt_shadows\":[\"0x42\",\"0x43\"]\
			}",
		);
	}

	#[test]
	fn return_document_key_shadow_err_works() {
		assert_access_denied_response(return_document_key_shadow(
			&default_decomposed_request(),
			AllowCors::NotRequired,
			Err(Error::SecretStore(SecretStoreError::AccessDenied)),
		));
	}

	#[test]
	fn return_encrypted_message_signature_ok_works() {
		let response = futures::executor::block_on(
			return_encrypted_message_signature(
				&default_decomposed_request(),
				AllowCors::NotRequired,
				ready(Ok(vec![0x42])),
			)
		);
		assert_eq!(response.status(), StatusCode::OK);
		assert_eq!(
			futures::executor::block_on(hyper::body::to_bytes(response.into_body())).unwrap(),
			"\"0x42\"",
		);
	}

	#[test]
	fn return_encrypted_message_signature_err_works() {
		assert_access_denied_response(futures::executor::block_on(
			return_encrypted_message_signature(
				&default_decomposed_request(),
				AllowCors::NotRequired,
				ready(Err(Error::SecretStore(SecretStoreError::AccessDenied))),
			)
		));
	}

	#[test]
	fn serve_decomposed_http_request_schedules_generate_server_key_request() {
		let key_server = Arc::new(AccumulatingKeyServer::default());
		let service_task = ServiceTask::GenerateServerKey(
			[1u8; 32].into(),
			Requester::Address([2u8; 20].into()),
			42,
		);
		futures::executor::block_on(serve_service_task(
			default_decomposed_request(),
			key_server.clone(),
			AllowCors::NotRequired,
			service_task.clone(),
		)).unwrap();
		assert_eq!(key_server.accumulated_tasks(), vec![service_task]);
	}

	#[test]
	fn serve_decomposed_http_request_schedules_retrieve_server_key_request() {
		let key_server = Arc::new(AccumulatingKeyServer::default());
		let service_task = ServiceTask::RetrieveServerKey(
			[1u8; 32].into(),
			Some(Requester::Address([2u8; 20].into())),
		);
		futures::executor::block_on(serve_service_task(
			default_decomposed_request(),
			key_server.clone(),
			AllowCors::NotRequired,
			service_task.clone(),
		)).unwrap();
		assert_eq!(key_server.accumulated_tasks(), vec![service_task]);
	}

	#[test]
	fn serve_decomposed_http_request_schedules_generate_document_key_request() {
		let key_server = Arc::new(AccumulatingKeyServer::default());
		let service_task = ServiceTask::GenerateDocumentKey(
			[1u8; 32].into(),
			Requester::Public([2u8; 64].into()),
			42,
		);
		futures::executor::block_on(serve_service_task(
			default_decomposed_request(),
			key_server.clone(),
			AllowCors::NotRequired,
			service_task.clone(),
		)).unwrap();
		assert_eq!(key_server.accumulated_tasks(), vec![service_task]);
	}

	#[test]
	fn serve_decomposed_http_request_schedules_store_document_key_request() {
		let key_server = Arc::new(AccumulatingKeyServer::default());
		let service_task = ServiceTask::StoreDocumentKey(
			[1u8; 32].into(),
			Requester::Public([2u8; 64].into()),
			[3u8; 64].into(),
			[4u8; 64].into(),
		);
		futures::executor::block_on(serve_service_task(
			default_decomposed_request(),
			key_server.clone(),
			AllowCors::NotRequired,
			service_task.clone(),
		)).unwrap();
		assert_eq!(key_server.accumulated_tasks(), vec![service_task]);
	}

	#[test]
	fn serve_decomposed_http_request_schedules_retrieve_document_key_request() {
		let key_server = Arc::new(AccumulatingKeyServer::default());
		let service_task = ServiceTask::RetrieveDocumentKey(
			[1u8; 32].into(),
			Requester::Public([2u8; 64].into()),
		);
		futures::executor::block_on(serve_service_task(
			default_decomposed_request(),
			key_server.clone(),
			AllowCors::NotRequired,
			service_task.clone(),
		)).unwrap();
		assert_eq!(key_server.accumulated_tasks(), vec![service_task]);
	}

	#[test]
	fn serve_decomposed_http_request_schedules_retrieve_document_key_shadow_request() {
		let key_server = Arc::new(AccumulatingKeyServer::default());
		let service_task = ServiceTask::RetrieveShadowDocumentKey(
			[1u8; 32].into(),
			Requester::Public([2u8; 64].into()),
		);
		futures::executor::block_on(serve_service_task(
			default_decomposed_request(),
			key_server.clone(),
			AllowCors::NotRequired,
			service_task.clone(),
		)).unwrap();
		assert_eq!(key_server.accumulated_tasks(), vec![service_task]);
	}

	#[test]
	fn serve_decomposed_http_request_schedules_schnorr_sign_message_request() {
		let key_server = Arc::new(AccumulatingKeyServer::default());
		let service_task = ServiceTask::SchnorrSignMessage(
			[1u8; 32].into(),
			Requester::Public([2u8; 64].into()),
			[3u8; 32].into(),
		);
		futures::executor::block_on(serve_service_task(
			default_decomposed_request(),
			key_server.clone(),
			AllowCors::NotRequired,
			service_task.clone(),
		)).unwrap();
		assert_eq!(key_server.accumulated_tasks(), vec![service_task]);
	}

	#[test]
	fn serve_decomposed_http_request_schedules_ecdsa_sign_message_request() {
		let key_server = Arc::new(AccumulatingKeyServer::default());
		let service_task = ServiceTask::EcdsaSignMessage(
			[1u8; 32].into(),
			Requester::Public([2u8; 64].into()),
			[3u8; 32].into(),
		);
		futures::executor::block_on(serve_service_task(
			default_decomposed_request(),
			key_server.clone(),
			AllowCors::NotRequired,
			service_task.clone(),
		)).unwrap();
		assert_eq!(key_server.accumulated_tasks(), vec![service_task]);
	}

	#[test]
	fn serve_decomposed_http_request_schedules_change_servers_set_request() {
		let key_server = Arc::new(AccumulatingKeyServer::default());
		let service_task = ServiceTask::ChangeServersSet(
			[1u8; 65].into(),
			[2u8; 65].into(),
			vec![
				[3u8; 20].into(),
				[4u8; 20].into(),
			].into_iter().collect(),
		);
		futures::executor::block_on(serve_service_task(
			default_decomposed_request(),
			key_server.clone(),
			AllowCors::NotRequired,
			service_task.clone(),
		)).unwrap();
		assert_eq!(key_server.accumulated_tasks(), vec![service_task]);
	}
}
