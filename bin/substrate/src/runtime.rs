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

//! The binary is 'generic' over runtime in its own way - you need to define
//! runtime types (or aliases) and methods here. Or course after fixing refernces
//! in Cargo.toml.

use codec::Encode;
use sp_core::crypto::Pair as _;
use sp_runtime::traits::{IdentifyAccount, NumberFor};

/// System::events storage key. Calculated as:
/// twox_128(b"System").to_vec() ++ twox_128(b"Events").to_vec()
pub const SYSTEM_EVENTS_KEY: &'static str = "26aa394eea5630e07c48ae0c9558cef780d41e5e16056765bc8461851072c9d7";

/// Block hash type.
pub type BlockHash = substrate_runtime::Hash;
/// Block number type.
pub type BlockNumber = NumberFor<substrate_runtime::Block>;
/// Transaction hash type.
pub type TransactionHash = substrate_runtime::Hash;
/// Block header type.
pub type Header = substrate_runtime::Header;
/// Block event type.
pub type Event = substrate_runtime::Event;
/// Runtime call type.
pub type Call = substrate_runtime::Call;
/// Secret Store runtiem call type.
pub type SecretStoreCall = substrate_runtime::SecretStoreCall<Runtime>;
/// Runtime itself.
pub type Runtime = substrate_runtime::Runtime;
/// Signed payload of the runtime.
pub type SignedPayload = substrate_runtime::SignedPayload;
/// Unchecked extrinsic of the runtime.
pub type UncheckedExtrinsic = substrate_runtime::UncheckedExtrinsic;

/// Account ID of the runtime.
pub type AccountId = substrate_runtime::AccountId;
/// Account balance of the runtime.
pub type Balance = substrate_runtime::Balance;
/// Account index of the runtime.
pub type Index = substrate_runtime::Index;

/// Crypto pair that is used to sign transactions.
pub type Pair = sp_core::sr25519::Pair;

/// Create signer from given SURI and password.
pub fn create_transaction_signer(
	signer_uri: &str,
	signer_password: Option<&str>,
) -> Result<Pair, String> {
	Pair::from_string(signer_uri, signer_password)
		.map_err(|err| format!("Failed to create signer Pair: {:?}", err))
}

/// Encode and sign runtime transaction.
pub fn create_transaction(
	call: Call,
	signer: &Pair,
	index: Index,
	genesis_hash: BlockHash,
	runtime_version: u32,
) -> UncheckedExtrinsic {
	let extra = |i: Index, f: Balance| {
		(
			frame_system::CheckVersion::<Runtime>::new(),
			frame_system::CheckGenesis::<Runtime>::new(),
			frame_system::CheckEra::<Runtime>::from(sp_runtime::generic::Era::Immortal),
			frame_system::CheckNonce::<Runtime>::from(i),
			frame_system::CheckWeight::<Runtime>::new(),
			pallet_transaction_payment::ChargeTransactionPayment::<Runtime>::from(f),
		)
	};
	let raw_payload = SignedPayload::from_raw(
		call,
		extra(index, 0),
		(
			runtime_version,
			genesis_hash,
			genesis_hash,
			(),
			(),
			(),
		),
	);
	let signature = raw_payload.using_encoded(|payload| signer.sign(payload));
	let signer: sp_runtime::MultiSigner = signer.public().into();
	let (function, extra, _) = raw_payload.deconstruct();

	UncheckedExtrinsic::new_signed(
		function,
		signer.into_account().into(),
		signature.into(),
		extra,
	)
}
