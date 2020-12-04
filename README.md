# Secret-Store 2.0
The work is in progress. Please do not use it in production.

# Secret-Store 1.0
To reference this version of Secret Store, use [this commit](https://github.com/paritytech/secret-store/commit/ebe751db6af07425d2e1823ac05a84d0fafe3dad).

This is Parity Secret Store. Detailed information about the solution can be found on [OpenEthereum wiki](https://openethereum.github.io/Secret-Store.html)

The entry point for the library is the method for launching new key server instance:

```
pub fn start(trusted_client: Arc<dyn SecretStoreChain>, self_key_pair: Arc<dyn SigningKeyPair>, mut config: ServiceConfiguration,
	db: Arc<dyn KeyValueDB>, executor: Executor) -> Result<Box<dyn KeyServer>, Error>
```

The client has to provide its own implementations of SecretStoreChain, key pair, database instance and configuration parameters.
For the reference implementation see the corresponding code in Parity Ethereum client:

https://github.com/paritytech/parity-ethereum/blob/master/parity/secretstore/server.rs

