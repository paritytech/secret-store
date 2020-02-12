# secret-store
This is Parity Secret Store. Detailed information about the solution can be found on [Parity wiki](https://wiki.parity.io/Secret-Store)

The entry point for the library is the method for launching new key server instance:

```
pub fn start(trusted_client: Arc<dyn SecretStoreChain>, self_key_pair: Arc<dyn SigningKeyPair>, mut config: ServiceConfiguration,
	db: Arc<dyn KeyValueDB>, executor: Executor) -> Result<Box<dyn KeyServer>, Error>
```

The client has to provide its own implementations of SecretStoreChain, key pair, database instance and configuration parameters.
For the reference implementation see the corresponding code in Parity Ethereum client:

https://github.com/paritytech/parity-ethereum/blob/master/parity/secretstore/server.rs

