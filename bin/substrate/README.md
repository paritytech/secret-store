# Secret Store for Substrate

More docs will be added later...

## Quick start

```bash
#!/bin/bash
set -e

rm -rf db
rm -rf ssdb.1
rm -rf ssdb.2
rm -rf ssdb.3
rm -rf ssdb.4

cargo build --manifest-path=../secret-store/Cargo.toml -p parity-secretstore-substrate-node
cp ../secret-store/target/debug/parity-secretstore-substrate-node .
cargo build --manifest-path=../secret-store/Cargo.toml -p parity-secretstore-substrate
cp ../secret-store/target/debug/parity-secretstore-substrate .

RUST_LOG=sc_rpc=trace,txpool=trace,txqueue=trace unbuffer ./parity-secretstore-substrate-node --dev --base-path db 2>&1 | unbuffer -p gawk '{ print strftime("Node: [%Y-%m-%d %H:%M:%S]"), $0 }' | unbuffer -p tee ssnode.log&
sleep 10
RUST_LOG=secretstore=trace,secretstore_net=trace unbuffer ./parity-secretstore-substrate --self-secret=0101010101010101010101010101010101010101010101010101010101010101 --db-path=ssdb.1 --net-port=10000 --sub-signer=//Alice 2>&1 | unbuffer -p gawk '{ print strftime("Alice: [%Y-%m-%d %H:%M:%S]"), $0 }' | unbuffer -p tee ssalice.log&
RUST_LOG=secretstore=trace,secretstore_net=trace unbuffer ./parity-secretstore-substrate --self-secret=0202020202020202020202020202020202020202020202020202020202020202 --db-path=ssdb.2 --net-port=10001 --sub-signer=//Bob 2>&1 | unbuffer -p gawk '{ print strftime("Bob: [%Y-%m-%d %H:%M:%S]"), $0 }' | unbuffer -p tee ssbob.log&
RUST_LOG=secretstore=trace,secretstore_net=trace unbuffer ./parity-secretstore-substrate --self-secret=0303030303030303030303030303030303030303030303030303030303030303 --db-path=ssdb.3 --net-port=10002 --sub-signer=//Charlie 2>&1 | unbuffer -p gawk '{ print strftime("Charlie: [%Y-%m-%d %H:%M:%S]"), $0 }' | unbuffer -p tee sscharlie.log&
RUST_LOG=secretstore=trace,secretstore_net=trace unbuffer ./parity-secretstore-substrate --self-secret=0404040404040404040404040404040404040404040404040404040404040404 --db-path=ssdb.4 --net-port=10003 --sub-signer=//Dave 2>&1 | unbuffer -p gawk '{ print strftime("Dave: [%Y-%m-%d %H:%M:%S]"), $0 }' | unbuffer -p tee ssdave.log&
```
