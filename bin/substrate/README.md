# Secret Store for Substrate

More docs will be added later...

## Quick start: running key servers

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

## Quick start: generating, storing and retrieving keys

```bash
# //Alice claims 'ownership' of key 0x0101010101010101010101010101010101010101010101010101010101010101
./parity-secretstore-substrate submit-transaction --wait-processed --transaction="ClaimKey(0x0101010101010101010101010101010101010101010101010101010101010101)"
2020-03-27 12:33:36  INFO secretstore Transaction has been accepted to Ready queue
2020-03-27 12:33:42  INFO secretstore Transaction is mined in block: 0x84cd4b2433546d146b33968f66989f2dc2916a04d973e3e82ebbf7d015394b18

# //Alice asks to generate server key 0x0101010101010101010101010101010101010101010101010101010101010101
# with threshold = 1
./parity-secretstore-substrate submit-transaction --wait-processed --transaction="GenerateServerKey(0101010101010101010101010101010101010101010101010101010101010101, 1)"
2020-03-27 12:34:00  INFO secretstore Transaction has been accepted to Ready queue
2020-03-27 12:34:06  INFO secretstore Transaction is mined in block: 0xf472aefc1436c5d687876f3c4a563a08af042badef4a5371787645a470669b33
2020-03-27 12:34:19  INFO secretstore Transaction block is finalized: 0xf472aefc1436c5d687876f3c4a563a08af042badef4a5371787645a470669b33
2020-03-27 12:34:24  INFO secretstore Server key has been generated: 0x126e2601cdb257e089685a5ab9978c417cf7e75b0d45d9c07c00fdacb4b00f58196717456eaf3bf1d3edfa776d035a469542668c0bbd78817e1dfae80ecaa434

# //Alice generates document key (offline operation).
#
# Single key is generated, but it comes in two forms:
# 1) common and encrypted point is the input data for StoreDocumentKey transaction;
# 2) encrypted key could be used to encrypt arbitrary message locally.
./parity-secretstore-substrate generate-document-key --server-key=0x126e2601cdb257e089685a5ab9978c417cf7e75b0d45d9c07c00fdacb4b00f58196717456eaf3bf1d3edfa776d035a469542668c0bbd78817e1dfae80ecaa434 --author-key=0x1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f70beaf8f588b541507fed6a642c5ab42dfdf8120a7f639de5122d47a69a8e8d1
2020-03-27 12:35:11  INFO secretstore Common point: 0x12e20fd9ab6697e120a47ff1f278d3c85ef20d7044f6bcc780801c5bc2ee1be574dd69772ebab548ddddc6e901cbc2a5362e3fb920367898ab8749d09297a1ee
2020-03-27 12:35:11  INFO secretstore Encrypted point: 0x6e21608df33c8927abc756a8f7c71998728bf4be0ae0f09b1780ac6a4c83f86251a710d29b3cfe17129f0a5612c5f2b0fb9a2fb20011dab3623a86460b58d80b
2020-03-27 12:35:11  INFO secretstore Encrypted key: 0x0417cabe0bd7df0a8f1034d5fe99e8ce7ef81e5802acdb33ef977b2812a9f0cac5d8fd9cc534d75bb6079f56d6b6392ef8b73abfaf636eec54bebd5ac1ae6ae2457cff98454326d6ec711da12fc08c4dbf9f3565d8254aa9f89c8f94685d322cc1babca189cebe624ba3e8b3cc8bc2b46a979fcf5b2995a2de148d9e4cf15ff79b7eb2ed1e7d7aa1ccc4929676c114f4df39687c9a4bd44bc3c6f4e1a23a718113ccc4d1a2fde29e5a625322db642f573c

# //Alice encrypts message (offline operation).
#
# Encrypted message can now be shared, but only //Alice has access to the key.
./parity-secretstore-substrate encrypt-message --encrypted-document-key=0x0417cabe0bd7df0a8f1034d5fe99e8ce7ef81e5802acdb33ef977b2812a9f0cac5d8fd9cc534d75bb6079f56d6b6392ef8b73abfaf636eec54bebd5ac1ae6ae2457cff98454326d6ec711da12fc08c4dbf9f3565d8254aa9f89c8f94685d322cc1babca189cebe624ba3e8b3cc8bc2b46a979fcf5b2995a2de148d9e4cf15ff79b7eb2ed1e7d7aa1ccc4929676c114f4df39687c9a4bd44bc3c6f4e1a23a718113ccc4d1a2fde29e5a625322db642f573c --author-secret=0x0101010101010101010101010101010101010101010101010101010101010101 --message="Hello, world!"
2020-03-27 12:39:44  INFO secretstore Encrypted message: 0x61a0328d8735d1fd0b2230d78b07a7f364a361c5bd11ecb8d485771af2

# //Alice just checks that (local) decryption works (offline operation).
./parity-secretstore-substrate decrypt-message --encrypted-document-key=0x0417cabe0bd7df0a8f1034d5fe99e8ce7ef81e5802acdb33ef977b2812a9f0cac5d8fd9cc534d75bb6079f56d6b6392ef8b73abfaf636eec54bebd5ac1ae6ae2457cff98454326d6ec711da12fc08c4dbf9f3565d8254aa9f89c8f94685d322cc1babca189cebe624ba3e8b3cc8bc2b46a979fcf5b2995a2de148d9e4cf15ff79b7eb2ed1e7d7aa1ccc4929676c114f4df39687c9a4bd44bc3c6f4e1a23a718113ccc4d1a2fde29e5a625322db642f573c --requester-secret=0x0101010101010101010101010101010101010101010101010101010101010101 --encrypted-message=0x61a0328d8735d1fd0b2230d78b07a7f364a361c5bd11ecb8d485771af2
2020-03-27 12:40:03  INFO secretstore Decrypted message: "Hello, world!"

# //Alice asks Secret Store to store generated document key.
./parity-secretstore-substrate submit-transaction --wait-processed --transaction="StoreDocumentKey(0101010101010101010101010101010101010101010101010101010101010101, 0x12e20fd9ab6697e120a47ff1f278d3c85ef20d7044f6bcc780801c5bc2ee1be574dd69772ebab548ddddc6e901cbc2a5362e3fb920367898ab8749d09297a1ee, 0x6e21608df33c8927abc756a8f7c71998728bf4be0ae0f09b1780ac6a4c83f86251a710d29b3cfe17129f0a5612c5f2b0fb9a2fb20011dab3623a86460b58d80b)"
2020-03-27 12:41:07  INFO secretstore Transaction has been accepted to Ready queue
2020-03-27 12:41:12  INFO secretstore Transaction is mined in block: 0x8268317c5d62efdc8eed5ccdf7f4a7dc7fbeaca8a8635f346f95cdded2a95769
2020-03-27 12:41:25  INFO secretstore Transaction block is finalized: 0x8268317c5d62efdc8eed5ccdf7f4a7dc7fbeaca8a8635f346f95cdded2a95769
2020-03-27 12:41:30  INFO secretstore Document key has been stored

# //Alice asks Secret Store to retrieve document key shadow.
./parity-secretstore-substrate submit-transaction --wait-processed --transaction="RetrieveDocumentKeyShadow(0101010101010101010101010101010101010101010101010101010101010101, 0x1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f70beaf8f588b541507fed6a642c5ab42dfdf8120a7f639de5122d47a69a8e8d1)"
020-03-27 12:42:15  INFO secretstore Transaction has been accepted to Ready queue
2020-03-27 12:42:18  INFO secretstore Transaction is mined in block: 0xc3d386552029be0dd8e7f262f8525f0bf6c39d656ddc5455f5356dfe8284cf02
2020-03-27 12:42:31  INFO secretstore Transaction block is finalized: 0xc3d386552029be0dd8e7f262f8525f0bf6c39d656ddc5455f5356dfe8284cf02
2020-03-27 12:42:36  INFO secretstore Common portion of document key has been retrieved: threshold = 1, common_point = 0x12e20fd9ab6697e120a47ff1f278d3c85ef20d7044f6bcc780801c5bc2ee1be58b229688d1454ab722223916fe343d5ac9d1c046dfc987675478b62e6d685a41
2020-03-27 12:42:54  INFO secretstore Adding new personal entry candidate: 0xb8a7bbf1894c3a7991273818c1381dbf48132c6b92442caa4dc40f6a86dd39068ecfd4f385e94a49494bf101d18bf5e79b433629467a3bd383f160d8193509ba
2020-03-27 12:42:54  INFO secretstore Received shadow for personal entry: 0xb8a7bbf1894c3a7991273818c1381dbf48132c6b92442caa4dc40f6a86dd39068ecfd4f385e94a49494bf101d18bf5e79b433629467a3bd383f160d8193509ba. 1 More required
2020-03-27 12:42:54  INFO secretstore Received last required shadow for personal entry: 0xb8a7bbf1894c3a7991273818c1381dbf48132c6b92442caa4dc40f6a86dd39068ecfd4f385e94a49494bf101d18bf5e79b433629467a3bd383f160d8193509ba
2020-03-27 12:42:54  INFO secretstore Final shadows list: ["0x04195e1c00655d2828ee5fcf709f60ab430f0280d61954c201fb6a3038636bd78357ddcce876718c1a6b438c81edfde567f77cf54ddf3aa6f1a93e16d54259da713d756e581976c21e5acba3b887c0a0b73fd27ff75468fc1818257550b6b6c6e95bb3fe33ab94bbbdd4c28823c63f5be18b2c23c071142789875c61cf04cfac712d20f414ee5b1578fc0766cc10a33cf6", "0x0440ca8a95106281a2e3bbf4b6d34033f4951371f99b85db08e2b838e9ab6e78997643196e640981d6e7b662267e0847aca461d09f7711b249bc31ac72e21784f84eb7f5a9fd4359dd298a9d2272463a6c35c071d8a9a27bf5dc0ec63cd8f60fb18653c5cc1ab92c8037b74fb78dec2a4ddb581b0c6839a9f4c36e9ca18bf8c0d6e749a0e201cde5fb5f5fa587f0d2efd5"]

# //Alice just checks that decryption works (offline operation).
./parity-secretstore-substrate shadow-decrypt-message --common-point=0x12e20fd9ab6697e120a47ff1f278d3c85ef20d7044f6bcc780801c5bc2ee1be58b229688d1454ab722223916fe343d5ac9d1c046dfc987675478b62e6d685a41 --decrypted-secret=0xb8a7bbf1894c3a7991273818c1381dbf48132c6b92442caa4dc40f6a86dd39068ecfd4f385e94a49494bf101d18bf5e79b433629467a3bd383f160d8193509ba --decrypt-shadows=0x04195e1c00655d2828ee5fcf709f60ab430f0280d61954c201fb6a3038636bd78357ddcce876718c1a6b438c81edfde567f77cf54ddf3aa6f1a93e16d54259da713d756e581976c21e5acba3b887c0a0b73fd27ff75468fc1818257550b6b6c6e95bb3fe33ab94bbbdd4c28823c63f5be18b2c23c071142789875c61cf04cfac712d20f414ee5b1578fc0766cc10a33cf6 --decrypt-shadows=0x0440ca8a95106281a2e3bbf4b6d34033f4951371f99b85db08e2b838e9ab6e78997643196e640981d6e7b662267e0847aca461d09f7711b249bc31ac72e21784f84eb7f5a9fd4359dd298a9d2272463a6c35c071d8a9a27bf5dc0ec63cd8f60fb18653c5cc1ab92c8037b74fb78dec2a4ddb581b0c6839a9f4c36e9ca18bf8c0d6e749a0e201cde5fb5f5fa587f0d2efd5 --requester-secret=0x0101010101010101010101010101010101010101010101010101010101010101 --encrypted-message=0x61a0328d8735d1fd0b2230d78b07a7f364a361c5bd11ecb8d485771af2
2020-03-27 12:44:45  INFO secretstore Decrypted message: "Hello, world!"

# //Alice transfers key ownership to //Bob.
#
# This means that //Alice now can't recover key and //Bob can.
# (note that in our case //Alice still knows the document key, because she has generated it)
./parity-secretstore-substrate submit-transaction --wait-processed --transaction="TransferKey(0x0101010101010101010101010101010101010101010101010101010101010101, 0x5050a4f4b3f9338c3472dcc01a87c76a144b3c9c)"
2020-03-27 12:49:08  INFO secretstore Transaction has been accepted to Ready queue
2020-03-27 12:49:12  INFO secretstore Transaction is mined in block: 0x76d8685136af8096264ac98fa85c0fd2f3f8840a191af3441d2b9ed4c2c50ed8
```