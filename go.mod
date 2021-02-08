module github.com/polynetwork/eth_relayer

go 1.14

require (
	github.com/boltdb/bolt v1.3.1
	github.com/btcsuite/btcd v0.20.1-beta
	github.com/ethereum/go-ethereum v1.9.15
	github.com/ontio/ontology v1.11.1-0.20200812075204-26cf1fa5dd47
	github.com/ontio/ontology-crypto v1.0.9
	github.com/polynetwork/eth-contracts v0.0.0-20200814062128-70f58e22b014
	github.com/polynetwork/poly v0.0.0-20210108071928-86193b89e4e0
	github.com/polynetwork/poly-go-sdk v0.0.0-20200817120957-365691ad3493
	github.com/stretchr/testify v1.6.1
	github.com/urfave/cli v1.22.4
	poly-bridge v0.0.0-00010101000000-000000000000
)

replace poly-bridge => github.com/polynetwork/poly-bridge v0.0.0-20210205080948-5a45ee387277
