## Smart Wallet bench

Simple repo used to perform quick benchmark of different Smart Wallet.

The initial goal of this repo is to compare gas consumption between Safe Wallet and Kernel wallet for:
 - Initial deployment / setup
 - User operation (or wallet actions?) validation and execution
 - Signature verification

The idea is to first test with regular ECDSA signature, and then test with P256 signature.


## Usage

### Build

```shell
$ forge build
```

### Test

```shell
$ forge test
```

### Format

```shell
$ forge fmt
```

### Gas Snapshots

```shell
$ forge snapshot
```
