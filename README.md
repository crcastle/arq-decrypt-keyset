This implements the password / data integrity verification described at https://www.arqbackup.com/docs/arqcloudbackup/English.lproj/dataFormat.html
to extract the keys from the `encrypted_master_keys.dat`.

Grab a pre-compiled binary from the [Releases section](https://github.com/crcastle/arq-decrypt-keyset/releases/) or compile it yourself.

## Run

```
Usage: arq-keys <path-to-encrypted_master_keys.dat> <password>
```

## Compile

```
go build
```

That's it! (Compiled with Go 1.24.2)
