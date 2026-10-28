# sypt.io - core
A small library that helps to cipher a secret and sign it.

## Start a KeyStore with keytool
You can create a KeyStore with keytool to initialize your process

```bash
# Double RSA pair: sypt-crypto-data-sig to sign and sypt-crypto-data-enc to encrypt
keytool -genkeypair -validity 730 -alias sypt-crypto-data-sig -keystore C:\Cert\sypt-crypto-data-ec.p12 -keypass sypt-crypto-data-pass -storepass sypt-crypto-data-pass -groupname secp384r1 -keyalg EC -dname "CN=sypt.io" -storetype PKCS12
keytool -genkeypair -validity 730 -alias sypt-crypto-data-enc -keystore C:\Cert\sypt-crypto-data-ec.p12 -keypass sypt-crypto-data-pass -storepass sypt-crypto-data-pass -groupname secp384r1 -keyalg EC -dname "CN=sypt.io" -storetype PKCS12

# Double EC pair: sypt-crypto-data-sig to sign and sypt-crypto-data-enc to encrypt
keytool -genkeypair -validity 730 -alias sypt-crypto-data-sig -keystore C:\Cert\sypt-crypto-data-rsa.p12 -keypass sypt-crypto-data-pass -storepass sypt-crypto-data-pass -keysize 4096 -keyalg RSA -dname "CN=sypt.io" -storetype PKCS12
keytool -genkeypair -validity 730 -alias sypt-crypto-data-enc -keystore C:\Cert\sypt-crypto-data-rsa.p12 -keypass sypt-crypto-data-pass -storepass sypt-crypto-data-pass -keysize 4096 -keyalg RSA -dname "CN=sypt.io" -storetype PKCS12

# Double PQC pair: sypt-crypto-data-sig to sign and sypt-crypto-data-enc to encrypt
keytool -genkeypair -validity 730 -alias sypt-crypto-data-sig -keystore C:\Cert\sypt-crypto-data-pqc.p12 -keypass sypt-crypto-data-pass -storepass sypt-crypto-data-pass -keyalg ML-DSA-87 -dname "CN=sypt.io" -storetype PKCS12
keytool -genkeypair -validity 730 -alias sypt-crypto-data-enc -keystore C:\Cert\sypt-crypto-data-pqc.p12 -keypass sypt-crypto-data-pass -storepass sypt-crypto-data-pass -keyalg ML-KEM-1024 -dname "CN=sypt.io" -storetype PKCS12 -signer sypt-crypto-data-sig
```

Then load your KSM with the following

```java
// Create your KSM using BouncyCastle
try (KSM ksm = new FileKSM("classpath:keystore/sypt-crypto-data-pqc.p12", "sypt-crypto-data-pass".toCharArray(), "BC")) {
	// Now your KSM is available
}
```

## Generate a KeyStore
Once your initial KM is loaded, you can generate a new one

```java
// Build a new KeyStore
try (KSM masterKsm = new FileKSM("classpath:keystore/sypt-crypto-data-pqc.p12", "sypt-crypto-data-pass".toCharArray(), "BC")) {
	KSMValues ksmValues = KSMFactory.builder()
		.keyStoreManager(masterKsm, "sypt-crypto-data")
		.alias(alias)
		.domain(domain)
		.usage(Usage.SYPT)
		.encryptedPassword(false) // set to true if the password must be sypted with the masterKsm
		.type(KSMType.PQC_L5);	  // this will generate a PQC KSM, you can change it to RSA / EC
		.build();
	    
	// Access the KeyStore
	ksmValues.getKeyStore();
	
	// Access the password (encrypted here using the master KSM)
	ksmValues.getPassword();
	
	// keystore and password are Base64 encoded and can therefore be stored anywhere
}
```

## Use the KeyStore to encrypt / sign your data

```java
// Create your KSM using BouncyCastle
try (KSM ksm = new DataKSM(new ByteArrayInputStream(Base64.decode(ksmValues.getKeyStore())), ksmValues.getPassword()) {
	// Create your Sypter
	Sypter<YourSypterable> sypter = new YourSypter(ksm);
	// Sypt your data
	String encryptedData = sypter.syptAndEncode(new YourSypterable(yourData));
}
```

### Data representation
You will receive a Base64 encoded JSON

```
eyJvYmplY3QiOiJleUpsYm1OeWVYQjBaV1JFWVhSaElqb2lhR0ZPU2pWQ1Iybb...
```

This represents a JSON with following values

```json
{
	"key": "...",
	"encAlgo": "...",
	"sigAlgo": "...",
	"object": "...",
	"signature": "...", // Remember: PQC signature are huge
	"timestamp": "..."
}
```

The values 'object' is itself a Base64 encoded JSON containing the encrypted values

```json
{
	"encryptedData": "...",
	"encryptedIv": "...",
	"encryptedSecretKey" : "..." // this is the AES key encrypted by the KeyStore's encryption key (RSA / EC) or the encapsulation (PQC)
}
```

## Use the KeyStore to decrypt / verify your data

```java
// Create your KSM using BouncyCastle
try (KSM ksm = new DataKSM(new ByteArrayInputStream(Base64.decode(ksmValues.getKeyStore())), ksmValues.getPassword()) {
	// Create your Sypter
	Sypter<YourSypterable> sypter = new YourSypter(ksm);
	// Unsypt your data
	YourSypterable yourData = sypter.decodeAndUnsypt(encryptedData, YourSypterable.class);
}
```