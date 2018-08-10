package main

import (
	"fmt"
	//"github.com/gbolo/go-util/lib/debugging"
	"crypto/sha256"
	"encoding/asn1"
	"github.com/miekg/pkcs11"
	"github.com/miekg/pkcs11/p11"
	"os"
	"time"
)


var (
	libpath         = "/usr/lib/softhsm/libsofthsm2.so"
	tokenLabel      = "ForFabric"
	privateKeyLabel = "fd6eaeb99b2eea3f51c30acc83242ac9430d800183abf90a1f47c754cf9fc0f8"
	pin             = "98765432"
)

func init() {
	if x := os.Getenv("SOFTHSM_LIB"); x != "" {
		libpath = x
	}
	if x := os.Getenv("SOFTHSM_TOKENLABEL"); x != "" {
		tokenLabel = x
	}
	if x := os.Getenv("SOFTHSM_PRIVKEYLABEL"); x != "" {
		privateKeyLabel = x
	}
	if x := os.Getenv("SOFTHSM_PIN"); x != "" {
		pin = x
	}
	wd, _ := os.Getwd()
	os.Setenv("SOFTHSM_CONF", wd+"/softhsm.conf")
}

func exitWhenError(err error) {
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
}

func main() {

	testDisconnect()
}

func testDisconnect() {

	fmt.Println("Starting testDisconnect")

	module, err := p11.OpenModule(libpath)
	exitWhenError(err)

	slots, err := module.Slots()
	exitWhenError(err)
	fmt.Printf("FOUND %d SLOTS\n", len(slots))

	mySlot := p11.Slot{}
	for _, slot := range slots {

		tinfo, err := slot.TokenInfo()
		exitWhenError(err)

		if tinfo.Label == tokenLabel {
			mySlot = slot
		}

	}

	// open a bunch of sessions
	session1, err := mySlot.OpenWriteSession()
	exitWhenError(err)

	session2, err := mySlot.OpenWriteSession()
	exitWhenError(err)

	session3, err := mySlot.OpenWriteSession()
	exitWhenError(err)

	// do a login to one of them
	err = session1.Login(pin)
	exitWhenError(err)

	// generate a keypair on a different session
	p11PubAttr, p11PrivAttr := getP11Attributes()
	keypair2, err := session2.GenerateKeyPair(p11.GenerateKeyPairRequest{
		Mechanism:            *pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil),
		PublicKeyAttributes:  p11PubAttr,
		PrivateKeyAttributes: p11PrivAttr,
	})
	exitWhenError(err)

	fmt.Println("KEYGEN SUCCESS")

	// test a sign on an new keypair
	digest := getMessageDigest()
	_, err = keypair2.Private.Sign(*pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil), []byte(digest))
	exitWhenError(err)
	fmt.Println("SIGN SUCCESS")

	// ------ DISCONNECTED ---------------------------------------------------
	fmt.Println("SLEEPING FOR 20 SECONDS... DISCONNECT HSM NOW")
	time.Sleep(20 * time.Second)

	_, err = keypair2.Private.Sign(*pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil), []byte(digest))
	if err != nil {
		fmt.Printf("EXPECTED SIGN ERR: %s\n", err)
	} else {

	}
	err = nil

	fmt.Println("DOING RELOGIN")
	err = session3.Login(pin)
	if err != pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
		//exitWhenError(err)
		fmt.Printf("EXPECTED LOGIN ERR: %s\n", err)
	}
	err = nil

	// when opening new session: CKR_TOKEN_NOT_PRESENT
	// lets try to reload the library?

	fmt.Println("SLEEPING FOR 20 SECONDS... RECONNECT HSM NOW")
	time.Sleep(20 * time.Second)

	modulenew, err := module.ReloadModule(libpath)
	module = modulenew
	fmt.Println("USED LIB AGAIN")
	exitWhenError(err)

	slots, err = module.Slots()
	exitWhenError(err)
	fmt.Printf("FOUND %d SLOTS\n", len(slots))

	for _, slot := range slots {

		tinfo, err := slot.TokenInfo()
		exitWhenError(err)

		if tinfo.Label == tokenLabel {
			mySlot = slot
		}

	}

	// open a bunch of sessions
	session1, err = mySlot.OpenWriteSession()
	exitWhenError(err)

	session2, err = mySlot.OpenWriteSession()
	exitWhenError(err)

	session3, err = mySlot.OpenWriteSession()
	exitWhenError(err)
	// do a login to one of them
	err = session1.Login(pin)
	exitWhenError(err)

	_, err = session3.GenerateKeyPair(p11.GenerateKeyPairRequest{
		Mechanism:            *pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil),
		PublicKeyAttributes:  p11PubAttr,
		PrivateKeyAttributes: p11PrivAttr,
	})

	if err != nil {
		fmt.Printf("KEYGEN ERR: %s", err)
	} else {
		fmt.Println("KEYGEN SUCCESS")
	}
}

func getP11Attributes() (pub, priv []*pkcs11.Attribute) {

	ecParam, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7})

	pub = []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false), /* session only. destroy later */
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ecParam),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte("gbolotest")),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "gbolotest"),
		// public key should be easily accessed
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),
	}

	priv = []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false), /* session only. destroy later */
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte("gbolotest")),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "gbolotest"),
		// TODO: make these options configurable...
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		// support key derivation by default for now...
		pkcs11.NewAttribute(pkcs11.CKA_DERIVE, true),
		// pkcs11.NewAttribute(pkcs11.CKR_ATTRIBUTE_SENSITIVE, false),
	}

	return
}

func getP11KeyAttributes() (priv []*pkcs11.Attribute) {
	priv = []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, privateKeyLabel),
	}

	return
}

func getMessageDigest() (digest []byte) {
	message := "some test message"
	d := sha256.Sum256([]byte(message))
	digest = d[:]

	return
}
