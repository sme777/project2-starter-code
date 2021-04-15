package proj2

// CS 161 Project 2

// You MUST NOT change these default imports.  ANY additional imports it will
// break the autograder and everyone will be sad.

import (
	"bytes"

	"github.com/cs161-staff/userlib"

	// The JSON library will be useful for serializing go structs.
	// See: https://cs161.org/assets/projects/2/docs/coding_tips/json.html.
	"encoding/json"

	// Likewise, useful for debugging, etc.
	"encoding/hex"

	// The Datastore requires UUIDs to store key-value entries.
	// See: https://cs161.org/assets/projects/2/docs/coding_tips/uuid.html.
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys.
	"strings"

	// Want to import errors.
	"errors"

	// Optional. You can remove the "_" there, but please do not touch
	// anything else within the import bracket.
	_ "strconv"
	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg.
	// see someUsefulThings() below:
)

// This serves two purposes:
// a) It shows you some useful primitives, and
// b) it suppresses warnings for items not being imported.
// Of course, this function can be deleted.
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("Key is %v, %v", pk, sk)
}

// Helper function: Takes the first 16 bytes and converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

// User is the structure definition for a user record.
type User struct {
	Username             string
	DataStoreLocationKey []byte
	DataStoreUUID        userlib.UUID
	PublicRSAKey         userlib.PKEEncKey
	PrivateRSAKey        userlib.PKEDecKey
	FileEncKey           []byte
	HMACKey              []byte
	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

// InitUser will be called a single time to initialize a new user.
func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata
	//var UUIDerr error
	//var RSAErr error

	_, exists := userlib.KeystoreGet(username)

	if !exists {
		return nil, errors.New("username already taken")
	}

	//TODO: This is a toy implementation.
	userdata.Username = username
	//End of toy implementation

	//This will be where we store the encrypted user struct in Datastore
	userdata.DataStoreLocationKey = userlib.Argon2Key([]byte(password), []byte(username), 128)
	userdata.DataStoreUUID, _ = uuid.FromBytes(userdata.DataStoreLocationKey)

	//Generating RSA keys for user
	userdata.PublicRSAKey, userdata.PrivateRSAKey, _ = userlib.PKEKeyGen()

	//Generating symmetric encryption keys
	userdata.FileEncKey = userlib.Argon2Key([]byte(password), []byte(username+password), 128)
	userdata.HMACKey = userlib.Argon2Key([]byte(password), []byte(username+password+username), 128)

	//Serializing our user struct
	serial, _ := json.Marshal(userdata)

	//Encrypting userdata
	encryptedUserData := userlib.SymEnc(userdata.FileEncKey, userlib.RandomBytes(16), serial)

	//HMAC-ing encrypted userdata
	HMACofEncryptedUserData, _ := userlib.HMACEval(userdata.HMACKey, encryptedUserData)

	//Storing in DataStore
	userlib.DatastoreSet(userdata.DataStoreUUID, append(encryptedUserData, HMACofEncryptedUserData...))

	//Storing public RSA key in Keystore
	userlib.KeystoreSet(username, userdata.PublicRSAKey)

	//Return error for non-unique username
	return &userdata, nil
}

// GetUser is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/getuser.html
func GetUser(username string, password string) (userdataptr *User, err error) {
	//TODO: CHECK USERNAME AND PASSWORD
	var userdata User
	userdataptr = &userdata

	//Retrieving the UUID of where the struct is in the Datastore
	DataStoreLocationKey := userlib.Argon2Key([]byte(password), []byte(username), 128)
	DataStoreUUID, _ := uuid.FromBytes(DataStoreLocationKey)

	//Getting the encrypted data from DataStore
	encryptedRetrievedData, _ := userlib.DatastoreGet(DataStoreUUID)

	//Verifying authenticity/integrity

	//Generating HMAC key
	actualHMACKey := userlib.Argon2Key([]byte(password), []byte(username+password+username), 128)

	//Retrieving HMAC from data pulled from DataStore
	lengthEncData := len(encryptedRetrievedData)
	retrievedHMAC := encryptedRetrievedData[lengthEncData-64:]

	//Retrieving and decrypting user struct data from DataStore
	encryptedDataSection := encryptedRetrievedData[:lengthEncData-64]
	userFileEncKey := userlib.Argon2Key([]byte(password), []byte(username+password), 128)
	serializedDecryptedUserData := userlib.SymDec(userFileEncKey, encryptedDataSection)

	var userdataTest User
	userdataptrTest := &userdataTest

	json.Unmarshal(serializedDecryptedUserData, userdataptrTest)

	//getting HMAC key from decrypted data
	retrievedHMACKey := userdataTest.HMACKey

	if !bytes.Equal(retrievedHMACKey, actualHMACKey) {
		return nil, errors.New("integrity could not be verified")
	}

	//Comparing generated HMACs

	generatedHMACFromRetrieved, _ := userlib.HMACEval(retrievedHMACKey, encryptedDataSection)

	if !bytes.Equal(retrievedHMAC, generatedHMACFromRetrieved) {
		return nil, errors.New("integrity could not be verified")
	}

	userdata = userdataTest

	return userdataptr, nil
}

// StoreFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/storefile.html
func (userdata *User) StoreFile(filename string, data []byte) (err error) {

	//NEED to generate hmac and encryption keys
	//NEED to store owner of file
	//NEED to store # of append files (links)
	//NEED to overwrite the file

	var hmac_key = userlib.Argon2Key([]byte(filename), userlib.RandomBytes(16), 128)
	var encryption_key = userlib.Argon2Key(userlib.RandomBytes(16), []byte(filename), 128)

	var encrypted_data = userlib.SymEnc(encryption_key, userlib.RandomBytes(16), data)
	var hmac_data, _ = userlib.HMACEval(hmac_key, encrypted_data)

	//TODO: This is a toy implementation.
	storageKey, _ := uuid.FromBytes([]byte(filename + userdata.Username)[:16])
	//jsonData, _ := json.Marshal(data)
	//userlib.DatastoreSet(storageKey, jsonData)
	//End of toy implementation

	userlib.DatastoreSet(storageKey, append(encrypted_data, hmac_data...))

	return
}

// AppendFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/appendfile.html
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	return
}

// LoadFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/loadfile.html
func (userdata *User) LoadFile(filename string) (dataBytes []byte, err error) {

	//TODO: This is a toy implementation.
	storageKey, _ := uuid.FromBytes([]byte(filename + userdata.Username)[:16])
	dataJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil, errors.New(strings.ToTitle("File not found!"))
	}
	json.Unmarshal(dataJSON, &dataBytes)
	return dataBytes, nil
	//End of toy implementation

	return
}

// ShareFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/sharefile.html
func (userdata *User) ShareFile(filename string, recipient string) (
	accessToken uuid.UUID, err error) {

	return
}

// ReceiveFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/receivefile.html
func (userdata *User) ReceiveFile(filename string, sender string,
	accessToken uuid.UUID) error {
	return nil
}

// RevokeFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/revokefile.html
func (userdata *User) RevokeFile(filename string, targetUsername string) (err error) {
	return
}
