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
	FindKeys             map[userlib.UUID]map[string][]byte
	Hashword             []byte
	SharedFilesToUUID    map[string]userlib.UUID
	MyFilesToUUID        map[string]userlib.UUID
	FileOwners           map[string]string
	SharingDataAccess    map[string]map[string]userlib.UUID
	//FileNumAppends       map[string]int
	//SignitureKeys		 map[string]userlib.DSSignKey
	// your username + filename + x, then hash
	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

type FileAccess struct {
	//This maps users and where the keys for the files are stored for the users
	UserKeyLocations map[string]map[userlib.UUID]userlib.UUID
}

type FileShareMeta struct {
	NumAppends int
	Keys       map[string][]byte
}

// Defining a useful struct
type File struct {
	//LOTS OF PEOPLE DO SHARES, BUT ONLY ONE PERSON NEEDS TO KNOW ABOUT IT
	//maps integer to UUID of append...1: UUID of first appendage, 2: UUID of second appendage
	NumAppends int
	Contents   []byte
	Owner      string
	//TODO: KEEP TRACK OF OWNERS OF ANY FILES SHARED WITH U
	//File X, use append map to find UUIDs of file struct of File Y and Z, from those structs, pull
	//contents
	//TODO: keep track of users with access
}

/*** USEFUL HELPER FUNCTIONS ***/
/*** USEFUL HELPER FUNCTIONS END ***/

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

	//Storing user's password
	userdata.Hashword = userlib.Hash(append([]byte(password), userlib.RandomBytes(16)...))

	//Making maps
	userdata.SharedFilesToUUID = make(map[string]userlib.UUID)
	userdata.FindKeys = make(map[userlib.UUID]map[string][]byte)
	userdata.MyFilesToUUID = make(map[string]userlib.UUID)
	userdata.FileOwners = make(map[string]string)
	userdata.SharingDataAccess = make(map[string]map[string]uuid.UUID)
	//userdata.FileNumAppends = make(map[string]int)

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

	//Generating File struct to store the contents of the file
	var FileData File
	FileData.NumAppends = 0
	FileData.Contents = data
	jsonData, _ := json.Marshal(FileData)

	//generating UUID to store file in Datastore
	UUIDSeed := userlib.Hash([]byte(filename + userdata.Username + string(0)))
	storageKey, _ := uuid.FromBytes(UUIDSeed[:16])

	//Generating encryption keys for the file
	var hmac_key = userlib.Argon2Key(append(UUIDSeed, userdata.Hashword...), userlib.RandomBytes(16), 128)
	var encryption_key = userlib.Argon2Key(append(UUIDSeed, userdata.Hashword...), userlib.RandomBytes(16), 128)

	//Encrypting the file struct
	var encrypted_data = userlib.SymEnc(encryption_key, userlib.RandomBytes(16), jsonData)
	var hmac_data, _ = userlib.HMACEval(hmac_key, encrypted_data)

	//Storing file in Datastore
	userlib.DatastoreSet(storageKey, append(encrypted_data, hmac_data...))

	//Storing file's encryption keys for the user
	keysToAdd := make(map[string][]byte)
	keysToAdd["HMAC"] = hmac_key
	keysToAdd["AES-CFB"] = encryption_key
	userdata.FindKeys[storageKey] = keysToAdd

	//Adding to my files map
	userdata.MyFilesToUUID[string(UUIDSeed)] = storageKey
	//Adding to ownership map
	userdata.FileOwners[string(UUIDSeed)] = userdata.Username
	//TODO: ADD UUID OF FILE TO FILENAME -> UUID MAP IN USER STRUCT

	return
}

// AppendFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/appendfile.html
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	//TODO: Write file verify helper function
	//TODO: DONT NEED TO GENERATE ORIGINAL UUID, CAN JUST PULL FROM FILENAME -> UUID MAP IN USER STRUCT

	//Initializing a File struct for storing the appendage
	var AppendData File
	AppendData.NumAppends = 0
	AppendData.Contents = data
	AppendData.Owner = userdata.FileOwners[filename]
	jsonData, _ := json.Marshal(AppendData)

	//Finding UUID and encryption keys of the original file to append to
	originalUUIDSeed := userlib.Hash([]byte(filename + userdata.FileOwners[filename] + string(0)))
	storageKey, _ := uuid.FromBytes(originalUUIDSeed[:16])
	encryptedData, _ := userlib.DatastoreGet(storageKey)
	keysToDecrypt := userdata.FindKeys[storageKey]

	//Initializing File struct to put original file inside
	var filedataTest File
	filedataptrTest := &filedataTest

	//Verifying integrity/authenticity of the original file retrieved from Datastore
	lengthEncData := len(encryptedData)
	hmacOfPulledFile := encryptedData[lengthEncData-64:]
	encryptedPulledFileData := encryptedData[:lengthEncData-64]

	verificationHMAC, _ := userlib.HMACEval(keysToDecrypt["HMAC"], encryptedPulledFileData)

	if !userlib.HMACEqual(hmacOfPulledFile, verificationHMAC) {
		return errors.New("integrity could not be verified")
	}

	//Decrypting the original File struct to change number of appendages
	decryptedSerializedData := userlib.SymDec(keysToDecrypt["AES-CFB"], encryptedPulledFileData)
	json.Unmarshal(decryptedSerializedData, filedataptrTest)
	filedataTest.NumAppends += 1

	//Re-encrypting and uploading the original file struct
	jsonDataOriginalAppendUpdate, _ := json.Marshal(filedataTest)
	var encrypted_original_updated_data = userlib.SymEnc(keysToDecrypt["AES-CFB"], userlib.RandomBytes(16), jsonDataOriginalAppendUpdate)
	var hmac_original_updated_data, _ = userlib.HMACEval(keysToDecrypt["HMAC"], encrypted_original_updated_data)
	userlib.DatastoreSet(storageKey, append(encrypted_original_updated_data, hmac_original_updated_data...))

	//Generating UUID to store appendage inside
	UUIDSeed := userlib.Hash([]byte(filename + userdata.FileOwners[filename] + string(filedataTest.NumAppends)))
	UUIDToStoreAppend, _ := uuid.FromBytes(UUIDSeed[:16])

	//Generating keys to use for appendage
	var hmac_key_appendage = keysToDecrypt["HMAC"]
	var encryption_key_appendage = keysToDecrypt["AES-CFB"]

	//Encrypting and HMACing appendage
	var encrypted_appendage = userlib.SymEnc(encryption_key_appendage, userlib.RandomBytes(16), jsonData)
	var hmac_appendage, _ = userlib.HMACEval(hmac_key_appendage, encrypted_appendage)

	//uploading appendage to datastore
	userlib.DatastoreSet(UUIDToStoreAppend, append(encrypted_appendage, hmac_appendage...))

	//storing keys for appendage
	appendageKeys := make(map[string][]byte)
	appendageKeys["AES-CFB"] = encryption_key_appendage
	appendageKeys["HMAC"] = hmac_key_appendage

	if userdata.FileOwners[filename] == userdata.Username {
		userdata.MyFilesToUUID[string(UUIDSeed)] = UUIDToStoreAppend
	} else {
		userdata.SharedFilesToUUID[string(UUIDSeed)] = UUIDToStoreAppend
	}
	userdata.FileOwners[string(UUIDSeed)] = userdata.FileOwners[filename]

	return
}

// LoadFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/loadfile.html
func (userdata *User) LoadFile(filename string) (dataBytes []byte, err error) {
	//DONT store UUIDs, derive deterministically

	//TODO: This is a toy implementation.
	// storageKey, _ := uuid.FromBytes([]byte(filename + userdata.Username)[:16])
	// dataJSON, ok := userlib.DatastoreGet(storageKey)
	// if !ok {
	// 	return nil, errors.New(strings.ToTitle("File not found!"))
	// }
	// json.Unmarshal(dataJSON, &dataBytes)
	// return dataBytes, nil
	//End of toy implementation

	//Pulling original file'd UUID
	var originalUUID userlib.UUID
	var finalFile []byte

	originalUUID, ok := userdata.MyFilesToUUID[filename]
	if !ok {
		originalUUID, ok2 := userdata.SharedFilesToUUID[filename]
		if !ok2 {
			return nil, errors.New("File don't exist")
		}
	}

	//Pulling the file struct for original file
	encryptedPulledFileData, _ := userlib.DatastoreGet(originalUUID)
	HMACencryptedPulledFileData := encryptedPulledFileData[len(encryptedPulledFileData)-64:]

	//Pulling keys for file decryption
	verificationHMAC, _ := userlib.HMACEval(userdata.FindKeys[originalUUID]["HMAC"], encryptedPulledFileData)
	if !userlib.HMACEqual(HMACencryptedPulledFileData, verificationHMAC) {
		return nil, errors.New("Integrity issue")
	}

	//decrypting original File's struct
	decryptedSerializedOriginalData := userlib.SymDec(userdata.FindKeys[originalUUID]["AES-CFB"], encryptedPulledFileData[:len(encryptedPulledFileData)-64])
	var filedataTest File
	filedataptrTest := &filedataTest
	json.Unmarshal(decryptedSerializedOriginalData, filedataptrTest)
	finalFile = append(finalFile, filedataTest.Contents...)

	for i := 1; i < filedataTest.NumAppends; i++ {
		UUIDSeed := userlib.Hash([]byte(filename + filedataTest.Owner + string(filedataTest.NumAppends)))
		appendageUUID, _ := uuid.FromBytes(UUIDSeed[:16])

		encryptedData, _ := userlib.DatastoreGet(appendageUUID)
		HMACencryptedPulledFileData := encryptedData[len(encryptedData)-64:]

		//Pulling keys for file decryption
		verificationHMAC, _ := userlib.HMACEval(userdata.FindKeys[originalUUID]["HMAC"], encryptedData)
		if !userlib.HMACEqual(HMACencryptedPulledFileData, verificationHMAC) {
			return nil, errors.New("Integrity issue")
		}

		//decrypting original File's struct
		decryptedSerializedAppendageData := userlib.SymDec(userdata.FindKeys[originalUUID]["AES-CFB"], encryptedData[:len(encryptedPulledFileData)-64])

		var filedataTestAppendage File
		filedataptrTestAppendage := &filedataTestAppendage
		json.Unmarshal(decryptedSerializedAppendageData, filedataptrTestAppendage)
		finalFile = append(finalFile, filedataTestAppendage.Contents...)
	}

	return finalFile, nil
}

// ShareFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/sharefile.html
func (userdata *User) ShareFile(filename string, recipient string) (
	accessToken uuid.UUID, err error) {

	// instanciate a new file share metadata
	var newFileShareMeta FileShareMeta

	// pulling original file to get # of append
	originalUUID, ok := userdata.MyFilesToUUID[filename]
	if !ok {
		originalUUID, ok2 := userdata.SharedFilesToUUID[filename]
		if !ok2 {
			return nil, errors.New("File don't exist")
		}
	}

	//Pulling the file struct for original file
	encryptedPulledFileData, _ := userlib.DatastoreGet(originalUUID)
	HMACencryptedPulledFileData := encryptedPulledFileData[len(encryptedPulledFileData)-64:]

	//Pulling keys for file decryption
	//possible pitfall with returning new random UUID when encountering an error
	verificationHMAC, _ := userlib.HMACEval(userdata.FindKeys[originalUUID]["HMAC"], encryptedPulledFileData)
	if !userlib.HMACEqual(HMACencryptedPulledFileData, verificationHMAC) {
		return uuid.New(), errors.New("Integrity issue")
	}

	//decrypting original File's struct
	decryptedSerializedOriginalData := userlib.SymDec(userdata.FindKeys[originalUUID]["AES-CFB"], encryptedPulledFileData[:len(encryptedPulledFileData)-64])
	var filedataTest File
	filedataptrTest := &filedataTest
	json.Unmarshal(decryptedSerializedOriginalData, filedataptrTest)

	newFileShareMeta.NumAppends = filedataTest.NumAppends
	newFileShareMeta.Keys["HMAC"] = userdata.FindKeys[originalUUID]["HMAC"]
	newFileShareMeta.Keys["AES-CFB"] = userdata.FindKeys[originalUUID]["AES-CFB"]

	// serializing share file meta struct
	jsonData, _ := json.Marshal(newFileShareMeta)

	// pulling recipient's RSA key
	//possible pitfall with returning new random UUID when encountering an error
	recipientPublicRSAKey, ok3 := userlib.KeystoreGet(recipient)
	if !ok3 {
		return uuid.New(), errors.New("User does not exist.")
	}
	//encrypting share file meta struct
	encryptedData, _ := userlib.PKEEnc(recipientPublicRSAKey, jsonData)
	//HMACing encrypted data
	HMACencryptedData, _ := userlib.HMACEval(userdata.FindKeys[originalUUID]["HMAC"], encryptedData)
	//appending HMAC to encryption
	encryptHMACData := append(encryptedData, HMACencryptedData...)
	//signing
	signature, _ := userlib.DSSign(userdata.PrivateRSAKey, encryptHMACData)
	//appending signature to HMACed encryption
	signedEnctyptedHMACData := append(encryptHMACData, signature...)
	//generating a random UUID and storing in sharing access map
	newRandomUUID := uuid.New()
	userdata.SharingDataAccess[filename][recipient] = newRandomUUID
	//storing the signed HMACed and encrypted data to Datastore
	userlib.DatastoreSet(newRandomUUID, signedEnctyptedHMACData)
	return newRandomUUID, nil
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
