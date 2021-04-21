package proj2

// CS 161 Project 2

// You MUST NOT change these default imports.  ANY additional imports it will
// break the autograder and everyone will be sad.

import (
	"bytes"
	"fmt"

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
	FindKeys             map[string]map[string][]byte
	Hashword             []byte
	FileNamesToUUID      map[string]userlib.UUID
	SharingDataAccess    map[string]map[string]userlib.UUID
	FilenamesToCloud     map[string]userlib.UUID
	FilesIOwn			 map[string]userlib.UUID

	//points to who shared with (filename)(username)(cloud uuid)
	Ancestry             map[string]map[string]userlib.UUID
	AncestryKeys         map[string]map[string]map[string] []byte

	//points to trees for files I need to update
	TreesIUpdateLoc      map[string]userlib.UUID
	TreesIUpdateKeys     map[string]map[string][]byte

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
	UUIDofFileTree userlib.UUID
	TreeKeys   map[string][]byte

	FileUUID   userlib.UUID
	Keys       map[string][]byte
}

type FileTree struct {
	ISharedWith map[string]userlib.UUID
}

// Defining a useful struct
type File struct {
	//LOTS OF PEOPLE DO SHARES, BUT ONLY ONE PERSON NEEDS TO KNOW ABOUT IT
	//maps integer to UUID of append...1: UUID of first appendage, 2: UUID of second appendage
	NumAppends int
	Contents   []byte
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
	userdata.FindKeys = make(map[string]map[string][]byte)
	userdata.FileNamesToUUID = make(map[string]userlib.UUID)
	userdata.SharingDataAccess = make(map[string]map[string]userlib.UUID)
	userdata.FilenamesToCloud = make(map[string]userlib.UUID)
	userdata.FilesIOwn = make(map[string]userlib.UUID)
	userdata.Ancestry = make(map[string]map[string]uuid.UUID)
	userdata.AncestryKeys = make(map[string]map[string]map[string][]byte)
	userdata.TreesIUpdateLoc = make(map[string]uuid.UUID)
	userdata.TreesIUpdateKeys = make(map[string]map[string][]byte)
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

//This pulls and returns the file struct for a file from Datastore, given a filename
//Errors if no such file exists in filespace 
func (userdata *User) PullFile(filename string) (theFilePtr *File, err error) {
	storageKey, filenameExists := userdata.FileNamesToUUID[filename]
	
	if (!filenameExists) {
		return nil, errors.New("invalid filename supplied for pulling")
	}

	supposedFile, fileExists := userlib.DatastoreGet(storageKey)

	if (!fileExists) {
		return nil, errors.New("no such file exists in Datastore")
	}

	pulledHMAC := supposedFile[len(supposedFile) - 64:]
	encryptedFileData := supposedFile[:len(supposedFile) - 64]

	//decrypting serialized file data
	decryptedSerializedFile := userlib.SymDec(userdata.FindKeys[filename]["AES-CFB"], encryptedFileData)

	var theFile File
	theFilePtr = &theFile
	json.Unmarshal(decryptedSerializedFile, theFilePtr)

	//verifying HMAC of file
	ownComputedHMAC, _ := userlib.HMACEval(userdata.FindKeys[filename]["HMAC"], decryptedSerializedFile)
	if (userlib.HMACEqual(pulledHMAC, ownComputedHMAC)) {
		return nil, errors.New("the file you're trying to pull has been tampered with")
	}

	return theFilePtr, nil
}

//Creates a file's metadata cloud and uploads it to Datastore
//Return UUID of cloud
func (userdata *User) makeCloud(filename string, sender string, recipient string) (cloudUUID *userlib.UUID, err error) {
	storageKey, doIHaveThis := userdata.FileNamesToUUID[filename]

	if !doIHaveThis {
		return nil, errors.New("you don't have such a file dufus.")
	}

	//Creating filesharemeta object
	var filesCloud FileShareMeta
	filesCloud.FileUUID = storageKey
	filesCloud.Keys["HMAC"] = userdata.FindKeys[filename]["HMAC"]
	filesCloud.Keys["AES-CFB"] = userdata.FindKeys[filename]["AES-CFB"]

	//Encrypting and uploading cloud
	myPublicRSAKey, _ := userlib.KeystoreGet(recipient)
	jsonDataMeta, _ := json.Marshal(filesCloud)

	//Generating UUID for cloud
	newRandomUUID := uuid.New()

	//encrypting share file meta struct
	encryptedCloud, _ := userlib.PKEEnc(myPublicRSAKey, jsonDataMeta)
	//HMACing encrypted data
	HMACencryptedMetaData, _ := userlib.HMACEval(userdata.FindKeys[filename]["HMAC"], encryptedCloud)

	//appending HMAC to encryption
	encryptHMACDataCloud := append(encryptedCloud, HMACencryptedMetaData...)

	//signing
	signature, _ := userlib.DSSign(userdata.PrivateRSAKey, encryptHMACDataCloud)
	//appending signature to HMACed encryption
	signedEnctyptedHMACDataCloud := append(encryptHMACDataCloud, signature...)
	//storing the signed HMACed and encrypted data to Datastore
	userlib.DatastoreSet(newRandomUUID, signedEnctyptedHMACDataCloud)
	//adding to clouds hashmap
	userdata.FilenamesToCloud[filename] = newRandomUUID

	//seeing if I should start the tree
	storageKey, IOwnThis := userdata.FilesIOwn[filename]
	if IOwnThis {
		//generating treeData
		treeUUID, _ := uuid.FromBytes(append([]byte("tree"), userlib.RandomBytes(16)...))
		filesCloud.TreeKeys = make(map[string][]byte)
		filesCloud.TreeKeys["AES-CFB"] = userlib.Argon2Key(append([]byte(filename + "tree"), userdata.Hashword...), userlib.RandomBytes(16), 128)
		filesCloud.TreeKeys["HMAC"] = userlib.Argon2Key(append([]byte(filename + "tree"), userdata.Hashword...), userlib.RandomBytes(16), 128)
		filesCloud.UUIDofFileTree = treeUUID

		//Creating and uploading tree struct
		var fileTreeForFile FileTree
		shares := make(map[string]userlib.UUID)
		shares[recipient] = newRandomUUID
		fileTreeForFile.ISharedWith = shares
		//encrypting and uploading filetree
		serializedTree, _ := json.Marshal(fileTreeForFile)
		encryptedSerializedTree := userlib.SymEnc(filesCloud.TreeKeys["AES-CFB"], userlib.RandomBytes(16), serializedTree)
		HMACencryptedSerializedTree := userlib.SymEnc(filesCloud.TreeKeys["HMAC"], userlib.RandomBytes(16), encryptedSerializedTree)
		userlib.DatastoreSet(treeUUID, append(encryptedSerializedTree,HMACencryptedSerializedTree...))
		//updatingAncestry
		userdata.Ancestry[filename][recipient] = treeUUID
		userdata.AncestryKeys[filename][recipient]["HMAC"] = filesCloud.TreeKeys["HMAC"]
		userdata.AncestryKeys[filename][recipient]["AES-CFB"] = filesCloud.TreeKeys["AES-CFB"]
	} else {
		treeUUID := userdata.TreesIUpdateLoc[filename]
		treeEnc := userdata.TreesIUpdateKeys[filename]["AES-CFB"]
		treeHMAC := userdata.TreesIUpdateKeys[filename]["HMAC"]
		//getting tree I'm supposed to update
		encryptedShareTree, _ := userlib.DatastoreGet(treeUUID)
		//encryptedTreeHMAC := encryptedShareTree[len(encryptedShareTree) - 64:]
		encryptedTreeEnc := encryptedShareTree[:len(encryptedShareTree) - 64]

		decryptedShareTreeSerialized := userlib.SymDec(treeEnc, encryptedTreeEnc)
		var ShareTree FileTree
		ShareTreePtr := &ShareTree
		json.Unmarshal(decryptedShareTreeSerialized, ShareTreePtr)


		//Creating and uploading tree struct
		ShareTree.ISharedWith[recipient] = newRandomUUID
		//encrypting and uploading filetree
		serializedTree, _ := json.Marshal(ShareTree)
		encryptedSerializedTree := userlib.SymEnc(treeEnc, userlib.RandomBytes(16), serializedTree)
		HMACencryptedSerializedTree := userlib.SymEnc(treeHMAC, userlib.RandomBytes(16), encryptedSerializedTree)
		userlib.DatastoreSet(treeUUID, append(encryptedSerializedTree,HMACencryptedSerializedTree...))

	}
	return &newRandomUUID, nil
}

//Fetches the most recent keys for a file, also updating the user's findKeys
func (userdata *User) updateKeys(filename string) (err error) {
	_, doIHaveThis := userdata.FileNamesToUUID[filename]

	if !doIHaveThis {
		return errors.New("you don't have such a file dufus")
	}

	//Pulling most recent keys
	UUIDofCloud := userdata.FilenamesToCloud[filename]
	FileCloudData, _ := userlib.DatastoreGet(UUIDofCloud)
	cloudDataToDecrypt := FileCloudData[:len(FileCloudData)-320]

	//getting sent HMAC key and Verifying HMAC of Cloud
	decryptedDataCloud, _ := userlib.PKEDec(userdata.PrivateRSAKey, cloudDataToDecrypt)
	var cloudFinal FileShareMeta
	cloudFinalPtr := &cloudFinal
	json.Unmarshal(decryptedDataCloud, cloudFinalPtr)

	newHMAC, _ := userlib.HMACEval(cloudFinal.Keys["HMAC"], decryptedDataCloud)
	verifyHMACCloud := FileCloudData[len(FileCloudData)-320 : len(FileCloudData)-256]
	ok2 := userlib.HMACEqual(newHMAC, verifyHMACCloud)
	if !ok2 {
		return errors.New("integirty/authencity issue")
	}

	userdata.FindKeys[filename]["HMAC"] = cloudFinal.Keys["HMAC"]
	userdata.FindKeys[filename]["AES-CFB"] = cloudFinal.Keys["AES-CFB"]
	return
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
	storageKey, doIHaveThis := userdata.FileNamesToUUID[filename]
	_, exists := userlib.DatastoreGet(storageKey)

	if exists {
		if !doIHaveThis {
			return errors.New("you don't have such a file dufus")
		}
		userdata.updateKeys(filename)
		//Encrypting the file struct
		var encrypted_data = userlib.SymEnc(userdata.FindKeys[filename]["AES-CFB"], userlib.RandomBytes(16), jsonData)
		var hmac_data, _ = userlib.HMACEval(userdata.FindKeys[filename]["HMAC"], encrypted_data)
		userlib.DatastoreSet(storageKey, append(encrypted_data, hmac_data...)) 
	} else {
		//Generating UUID to store file
		newUUIDSeed := userlib.Hash(append([]byte(filename),userlib.RandomBytes(16)...))
		newUUID, _ := uuid.FromBytes(newUUIDSeed[:16])
		//Generating encryption keys for the file
		var hmac_key = userlib.Argon2Key(append([]byte(filename), userdata.Hashword...), userlib.RandomBytes(16), 128)
		var encryption_key = userlib.Argon2Key(append([]byte(filename), userdata.Hashword...), userlib.RandomBytes(16), 128)

		//Encrypting the file struct
		var encrypted_data = userlib.SymEnc(encryption_key, userlib.RandomBytes(16), jsonData)
		var hmac_data, _ = userlib.HMACEval(hmac_key, encrypted_data)

		//Storing file in Datastore
		userlib.DatastoreSet(newUUID, append(encrypted_data, hmac_data...))

		//Storing file's encryption keys for the user
		keysToAdd := make(map[string][]byte)
		keysToAdd["HMAC"] = hmac_key
		keysToAdd["AES-CFB"] = encryption_key
		userdata.FindKeys[filename] = keysToAdd

		//Adding to my files map
		userdata.FileNamesToUUID[filename] = newUUID

		//taking care of file cloud
		UUIDofCloud, _ := userdata.makeCloud(filename, userdata.Username, userdata.Username)

		//Sharing to myself
		userdata.SharingDataAccess[filename][userdata.Username] = *UUIDofCloud

		userdata.FilesIOwn[filename] = newUUID

	}
	
	return nil
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
	jsonData, _ := json.Marshal(AppendData)

	//Finding UUID and encryption keys of the original file to append to
	storageKeyOriginal := userdata.FileNamesToUUID[filename]

	userdata.updateKeys(filename)

	keysToDecrypt := userdata.FindKeys[filename]

	originalFileChanged, _ := userdata.PullFile(filename)
	originalFileChanged.NumAppends += 1

	//Re-encrypting and uploading the original file struct
	jsonDataOriginalAppendUpdate, _ := json.Marshal(originalFileChanged)
	var encrypted_original_updated_data = userlib.SymEnc(keysToDecrypt["AES-CFB"], userlib.RandomBytes(16), jsonDataOriginalAppendUpdate)
	var hmac_original_updated_data, _ = userlib.HMACEval(keysToDecrypt["HMAC"], encrypted_original_updated_data)
	userlib.DatastoreSet(storageKeyOriginal, append(encrypted_original_updated_data, hmac_original_updated_data...))

	//Generating UUID to store appendage inside
	UUIDSeed := userlib.Hash(append(keysToDecrypt["AES-CFB"], []byte(fmt.Sprint(originalFileChanged.NumAppends))...))
	UUIDToStoreAppend, _ := uuid.FromBytes(UUIDSeed[:16])

	//Encrypting and HMACing appendage
	var encrypted_appendage = userlib.SymEnc(keysToDecrypt["AES-CFB"], userlib.RandomBytes(16), jsonData)
	var hmac_appendage, _ = userlib.HMACEval(keysToDecrypt["HMAC"], encrypted_appendage)

	//uploading appendage to datastore
	userlib.DatastoreSet(UUIDToStoreAppend, append(encrypted_appendage, hmac_appendage...))

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

	//defining finalfile
	var finalFile File

	//Pulling original file'd UUID
	//generating UUID to store file in Datastore
	_, doIHaveThis := userdata.FileNamesToUUID[filename]

	if !doIHaveThis {
		return nil, errors.New("you don't have such a file dufus")
	}
	
	userdata.updateKeys(filename)

	originalFile, _ := userdata.PullFile(filename)
	finalFile.NumAppends = originalFile.NumAppends

	finalFile.Contents = append(finalFile.Contents, originalFile.Contents...)

	for i := 1; i < finalFile.NumAppends; i++ {
		UUIDSeed := userlib.Hash(append(userdata.FindKeys[filename]["AES-CFB"], []byte(fmt.Sprint(originalFile.NumAppends))...))
		appendageUUID, _ := uuid.FromBytes(UUIDSeed[:16])

		encryptedData, _ := userlib.DatastoreGet(appendageUUID)
		HMACencryptedPulledFileData := encryptedData[len(encryptedData)-64:]

		//Pulling keys for file decryption
		verificationHMAC, _ := userlib.HMACEval(userdata.FindKeys[filename]["HMAC"], encryptedData)

		if !userlib.HMACEqual(HMACencryptedPulledFileData, verificationHMAC) {
			return nil, errors.New("integrity issue")
		}

		//decrypting original appendage file struct
		decryptedSerializedAppendageData := userlib.SymDec(userdata.FindKeys[filename]["AES-CFB"], encryptedData[:len(encryptedData)-64])

		var filedataTestAppendage File
		filedataptrTestAppendage := &filedataTestAppendage
		json.Unmarshal(decryptedSerializedAppendageData, filedataptrTestAppendage)
		finalFile.Contents = append(finalFile.Contents, filedataTestAppendage.Contents...)
	}

	return finalFile.Contents, nil
}

// ShareFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/sharefile.html
func (userdata *User) ShareFile(filename string, recipient string) (
	accessToken uuid.UUID, err error) {

	// instanciate a new file share metadata
	UUIDofCloud, _ := userdata.makeCloud(filename, userdata.Username, recipient)
	userdata.SharingDataAccess[filename][recipient] = *UUIDofCloud

	return *UUIDofCloud, nil
}

// ReceiveFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/receivefile.html
func (userdata *User) ReceiveFile(filename string, sender string,
	accessToken uuid.UUID) (err error) {

	//verifying that the file does not exist
	_, doIHaveThis := userdata.FileNamesToUUID[filename]

	if !doIHaveThis {
		return errors.New("you already have that file dufus")
	}

	//pulling the file
	recievedFileData, ok := userlib.DatastoreGet(accessToken)

	if !ok {
		return errors.New("share does not exist or has been revoked")
	}

	//seperating Data, HMAC, Signiture
	verifySignature := recievedFileData[len(recievedFileData)-256:]
	verifyHMAC := recievedFileData[len(recievedFileData)-320 : len(recievedFileData)-256]
	verifyData := recievedFileData[:len(recievedFileData)-320]

	//getting sender's public rsa key
	senderRSAKey, _ := userlib.KeystoreGet(sender)
	//verifying sender
	sigError := userlib.DSVerify(senderRSAKey, recievedFileData[:len(recievedFileData)-256], verifySignature)
	if sigError != nil {
		return errors.New("sender could not be verified")
	}

	//getting sent HMAC key and Verifying HMAC
	decryptedData, _ := userlib.PKEDec(userdata.PrivateRSAKey, verifyData)
	var recieveFileShareMeta FileShareMeta
	recieveFileShareMetaPtr := &recieveFileShareMeta
	json.Unmarshal(decryptedData, recieveFileShareMetaPtr)
	newHMAC, _ := userlib.HMACEval(verifyHMAC, verifyData)
	ok2 := userlib.HMACEqual(newHMAC, verifyHMAC)
	if !ok2 {
		return errors.New("integirty/authencity issue")
	}
	
	//updating filename to UUID for user
	userdata.FileNamesToUUID[filename] = recieveFileShareMeta.FileUUID
	userdata.FilenamesToCloud[filename] = accessToken

	//updating key-maps for recieving user
	userdata.updateKeys(filename)

	//Storing Tree info for when I share
	userdata.TreesIUpdateLoc[filename] = recieveFileShareMeta.UUIDofFileTree
	userdata.TreesIUpdateKeys[filename] = recieveFileShareMeta.Keys

	//take care of 126 bytes limit
	return nil
}

// RevokeFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/revokefile.html
func (userdata *User) RevokeFile(filename string, targetUsername string) (err error) {

	//new UUID to store file in
	newUUIDSeed := userlib.Hash(append([]byte(filename),userlib.RandomBytes(16)...))
	newUUID, _ := uuid.FromBytes(newUUIDSeed[:16])

	//originalFileStruct
	pulledOriginal, _ := userdata.PullFile(filename)
	serializedOriginal, _ := json.Marshal(pulledOriginal)

	//re-encrypting original file and uploading to new UUID
	newEncKey := userlib.Argon2Key(append(userlib.RandomBytes(16), userdata.Hashword...), userlib.RandomBytes(16), 128)
	newHMACKey := userlib.Argon2Key(append(userlib.RandomBytes(16), userdata.Hashword...), userlib.RandomBytes(16), 128)
	userdata.FindKeys[filename]["AES-CFB"] = newEncKey
	userdata.FindKeys[filename]["HMAC"] = newHMACKey
	var encrypted_data = userlib.SymEnc(userdata.FindKeys[filename]["AES-CFB"], userlib.RandomBytes(16), serializedOriginal)
	var hmac_data, _ = userlib.HMACEval(userdata.FindKeys[filename]["HMAC"], encrypted_data)
	userlib.DatastoreSet(newUUID, append(encrypted_data, hmac_data...))

	//communicating changes
	for child := range userdata.Ancestry[filename] {
		if child != targetUsername {
			//Pulling child's share tree
			childsShareTreeUUID := userdata.Ancestry[filename][child]
			childsShareTreeKeys := userdata.AncestryKeys[filename][child]
			encryptedChildsShareTree, _ := userlib.DatastoreGet(childsShareTreeUUID)
			//encryptedChildTreeHMAC := encryptedChildsShareTree[len(encryptedChildsShareTree) - 64:]
			encryptedChildTreeEnc := encryptedChildsShareTree[:len(encryptedChildsShareTree) - 64]

			decryptedChildsShareTreeSerialized := userlib.SymDec(childsShareTreeKeys["AES-CFB"], encryptedChildTreeEnc)
			var childsTree FileTree
			childsTreePtr := &childsTree
			json.Unmarshal(decryptedChildsShareTreeSerialized, childsTreePtr)
			for key, value := range childsTree.ISharedWith {
				userdata.RevokeHelper(child, key, filename, &newUUID, newHMACKey, newEncKey, &value)
			}
		}
	}


	return
}

func (userdata *User) RevokeHelper(childorigin string, child string, filename string, newUUID *userlib.UUID, newHMAC []byte, newEnc []byte, childCloudUUID *userlib.UUID) {
	//base case

	//child's publicRSA key
	childsRSAKey, _ := userlib.KeystoreGet(child)
	//creating new cloud
	var FileShareMetaNew FileShareMeta
	FileShareMetaNew.FileUUID = *newUUID
	newKeys := make(map[string][]byte)
	newKeys["AES-CFB"] = newEnc
	newKeys["HMAC"] = newHMAC
	FileShareMetaNew.Keys = newKeys
	FileShareMetaNew.UUIDofFileTree = userdata.Ancestry[filename][childorigin]
	newTreeKeys := make(map[string][]byte)
	newTreeKeys["AES-CFB"] = userdata.AncestryKeys[filename][childorigin]["AES-CFB"]
	newTreeKeys["HMAC"] = userdata.AncestryKeys[filename][childorigin]["HMAC"]
	FileShareMetaNew.TreeKeys = newTreeKeys
	//serializing new cloud
	serializedCloud, _ := json.Marshal(FileShareMetaNew)
	encryptedSerializedCloud, _ := userlib.PKEEnc(childsRSAKey, serializedCloud)
	//HMACing new cloud
	encryptedHMACSerializedCloud, _ := userlib.HMACEval(newHMAC, encryptedSerializedCloud)

	//Old cloud
	childCloud, _ := userlib.DatastoreGet(*childCloudUUID)
	childCloudNew := append(encryptedHMACSerializedCloud, childCloud[len(childCloud)-256:]...)

	//writing new metadata cloud
	userlib.DatastoreSet(*childCloudUUID, childCloudNew)
}
