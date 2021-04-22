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
	DataStoreUUID        uuid.UUID
	PublicRSAKey         userlib.PKEEncKey
	PrivateRSAKey        userlib.PKEDecKey
	FileEncKey           []byte
	HMACKey              []byte
	FindKeys             map[string]map[string][]byte
	Hashword             []byte
	FileNamesToUUID      map[string]uuid.UUID
	//SharingDataAccess    map[string]map[string]userlib.UUID
	FilenamesToCloud                map[string]uuid.UUID
	FilesIOwn                       map[string]uuid.UUID
	FilenamesToUsernamesToCloudKeys map[string]map[string]map[string][]byte
	FilenamesToMyCloudKeys          map[string]map[string][]byte

	//points to who shared with (filename)(username)(cloud uuid)
	Ancestry     map[string]map[string]uuid.UUID
	AncestryKeys map[string]map[string]map[string][]byte

	//points to trees for files I need to update
	TreesIUpdateLoc  map[string]uuid.UUID
	TreesIUpdateKeys map[string]map[string][]byte

	//storing signature keys
	privateSign userlib.DSSignKey
	publicSign  userlib.DSVerifyKey

	//FileNumAppends       map[string]int
	//SignitureKeys		 map[string]userlib.DSSignKey
	// your username + filename + x, then hash
	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

type FileShareMeta struct {
	UUIDofFileTree uuid.UUID
	TreeKeys       map[string][]byte

	FileUUID uuid.UUID
	Keys     map[string][]byte
}

type FileTree struct {
	SharedWith     map[string][]byte
	SharedWithKeys map[string]map[string][]byte
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
func pad(unpaddedmsg []byte) []byte {
	msgLen := len(unpaddedmsg)
	n := ((msgLen + 16 - 1) / 16) * 16
	paddedmsg := make([]byte, n)

	for i := 0; i < msgLen; i++ {
		paddedmsg[i] = unpaddedmsg[i]
	}
	for i := msgLen; i < n; i++ {
		paddedmsg[i] = byte(n - msgLen)
	}
	return paddedmsg
}

func depad(paddedmsg []byte) []byte {
	numberOfBytesToRemove := int(paddedmsg[len(paddedmsg)-1])
	startIndex := len(paddedmsg) - numberOfBytesToRemove
	if startIndex >= 0 {
		unpaddedMsg := make([]byte, startIndex)
		for i := 0; i < startIndex; i++ {
			unpaddedMsg[i] = paddedmsg[i]
		}
		return unpaddedMsg
	} else {
		return paddedmsg
	}
}

//This pulls and returns the file struct for a file from Datastore, given a filename
//Errors if no such file exists in filespace
func (userdata *User) PullFile(filename string) (contents []byte, numApp int, err error) {
	userdata.updateKeys(filename)
	storageKey, filenameExists := userdata.FileNamesToUUID[filename]
	if !filenameExists {
		return nil, 0, errors.New("invalid filename supplied for pulling")
	}

	supposedFile, fileExists := userlib.DatastoreGet(storageKey)

	if !fileExists {
		return nil, 0, errors.New("no such file exists in Datastore")
	}

	if len(supposedFile) <= 64 {
		return nil, 0, errors.New("something wrong with length")
	}

	pulledHMAC := supposedFile[len(supposedFile)-64:]
	encryptedFileData := supposedFile[:len(supposedFile)-64]

	//decrypting serialized file data
	decryptedSerializedFile := userlib.SymDec(userdata.FindKeys[filename]["AES-CFB"], encryptedFileData)
	decryptedSerializedFile = depad(decryptedSerializedFile)
	var theFile File
	theFilePtr := &theFile
	json.Unmarshal(decryptedSerializedFile, theFilePtr)

	//verifying HMAC of file
	ownComputedHMAC, _ := userlib.HMACEval(userdata.FindKeys[filename]["HMAC"], decryptedSerializedFile)
	if userlib.HMACEqual(pulledHMAC, ownComputedHMAC) {
		return nil, 0, errors.New("the file you're trying to pull has been tampered with")
	}

	return theFile.Contents, theFile.NumAppends, nil
}

//Creates a file's cloud and it's access token
//Return UUID of cloud, then access token
func (userdata *User) makeCloud(filename string, sender string, recipient string) (returnedCloudUUID *uuid.UUID, accessTokenID *uuid.UUID, err error) {
	storageKey, doIHaveThis := userdata.FileNamesToUUID[filename]
	var err1 error
	if !doIHaveThis {
		return nil, nil, errors.New("you don't have such a file dufus")
	}

	//Creating filesharemeta object
	var filesCloud FileShareMeta
	filesCloud.FileUUID = storageKey
	filesCloudKeysMap := make(map[string][]byte)
	filesCloudKeysMap["HMAC"] = userdata.FindKeys[filename]["HMAC"]
	filesCloudKeysMap["AES-CFB"] = userdata.FindKeys[filename]["AES-CFB"]
	filesCloud.Keys = filesCloudKeysMap

	//Generating Enc Key for Cloud
	cloudEncKey := userlib.Argon2Key(append(userdata.Hashword, []byte(filename+"cloudenc")...), userlib.RandomBytes(16), 16)

	//Generating HMAC Key for Cloud
	cloudHMACKey := userlib.Argon2Key(append(userdata.Hashword, []byte(filename+"cloudhash")...), userlib.RandomBytes(16), 16)

	//Generating UUID for cloud
	cloudUUIDSeed := userlib.RandomBytes(16)
	cloudUUID, _ := uuid.FromBytes(cloudUUIDSeed)

	//Creating and encrypting access token
	myPublicRSAKey, kexist := userlib.KeystoreGet(recipient)
	accessToken := append(cloudUUIDSeed, cloudEncKey...)
	accessToken = append(accessToken, cloudHMACKey...)

	//Encrypting access token
	encryptedToken, _ := userlib.PKEEnc(myPublicRSAKey, accessToken)

	//HMACing access token
	HMACofAccessToken, _ := userlib.HMACEval(cloudHMACKey, encryptedToken)
	encryptedHMACdAccessToken := append(encryptedToken, HMACofAccessToken...)

	//signing
	signature, _ := userlib.DSSign(userdata.privateSign, encryptedHMACdAccessToken)
	//appending signature to HMACed encryption of access token
	signedEnctyptedHMACAccessToken := append(encryptedHMACdAccessToken, signature...)
	//generating access token UUID
	accessTokenUUID := uuid.New()
	//storing the signed HMACed and encrypted data to Datastore
	userlib.DatastoreSet(accessTokenUUID, signedEnctyptedHMACAccessToken)

	//adding to clouds uuid and key hashmaps
	userdata.FilenamesToCloud[filename] = cloudUUID
	cloudKeyHolder := make(map[string][]byte)
	cloudKeyHolder["HMAC"] = cloudHMACKey
	cloudKeyHolder["AES-CFB"] = cloudEncKey

	usernameToKeys := make(map[string]map[string][]byte)
	usernameToKeys[recipient] = cloudKeyHolder

	userdata.FilenamesToUsernamesToCloudKeys[filename] = usernameToKeys

	//seeing if I should start the tree
	storageKey, IOwnThis := userdata.FilesIOwn[filename]
	if IOwnThis {
		//generating treeData
		treeUUID, _ := uuid.FromBytes(userlib.RandomBytes(16))
		filesCloud.TreeKeys = make(map[string][]byte)
		filesCloud.TreeKeys["AES-CFB"] = userlib.Argon2Key(append([]byte(filename+"tree"), userdata.Hashword...), userlib.RandomBytes(16), 16)
		filesCloud.TreeKeys["HMAC"] = userlib.Argon2Key(append([]byte(filename+"tree"), userdata.Hashword...), userlib.RandomBytes(16), 16)
		filesCloud.UUIDofFileTree = treeUUID

		//Creating and uploading tree struct
		var fileTreeForFile FileTree
		fileTreeForFile.SharedWith = make(map[string][]byte)
		fileTreeForFile.SharedWith[recipient] = cloudUUIDSeed

		sharesKeyHolder := make(map[string][]byte)
		sharesKeyHolder["AES-CFB"] = cloudEncKey
		sharesKeyHolder["HMAC"] = cloudHMACKey
		fileTreeForFile.SharedWithKeys = make(map[string]map[string][]byte)
		fileTreeForFile.SharedWithKeys[recipient] = sharesKeyHolder

		//encrypting and uploading filetree
		serializedTree, _ := json.Marshal(fileTreeForFile)
		encryptedSerializedTree := userlib.SymEnc(filesCloud.TreeKeys["AES-CFB"], userlib.RandomBytes(16), pad(serializedTree))
		HMACencryptedSerializedTree, _ := userlib.HMACEval(filesCloud.TreeKeys["HMAC"], encryptedSerializedTree)
		userlib.DatastoreSet(treeUUID, append(encryptedSerializedTree, HMACencryptedSerializedTree...))

		//updatingAncestry
		// recipientsMap := make(map[string]userlib.UUID)
		// recipientsMap[recipient] = treeUUID
		userdata.Ancestry[filename][recipient] = treeUUID

		//recipientsKeysMap := make(map[string]map[string][]byte)
		recipientsKeysMapKeyHolder := make(map[string][]byte)
		recipientsKeysMapKeyHolder["HMAC"] = filesCloud.TreeKeys["HMAC"]
		recipientsKeysMapKeyHolder["AES-CFB"] = filesCloud.TreeKeys["AES-CFB"]
		//recipientsKeysMap[recipient] = recipientsKeysMapKeyHolder
		userdata.AncestryKeys[filename][recipient] = recipientsKeysMapKeyHolder

	} else {
		treeUUID := userdata.TreesIUpdateLoc[filename]
		treeEnc := userdata.TreesIUpdateKeys[filename]["AES-CFB"]
		treeHMAC := userdata.TreesIUpdateKeys[filename]["HMAC"]

		filesCloud.TreeKeys = make(map[string][]byte)
		filesCloud.TreeKeys["AES-CFB"] = treeEnc
		filesCloud.TreeKeys["HMAC"] = treeHMAC
		filesCloud.UUIDofFileTree = treeUUID

		//getting tree I'm supposed to update
		encryptedShareTree, _ := userlib.DatastoreGet(treeUUID)
		//encryptedTreeHMAC := encryptedShareTree[len(encryptedShareTree) - 64:]
		if len(encryptedShareTree) <= 64 {
			return nil, nil, errors.New("something wrong with length")
		}

		encryptedTreeEnc := encryptedShareTree[:len(encryptedShareTree)-64]

		decryptedShareTreeSerialized := userlib.SymDec(treeEnc, encryptedTreeEnc)
		decryptedShareTreeSerialized = depad(decryptedShareTreeSerialized)
		var ShareTree FileTree
		ShareTreePtr := &ShareTree
		json.Unmarshal(decryptedShareTreeSerialized, ShareTreePtr)

		shareMap := make(map[string][]byte)
		shareMap[recipient] = cloudUUIDSeed
		//Creating and uploading tree struct
		ShareTree.SharedWith = shareMap
		keyHolderForSharee := make(map[string][]byte)
		keyHolderForSharee["HMAC"] = cloudHMACKey
		keyHolderForSharee["AES-CFB"] = cloudEncKey

		mapForShareeKeys := make(map[string]map[string][]byte)
		mapForShareeKeys[recipient] = keyHolderForSharee

		//encrypting and uploading filetree
		serializedTree, _ := json.Marshal(ShareTree)
		encryptedSerializedTree := userlib.SymEnc(treeEnc, userlib.RandomBytes(16), pad(serializedTree))
		HMACencryptedSerializedTree := userlib.SymEnc(treeHMAC, userlib.RandomBytes(16), pad(encryptedSerializedTree))
		userlib.DatastoreSet(treeUUID, append(encryptedSerializedTree, HMACencryptedSerializedTree...))

	}

	//Serializing Cloud
	jsonDataCloud, _ := json.Marshal(filesCloud)
	//Encryptin Serialized cloud
	encryptedCloud := userlib.SymEnc(cloudEncKey, userlib.RandomBytes(16), pad(jsonDataCloud))
	//HMACing encrypted serialized cloud
	HMACofEncryptedCloud, _ := userlib.HMACEval(cloudHMACKey, encryptedCloud)
	HMACdEncryptedCloud := append(encryptedCloud, HMACofEncryptedCloud...)
	//Storing cloud in datastore
	userlib.DatastoreSet(cloudUUID, HMACdEncryptedCloud)

	//Getting cloud keys if I don't have them
	_, doIHaveCloudKeys := userdata.FilenamesToMyCloudKeys[filename]
	if !doIHaveCloudKeys {
		myCloudKeyHolder := make(map[string][]byte)
		myCloudKeyHolder["HMAC"] = cloudHMACKey
		myCloudKeyHolder["AES-CFB"] = cloudEncKey
		userdata.FilenamesToMyCloudKeys[filename] = myCloudKeyHolder
	}

	if !kexist {
		err1 = errors.New("keystore key doesn't have value")
	} else {
		err1 = nil
	}

	return &cloudUUID, &accessTokenUUID, err1
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
	if len(FileCloudData) <= 64 {
		return errors.New("something wrong with length")
	}
	cloudDataToDecrypt := FileCloudData[:len(FileCloudData)-64]
	pulledCloudHMAC := FileCloudData[len(FileCloudData)-64:]

	//getting sent HMAC key and Verifying HMAC of Cloud
	decryptedSerializedDataCloud := userlib.SymDec(userdata.FilenamesToMyCloudKeys[filename]["AES-CFB"], cloudDataToDecrypt)
	decryptedSerializedDataCloud = depad(decryptedSerializedDataCloud)
	computedHMAC, _ := userlib.HMACEval(userdata.FilenamesToMyCloudKeys[filename]["HMAC"], cloudDataToDecrypt)

	if !userlib.HMACEqual(computedHMAC, pulledCloudHMAC) {
		return errors.New("someone messed with yo cloud")
	}

	var cloudFinal FileShareMeta
	cloudFinalPtr := &cloudFinal
	json.Unmarshal(decryptedSerializedDataCloud, cloudFinalPtr)

	filesKeyHolder := make(map[string][]byte)
	filesKeyHolder["AES-CFB"] = cloudFinal.Keys["AES-CFB"]
	filesKeyHolder["HMAC"] = cloudFinal.Keys["HMAC"]

	userdata.FindKeys[filename] = filesKeyHolder
	userdata.FileNamesToUUID[filename] = cloudFinal.FileUUID
	return
}

/*** USEFUL HELPER FUNCTIONS END ***/

// InitUser will be called a single time to initialize a new user.
func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata
	//var UUIDerr error
	//var RSAErr error

	_, exists := userlib.KeystoreGet(username)

	if exists {
		return nil, errors.New("username already taken")
	}

	//TODO: This is a toy implementation.
	userdata.Username = username
	//End of toy implementation

	//This will be where we store the encrypted user struct in Datastore
	userdata.DataStoreLocationKey = userlib.Argon2Key([]byte(password), []byte(username), 16)
	userdata.DataStoreUUID, _ = uuid.FromBytes(userdata.DataStoreLocationKey)

	//Generating RSA keys for user
	userdata.PublicRSAKey, userdata.PrivateRSAKey, _ = userlib.PKEKeyGen()

	//Generating symmetric encryption keys
	userdata.FileEncKey = userlib.Argon2Key([]byte(password), []byte(username+password), 16)
	userdata.HMACKey = userlib.Argon2Key([]byte(password), []byte(username+password+username), 16)

	//Storing user's password
	userdata.Hashword = userlib.Hash(append([]byte(password), userlib.RandomBytes(16)...))

	//Making maps
	userdata.FindKeys = make(map[string]map[string][]byte)
	userdata.FileNamesToUUID = make(map[string]uuid.UUID)
	//userdata.SharingDataAccess = make(map[string]map[string]userlib.UUID)
	userdata.FilenamesToCloud = make(map[string]uuid.UUID)
	userdata.FilesIOwn = make(map[string]uuid.UUID)
	userdata.Ancestry = make(map[string]map[string]uuid.UUID)
	userdata.AncestryKeys = make(map[string]map[string]map[string][]byte)
	userdata.TreesIUpdateLoc = make(map[string]uuid.UUID)
	userdata.TreesIUpdateKeys = make(map[string]map[string][]byte)
	userdata.FilenamesToUsernamesToCloudKeys = make(map[string]map[string]map[string][]byte)
	userdata.FilenamesToMyCloudKeys = make(map[string]map[string][]byte)
	//userdata.FileNumAppends = make(map[string]int)

	//generating signature
	//Storing public Sign key in Keystore
	privSign, pubSign, _ := userlib.DSKeyGen()
	userdata.privateSign = privSign
	userdata.publicSign = pubSign

	//Storing public sign key key in Keystore
	signname := string(userlib.Hash([]byte("signature"))) + string(userlib.Hash([]byte(username)))
	userlib.KeystoreSet(signname, userdata.publicSign)

	//Serializing our user struct
	serial, _ := json.Marshal(userdata)

	//Encrypting userdata
	encryptedUserData := userlib.SymEnc(userdata.FileEncKey, userlib.RandomBytes(16), pad(serial))

	//HMAC-ing encrypted userdata
	HMACofEncryptedUserData, _ := userlib.HMACEval(userdata.HMACKey, encryptedUserData)

	//Storing in DataStore
	userlib.DatastoreSet(userdata.DataStoreUUID, append(encryptedUserData, HMACofEncryptedUserData...))

	//Storing user in Keystore
	userlib.KeystoreSet(username, userdata.PublicRSAKey)

	//Return error for non-unique username
	return &userdata, nil
}

// GetUser is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/getuser.html
func GetUser(username string, password string) (userdataptr *User, err error) {
	//checking if user was initialized
	_, initialized := userlib.KeystoreGet(username)
	if !initialized {
		return nil, errors.New("user has not been initialized")
	}
	var userdata User
	userdataptr = &userdata

	//Retrieving the UUID of where the struct is in the Datastore
	DataStoreLocationKey := userlib.Argon2Key([]byte(password), []byte(username), 16)
	DataStoreUUID, _ := uuid.FromBytes(DataStoreLocationKey)

	//Getting the encrypted data from DataStore
	encryptedRetrievedData, doesItExist := userlib.DatastoreGet(DataStoreUUID)
	if !doesItExist {
		return nil, errors.New("user not found, probably invalid credentials")
	}

	//Verifying authenticity/integritysignedEnctyptedHMACDataCloud

	//Generating HMAC key
	actualHMACKey := userlib.Argon2Key([]byte(password), []byte(username+password+username), 16)

	//Retrieving HMAC from data pulled from DataStore
	lengthEncData := len(encryptedRetrievedData)
	if lengthEncData <= 64 {
		return nil, errors.New("something wrong with length")
	}
	retrievedHMAC := encryptedRetrievedData[lengthEncData-64:]

	//Retrieving and decrypting user struct data from DataStore
	encryptedDataSection := encryptedRetrievedData[:lengthEncData-64]
	userFileEncKey := userlib.Argon2Key([]byte(password), []byte(username+password), 16)
	serializedDecryptedUserData := userlib.SymDec(userFileEncKey, encryptedDataSection)
	serializedDecryptedUserData = depad(serializedDecryptedUserData)
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
	storageKey, doIHaveThis := userdata.FileNamesToUUID[filename]
	_, exists := userlib.DatastoreGet(storageKey)

	if exists {
		if !doIHaveThis {
			return errors.New("you don't have such a file dufus")
		}
		userdata.updateKeys(filename)
		//Encrypting the file struct
		var encrypted_data = userlib.SymEnc(userdata.FindKeys[filename]["AES-CFB"], userlib.RandomBytes(16), pad(jsonData))
		var hmac_data, _ = userlib.HMACEval(userdata.FindKeys[filename]["HMAC"], encrypted_data)
		userlib.DatastoreSet(storageKey, append(encrypted_data, hmac_data...))
	} else {
		//Generating UUID to store file
		newUUIDSeed := userlib.Hash(userlib.RandomBytes(16))
		newUUID, _ := uuid.FromBytes(newUUIDSeed[:16])
		//Generating encryption keys for the file
		var hmac_key = userlib.Argon2Key(append([]byte(filename), userdata.Hashword...), userlib.RandomBytes(16), 16)
		var encryption_key = userlib.Argon2Key(append([]byte(filename), userdata.Hashword...), userlib.RandomBytes(16), 16)

		//Encrypting the file struct
		var encrypted_data = userlib.SymEnc(encryption_key, userlib.RandomBytes(16), pad(jsonData))
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

		//Sharing to myself

		userdata.FilesIOwn[filename] = newUUID

		//taking care of file cloud
		//making ancestry map
		filesAncestry := make(map[string]uuid.UUID)
		userdata.Ancestry[filename] = filesAncestry
		//making ancestry keys map
		fileAncestryKeys := make(map[string]map[string][]byte)
		userdata.AncestryKeys[filename] = fileAncestryKeys
		userdata.makeCloud(filename, userdata.Username, userdata.Username)
		//userdata.SharingDataAccess[filename][userdata.Username] = *UUIDofCloud
	}

	return nil
}

// AppendFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/appendfile.html
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	//TODO: Write file verify helper function
	//TODO: DONT NEED TO GENERATE ORIGINAL UUID, CAN JUST PULL FROM FILENAME -> UUID MAP IN USER STRUCT
	_, supposedExist := userdata.FileNamesToUUID[filename]
	if !supposedExist {
		return errors.New("file doesn't exist in your namespace, dummy")
	}
	userdata.updateKeys(filename)

	_, supposedDataStoreExist := userlib.DatastoreGet(userdata.FileNamesToUUID[filename])
	if !supposedDataStoreExist {
		return errors.New("can't append, file not in datastore")
	}
	//Initializing a File struct for storing the appendage
	var AppendData File
	AppendData.NumAppends = 0
	AppendData.Contents = data
	jsonData, _ := json.Marshal(AppendData)

	userdata.updateKeys(filename)
	//Finding UUID and encryption keys of the original file to append to
	storageKeyOriginal := userdata.FileNamesToUUID[filename]

	var originalFileChanged File
	originalFileChanged.Contents, originalFileChanged.NumAppends, _ = userdata.PullFile(filename)
	originalFileChanged.NumAppends += 1

	//Re-encrypting and uploading the original file struct
	jsonDataOriginalAppendUpdate, _ := json.Marshal(originalFileChanged)
	var encrypted_original_updated_data = userlib.SymEnc(userdata.FindKeys[filename]["AES-CFB"], userlib.RandomBytes(16), pad(jsonDataOriginalAppendUpdate))
	var hmac_original_updated_data, _ = userlib.HMACEval(userdata.FindKeys[filename]["HMAC"], encrypted_original_updated_data)
	userlib.DatastoreSet(storageKeyOriginal, append(encrypted_original_updated_data, hmac_original_updated_data...))

	//Generating UUID to store appendage inside
	byteArrayToHoldInt := make([]byte, 1)
	byteArrayToHoldInt[0] = byte(originalFileChanged.NumAppends)
	UUIDSeed := userlib.Hash(append(userdata.FindKeys[filename]["AES-CFB"], byteArrayToHoldInt...))
	UUIDToStoreAppend, _ := uuid.FromBytes(UUIDSeed[:16])

	//Encrypting and HMACing appendage
	var encrypted_appendage = userlib.SymEnc(userdata.FindKeys[filename]["AES-CFB"], userlib.RandomBytes(16), pad(jsonData))
	var hmac_appendage, _ = userlib.HMACEval(userdata.FindKeys[filename]["HMAC"], encrypted_appendage)

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
	_, doesDataStoreHaveThis := userlib.DatastoreGet(userdata.FileNamesToUUID[filename])
	if !doesDataStoreHaveThis {
		return nil, errors.New("file isn't there, revoked or deleted")
	}
	var originalFile File
	originalFile.Contents, originalFile.NumAppends, _ = userdata.PullFile(filename)
	finalFile.NumAppends = originalFile.NumAppends

	finalFile.Contents = append(finalFile.Contents, originalFile.Contents...)

	for i := 1; i < finalFile.NumAppends+1; i++ {
		byteArrayToHoldInt := make([]byte, 1)
		byteArrayToHoldInt[0] = byte(i)
		UUIDSeed := userlib.Hash(append(userdata.FindKeys[filename]["AES-CFB"], byteArrayToHoldInt...))
		appendageUUID, _ := uuid.FromBytes(UUIDSeed[:16])

		encryptedData, _ := userlib.DatastoreGet(appendageUUID)
		if len(encryptedData) <= 64 {
			return nil, errors.New("something wrong with length")
		}
		HMACencryptedPulledFileData := encryptedData[len(encryptedData)-64:]

		//Pulling keys for file decryption
		verificationHMAC, _ := userlib.HMACEval(userdata.FindKeys[filename]["HMAC"], encryptedData[:len(encryptedData)-64])

		if !userlib.HMACEqual(HMACencryptedPulledFileData, verificationHMAC) {
			return nil, errors.New("integrity issue")
		}

		//decrypting original appendage file struct
		decryptedSerializedAppendageData := userlib.SymDec(userdata.FindKeys[filename]["AES-CFB"], encryptedData[:len(encryptedData)-64])
		decryptedSerializedAppendageData = depad(decryptedSerializedAppendageData)
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
	_, ok1 := userdata.FilesIOwn[filename]
	_, ok2 := userdata.FileNamesToUUID[filename]
	if !ok1 && !ok2 {
		return uuid.New(), errors.New("File does not exist in namespace")
	}
	// instanciate a new file cloud and access token
	_, UUIDofAccessToken, _ := userdata.makeCloud(filename, userdata.Username, recipient)
	//userdata.SharingDataAccess[filename][recipient] = *UUIDofCloud

	return *UUIDofAccessToken, nil
}

// ReceiveFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/receivefile.html
func (userdata *User) ReceiveFile(filename string, sender string,
	accessToken uuid.UUID) (err error) {
	//verifying that the file does not exist
	_, doIHaveThis := userdata.FileNamesToUUID[filename]

	if doIHaveThis {
		return errors.New("you already have that file dufus")
	}

	//pulling the file
	recievedFileData, ok := userlib.DatastoreGet(accessToken)
	if len(recievedFileData) <= 64 {
		return errors.New("somethings up with length")
	}

	if !ok {
		return errors.New("share does not exist or has been revoked")
	}

	//seperating Data, HMAC, Signiture
	verifySignature := recievedFileData[len(recievedFileData)-256:]
	verifyHMAC := recievedFileData[len(recievedFileData)-320 : len(recievedFileData)-256]
	verifyData := recievedFileData[:len(recievedFileData)-320]

	//getting sender's public sign key
	signname := string(userlib.Hash([]byte("signature"))) + string(userlib.Hash([]byte(sender)))
	verifyKey, kexist := userlib.KeystoreGet(signname)
	if !kexist {
		return errors.New("keystore key doesn't have value")
	}

	//verifying sender
	sigError := userlib.DSVerify(verifyKey, recievedFileData[:len(recievedFileData)-256], verifySignature)
	if sigError != nil {
		return errors.New("sender could not be verified")
	}

	//getting sent HMAC key and Verifying HMAC
	decryptedData, _ := userlib.PKEDec(userdata.PrivateRSAKey, verifyData)

	//getting send cloud UUID
	cloudUUIDSeed := decryptedData[:16]
	cloudUUID, _ := uuid.FromBytes(cloudUUIDSeed)
	//getting sent aes cfb key
	cloudEnc := decryptedData[16:32]
	//getting sent hmac key
	cloudHMAC := decryptedData[32:]

	//veryifying HMAC
	computedTokenHMAC, _ := userlib.HMACEval(cloudHMAC, verifyData)
	ok2 := userlib.HMACEqual(computedTokenHMAC, verifyHMAC)
	if !ok2 {
		return errors.New("integirty/authencity issue")
	}

	//Accessing cloud data
	encryptedSerializedData, _ := userlib.DatastoreGet(cloudUUID)
	if len(encryptedSerializedData) <= 64 {
		return errors.New("something wrong with length")
	}
	//verifying HMAC of cloud
	pulledHMACofCloud := encryptedSerializedData[len(encryptedSerializedData)-64:]
	//decrypting cloud structure
	decryptedSerializedData := userlib.SymDec(cloudEnc, encryptedSerializedData[:len(encryptedSerializedData)-64])
	decryptedSerializedData = depad(decryptedSerializedData)
	//verifying hmac of cloud struct
	computedCloudHMAC, _ := userlib.HMACEval(cloudHMAC, encryptedSerializedData[:len(encryptedSerializedData)-64])
	okcloud := userlib.HMACEqual(pulledHMACofCloud, computedCloudHMAC)
	if !okcloud {
		return errors.New("integirty/authencity issue with cloud")
	}

	var recieveFileShareMeta FileShareMeta
	recieveFileShareMetaPtr := &recieveFileShareMeta
	json.Unmarshal(decryptedSerializedData, recieveFileShareMetaPtr)

	//updating filename to UUID for user
	userdata.FileNamesToUUID[filename] = recieveFileShareMeta.FileUUID
	userdata.FilenamesToCloud[filename] = cloudUUID
	myCloudKeysHolder := make(map[string][]byte)
	myCloudKeysHolder["HMAC"] = cloudHMAC
	myCloudKeysHolder["AES-CFB"] = cloudEnc
	userdata.FilenamesToMyCloudKeys[filename] = myCloudKeysHolder

	//updating key-maps for recieving user
	userdata.updateKeys(filename)

	//Storing Tree info for when I share
	userdata.TreesIUpdateLoc[filename] = recieveFileShareMeta.UUIDofFileTree
	userdata.TreesIUpdateKeys[filename] = recieveFileShareMeta.Keys

	// //Updating tree that I received file

	// treeUUID := userdata.TreesIUpdateLoc[filename]
	// treeEnc := userdata.TreesIUpdateKeys[filename]["AES-CFB"]
	// treeHMAC := userdata.TreesIUpdateKeys[filename]["HMAC"]
	// 	//getting tree I'm supposed to update
	// encryptedShareTree, _ := userlib.DatastoreGet(treeUUID)
	// 	//encryptedTreeHMAC := encryptedShareTree[len(encryptedShareTree) - 64:]
	// encryptedTreeEnc := encryptedShareTree[:len(encryptedShareTree) - 64]

	// decryptedShareTreeSerialized := userlib.SymDec(treeEnc, encryptedTreeEnc)
	// decryptedShareTreeSerialized = depad(decryptedShareTreeSerialized)
	// var ShareTree FileTree
	// ShareTreePtr := &ShareTree
	// json.Unmarshal(decryptedShareTreeSerialized, ShareTreePtr)

	// shareMap := make(map[string][]byte)
	// shareMap[userdata.Username] = cloudUUIDSeed
	// 	//Creating and uploading tree struct
	// ShareTree.SharedWith = shareMap
	// keyHolderForSharee := make(map[string][]byte)
	// keyHolderForSharee["HMAC"] = cloudHMAC
	// keyHolderForSharee["AES-CFB"] = cloudEnc

	// mapForShareeKeys := make(map[string]map[string][]byte)
	// mapForShareeKeys[userdata.Username] = keyHolderForSharee

	// 	//encrypting and uploading filetree
	// serializedTree, _ := json.Marshal(ShareTree)
	// encryptedSerializedTree := userlib.SymEnc(treeEnc, userlib.RandomBytes(16), pad(serializedTree))
	// HMACencryptedSerializedTree := userlib.SymEnc(treeHMAC, userlib.RandomBytes(16), pad(encryptedSerializedTree))
	// userlib.DatastoreSet(treeUUID, append(encryptedSerializedTree,HMACencryptedSerializedTree...))

	//take care of 126 bytes limit
	return nil
}

// RevokeFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/revokefile.html
func (userdata *User) RevokeFile(filename string, targetUsername string) (err error) {
	userdata.updateKeys(filename)
	_, fileInMySpace := userdata.FileNamesToUUID[filename]
	if !fileInMySpace {
		return errors.New("you don't have such a filename")
	}
	_, supposedShare := userdata.Ancestry[filename][targetUsername]
	if !supposedShare {
		return errors.New("you haven't shared with this user")
	}

	//new UUID to store file in
	newUUIDSeed := userlib.Hash(append([]byte(filename), userlib.RandomBytes(16)...))
	newUUID, _ := uuid.FromBytes(newUUIDSeed[:16])

	// //originalFileStruct
	// var pulledOriginal File
	// pulledOriginal.Contents, pulledOriginal.NumAppends, _ = userdata.PullFile(filename)
	// serializedOriginal, _ := json.Marshal(pulledOriginal)

	//re-encrypting original file and uploading to new UUID
	newEncKey := userlib.Argon2Key(append(userlib.RandomBytes(16), userdata.Hashword...), userlib.RandomBytes(16), 16)
	newHMACKey := userlib.Argon2Key(append(userlib.RandomBytes(16), userdata.Hashword...), userlib.RandomBytes(16), 16)

	// var encrypted_data = userlib.SymEnc(userdata.FindKeys[filename]["AES-CFB"], userlib.RandomBytes(16), pad(serializedOriginal))
	// var hmac_data, _ = userlib.HMACEval(userdata.FindKeys[filename]["HMAC"], encrypted_data)
	// userlib.DatastoreSet(newUUID, append(encrypted_data, hmac_data...))
	userdata.FileReencryptor(filename, newUUID, newEncKey, newHMACKey)

	//Updating my own stuff
	userdata.FindKeys[filename]["AES-CFB"] = newEncKey
	userdata.FindKeys[filename]["HMAC"] = newHMACKey
	userlib.DatastoreDelete(userdata.FilenamesToCloud[filename])
	userlib.DatastoreDelete(userdata.FileNamesToUUID[filename])
	userdata.FileNamesToUUID[filename] = newUUID
	userdata.makeCloud(filename, userdata.Username, userdata.Username)

	//communicating changes
	for child := range userdata.Ancestry[filename] {
		if child != targetUsername && child != userdata.Username {
			//Pulling child's share tree
			childsShareTreeUUID := userdata.Ancestry[filename][child]
			childsShareTreeKeys := userdata.AncestryKeys[filename][child]
			encryptedChildsShareTree, _ := userlib.DatastoreGet(childsShareTreeUUID)
			//encryptedChildTreeHMAC := encryptedChildsShareTree[len(encryptedChildsShareTree) - 64:]
			if len(encryptedChildsShareTree) <= 64 {
				return errors.New("something wrong with length")
			}
			encryptedChildTreeEnc := encryptedChildsShareTree[:len(encryptedChildsShareTree)-64]

			decryptedChildsShareTreeSerialized := userlib.SymDec(childsShareTreeKeys["AES-CFB"], encryptedChildTreeEnc)
			decryptedChildsShareTreeSerialized = depad(decryptedChildsShareTreeSerialized)
			var childsTree FileTree
			childsTreePtr := &childsTree
			json.Unmarshal(decryptedChildsShareTreeSerialized, childsTreePtr)
			for ancestor, ancestorUUIDSeed := range childsTree.SharedWith {
				if ancestor != targetUsername && ancestor != userdata.Username {
					ancestorEncKey := childsTree.SharedWithKeys[ancestor]["AES-CFB"]
					ancestorHMACKey := childsTree.SharedWithKeys[ancestor]["HMAC"]
					ancestorUUID, _ := uuid.FromBytes(ancestorUUIDSeed)
					userdata.RevokeHelper(child, ancestor, filename, &newUUID, newHMACKey, newEncKey, &ancestorUUID, ancestorEncKey, ancestorHMACKey)
				}
			}
		}
	}
	return
}

func (userdata *User) FileReencryptor(filename string, newUUID uuid.UUID, newEnc []byte, newHMAC []byte) error {
	//new UUID to store file in
	//originalFileStruct
	var pulledOriginal File
	pulledOriginal.Contents, pulledOriginal.NumAppends, _ = userdata.PullFile(filename)
	serializedOriginal, _ := json.Marshal(pulledOriginal)

	var encrypted_data = userlib.SymEnc(newEnc, userlib.RandomBytes(16), pad(serializedOriginal))
	var hmac_data, _ = userlib.HMACEval(newHMAC, encrypted_data)
	userlib.DatastoreSet(newUUID, append(encrypted_data, hmac_data...))

	for i := 1; i < pulledOriginal.NumAppends+1; i++ {
		byteArrayToHoldInt := make([]byte, 1)
		byteArrayToHoldInt[0] = byte(i)

		UUIDSeed := userlib.Hash(append(userdata.FindKeys[filename]["AES-CFB"], byteArrayToHoldInt...))
		appendageUUID, _ := uuid.FromBytes(UUIDSeed[:16])

		encryptedData, _ := userlib.DatastoreGet(appendageUUID)
		if len(encryptedData) <= 64 {
			return errors.New("somethings wrong idk lol")
		}
		HMACencryptedPulledFileData := encryptedData[len(encryptedData)-64:]

		//Pulling keys for file decryption
		verificationHMAC, _ := userlib.HMACEval(newHMAC, encryptedData[:len(encryptedData)-64])

		if !userlib.HMACEqual(HMACencryptedPulledFileData, verificationHMAC) {
			return nil
		}

		//decrypting original appendage file struct
		decryptedSerializedAppendageData := userlib.SymDec(userdata.FindKeys[filename]["AES-CFB"], encryptedData[:len(encryptedData)-64])
		decryptedSerializedAppendageData = depad(decryptedSerializedAppendageData)
		var filedataTestAppendage File
		filedataptrTestAppendage := &filedataTestAppendage
		json.Unmarshal(decryptedSerializedAppendageData, filedataptrTestAppendage)

		newUUIDSeed := userlib.Hash(append(newEnc, byteArrayToHoldInt...))
		newAppendageUUID, _ := uuid.FromBytes(newUUIDSeed[:16])

		reserApp, _ := json.Marshal(filedataTestAppendage)
		reEncApp := userlib.SymEnc(newEnc, userlib.RandomBytes(16), reserApp)
		reEncAppHMAC, _ := userlib.HMACEval(newHMAC, reEncApp)
		userlib.DatastoreSet(newAppendageUUID, append(reEncApp, reEncAppHMAC...))
	}
	return nil
}

func (userdata *User) RevokeHelper(childorigin string, child string, filename string,
	newUUID *uuid.UUID, newHMAC []byte, newEnc []byte,
	ancestorCloudUUID *uuid.UUID, ancestorEncKey []byte, ancestorHMACKey []byte) (err error) {
	//base case
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

	//getting ancestor's cloud keys
	serializedCloudEncrypted := userlib.SymEnc(ancestorEncKey, userlib.RandomBytes(16), pad(serializedCloud))
	//HMACing ancestor's cloud
	HMACAncestorNewCloud, _ := userlib.HMACEval(ancestorHMACKey, serializedCloudEncrypted)
	//writing new metadata cloud
	userlib.DatastoreSet(*ancestorCloudUUID, append(serializedCloudEncrypted, HMACAncestorNewCloud...))
	return
}
