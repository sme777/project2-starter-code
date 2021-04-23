package proj2

// You MUST NOT change these default imports.  ANY additional imports it will
// break the autograder and everyone will be sad.

import (
	_ "encoding/hex"
	_ "encoding/json"
	_ "errors"
	"fmt"
	"reflect"
	_ "strconv"
	_ "strings"
	"testing"

	"github.com/cs161-staff/userlib"
	"github.com/google/uuid"
	_ "github.com/google/uuid"
)

func clear() {
	// Wipes the storage so one test does not affect another
	userlib.DatastoreClear()
	userlib.KeystoreClear()
}

func TestInit0(t *testing.T) {
	clear()
	u1, err1 := InitUser("alice", "fubar")
	if err1 != nil {
		t.Error("Failed to initialize user", err1)
		return
	}
	u2, err2 := GetUser("alice", "fubar")
	if err2 != nil {
		t.Error("Failed to initialize user", err2)
		return
	}

	if !reflect.DeepEqual(u1, u2) {
		t.Error("Should say that these are the same user")
		return
	}

}

func TestInit(t *testing.T) {
	clear()
	t.Log("Initialization test")

	// You can set this to false!
	userlib.SetDebugStatus(true)

	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got user", u)
	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.
}

func TestInit2(t *testing.T) {
	clear()
	t.Log("Testing User with Repeated Name")

	userlib.SetDebugStatus(true)

	u, err := InitUser("bob", "bobbydean")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "deanbobby")
	if err2 == nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got user", u)
	t.Log("Didn't get user", u2)
}

func TestInit3(t *testing.T) {
	clear()
	user, _ := InitUser("mxo", "klor")
	user1, err := GetUser("mxo", "klor")
	if err != nil {
		t.Error("Failed to get user")
		return
	}
	if !reflect.DeepEqual(user1, user) {
		t.Error("Should say that these are the same user")
		return
	}
}

func TestGet(t *testing.T) {
	clear()
	t.Log("Initialization test")

	// You can set this to false!
	userlib.SetDebugStatus(true)

	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got user", u)
	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.
	u2, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to get user", err)
		return
	}
	if !reflect.DeepEqual(u2, u) {
		fmt.Println("poo")
	}
}

func TestGet2(t *testing.T) {
	clear()
	t.Log("Initialization test")

	// You can set this to false!
	userlib.SetDebugStatus(true)

	u, err := InitUser("bob", "urchi")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got user", u)
	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.
	_, err2 := GetUser("bob", "urchik")
	if err2 == nil {
		t.Error("Failed to get user", err)
		return
	}

	_, err3 := GetUser("alice", "putanka")
	if err3 == nil {
		t.Error("Failed to get user", err)
		return
	}
}

func TestGet3(t *testing.T) {
	_, err := GetUser("arikus", "marikus")
	if err == nil {
		t.Error("Should not be able to get a non existing user")
		return
	}
}

func TestGet4(t *testing.T) {
	clear()
	_, _ = InitUser("mxo", "klor")

	_, err := GetUser("mxo", "qarakusi")
	if err == nil {
		t.Error("Invalidate credentials")
		return
	}
}

func TestStorage(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}
}

func TestStorage2(t *testing.T) {
	clear()
	u, err := InitUser("alice", "gyot")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("Cereteli Alyoshka")
	u.StoreFile("file1", v)

	v_new := []byte("Teci Rubosh")
	u.StoreFile("file1", v_new)

	v_final, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if reflect.DeepEqual(v, v_final) {
		t.Error("Downloaded file is the same", v, v_final)
		return
	}
}

func TestInvalidFile(t *testing.T) {
	clear()
	user, _ := InitUser("alice", "fubar")

	_, err2 := user.LoadFile("this file does not exist")
	if err2 == nil {
		t.Error("Downloaded a ninexistent file", err2)
		return
	}
}

func TestShare0(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	var v2 []byte
	var accessToken uuid.UUID

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	accessToken, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", accessToken)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}
}

func TestShare1(t *testing.T) {
	clear()
	t.Log("Testing sharing file that I don't own")

	user1, _ := InitUser("sasunci mkrtich", "sasun")
	_, _ = InitUser("gandonchik", "plan")
	_, err := user1.ShareFile("file1", "gandonchik")
	if err == nil {
		t.Error("Cannot share file that I don't own", err)
		return
	}
}

func TestShare2(t *testing.T) {
	clear()
	t.Log("Sharing a file shared with me")
	user1, _ := InitUser("sasunci mkrtich", "sasun")
	user2, _ := InitUser("hachnci gvenik", "plan")
	user3, _ := InitUser("Yonjlaqci bluetotik", "siktir")

	v := []byte("Cereteli Alyoshka")
	user1.StoreFile("file1", v)

	token, err := user1.ShareFile("file1", "hachnci gvenik")
	if err != nil {
		t.Error("Cannot share file that I own", err)
		return
	}

	err2 := user2.ReceiveFile("file1", "sasunci mkrtich", token)
	if err2 != nil {
		t.Error("Cannot receive file with valid access token", err)
		return
	}

	token2, err3 := user2.ShareFile("file1", "Yonjlaqci bluetotik")
	if err3 != nil {
		t.Error("Cannot share file that I have access to", err)
		return
	}

	err4 := user3.ReceiveFile("file1", "hachnci gvenik", token2)
	if err4 != nil {
		t.Error("Cannot receive file with valid access token", err)
		return
	}
}

func TestShare3(t *testing.T) {
	clear()
	t.Log("Sharing a file with invalid user")
	user1, _ := InitUser("heros andranik", "sasun")
	v := []byte("Cereteli Kara")
	user1.StoreFile("file1", v)
	_, err := user1.ShareFile("file1", "hachnci gvenik")

	if err == nil {
		t.Error("Trying to share a file with unknown user", err)
		return
	}
}

func TestAppend0(t *testing.T) {
	clear()

	file1data := []byte("File 1 data woohoo")
	file1dataAppend1 := []byte(" here is more yeet")
	file1dataAppend2 := []byte(" and even more!!")

	u, err := InitUser("nick", "weaver")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	u.StoreFile("file1", file1data)
	u.AppendFile("file1", file1dataAppend1)
	u.AppendFile("file1", file1dataAppend2)

	v1, err := u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}

	v2 := append(file1data, file1dataAppend1...)
	v2 = append(v2, file1dataAppend2...)

	fmt.Println(string(v1))
	fmt.Println(string(v2))

	if !reflect.DeepEqual(v1, v2) {
		t.Error("Appended file is not the same", v1, v2)
		return
	}
}

func TestAppend1(t *testing.T) {
	clear()
	t.Log("Trying to append for non existent file")
	user1, _ := InitUser("sasunci mkrtich", "sasun")
	err := user1.AppendFile("ccashat", []byte("inchqan mec enqanlav"))
	if err == nil {
		t.Error("Appended file that does not exist")
		return
	}
}

func TestAppend2(t *testing.T) {
	clear()
	t.Log("Trying to append to file with no access")
	user1, _ := InitUser("sasunci mkrtich", "sasun")
	user2, _ := InitUser("bob", "marley")

	file1 := []byte("some cool stuff")
	user1.StoreFile("file1", file1)
	access, err := user1.ShareFile("file1", "bob")

	if err != nil {
		t.Error("Sharing should work for user with file")
		return
	}

	user2.ReceiveFile("file1", "sasunci mkrtich", access)
	err2 := user2.AppendFile("file1", []byte("more cool stuff"))

	//err := user1.AppendFile("ccashat", []byte("inchqan mec enqanlav"))
	if err2 != nil {
		t.Error("Appended file should work for user with access token")
		return
	}
}

func TestAppend3(t *testing.T) {
	clear()
	t.Log("Trying to append to file with no access")
	user1, _ := InitUser("sasunci mkrtich", "sasun")
	user2, _ := InitUser("bob", "marley")

	file1 := []byte("some cool stuff")
	user1.StoreFile("file1", file1)
	access, err := user1.ShareFile("file1", "bob")

	if err != nil {
		t.Error("Sharing should work for user with file")
		return
	}

	user2.ReceiveFile("file1", "sasunci mkrtich", access)
	err2 := user2.AppendFile("file1", []byte("more cool stuff"))

	if err2 != nil {
		t.Error("Appended file should work for user with access token")
		return
	}

	err3 := user1.RevokeFile("file1", "bob")

	if err3 != nil {
		t.Error("Revoking should work for existing user")
		return
	}

	err4 := user2.AppendFile("file1", []byte("evenn more cool stuff"))
	if err4 == nil {
		t.Error("Appended file should not work for user with invalid access token")
		return
	}

}

func TestAppend4(t *testing.T) {

	user1, _ := InitUser("mxo", "klor")
	user2, _ := InitUser("sme", "qarakusi")

	data := []byte("Here we go again, klris")
	_ = user1.StoreFile("file1", data)

	v, err := user1.LoadFile("file1")
	if err != nil {
		t.Error("Should be able to load the data")
		return
	}

	token, err2 := user1.ShareFile("file1", "sme")
	if err2 != nil {
		t.Error("Should be able to share file")
		return
	}

	err3 := user2.ReceiveFile("file2", "mxo", token)
	if err3 != nil {
		t.Error("Could not recieve file with a valid access token")
		return
	}
	new_data := []byte("Qunem turqi berany")
	user1.AppendFile("file1", new_data)

	user2.AppendFile("file2", new_data)

	v2 := append(v, new_data...)
	v2 = append(v2, new_data...)

	load1, err4 := user1.LoadFile("file1")
	load2, err5 := user2.LoadFile("file2")

	if err4 != nil || err5 != nil {
		t.Error("An error occured while trying to load file")
		return
	}
	if !reflect.DeepEqual(load1, v2) || !reflect.DeepEqual(load2, v2) {
		t.Error("The shared data is no longer the same")
		return
	}
}

func TestAppend5(t *testing.T) {
	clear()
	user1, _ := InitUser("mxo", "klor")

	v := []byte("hello world")
	user1.StoreFile("file1", v)

	for i := 0; i < 200; i++ {
		err := user1.AppendFile("file1", []byte(" hi"))
		if err != nil {
			t.Error("Should be able to append to a file")
			return
		}
	}

	v2, err2 := user1.LoadFile("file1")
	if err2 != nil {
		t.Error("Should be able to download the file")
		return
	}

	if reflect.DeepEqual(v, v2) {
		t.Error("Should not be equal to original file")
		return
	}
}

func TestLoad0(t *testing.T) {
	clear()
	t.Log("Testing loading user owned files")
	//initialize user
	user1, _ := InitUser("mxo", "urod")
	file1 := []byte("matroyshka")
	user1.StoreFile("klor", file1)
	loadFile1, err := user1.LoadFile("klor")
	if err != nil {
		t.Error("failed download")
		return
	}
	if !reflect.DeepEqual(loadFile1, file1) {
		t.Error("file is diffrent")
		return
	}
}

func TestRecieve0(t *testing.T) {
	clear()
	t.Log("Testing recieving for non existant user")
	user1, _ := InitUser("charles", "king")
	err := user1.ReceiveFile("sexy pics", "elizabeth", uuid.New())
	if err == nil {
		t.Error("Should not recieve non existant files. Awrr, where are my pics!")
	}
}

func TestRecieve1(t *testing.T) {
	clear()
	t.Log("Testing recieving right after revoking")
	user1, _ := InitUser("phillip", "king")
	user2, _ := InitUser("elizabeth", "queen")
	sexy_pics := []byte("heeree are some pictures of me darling [file size = 1.5GB]")
	user2.StoreFile("my sexy pics", sexy_pics)
	token, _ := user2.ShareFile("my sexy pics", "phillip")
	// oh no, i sent it to the wrong king!
	user2.RevokeFile("my sexy pics", "phillip")
	err := user1.ReceiveFile("my sexy pics", "elizabeth", token)
	if err == nil {
		t.Error("Should not recieve revoked files!")
	}
}

func TestReceive2(t *testing.T) {
	user1, _ := InitUser("mxo", "klor")
	user2, _ := InitUser("sme", "karol")

	file1 := "krilo"
	data := []byte("goxakan jan")
	user1.StoreFile(file1, data)

	load, _ := user1.LoadFile(file1)

	if !reflect.DeepEqual(data, load) {
		t.Error("Different file")
	}

	token, _ := user1.ShareFile(file1, "sme")

	file_rec := "bob's brilliant file"
	user2.ReceiveFile(file_rec, "mxo", token)
	newoad, err := user2.LoadFile(file_rec)
	if err != nil {
		t.Error("Could not receive the shared file")
		return
	}
	if !reflect.DeepEqual(data, newoad) {
		t.Error("Incorrect files")
	}
}

func TestReceive3(t *testing.T) {
	clear()
	user1, _ := InitUser("johnny", "you know who")

	user2, _ := InitUser("margaret", "cool")

	v := []byte("Super secret info")
	user1.StoreFile("file1", v)

	v2 := []byte("CIA classified info")
	user2.StoreFile("file2", v2)

	token, _ := user1.ShareFile("file1", "margaret")

	err := user2.ReceiveFile("new file", "mallory", token)
	if err == nil {
		t.Error("Should not recieve file from wrong User")
		return
	}

	err2 := user2.ReceiveFile("new file", "margaret", uuid.New())
	if err2 == nil {
		t.Error("Should not recieve invalid token")
		return
	}
}

func TestLoad1(t *testing.T) {
	clear()
	t.Log("Testing loading not user owned files")
	//initialize user
	user1, _ := InitUser("mxo", "urod")
	user2, _ := InitUser("samo", "simpo")
	file1 := []byte("matroyshka")
	file2 := []byte("inch xeris matroyshka ara")
	user1.StoreFile("klor", file1)
	user2.StoreFile("qarakusi", file2)

	_, err := user1.LoadFile("qarakusi")
	if err == nil {
		t.Error("should not have access to this file")
		return
	}

	loadFile2, err := user2.LoadFile("qarakusi")
	if err != nil {
		t.Error("should not have access to this file")
		return
	}
	if !reflect.DeepEqual(file2, loadFile2) {
		t.Error("file is diffrent")
		return
	}
}

func TestRevoke0(t *testing.T) {

	clear()
	file1data := []byte("File 1 data woohoo")
	otherAppend := []byte(" Other append to file")
	//rogueAppend := []byte(" Rogue append to file")

	creator, _ := InitUser("nick", "weaver")
	revoked, _ := InitUser("paul", "legler")
	non_revoked, _ := InitUser("evan", "bot")

	creator.StoreFile("file1", file1data)

	token1, _ := creator.ShareFile("file1", "paul")
	revoked.ReceiveFile("file2", "nick", token1)

	token2, _ := creator.ShareFile("file1", "evan")
	non_revoked.ReceiveFile("file3", "nick", token2)

	creator.RevokeFile("file1", "paul")

	creator.AppendFile("file1", otherAppend)

	// - /* check for error post revoking (this should fail or return old data) */
	// _, err0 := revoked.LoadFile("file2")
	// if err0 != nil {
	// 	t.Error("Failed to download the file", err0)
	// }

	// - /* check non-revoked child can see update (should succeed) */
	v1, err1 := non_revoked.LoadFile("file3")
	if err1 != nil {
		t.Error("Failed to download the file, even though supposed to", err1)
		return
	}

	creatorsVersion, creatorLoadError := creator.LoadFile("file1")

	if creatorLoadError != nil {
		t.Error("Failed to load your own file")
		return
	}

	if !reflect.DeepEqual(v1, creatorsVersion) {
		t.Error("Appended file is not the same", v1, creatorsVersion)
		return
	}

	// - /* revoked user trying to append to file */
	// revokedAppendErr := revoked.AppendFile("file2", rogueAppend)
	// if revokedAppendErr != nil {
	// 	t.Error("Revokee couldn't append to file", revokedAppendErr)
	// }

	// - /* checking revoker can't observe revoked user's append */
	creatorLoad2, _ := creator.LoadFile("file1")

	if !reflect.DeepEqual(creatorLoad2, creatorsVersion) {
		t.Error("Appended file is not the same", creatorLoad2, creatorsVersion)
		return
	}
}

func TestRevoke1(t *testing.T) {
	clear()
	// make user
	user1, _ := InitUser("mxo", "rambo")
	user2, _ := InitUser("samo", "rock")
	user3, _ := InitUser("arik", "krakadil")

	user1.StoreFile("file1", []byte("rambo qacov tvec arikusi dzverin"))

	accessToken1, _ := user1.ShareFile("file1", "samo")
	_ = user2.ReceiveFile("file1", "mxo", accessToken1)

	accessToken2, _ := user2.ShareFile("file1", "arik")
	_ = user3.ReceiveFile("file1", "mxo", accessToken2)

	err := user2.RevokeFile("file1", "arik")
	if err == nil {
		t.Error("Can't share when you don't own")
	}
}

func TestRevoke2(t *testing.T) {
	clear()
	user1, _ := InitUser("mxo", "rambo")
	_, _ = InitUser("samo", "rocky")
	_, shareError := user1.ShareFile("xinkali", "samo")
	if shareError == nil {
		t.Error("File does not exist")
		return
	}
}

func TestRevoke3(t *testing.T) {
	clear()
	user1, _ := InitUser("mxo", "1")
	user2, _ := InitUser("samo", "2")
	user3, _ := InitUser("arikus", "3")
	user1.StoreFile("file1", []byte("nice"))

	token1, _ := user1.ShareFile("file1", "samo")
	_ = user2.ReceiveFile("file2", "mxo", token1)

	token2, _ := user2.ShareFile("file2", "arikus")
	_ = user3.ReceiveFile("file3", "samo", token2)

	err := user1.RevokeFile("file1", "arikus")
	if err == nil {
		t.Error("Can't revoke access from indirect children")
	}
}

func TestRevoke4(t *testing.T) {
	clear()
	user1, _ := InitUser("mxo", "1")
	user2, _ := InitUser("samo", "2")
	user3, _ := InitUser("arikus", "3")
	user1.StoreFile("file1", []byte("nice"))

	token1, _ := user1.ShareFile("file1", "samo")
	_ = user2.ReceiveFile("file2", "mxo", token1)

	token2, _ := user2.ShareFile("file2", "arikus")
	_ = user3.ReceiveFile("file3", "samo", token2)

	err := user2.RevokeFile("file1", "arikus")
	if err == nil {
		t.Error("Can't revoke access if not the owner")
	}
}

func datastoreShuffle() {
	datastoreMap := userlib.DatastoreGetMap()
	randomNum := userlib.RandomBytes(16)
	for i := range datastoreMap {
		userlib.DatastoreSet(i, randomNum)
	}
}

func TestAdv1(t *testing.T) {
	clear()
	mxo, _ := InitUser("mxo", "plorik")
	sme, _ := InitUser("sme", "gazanik")

	if reflect.DeepEqual(mxo, sme) {
		t.Error("Init returned the same values for mxo and sme")
		return
	}
	datastoreShuffle()
	_, _ = GetUser("mxo", "sme")

}

func TestAdv2(t *testing.T) {
	clear()
	user1, _ := InitUser("mxo", "klor")
	user2, _ := InitUser("arikus", "pulikus")

	v := []byte("goodies")
	user1.StoreFile("file1", v)

	datastoreShuffle()
	token, err := user1.ShareFile("file1", "arikus")
	if err == nil {
		t.Error("Should have caught the corrupt file")
		return
	}
	err2 := user2.ReceiveFile("file2", "mxo", token)
	if err2 == nil {
		t.Error("Should have caught the corrupt file")
		return
	}
}

func TestAdv3(t *testing.T) {
	clear()
	user1, _ := InitUser("sme", "goxakan")
	v := []byte("steve wonders")
	user1.StoreFile("file1", v)
	datastoreShuffle()
	v2, err2 := user1.LoadFile("file1")
	if err2 == nil {
		t.Error("Should have caught the corrupt file")
		return
	}
	if reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file should be the same")
		return
	}
}

func TestAdv4(t *testing.T) {
	clear()
	datastoreShuffle()
	user1, _ := InitUser("mxo", "plorik")
	user2, _ := GetUser("mxo", "plorik")

	if !reflect.DeepEqual(user1, user2) {
		t.Error("Should output the correct user")
	}
	v := []byte("What a wonderful world")
	user1.StoreFile("file1", v)
	datastoreShuffle()
	err := user1.AppendFile("file1", v)
	if err == nil {
		t.Error("Should output failure")
		return
	}

}

func TestAdv5(t *testing.T) {
	clear()
	user1, _ := InitUser("mxo", "ccan")
	user2, _ := InitUser("sme", "kataxac")

	v := []byte("goodies")
	user1.StoreFile("file1", v)

	token, err := user1.ShareFile("file1", "sme")
	if err != nil {
		t.Error("Should have caught the corrupt file")
		return
	}
	datastoreShuffle()
	err = user2.ReceiveFile("file2", "mxo", token)
	if err == nil {
		t.Error("Should have caught the corrupt file")
		return
	}
}

func TestMix1(t *testing.T) {
	user1, _ := InitUser("michael", "klor")
	user2, _ := InitUser("samson", "qarakusi")

	v1 := []byte("goodies")
	user1.StoreFile("file1", v1)
	user2.StoreFile("file1", v1)

	v2 := []byte("more goodies")
	_ = user1.AppendFile("file1", v2)

	file2, err := user2.LoadFile("file1")
	if err != nil {
		t.Error("Something went wrong")
	}
	if !reflect.DeepEqual(file2, v1) {
		t.Error("File has been illegaly changed")
	}

	v3 := []byte("out of goodies")
	_ = user2.AppendFile("file1", v3)

	file1, err2 := user1.LoadFile("file1")
	if err2 != nil {
		t.Error("Something went wrong")
	}

	if !reflect.DeepEqual(file1, append(v1, v2...)) {
		t.Error("File has been illegaly changed")
	}

}

func TestMix2(t *testing.T) {
	user1, _ := InitUser("mxo", "klor")

	user2, _ := InitUser("sme", "gazan")

	file1 := "krilo"
	data := []byte("goxakan jan")
	user1.StoreFile(file1, data)

	token, _ := user1.ShareFile("file1", "sme")

	_ = user2.ReceiveFile("file2", "mxo", token)

	datastoreMap := userlib.DatastoreGetMap()

	dmKeys := make(map[string][]byte)
	for uuid, _ := range datastoreMap {
		dmKeys[uuid.String()] = datastoreMap[uuid]
	}

	user1.RevokeFile("file1", "sme")

	newDatastoreMap := userlib.DatastoreGetMap()

	for uuid, file := range newDatastoreMap {
		if !reflect.DeepEqual(file, dmKeys[uuid.String()]) {
			userlib.DatastoreSet(uuid, dmKeys[uuid.String()])
		}
	}

	_, err := user2.LoadFile("file2")
	if err == nil {
		t.Error("Did not notice file tampering")
		return
	}
}
