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
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	_, err2 := u.LoadFile("this file does not exist")
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
