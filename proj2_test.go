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

func TestShare(t *testing.T) {
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



