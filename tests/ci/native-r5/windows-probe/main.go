//go:build windows && amd64

// Diagnostic only. The imported frozen engine and all production guards are unchanged.
package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"oniondesk.local/offline/engine"
	"oniondesk.local/offline/engine/production"
)

const manifestPin = "09ae996ff86f97c1e38fdfb6b9e38cc7618e365ae4279d8fd806c4f7bee963d0"
const administrators = "S-1-5-32-544"

//go:embed manifest.json
var manifest []byte

var kernel = syscall.NewLazyDLL("kernel32.dll")

type snapshot struct {
	Exists          bool   `json:"exists"`
	OwnerUser       bool   `json:"owner_is_user"`
	OwnerAdmin      bool   `json:"owner_is_admin"`
	OwnerDefault    bool   `json:"owner_is_token_owner"`
	Protected       bool   `json:"dacl_protected"`
	SDDL            string `json:"sddl,omitempty"`
	DescriptorError string `json:"descriptor_error,omitempty"`
}

func systemDLL(name string) (*syscall.DLL, error) {
	buffer := make([]uint16, 32768)
	n, _, callErr := kernel.NewProc("GetSystemDirectoryW").Call(uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)))
	if n == 0 || n >= uintptr(len(buffer)) {
		return nil, callErr
	}
	return syscall.LoadDLL(filepath.Join(syscall.UTF16ToString(buffer[:n]), name))
}

func localCache(shell *syscall.DLL) (string, error) {
	ole, err := systemDLL("ole32.dll")
	if err != nil {
		return "", err
	}
	defer ole.Release()
	id := syscall.GUID{Data1: 0xf1b32785, Data2: 0x6fba, Data3: 0x4fcf, Data4: [8]byte{0x9d, 0x55, 0x7b, 0x8e, 0x7f, 0x15, 0x70, 0x91}}
	var value *uint16
	status, _, _ := shell.MustFindProc("SHGetKnownFolderPath").Call(uintptr(unsafe.Pointer(&id)), 0, 0, uintptr(unsafe.Pointer(&value)))
	if status != 0 || value == nil {
		return "", syscall.Errno(status)
	}
	defer ole.MustFindProc("CoTaskMemFree").Call(uintptr(unsafe.Pointer(value)))
	name := make([]uint16, 0, 256)
	for i := 0; i < 32768; i++ {
		item := *(*uint16)(unsafe.Add(unsafe.Pointer(value), uintptr(i)*2))
		if item == 0 {
			return filepath.Join(syscall.UTF16ToString(name), "OnionDesk-Offline"), nil
		}
		name = append(name, item)
	}
	return "", errors.New("known folder size exceeded")
}

func tokenIdentity() (user, owner string, elevated bool, err error) {
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return "", "", false, err
	}
	defer token.Close()
	u, err := token.GetTokenUser()
	if err != nil {
		return "", "", false, err
	}
	user, err = u.User.Sid.String()
	if err != nil {
		return "", "", false, err
	}
	buffer := make([]byte, 512)
	var required uint32
	if err := syscall.GetTokenInformation(token, syscall.TokenOwner, &buffer[0], uint32(len(buffer)), &required); err != nil {
		return "", "", false, err
	}
	owner, err = (*(**syscall.SID)(unsafe.Pointer(&buffer[0]))).String()
	runtime.KeepAlive(buffer)
	if err != nil {
		return "", "", false, err
	}
	var flag uint32
	if err := syscall.GetTokenInformation(token, syscall.TokenElevation, (*byte)(unsafe.Pointer(&flag)), 4, &required); err != nil {
		return "", "", false, err
	}
	return user, owner, flag != 0, nil
}

func describe(advapi *syscall.DLL, path, user, tokenOwner string) snapshot {
	result := snapshot{}
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return result
	} else if err != nil {
		result.DescriptorError = err.Error()
		return result
	}
	result.Exists = true
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		result.DescriptorError = err.Error()
		return result
	}
	var descriptor uintptr
	var owner *syscall.SID
	status, _, _ := advapi.MustFindProc("GetNamedSecurityInfoW").Call(uintptr(unsafe.Pointer(name)), 1, 5,
		uintptr(unsafe.Pointer(&owner)), 0, 0, 0, uintptr(unsafe.Pointer(&descriptor)))
	runtime.KeepAlive(name)
	if status != 0 {
		result.DescriptorError = syscall.Errno(status).Error()
		return result
	}
	defer syscall.LocalFree(syscall.Handle(descriptor))
	if owner == nil {
		result.DescriptorError = "owner unavailable"
		return result
	}
	ownerText, err := owner.String()
	if err != nil {
		result.DescriptorError = err.Error()
		return result
	}
	result.OwnerUser, result.OwnerAdmin, result.OwnerDefault = ownerText == user, ownerText == administrators, ownerText == tokenOwner
	var control uint16
	var revision uint32
	ok, _, callErr := advapi.MustFindProc("GetSecurityDescriptorControl").Call(descriptor, uintptr(unsafe.Pointer(&control)), uintptr(unsafe.Pointer(&revision)))
	if ok == 0 {
		result.DescriptorError = callErr.Error()
		return result
	}
	result.Protected = control&0x1000 != 0
	var text *uint16
	var count uint32
	ok, _, callErr = advapi.MustFindProc("ConvertSecurityDescriptorToStringSecurityDescriptorW").Call(descriptor, 1, 5,
		uintptr(unsafe.Pointer(&text)), uintptr(unsafe.Pointer(&count)))
	if ok == 0 {
		result.DescriptorError = callErr.Error()
		return result
	}
	defer syscall.LocalFree(syscall.Handle(uintptr(unsafe.Pointer(text))))
	if count > 32768 {
		result.DescriptorError = "descriptor exceeds diagnostic limit"
		return result
	}
	result.SDDL = syscall.UTF16ToString(unsafe.Slice(text, count))
	return result
}

func run() (map[string]any, error) {
	if len(os.Args) != 1 || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" || os.Getenv("CI_PUBLIC_REPOSITORY") != "true" ||
		os.Getenv("GITHUB_REPOSITORY") != "lindwerg/oniondesk" || os.Getenv("RUNNER_OS") != "Windows" || os.Getenv("RUNNER_ARCH") != "X64" {
		return nil, errors.New("public Windows runner required")
	}
	root, source := os.Getenv("ONIONDESK_CI_OWNED_ROOT"), os.Getenv("ONIONDESK_CI_PACKAGE_ROOT")
	owner := os.Getenv("ONIONDESK_CI_OWNER")
	marker, err := os.ReadFile(filepath.Join(root, ".owner"))
	if err != nil || len(owner) != 32 || string(marker) != owner || !filepath.IsAbs(root) || !filepath.IsAbs(source) {
		return nil, errors.New("private diagnostic ownership required")
	}
	relative, err := filepath.Rel(root, source)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, errors.New("package outside diagnostic root")
	}
	advapi, err := systemDLL("advapi32.dll")
	if err != nil {
		return nil, err
	}
	defer advapi.Release()
	shell, err := systemDLL("shell32.dll")
	if err != nil {
		return nil, err
	}
	defer shell.Release()
	cache, err := localCache(shell)
	if err != nil {
		return nil, err
	}
	user, tokenOwner, elevated, err := tokenIdentity()
	if err != nil {
		return nil, err
	}
	contract, err := engine.ParseManifest(manifest, manifestPin)
	if err != nil {
		return nil, err
	}
	catalog, err := production.LoadOnline()
	if err != nil {
		return nil, err
	}
	result := map[string]any{"go_version": runtime.Version(), "manifest": manifestPin, "cache": cache,
		"token_owner_equals_user": tokenOwner == user, "token_owner_is_admin": tokenOwner == administrators, "token_elevated": elevated,
		"root_before": describe(advapi, cache, user, tokenOwner), "child_before": describe(advapi, filepath.Join(cache, manifestPin), user, tokenOwner)}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	var download atomic.Bool
	_, restoreErr := engine.RestoreOnline(ctx, contract, filepath.Join(source, ".oniondesk", "transport", "blobs"), cache,
		filepath.Join(cache, "online-r5"), catalog, engine.Options{Progress: func(progress engine.Progress) {
			if progress.Phase == "downloading" {
				download.Store(true)
			}
		}})
	result["root_after"], result["child_after"] = describe(advapi, cache, user, tokenOwner), describe(advapi, filepath.Join(cache, manifestPin), user, tokenOwner)
	result["unsafe_error"], result["download_progress_seen"] = errors.Is(restoreErr, engine.ErrUnsafe), download.Load()
	result["deadline_reached"] = errors.Is(restoreErr, context.DeadlineExceeded)
	result["restore_lock_exists"] = false
	if _, err := os.Lstat(filepath.Join(cache, manifestPin, "restore.lock")); err == nil {
		result["restore_lock_exists"] = true
	}
	if restoreErr != nil {
		result["restore_error"] = restoreErr.Error()
	}
	return result, nil
}

func main() {
	result, err := run()
	if err != nil {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"diagnostic_error": err.Error()})
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, "diagnostic output unavailable")
		os.Exit(2)
	}
}
