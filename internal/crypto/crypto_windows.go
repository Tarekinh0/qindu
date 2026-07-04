//go:build windows

package crypto

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modadvapi32             = syscall.NewLazyDLL("advapi32.dll")
	procInitAcl             = modadvapi32.NewProc("InitializeAcl")
	procAddAccessAllowedAce = modadvapi32.NewProc("AddAccessAllowedAceEx")
)

const (
	aclRevision = 2 // ACL_REVISION
)

// validateKeyFilePermissions ensures the key file ACL grants owner+SYSTEM only.
func validateKeyFilePermissions(path string) error {
	if err := setKeyFileACL(path); err != nil {
		return fmt.Errorf("crypto: key file ACL validation failed for %s: %w", path, err)
	}
	return nil
}

// setPlatformACL sets restrictive ACL on Windows: owner+SYSTEM only.
func setPlatformACL(path string) error {
	if err := setKeyFileACL(path); err != nil {
		return err
	}
	return nil
}

// setKeyFileACL sets restrictive ACL on the file at path: owner+SYSTEM only.
// Uses SetNamedSecurityInfo from x/sys/windows with a manually constructed ACL.
func setKeyFileACL(path string) error {
	// Get current security descriptor to find the owner SID.
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("GetNamedSecurityInfo failed: %w", err)
	}

	ownerSID, _, err := sd.Owner()
	if err != nil || ownerSID == nil {
		return fmt.Errorf("could not determine owner SID: %w", err)
	}

	// Create SYSTEM SID.
	systemSid, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return fmt.Errorf("failed to create SYSTEM SID: %w", err)
	}

	// Build explicit ACL with two ACEs.
	acl, err := buildRestrictiveACL(ownerSID, systemSid)
	if err != nil {
		return fmt.Errorf("failed to build ACL: %w", err)
	}

	// Set the DACL on the file.
	err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil)
	if err != nil {
		return fmt.Errorf("SetNamedSecurityInfo failed: %w", err)
	}

	return nil
}

// buildRestrictiveACL creates an ACL with two ACCESS_ALLOWED_ACE entries:
// one for ownerSID and one for systemSID, both with generic read+write access.
// Returns a pointer to the ACL that can be passed to SetNamedSecurityInfo.
func buildRestrictiveACL(ownerSID, systemSID *windows.SID) (*windows.ACL, error) {
	accessMask := uint32(windows.GENERIC_READ | windows.GENERIC_WRITE)

	// Get SID lengths (in bytes)
	ownerSidLen := uint32(windows.GetLengthSid(ownerSID))
	systemSidLen := uint32(windows.GetLengthSid(systemSID))

	// Calculate ACL size:
	// ACL header: 8 bytes
	// ACE for owner: sizeof(ACCESS_ALLOWED_ACE) - sizeof(uint32) + ownerSidLen
	// ACE for system: sizeof(ACCESS_ALLOWED_ACE) - sizeof(uint32) + systemSidLen
	// ACE header is 12 bytes (ACCESS_ALLOWED_ACE minus the first SidStart DWORD is 8 bytes).
	// Actually, ACCESS_ALLOWED_ACE struct is:
	//   Header: AceType(1)+AceFlags(1)+AceSize(2) = 4 bytes
	//   Mask: 4 bytes
	//   SidStart: 4 bytes (first DWORD of SID)
	// So total fixed = 12 bytes, then remaining SID bytes beyond the first DWORD.
	aceFixedSize := uint32(unsafe.Sizeof(windows.ACCESS_ALLOWED_ACE{}))
	ownerAceSize := aceFixedSize - 4 + ownerSidLen // -4 because SidStart[0] is already counted via DWORD
	systemAceSize := aceFixedSize - 4 + systemSidLen

	aclSize := uint32(unsafe.Sizeof(windows.ACL{})) + ownerAceSize + systemAceSize

	// Allocate ACL buffer.
	aclBuf := make([]byte, aclSize)
	acl := (*windows.ACL)(unsafe.Pointer(&aclBuf[0]))

	// Call InitializeAcl
	ret, _, errno := procInitAcl.Call(
		uintptr(unsafe.Pointer(acl)),
		uintptr(aclSize),
		uintptr(aclRevision),
	)
	if ret == 0 {
		return nil, fmt.Errorf("InitializeAcl failed: %w", errno)
	}

	// Add ACE for owner.
	// AddAccessAllowedAceEx(pAcl, dwAceRevision, AceFlags, AccessMask, pSid)
	ret, _, errno = procAddAccessAllowedAce.Call(
		uintptr(unsafe.Pointer(acl)),
		uintptr(aclRevision),
		uintptr(0), // AceFlags — no inheritance needed for key file
		uintptr(accessMask),
		uintptr(unsafe.Pointer(ownerSID)),
	)
	if ret == 0 {
		return nil, fmt.Errorf("AddAccessAllowedAceEx(owner) failed: %w", errno)
	}

	// Add ACE for SYSTEM.
	ret, _, errno = procAddAccessAllowedAce.Call(
		uintptr(unsafe.Pointer(acl)),
		uintptr(aclRevision),
		uintptr(0),
		uintptr(accessMask),
		uintptr(unsafe.Pointer(systemSID)),
	)
	if ret == 0 {
		return nil, fmt.Errorf("AddAccessAllowedAceEx(SYSTEM) failed: %w", errno)
	}

	return acl, nil
}
