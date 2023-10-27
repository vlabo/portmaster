//go:build windows
// +build windows

package windowskext

import (
	"errors"

	"github.com/safing/portmaster/network"
	"github.com/vlabo/portmaster_windows_rust_kext/kext_interface"
	"golang.org/x/sys/windows"
)

// Package errors
var (
	ErrKextNotReady = errors.New("the windows kernel extension (driver) is not ready to accept commands")
	ErrNoPacketID   = errors.New("the packet has no ID, possibly because it was fast-tracked by the kernel extension")

	driverPath string

	service  *kext_interface.KextService
	kextFile *kext_interface.KextFile

	infoChannel chan *kext_interface.Info
)

const (
	winErrInvalidData     = uintptr(windows.ERROR_INVALID_DATA)
	winInvalidHandleValue = windows.Handle(^uintptr(0)) // Max value
	driverName            = "PortmasterTest"
)

// Init initializes the DLL and the Kext (Kernel Driver).
func Init(path string) error {
	driverPath = path
	var err error
	service, err = kext_interface.CreateKextService(driverName, driverPath)
	return err
}

func Delete() {
	service.Delete()
}

// Start intercepting.
func Start() error {
	service.Start(true)
	var err error
	kextFile, err = service.OpenFile()
	return err
}

// Stop intercepting.
func Stop() error {
	shutdownRequest()
	close(infoChannel)
	service.Stop(true)
	return nil
}

func shutdownRequest() error {
	kext_interface.WriteCommand(kextFile, kext_interface.BuildShutdown())
	return nil
}

func GetInfoChannel() chan *kext_interface.Info {
	infoChannel = make(chan *kext_interface.Info)
	go func() {
		kext_interface.ReadInfo(kextFile, infoChannel)
	}()
	return infoChannel
}

// SetVerdict sets the verdict for a packet and/or connection.
func SetVerdict(pkt *Packet, verdict network.Verdict) error {
	if verdict == network.VerdictRerouteToNameserver {
		redirect := kext_interface.Redirect{Id: pkt.verdictRequestId, RemoteAddress: []uint8{127, 0, 0, 53}, RemotePort: 53}
		command := kext_interface.BuildRedirect(redirect)
		kext_interface.WriteCommand(kextFile, command)
	} else if verdict == network.VerdictRerouteToTunnel {
		redirect := kext_interface.Redirect{Id: pkt.verdictRequestId, RemoteAddress: []uint8{127, 0, 0, 1}, RemotePort: 717}
		command := kext_interface.BuildRedirect(redirect)
		kext_interface.WriteCommand(kextFile, command)
	} else {
		verdict := kext_interface.Verdict{Id: pkt.verdictRequestId, Verdict: uint8(verdict)}
		command := kext_interface.BuildVerdict(verdict)
		kext_interface.WriteCommand(kextFile, command)
	}
	return nil
}

func UpdateVerdict(conn *network.Connection) error {

	return nil
}

func GetVersion() (*VersionInfo, error) {
	version_array, err := kext_interface.ReadVersion(kextFile)
	if err != nil {
		return nil, err
	}

	version := &VersionInfo{
		major:    version_array[0],
		minor:    version_array[1],
		revision: version_array[2],
		build:    version_array[3],
	}
	return version, nil
}
