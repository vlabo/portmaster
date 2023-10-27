//go:build windows
// +build windows

package windowskext

import (
	"context"
	"fmt"
	"time"

	"github.com/safing/portmaster/process"

	"github.com/tevino/abool"

	"github.com/safing/portbase/log"
	"github.com/safing/portmaster/network/packet"
)

type VersionInfo struct {
	major    uint8
	minor    uint8
	revision uint8
	build    uint8
}

func (v *VersionInfo) String() string {
	return fmt.Sprintf("%d.%d.%d.%d", v.major, v.minor, v.revision, v.build)
}

// Handler transforms received packets to the Packet interface.
func Handler(ctx context.Context, packets chan packet.Packet) {
	infoChan := GetInfoChannel()
	for {
		info, ok := <-infoChan
		if !ok {
			// Check if we are done with processing.

			log.Warningf("failed to get packet from windows kext: channel closed")
			return
		}

		if info == nil {
			continue
		}

		if info.Connection != nil {
			connection := info.Connection
			log.Debugf("packet: %+v", connection)

			// New Packet
			new := &Packet{
				verdictRequestId: connection.Id,
				verdictSet:       abool.NewBool(false),
			}
			info := new.Info()
			info.Inbound = connection.Direction > 0
			info.InTunnel = false
			info.Protocol = packet.IPProtocol(connection.Protocol)
			info.PID = int(*connection.ProcessId)
			info.SeenAt = time.Now()

			// Check PID
			if info.PID == 0 {
				// Windows does not have zero PIDs.
				// Set to UndefinedProcessID.
				info.PID = process.UndefinedProcessID
			}

			// Set IP version
			info.Version = packet.IPv4

			// Set IPs
			// Outbound
			info.Src = connection.LocalIp
			info.Dst = connection.RemoteIp

			// Set Ports
			// Outbound
			info.SrcPort = connection.LocalPort
			info.DstPort = connection.RemotePort

			packets <- new
		}
	}
}
