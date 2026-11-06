//go:build windows

package agentservice

import (
	"testing"
	"time"

	"golang.org/x/sys/windows/svc"
)

func TestToSvcStatus(t *testing.T) {
	for _, tc := range []struct {
		in   Status
		want svc.Status
	}{
		{
			Status{State: StartPending, CheckPoint: 3, WaitHint: 30 * time.Second},
			svc.Status{State: svc.StartPending, CheckPoint: 3, WaitHint: 30000},
		},
		{
			Status{State: Running, AcceptsStop: true},
			svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown},
		},
		{
			Status{State: StopPending, CheckPoint: 1, WaitHint: 30 * time.Second},
			svc.Status{State: svc.StopPending, CheckPoint: 1, WaitHint: 30000},
		},
	} {
		if got := toSvcStatus(tc.in); got != tc.want {
			t.Errorf("toSvcStatus(%+v) = %+v, want %+v", tc.in, got, tc.want)
		}
	}
}

func TestToServiceCommand(t *testing.T) {
	for in, want := range map[svc.Cmd]Command{
		svc.Interrogate: CmdInterrogate,
		svc.Stop:        CmdStop,
		svc.Shutdown:    CmdShutdown,
		svc.Pause:       CmdOther,
		svc.PreShutdown: CmdOther,
	} {
		if got := toCommand(in); got != want {
			t.Errorf("toCommand(%v) = %v, want %v", in, got, want)
		}
	}
}
