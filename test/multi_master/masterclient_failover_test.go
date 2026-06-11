package multi_master

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/seaweedfs/seaweedfs/weed/pb"
	"github.com/seaweedfs/seaweedfs/weed/pb/master_pb"
	"github.com/seaweedfs/seaweedfs/weed/wdclient"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// insecureDialOption is what filer/s3 effectively use to reach masters in tests.
func insecureDialOption() grpc.DialOption {
	return grpc.WithTransportCredentials(insecure.NewCredentials())
}

// masterServerDiscovery builds the http-form master list exactly like a filer
// configured with -master="127.0.0.1:p0,127.0.0.1:p1,127.0.0.1:p2".
func (mc *MasterCluster) masterServerDiscovery() pb.ServerDiscovery {
	addrs := []string{mc.NodeAddress(0), mc.NodeAddress(1), mc.NodeAddress(2)}
	return *pb.ServerAddresses(strings.Join(addrs, ",")).ToServiceDiscovery()
}

// probeAdvertisedLeader opens a KeepConnected stream to node i (exactly like a
// client) and returns the raw VolumeLocation.Leader string the server advertises.
func probeAdvertisedLeader(t *testing.T, mc *MasterCluster, i int) string {
	t.Helper()
	var leader string
	err := pb.WithMasterClient(true, pb.ServerAddress(mc.NodeAddress(i)), insecureDialOption(), false, func(client master_pb.SeaweedClient) error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		stream, err := client.KeepConnected(ctx)
		if err != nil {
			return err
		}
		if err := stream.Send(&master_pb.KeepConnectedRequest{
			ClientType:    "probe",
			ClientAddress: "probe-" + mc.NodeAddress(i),
		}); err != nil {
			return err
		}
		resp, err := stream.Recv()
		if err != nil {
			return err
		}
		if resp.VolumeLocation != nil {
			leader = resp.VolumeLocation.Leader
		}
		return nil
	})
	if err != nil {
		t.Logf("probe node %d (%s) KeepConnected error: %v", i, mc.NodeAddress(i), err)
	}
	return leader
}

// TestLeaderAddressFormatProbe answers the key empirical question: in what string
// format does the master advertise the raft leader to clients (grpc-only
// "host:grpcPort" vs combined "host:port.grpcPort"), and what does a real
// MasterClient resolve as its current master.
func TestLeaderAddressFormatProbe(t *testing.T) {
	mc := StartMasterCluster(t)

	leaderIdx, leaderAddr := mc.FindLeader()
	if leaderIdx < 0 {
		t.Fatal("no leader found")
	}
	t.Logf("leader: node %d http-addr=%s grpc-addr=%s", leaderIdx, leaderAddr, mc.NodeGRPCAddress(leaderIdx))

	for i := range 3 {
		adv := probeAdvertisedLeader(t, mc, i)
		t.Logf(">>> node %d advertises VolumeLocation.Leader = %q (http-form=%q)", i, adv, pb.ServerAddress(adv).ToHttpAddress())
	}

	// Now what does a real MasterClient (as filer/s3 use it) resolve?
	client := wdclient.NewMasterClient(insecureDialOption(), "", "probe-client", "", "", "", mc.masterServerDiscovery())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go client.KeepConnectedToMaster(ctx)

	resolveCtx, resolveCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer resolveCancel()
	resolved := client.GetMaster(resolveCtx)
	t.Logf(">>> MasterClient.GetMaster() resolved = %q (http-form=%q); expected leader http-addr=%q",
		resolved, resolved.ToHttpAddress(), leaderAddr)

	if resolved == "" {
		t.Errorf("MasterClient never resolved a master within 20s (stuck redirect bug)")
	} else if resolved.ToHttpAddress() != leaderAddr {
		t.Errorf("MasterClient resolved %q (http %q), but actual leader is %q", resolved, resolved.ToHttpAddress(), leaderAddr)
	}
}

// pollGetMasterHttp polls MasterClient.GetMaster until it resolves to wantHttpAddr
// or the timeout elapses. Returns the last resolved http-form address.
func pollGetMasterHttp(client *wdclient.MasterClient, wantHttpAddr string, timeout time.Duration) string {
	deadline := time.Now().Add(timeout)
	var last string
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		m := client.GetMaster(ctx)
		cancel()
		last = m.ToHttpAddress()
		if last == wantHttpAddr {
			return last
		}
		time.Sleep(300 * time.Millisecond)
	}
	return last
}

// TestMasterClientFollowsLeaderOnFailover reproduces the production symptom:
// after the leader is killed, a filer/s3-style MasterClient must converge to the
// NEW leader. If the leader-redirect mechanism is broken, GetMaster stays pinned
// to the dead/old leader (or never resolves) and the client is "stuck".
func TestMasterClientFollowsLeaderOnFailover(t *testing.T) {
	mc := StartMasterCluster(t)

	leaderIdx, leaderAddr := mc.FindLeader()
	if leaderIdx < 0 {
		t.Fatal("no leader found")
	}
	t.Logf("initial leader: node %d at %s", leaderIdx, leaderAddr)

	client := wdclient.NewMasterClient(insecureDialOption(), "", "failover-client", "", "", "", mc.masterServerDiscovery())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go client.KeepConnectedToMaster(ctx)

	// Initially the client must resolve the current leader.
	if got := pollGetMasterHttp(client, leaderAddr, 20*time.Second); got != leaderAddr {
		t.Fatalf("client failed to resolve initial leader %q, got %q", leaderAddr, got)
	}
	t.Logf("client resolved initial leader %s", leaderAddr)

	// Kill the leader.
	mc.StopNode(leaderIdx)
	t.Logf("stopped leader node %d", leaderIdx)

	newLeaderIdx, newLeaderAddr, err := mc.WaitForNewLeader(leaderAddr, leaderElectionTimeout)
	if err != nil {
		mc.DumpLogs()
		t.Fatalf("new leader not elected: %v", err)
	}
	t.Logf("new leader: node %d at %s", newLeaderIdx, newLeaderAddr)

	// The client must converge to the new leader. This is the crux of the bug.
	if got := pollGetMasterHttp(client, newLeaderAddr, 30*time.Second); got != newLeaderAddr {
		mc.DumpLogs()
		t.Fatalf("STUCK: client did not converge to new leader %q within 30s, still resolves %q", newLeaderAddr, got)
	}
	t.Logf("client converged to new leader %s", newLeaderAddr)
}
