package multi_master

import (
	"context"
	"strconv"
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

// assignErr issues an Assign RPC to whatever master the client currently points
// at and returns the error (nil on success). A non-leader master answers with
// raft.NotLeaderError ("Not current leader").
func assignErr(client *wdclient.MasterClient) (master string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	m := client.GetMaster(ctx)
	master = m.ToHttpAddress()
	if m == "" {
		return "", context.DeadlineExceeded
	}
	err = pb.WithMasterClient(false, m, insecureDialOption(), false, func(c master_pb.SeaweedClient) error {
		actx, acancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer acancel()
		_, e := c.Assign(actx, &master_pb.AssignRequest{Count: 1})
		return e
	})
	return master, err
}

// TestMasterClientStuckOnOldLeaderAfterQuorumLoss is the precise reproduction of
// the production symptom: filer/s3 keep talking to the OLD (now non-leader)
// master and keep getting NotLeaderError after the leader loses leadership.
//
// We force a clean step-down WITHOUT killing the leader process by stopping the
// two followers (quorum loss). The leader steps down but its KeepConnected
// stream to the client is NOT promptly closed because informNewLeader blocks in
// the 20s Topo.Leader() backoff while no new leader exists. During that window
// the client's currentMaster stays pinned to the old leader and every Assign
// returns "Not current leader".
func TestMasterClientStuckOnOldLeaderAfterQuorumLoss(t *testing.T) {
	mc := StartMasterCluster(t)

	leaderIdx, leaderAddr := mc.FindLeader()
	if leaderIdx < 0 {
		t.Fatal("no leader found")
	}
	t.Logf("initial leader: node %d at %s", leaderIdx, leaderAddr)

	client := wdclient.NewMasterClient(insecureDialOption(), "", "stuck-client", "", "", "", mc.masterServerDiscovery())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go client.KeepConnectedToMaster(ctx)

	if got := pollGetMasterHttp(client, leaderAddr, 20*time.Second); got != leaderAddr {
		t.Fatalf("client failed to resolve initial leader %q, got %q", leaderAddr, got)
	}
	t.Logf("client connected to leader %s; Assign works = %v", leaderAddr, func() bool {
		_, e := assignErr(client)
		return e == nil || !strings.Contains(strings.ToLower(fmtErr(e)), "leader")
	}())

	// Stop the two followers -> leader loses quorum and must step down.
	f1, f2 := (leaderIdx+1)%3, (leaderIdx+2)%3
	mc.StopNode(f1)
	mc.StopNode(f2)
	t.Logf("stopped followers %d and %d (quorum lost); old leader %d still running", f1, f2, leaderIdx)

	// Measure how long the client stays pinned to the old leader returning
	// NotLeaderError. A correct client should stop pointing at the demoted
	// master quickly (within ~one KeepConnected ticker interval, ~5-6s).
	// After a clean fix the demoted master closes the client's stream within
	// one KeepConnected ticker interval (~5s) plus step-down latency, instead of
	// blocking in the 20s Topo.Leader() backoff. 12s cleanly separates the
	// broken (~25s) from the fixed (~5-8s) behavior.
	const tolerance = 12 * time.Second
	start := time.Now()
	deadline := start.Add(25 * time.Second)
	var lastMaster, lastErr string
	stuckUntil := time.Time{}
	for time.Now().Before(deadline) {
		m, err := assignErr(client)
		isNotLeader := err != nil && strings.Contains(strings.ToLower(fmtErr(err)), "leader")
		if m == leaderAddr && isNotLeader {
			stuckUntil = time.Now()
			lastMaster, lastErr = m, fmtErr(err)
		}
		time.Sleep(500 * time.Millisecond)
	}

	if !stuckUntil.IsZero() {
		stuckFor := stuckUntil.Sub(start)
		t.Logf("client kept pointing at OLD leader %s with NotLeaderError for ~%v (last err: %q)", lastMaster, stuckFor.Round(time.Second), lastErr)
		if stuckFor > tolerance {
			t.Errorf("REPRO: client stuck on demoted master %s returning NotLeaderError for %v (> %v tolerance)", lastMaster, stuckFor.Round(time.Second), tolerance)
		}
	} else {
		t.Logf("client did not stay stuck on old leader returning NotLeaderError")
	}
}

func fmtErr(e error) string {
	if e == nil {
		return ""
	}
	return e.Error()
}

// aliasServerDiscovery builds the master list using "localhost:port" while the
// masters themselves are started with -ip=127.0.0.1 and therefore advertise the
// leader as "127.0.0.1:port.grpcPort". This mimics a Kubernetes setup where
// filer/s3 reach masters via a Service/DNS name that differs (as a string) from
// the per-pod -ip the masters advertise. Both resolve to the same host so
// connections succeed, but the advertised leader never string-matches a
// masters-list entry.
func (mc *MasterCluster) aliasServerDiscovery() pb.ServerDiscovery {
	addrs := make([]string, 3)
	for i := range 3 {
		addrs[i] = "localhost:" + strconv.Itoa(mc.nodes[i].port)
	}
	return *pb.ServerAddresses(strings.Join(addrs, ",")).ToServiceDiscovery()
}

// TestMasterClientDifferentAddressAlias reproduces the production topology
// (Kubernetes, masters addressed by a name that differs from their advertised
// -ip). It verifies that with the differing address the client still resolves
// the leader and still converges after a failover.
func TestMasterClientDifferentAddressAlias(t *testing.T) {
	mc := StartMasterCluster(t)

	leaderIdx, leaderAddr := mc.FindLeader() // "127.0.0.1:port"
	if leaderIdx < 0 {
		t.Fatal("no leader found")
	}
	aliasLeader := "localhost:" + strconv.Itoa(mc.nodes[leaderIdx].port)
	t.Logf("leader advertised as %s; client addresses it as %s", leaderAddr, aliasLeader)

	client := wdclient.NewMasterClient(insecureDialOption(), "", "alias-client", "", "", "", mc.aliasServerDiscovery())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go client.KeepConnectedToMaster(ctx)

	// The client must resolve to the leader. GetMaster will hold the advertised
	// (127.0.0.1) form, since the masters list (localhost) never matches it.
	resolveCtx, resolveCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer resolveCancel()
	resolved := client.GetMaster(resolveCtx)
	t.Logf("alias client resolved master = %q", resolved)
	if resolved == "" {
		t.Fatal("alias client never resolved a master (stuck on differing address)")
	}
	if resolved.ToHttpAddress() != leaderAddr {
		t.Errorf("alias client resolved %q (http %q), expected leader %q", resolved, resolved.ToHttpAddress(), leaderAddr)
	}

	// Failover: kill the leader, ensure the alias client converges to the new one.
	mc.StopNode(leaderIdx)
	newLeaderIdx, newLeaderAddr, err := mc.WaitForNewLeader(leaderAddr, leaderElectionTimeout)
	if err != nil {
		mc.DumpLogs()
		t.Fatalf("new leader not elected: %v", err)
	}
	t.Logf("new leader advertised as %s", newLeaderAddr)
	if got := pollGetMasterHttp(client, newLeaderAddr, 30*time.Second); got != newLeaderAddr {
		mc.DumpLogs()
		t.Fatalf("STUCK: alias client did not converge to new leader %q within 30s, still %q", newLeaderAddr, got)
	}
	t.Logf("alias client converged to new leader %s (node %d)", newLeaderAddr, newLeaderIdx)
}
