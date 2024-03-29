// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gobgp

import (
	"context"
	"testing"

	"github.com/cilium/cilium/pkg/bgpv1/types"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/stretchr/testify/require"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "bgp-test")
)

// TestGetPeerState confirms the parsing of go bgp ListPeers to cilium modes work as intended
func TestGetPeerState(t *testing.T) {
	type neighbor struct {
		peerASN     int
		peerAddress string
	}

	var table = []struct {
		// name of the test
		name string
		// neighbors to configure
		neighbors []neighbor
		// localASN is local autonomous number
		localASN uint32
		// error provided or nil
		err error
	}{
		{
			name: "basic config parsing",
			neighbors: []neighbor{
				{
					peerASN:     64125,
					peerAddress: "192.168.0.1/32",
				},
			},
			localASN: 64124,
			err:      nil,
		},
	}
	for _, tt := range table {
		srvParams := types.ServerParameters{
			Global: types.BGPGlobal{
				ASN:        tt.localASN,
				RouterID:   "127.0.0.1",
				ListenPort: -1,
			},
		}
		t.Run(tt.name, func(t *testing.T) {
			testSC, err := NewGoBGPServerWithConfig(context.Background(), log, srvParams)
			require.NoError(t, err)

			t.Cleanup(func() {
				testSC.Stop()
			})
			// create current vRouter config and add neighbors
			router := &v2alpha1api.CiliumBGPVirtualRouter{
				LocalASN:  int(tt.localASN),
				Neighbors: []v2alpha1api.CiliumBGPNeighbor{},
			}

			for _, n := range tt.neighbors {
				router.Neighbors = append(router.Neighbors, v2alpha1api.CiliumBGPNeighbor{
					PeerAddress: n.peerAddress,
					PeerASN:     n.peerASN,
				})
				testSC.AddNeighbor(context.Background(), types.NeighborRequest{
					Neighbor: &v2alpha1api.CiliumBGPNeighbor{
						PeerAddress: n.peerAddress,
						PeerASN:     n.peerASN,
					},
				})
			}

			res, err := testSC.GetPeerState(context.Background())
			require.NoError(t, err)

			// total neighbors should be 1
			require.Len(t, res.Peers, 1)

			// validate basic data is returned correctly
			require.Equal(t, int64(tt.localASN), res.Peers[0].LocalAsn)
			require.Equal(t, int64(tt.neighbors[0].peerASN), res.Peers[0].PeerAsn)

			// since there is no real neighbor, bgp session state will be either idle or active.
			require.Contains(t, []string{"idle", "active"}, res.Peers[0].SessionState)
		})
	}
}
