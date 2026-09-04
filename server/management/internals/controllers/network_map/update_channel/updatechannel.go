package update_channel

import (
	"context"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	"github.com/netbirdio/netbird/management/server/telemetry"
)

const channelBufferSize = 100

type PeersUpdateManager struct {
	// peerChannels is an update channel indexed by Peer.ID
	peerChannels map[string]chan *network_map.UpdateMessage
	// notificationChannels carry edge-triggered invalidations for clients
	// that fetch their network map on a separate request path. Keeping them
	// out of peerChannels means they do not make the network-map controller
	// build a SyncResponse they will never consume.
	notificationChannels map[string]chan struct{}
	// channelsMux keeps the mutex to access peerChannels
	channelsMux *sync.RWMutex
	// metrics provides method to collect application metrics
	metrics telemetry.AppMetrics
	// publishNotification is set only by the Postgres HA bootstrap. It runs
	// after local delivery, so a database outage cannot suppress a local push.
	publishNotification func(context.Context, string)
}

var _ network_map.PeersUpdateManager = (*PeersUpdateManager)(nil)

// NewPeersUpdateManager returns a new instance of PeersUpdateManager
func NewPeersUpdateManager(metrics telemetry.AppMetrics) *PeersUpdateManager {
	return &PeersUpdateManager{
		peerChannels:         make(map[string]chan *network_map.UpdateMessage),
		notificationChannels: make(map[string]chan struct{}),
		channelsMux:          &sync.RWMutex{},
		metrics:              metrics,
	}
}

// SendUpdate sends update message to the peer's channel
func (p *PeersUpdateManager) SendUpdate(ctx context.Context, peerID string, update *network_map.UpdateMessage) {
	start := time.Now()
	var found, dropped bool

	p.channelsMux.RLock()

	defer func() {
		p.channelsMux.RUnlock()
		if p.metrics != nil {
			p.metrics.UpdateChannelMetrics().CountSendUpdateDuration(time.Since(start), found, dropped)
		}
	}()

	if channel, ok := p.peerChannels[peerID]; ok {
		found = true
		select {
		case channel <- update:
			log.WithContext(ctx).Tracef("update was sent to channel for peer %s", peerID)
		default:
			dropped = true
			log.WithContext(ctx).Warnf("channel for peer %s is %d full or closed", peerID, len(channel))
		}
	} else {
		log.WithContext(ctx).Debugf("peer %s has no channel", peerID)
	}
	// Karst streams subscribe through the lightweight invalidation channel.
	// A remote replica cannot safely receive update's process-local payload, so
	// it re-fetches authoritative state after this edge-triggered signal.
	if p.publishNotification != nil {
		go p.SendNotification(ctx, peerID)
	}
}

// SendNotification tells a lightweight subscriber that its state changed.
// Notifications are deliberately coalesced: one pending invalidation is
// enough to make the subscriber re-fetch its authoritative state.
func (p *PeersUpdateManager) SendNotification(ctx context.Context, peerID string) {
	p.sendNotification(ctx, peerID, true)
}

func (p *PeersUpdateManager) sendNotification(ctx context.Context, peerID string, publish bool) {
	p.channelsMux.RLock()
	if ch, ok := p.notificationChannels[peerID]; ok {
		select {
		case ch <- struct{}{}:
			log.WithContext(ctx).Tracef("notification was sent to channel for peer %s", peerID)
		default:
			log.WithContext(ctx).Tracef("notification already pending for peer %s", peerID)
		}
	}
	publisher := p.publishNotification
	p.channelsMux.RUnlock()
	if publish && publisher != nil {
		publisher(ctx, peerID)
	}
}

// PublishNotificationsWith installs cross-replica edge-triggered delivery.
// receive must call DeliverNotification, never SendNotification, to avoid
// rebroadcast loops.
func (p *PeersUpdateManager) PublishNotificationsWith(publish func(context.Context, string)) {
	p.channelsMux.Lock()
	defer p.channelsMux.Unlock()
	p.publishNotification = publish
}

// DeliverNotification delivers a notification received from another replica.
func (p *PeersUpdateManager) DeliverNotification(ctx context.Context, peerID string) {
	p.sendNotification(ctx, peerID, false)
}

// CreateChannel creates a go channel for a given peer used to deliver updates relevant to the peer.
func (p *PeersUpdateManager) CreateChannel(ctx context.Context, peerID string) chan *network_map.UpdateMessage {
	start := time.Now()

	closed := false

	p.channelsMux.Lock()
	defer func() {
		p.channelsMux.Unlock()
		if p.metrics != nil {
			p.metrics.UpdateChannelMetrics().CountCreateChannelDuration(time.Since(start), closed)
		}
	}()

	if channel, ok := p.peerChannels[peerID]; ok {
		closed = true
		delete(p.peerChannels, peerID)
		close(channel)
	}
	// mbragin: todo shouldn't it be more? or configurable?
	channel := make(chan *network_map.UpdateMessage, channelBufferSize)
	p.peerChannels[peerID] = channel

	log.WithContext(ctx).Debugf("opened updates channel for a peer %s", peerID)

	return channel
}

// CreateNotificationChannel registers a lightweight invalidation subscriber.
func (p *PeersUpdateManager) CreateNotificationChannel(ctx context.Context, peerID string) chan struct{} {
	p.channelsMux.Lock()
	defer p.channelsMux.Unlock()

	if ch, ok := p.notificationChannels[peerID]; ok {
		delete(p.notificationChannels, peerID)
		close(ch)
	}
	ch := make(chan struct{}, 1)
	p.notificationChannels[peerID] = ch
	log.WithContext(ctx).Debugf("opened notification channel for peer %s", peerID)
	return ch
}

func (p *PeersUpdateManager) closeChannel(ctx context.Context, peerID string) {
	closed := false
	if channel, ok := p.peerChannels[peerID]; ok {
		delete(p.peerChannels, peerID)
		close(channel)
		closed = true
		log.WithContext(ctx).Debugf("closed updates channel of a peer %s", peerID)
	}
	if channel, ok := p.notificationChannels[peerID]; ok {
		delete(p.notificationChannels, peerID)
		close(channel)
		closed = true
		log.WithContext(ctx).Debugf("closed notification channel for peer %s", peerID)
	}
	if !closed {
		log.WithContext(ctx).Debugf("closing updates channel: peer %s has no channel", peerID)
	}
}

// CloseChannels closes updates channel for each given peer
func (p *PeersUpdateManager) CloseChannels(ctx context.Context, peerIDs []string) {
	start := time.Now()

	p.channelsMux.Lock()
	defer func() {
		p.channelsMux.Unlock()
		if p.metrics != nil {
			p.metrics.UpdateChannelMetrics().CountCloseChannelsDuration(time.Since(start), len(peerIDs))
		}
	}()

	for _, id := range peerIDs {
		p.closeChannel(ctx, id)
	}
}

// CloseChannel closes updates channel of a given peer
func (p *PeersUpdateManager) CloseChannel(ctx context.Context, peerID string) {
	start := time.Now()

	p.channelsMux.Lock()
	defer func() {
		p.channelsMux.Unlock()
		if p.metrics != nil {
			p.metrics.UpdateChannelMetrics().CountCloseChannelDuration(time.Since(start))
		}
	}()

	p.closeChannel(ctx, peerID)
}

// GetAllConnectedPeers returns a copy of the connected peers map
func (p *PeersUpdateManager) GetAllConnectedPeers() map[string]struct{} {
	start := time.Now()

	p.channelsMux.RLock()

	m := make(map[string]struct{})

	defer func() {
		p.channelsMux.RUnlock()
		if p.metrics != nil {
			p.metrics.UpdateChannelMetrics().CountGetAllConnectedPeersDuration(time.Since(start), len(m))
		}
	}()

	for ID := range p.peerChannels {
		m[ID] = struct{}{}
	}

	return m
}

// HasChannel returns true if peers has channel in update manager, otherwise false
func (p *PeersUpdateManager) HasChannel(peerID string) bool {
	start := time.Now()

	p.channelsMux.RLock()

	defer func() {
		p.channelsMux.RUnlock()
		if p.metrics != nil {
			p.metrics.UpdateChannelMetrics().CountHasChannelDuration(time.Since(start))
		}
	}()

	_, ok := p.peerChannels[peerID]

	return ok
}

// HasNotificationChannel reports whether peerID has a lightweight subscriber.
func (p *PeersUpdateManager) HasNotificationChannel(peerID string) bool {
	p.channelsMux.RLock()
	defer p.channelsMux.RUnlock()
	_, ok := p.notificationChannels[peerID]
	return ok
}

func (p *PeersUpdateManager) CountStreams() int {
	p.channelsMux.RLock()
	defer p.channelsMux.RUnlock()
	return len(p.peerChannels) + len(p.notificationChannels)
}
