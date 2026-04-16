// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kube // import "go.opentelemetry.io/obi/pkg/kube"

import (
	"encoding/json"
	"net/http"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/internal/kube"
)

// Debug types for JSON serialization of the store state.

type debugContainerInfo struct {
	ContainerID  string `json:"containerID"`
	PIDNamespace uint32 `json:"pidNamespace"`
}

type debugPodMeta struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace"`
	Kind        string            `json:"kind"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	NodeName    string            `json:"nodeName,omitempty"`
	Containers  []string          `json:"containers,omitempty"`
	OwnerChain  []string          `json:"ownerChain,omitempty"`
}

type debugNamespaceEntry struct {
	PID         app.PID `json:"pid"`
	ContainerID string  `json:"containerID"`
}

type debugServiceInfo struct {
	Name         string `json:"name"`
	Namespace    string `json:"namespace"`
	K8SNamespace string `json:"k8sNamespace"`
}

type debugStoreState struct {
	// PID namespace inode → list of (PID, containerID) entries
	Namespaces map[uint32][]debugNamespaceEntry `json:"namespaces"`
	// containerID → pod info
	PodsByContainer map[string]debugPodMeta `json:"podsByContainer"`
	// PID → container info
	ContainerByPID map[app.PID]debugContainerInfo `json:"containerByPID"`
	// IP → pod info
	ObjectMetaByIP map[string]debugPodMeta `json:"objectMetaByIP"`
	// IP → resolved service name/namespace
	OTELServiceInfoByIP map[string]debugServiceInfo `json:"otelServiceInfoByIP"`
	// ownerID → containerID → container name
	ContainersByOwner map[string]map[string]string `json:"containersByOwner"`
}

func podMetaToDebug(cmeta *kube.CachedObjMeta) debugPodMeta {
	d := debugPodMeta{
		Name:      cmeta.Meta.Name,
		Namespace: cmeta.Meta.Namespace,
		Kind:      cmeta.Meta.Kind,
	}
	if len(cmeta.Meta.Annotations) > 0 {
		d.Annotations = cmeta.Meta.Annotations
	}
	if len(cmeta.Meta.Labels) > 0 {
		d.Labels = cmeta.Meta.Labels
	}
	if cmeta.Meta.Pod != nil {
		d.NodeName = cmeta.Meta.Pod.NodeName
		for _, c := range cmeta.Meta.Pod.Containers {
			d.Containers = append(d.Containers, c.Name+"("+c.Id+")")
		}
		for _, o := range cmeta.Meta.Pod.Owners {
			d.OwnerChain = append(d.OwnerChain, o.Kind+"/"+o.Name)
		}
	}
	return d
}

// DumpState returns a JSON-serializable snapshot of the store's internal state.
func (s *Store) DumpState() debugStoreState {
	s.access.RLock()
	defer s.access.RUnlock()

	state := debugStoreState{
		Namespaces:          make(map[uint32][]debugNamespaceEntry),
		PodsByContainer:     make(map[string]debugPodMeta),
		ContainerByPID:      make(map[app.PID]debugContainerInfo),
		ObjectMetaByIP:      make(map[string]debugPodMeta),
		OTELServiceInfoByIP: make(map[string]debugServiceInfo),
		ContainersByOwner:   make(map[string]map[string]string),
	}

	for pidNs, pidMap := range s.namespaces {
		entries := make([]debugNamespaceEntry, 0, len(pidMap))
		for pid, info := range pidMap {
			entries = append(entries, debugNamespaceEntry{
				PID:         pid,
				ContainerID: info.ContainerID,
			})
		}
		state.Namespaces[pidNs] = entries
	}

	for cid, cmeta := range s.podsByContainer {
		state.PodsByContainer[cid] = podMetaToDebug(cmeta)
	}

	for pid, info := range s.containerByPID {
		state.ContainerByPID[pid] = debugContainerInfo{
			ContainerID:  info.ContainerID,
			PIDNamespace: info.PIDNamespace,
		}
	}

	for ip, cmeta := range s.objectMetaByIP {
		state.ObjectMetaByIP[ip] = podMetaToDebug(cmeta)
	}

	for ip, svcInfo := range s.otelServiceInfoByIP {
		state.OTELServiceInfoByIP[ip] = debugServiceInfo{
			Name:         svcInfo.Name,
			Namespace:    svcInfo.Namespace,
			K8SNamespace: svcInfo.K8SNamespace,
		}
	}

	for ownerID, containers := range s.containersByOwner {
		cMap := make(map[string]string)
		for cid, cinfo := range containers {
			cMap[cid] = cinfo.Name
		}
		state.ContainersByOwner[ownerID] = cMap
	}

	return state
}

func (s *Store) debugHTTPHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	state := s.DumpState()
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(state); err != nil {
		s.log.Error("failed to encode store debug state", "error", err)
	}
}
