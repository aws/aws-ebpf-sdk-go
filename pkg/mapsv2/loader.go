package mapsv2

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
	"unsafe"

	"github.com/aws/aws-ebpf-sdk-go/pkg/logger"
	"github.com/aws/aws-ebpf-sdk-go/pkg/maps"
	"golang.org/x/sys/unix"
)

var log = logger.Get()

// InMemoryBpfMap provides an in-memory representation of an eBPF map
// with synchronized updates to the underlying kernel map
type InMemoryBpfMap struct {
	// Underlying BPF map
	bpfMap *maps.BpfMap
	// In-memory representation of the map contents
	contents map[string][]byte
	// Mutex for thread safety
	mutex sync.RWMutex
}

// NewInMemoryBpfMap creates a new in-memory representation of an eBPF map
// and optionally loads the initial state from the kernel
func NewInMemoryBpfMap(bpfMap *maps.BpfMap) (*InMemoryBpfMap, error) {
	m := &InMemoryBpfMap{
		bpfMap:   bpfMap,
		contents: make(map[string][]byte),
	}

	log.Infof("creating new In memory map via loading bpf map %+v", bpfMap)
	if err := m.loadFromKernel(); err != nil {
		return nil, err
	}
	log.Infof("created in mem map")

	return m, nil
}

// loadFromKernel loads the current state of the eBPF map from the kernel
func (m *InMemoryBpfMap) loadFromKernel() error {
	startTime := time.Now()

	defer func() {
		totalTime := time.Since(startTime)
		log.Infof("loadFromKernel completed in %v ms, loaded %d entries from kernel map",
			totalTime.Milliseconds(), len(m.contents))
	}()

	log.Infof("Starting loadFromKernel operation")

	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Clear current contents
	m.contents = make(map[string][]byte)

	// Get all keys from the kernel map
	keys, err := m.bpfMap.GetAllMapKeys()
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			log.Info("No Entries found, Empty map")
			return nil
		}
		log.Errorf("Failed to get keys from kernel map: %v", err)
		return err
	}

	// For each key, get the value and store in memory
	for _, key := range keys {
		keyByte := []byte(key)
		keyPtr := uintptr(unsafe.Pointer(&keyByte[0]))

		// Create a buffer for the value based on map's value size
		value := make([]byte, m.bpfMap.MapMetaData.ValueSize)
		valuePtr := uintptr(unsafe.Pointer(&value[0]))

		if err := m.bpfMap.GetMapEntry(keyPtr, valuePtr); err != nil {
			log.Errorf("Failed to get value for key %s: %v", key, err)
			return err
		}

		m.contents[key] = value
	}

	log.Infof("Loaded %d entries from kernel map", len(m.contents))
	return nil
}

// Get retrieves a value from the in-memory map
// Note: The returned byte slice should not be modified by the caller
func (m *InMemoryBpfMap) Get(key string) ([]byte, bool) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	value, exists := m.contents[key]
	return value, exists
}

// Update updates both in-memory and kernel map
// Note: The map takes ownership of the value slice, which should not be modified after calling this method
func (m *InMemoryBpfMap) Update(key string, value []byte) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Store the value directly without copying
	m.contents[key] = value

	// Update kernel map immediately
	keyByte := []byte(key)
	keyPtr := uintptr(unsafe.Pointer(&keyByte[0]))
	valuePtr := uintptr(unsafe.Pointer(&value[0]))

	if err := m.bpfMap.UpdateMapEntry(keyPtr, valuePtr); err != nil {
		log.Errorf("Failed to update kernel map for key %s: %v", key, err)
		return err
	}

	return nil
}

// Delete removes an entry from both in-memory and kernel map
func (m *InMemoryBpfMap) Delete(key string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Delete from kernel map
	keyByte := []byte(key)
	keyPtr := uintptr(unsafe.Pointer(&keyByte[0]))
	if err := m.bpfMap.DeleteMapEntry(keyPtr); err != nil {
		log.Errorf("Failed to delete from kernel map for key %s: %v", key, err)
		return err
	}

	// Delete from in-memory representation
	delete(m.contents, key)

	return nil
}

// BulkUpdate efficiently updates multiple entries with optimized kernel updates
func (m *InMemoryBpfMap) BulkUpdate(updates map[string][]byte) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Calculate changes by comparing with current in-memory state
	toAdd := make(map[string][]byte)

	for k, v := range updates {
		currentVal, exists := m.contents[k]
		if !exists || !bytes.Equal(currentVal, v) {
			// Only update if the key doesn't exist or value has changed
			toAdd[k] = v
			m.contents[k] = v
		}
	}

	// Apply only the necessary updates to kernel
	for k, v := range toAdd {
		keyByte := []byte(k)
		keyPtr := uintptr(unsafe.Pointer(&keyByte[0]))
		valuePtr := uintptr(unsafe.Pointer(&v[0]))

		if err := m.bpfMap.UpdateMapEntry(keyPtr, valuePtr); err != nil {
			log.Errorf("Failed to update kernel map during bulk update for key %s: %v", k, err)
			return err
		}
	}

	log.Infof("Bulk updated %d entries in kernel map", len(toAdd))
	return nil
}

// BulkRefresh efficiently handles both additions and deletions in a single operation
func (m *InMemoryBpfMap) BulkRefresh(newMapContents map[string][]byte) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Find entries to add or update
	toAdd := make(map[string][]byte)
	for k, v := range newMapContents {
		currentVal, exists := m.contents[k]
		if !exists || !bytes.Equal(currentVal, v) {
			toAdd[k] = v
		}
	}

	// Find entries to delete
	toDelete := make([]string, 0)
	for k := range m.contents {
		if _, exists := newMapContents[k]; !exists {
			toDelete = append(toDelete, k)
		}
	}

	// Apply updates to kernel
	for k, v := range toAdd {
		keyByte := []byte(k)
		keyPtr := uintptr(unsafe.Pointer(&keyByte[0]))
		valuePtr := uintptr(unsafe.Pointer(&v[0]))

		if err := m.bpfMap.UpdateMapEntry(keyPtr, valuePtr); err != nil {
			log.Errorf("Failed to update kernel map during bulk refresh for key %s: %v", k, err)
			return err
		}

		// Update in-memory after successful kernel update
		m.contents[k] = v
	}

	// Apply deletes to kernel
	for _, k := range toDelete {
		keyByte := []byte(k)
		keyPtr := uintptr(unsafe.Pointer(&keyByte[0]))

		if err := m.bpfMap.DeleteMapEntry(keyPtr); err != nil {
			log.Errorf("Failed to delete from kernel map for key %s: %v", k, err)
			// Continue with other deletions
		}

		// Remove from in-memory regardless of kernel operation result
		delete(m.contents, k)
	}

	log.Infof("Bulk refresh: added/updated %d entries, deleted %d entries", len(toAdd), len(toDelete))
	return nil
}

// GetAllKeys returns all keys in the in-memory map
func (m *InMemoryBpfMap) GetAllKeys() []string {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	keys := make([]string, 0, len(m.contents))
	for k := range m.contents {
		keys = append(keys, k)
	}
	return keys
}

// GetAllEntries returns all entries in the in-memory map
// Note: The returned map and byte slices should not be modified by the caller
func (m *InMemoryBpfMap) GetAllEntries() map[string][]byte {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// Return a copy of the map but not the values
	entries := make(map[string][]byte, len(m.contents))
	for k, v := range m.contents {
		entries[k] = v
	}
	return entries
}

// Size returns the number of entries in the in-memory map
func (m *InMemoryBpfMap) Size() int {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return len(m.contents)
}

// Clear removes all entries from both in-memory and kernel maps
func (m *InMemoryBpfMap) Clear() error {
	keys := m.GetAllKeys()

	for _, k := range keys {
		if err := m.Delete(k); err != nil {
			return err
		}
	}

	return nil
}

// GetUnderlyingMap returns the underlying BpfMap
func (m *InMemoryBpfMap) GetUnderlyingMap() *maps.BpfMap {
	return m.bpfMap
}

// validateMapConsistency checks that both in-memory content and eBPF map content
// match the newMapContent (source of truth)
func (m *InMemoryBpfMap) validateMapConsistency(newMapContents map[string][]byte) {
	startTime := time.Now()
	defer func() {
		log.Infof("Map consistency validation completed in %v ms", time.Since(startTime).Milliseconds())
	}()

	log.Infof("Starting map consistency validation from newMapContents from %+v", m.bpfMap)

	// Step 1: Get all keys from the kernel map
	kernelKeys, err := m.bpfMap.GetAllMapKeys()
	if err != nil {
		log.Errorf("Failed to get keys from kernel map during validation: %v", err)
		return
	}

	sort.Strings(kernelKeys)
	keys := sortedStringKeys(newMapContents)
	log.Infof("kernel map keys: %v", kernelKeys)
	log.Infof("new map keys: %v", keys)

	// Create maps to track inconsistencies
	missingInMemory := make([]string, 0)
	missingInKernel := make([]string, 0)
	extraInMemory := make([]string, 0)
	extraInKernel := make([]string, 0)
	valueMismatchMemory := make([]string, 0)
	valueMismatchKernel := make([]string, 0)

	// Step 2: Check that all newMapContents keys exist in memory and kernel with matching values
	for key, expectedValue := range newMapContents {
		// Check in-memory map
		memoryValue, existsInMemory := m.contents[key]
		if !existsInMemory {
			missingInMemory = append(missingInMemory, key)
		} else if !bytes.Equal(memoryValue, expectedValue) {
			valueMismatchMemory = append(valueMismatchMemory, key)
		}

		// Check kernel map
		found := false
		for _, kernelKey := range kernelKeys {
			if key == kernelKey {
				found = true
				break
			}
		}

		if !found {
			missingInKernel = append(missingInKernel, key)
		} else {
			// Key exists in kernel, check value
			keyByte := []byte(key)
			keyPtr := uintptr(unsafe.Pointer(&keyByte[0]))
			kernelValue := make([]byte, m.bpfMap.MapMetaData.ValueSize)
			valuePtr := uintptr(unsafe.Pointer(&kernelValue[0]))

			if err := m.bpfMap.GetMapEntry(keyPtr, valuePtr); err != nil {
				log.Errorf("Failed to get value for key %s from kernel during validation: %v", key, err)
				continue
			}

			if !bytes.Equal(kernelValue, expectedValue) {
				valueMismatchKernel = append(valueMismatchKernel, key)
			}
		}
	}

	// Step 3: Check for extra keys in memory that don't exist in newMapContents
	for key := range m.contents {
		if _, exists := newMapContents[key]; !exists {
			extraInMemory = append(extraInMemory, key)
		}
	}

	// Step 4: Check for extra keys in kernel that don't exist in newMapContents
	for _, key := range kernelKeys {
		if _, exists := newMapContents[key]; !exists {
			extraInKernel = append(extraInKernel, key)
		}
	}

	// Log inconsistencies
	if len(missingInMemory) > 0 {
		log.Warnf("Inconsistency detected: %d keys from newMapContents missing in memory: %v",
			len(missingInMemory), truncateList(missingInMemory, 5))
	}

	if len(missingInKernel) > 0 {
		log.Warnf("Inconsistency detected: %d keys from newMapContents missing in kernel: %v",
			len(missingInKernel), truncateList(missingInKernel, 5))
	}

	if len(extraInMemory) > 0 {
		log.Warnf("Inconsistency detected: %d extra keys in memory not in newMapContents: %v",
			len(extraInMemory), truncateList(extraInMemory, 5))
	}

	if len(extraInKernel) > 0 {
		log.Warnf("Inconsistency detected: %d extra keys in kernel not in newMapContents: %v",
			len(extraInKernel), truncateList(extraInKernel, 5))
	}

	if len(valueMismatchMemory) > 0 {
		log.Warnf("Inconsistency detected: %d keys have different values in memory vs newMapContents: %v",
			len(valueMismatchMemory), truncateList(valueMismatchMemory, 5))
	}

	if len(valueMismatchKernel) > 0 {
		log.Warnf("Inconsistency detected: %d keys have different values in kernel vs newMapContents: %v",
			len(valueMismatchKernel), truncateList(valueMismatchKernel, 5))
	}

	// Log success if everything matches
	if len(missingInMemory) == 0 && len(missingInKernel) == 0 &&
		len(extraInMemory) == 0 && len(extraInKernel) == 0 &&
		len(valueMismatchMemory) == 0 && len(valueMismatchKernel) == 0 {
		log.Infof("Map consistency validation successful: all %d entries in newMapContents match both in-memory and eBPF map",
			len(newMapContents))
	}
}

// Helper function to truncate a list for logging
func truncateList(list []string, maxItems int) []string {
	if len(list) <= maxItems {
		return list
	}
	return append(list[:maxItems], fmt.Sprintf("... (%d more)", len(list)-maxItems))
}

func sortedStringKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
