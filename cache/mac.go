package cache

import (
	"net"
	"sync"
)

type MacCache struct {
	sync.RWMutex
	entries map[string]net.HardwareAddr
}

func NewMacCache() *MacCache {
	return &MacCache{
		entries: make(map[string]net.HardwareAddr),
	}
}
func (c *MacCache) Add(ip string, mac net.HardwareAddr) {
	c.Lock()
	defer c.Unlock()
	c.entries[ip] = mac
}
func (c *MacCache) Get(ip string) net.HardwareAddr {
	c.RLock()
	defer c.RUnlock()
	if mac, ok := c.entries[ip]; ok {
		return mac
	}
	return nil
}
func (c *MacCache) GetAll() map[string]net.HardwareAddr {
	c.RLock()
	defer c.RUnlock()
	return c.entries
}
func (c *MacCache) Reset() {
	c.Lock()
	defer c.Unlock()
	c.entries = make(map[string]net.HardwareAddr)
}
