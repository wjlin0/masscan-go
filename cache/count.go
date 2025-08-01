package cache

import "sync"

type ResultCache struct {
	sync.Mutex
	OpenIpCounts map[string]int
}

func NewResultCache() *ResultCache {
	return &ResultCache{
		OpenIpCounts: make(map[string]int),
	}
}
func (rc *ResultCache) Add(ip string) {
	rc.Lock()
	defer rc.Unlock()
	_, ok := rc.OpenIpCounts[ip]
	if !ok {
		rc.OpenIpCounts[ip] = 1
	} else {
		rc.OpenIpCounts[ip]++
	}

}
func (rc *ResultCache) Get(ip string) int {
	rc.Lock()
	defer rc.Unlock()
	count, ok := rc.OpenIpCounts[ip]
	if !ok {
		count = 0
	}
	return count

}
func (rc *ResultCache) GetAll() map[string]int {
	rc.Lock()
	defer rc.Unlock()
	return rc.OpenIpCounts
}
func (rc *ResultCache) Reset() {
	rc.Lock()
	defer rc.Unlock()
	rc.OpenIpCounts = make(map[string]int)
}
