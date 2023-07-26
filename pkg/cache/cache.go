// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License").
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
//limitations under the License.

package cache

import (
	"sync"

	"github.com/aws/aws-ebpf-sdk-go/pkg/logger"
)

var sdkCache *GlobalCacheMap
var log = logger.Get()

// Adding a struct if in future we need a cleanup routine
type CacheValue struct {
	mapFD int
}

type GlobalCacheMap struct {
	globalMap *sync.Map
}

func (c *GlobalCacheMap) Set(key string, value int) {
	c.globalMap.Store(key, CacheValue{mapFD: value})
}

func (c *GlobalCacheMap) Get(key string) (int, bool) {
	entry, found := c.globalMap.Load(key)
	if !found {
		return -1, false
	}
	cacheEntry := entry.(CacheValue)
	return cacheEntry.mapFD, true
}

func (c *GlobalCacheMap) Delete(key string) {
	c.globalMap.Delete(key)
}

func Get() *GlobalCacheMap {
	if sdkCache == nil {
		sdkCache = New()
		log.Info("Initialized new SDK cache as an existing instance was not found")
	}
	return sdkCache
}

func New() *GlobalCacheMap {
	sdkCache := &GlobalCacheMap{
		globalMap: new(sync.Map),
	}
	return sdkCache
}
