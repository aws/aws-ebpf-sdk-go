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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCache(t *testing.T) {
	SdkCache := New()

	value, _ := SdkCache.Get("invalidKey")
	assert.Equal(t, -1, value)

	SdkCache.Set("ingress-map", 10)

	value, _ = SdkCache.Get("ingress-map")
	assert.Equal(t, 10, value)

	SdkCache.Set("ingress-map", 11)

	value, _ = SdkCache.Get("ingress-map")
	assert.Equal(t, 11, value)

	SdkCache.Set("egress-map", 12)

	SdkCache.Delete("egress-map")

	value, _ = SdkCache.Get("egress-map")
	assert.Equal(t, -1, value)

	tempSdkCache := Get()
	value, _ = tempSdkCache.Get("ingress-map")
	assert.Equal(t, 11, value)

}

func TestCacheGetSameInstance(t *testing.T) {
	cache1 := Get()
	cache2 := Get()

	assert.True(t, cache1 == cache2)
}

func TestCacheNewAndGetSameInstance(t *testing.T) {
	cache1 := New()
	cache2 := Get()

	assert.True(t, cache1 == cache2)
}
