// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package osvdev

type ClientConfig struct {
	MaxConcurrentBatchRequests int
	MaxRetryAttempts           int
	JitterMultiplier           float64
	BackoffDurationExponential float64
	BackoffDurationMultiplier  float64
	UserAgent                  string
}

// DefaultConfig make a default client config
func DefaultConfig() ClientConfig {
	return ClientConfig{
		MaxRetryAttempts:           4,
		JitterMultiplier:           2,
		BackoffDurationExponential: 2,
		BackoffDurationMultiplier:  1,
		UserAgent:                  "osv-scalibr",
		MaxConcurrentBatchRequests: 10,
	}
}
