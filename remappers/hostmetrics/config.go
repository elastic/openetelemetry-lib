// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package hostmetrics

type config struct {
	SystemIntegrationDataset bool
}

// Option allows configuring the behavior of the hostmetrics remapper.
type Option func(config) config

func newConfig(opts ...Option) (cfg config) {
	for _, opt := range opts {
		cfg = opt(cfg)
	}
	return cfg
}

// WithSystemIntegrationDataset sets the dataset of the remapped metrics as
// as per the system integration. Example: system.cpu, system.memory, etc.
func WithSystemIntegrationDataset(b bool) Option {
	return func(c config) config {
		c.SystemIntegrationDataset = b
		return c
	}
}
