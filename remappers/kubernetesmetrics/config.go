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

package kubernetesmetrics

type config struct {
	KubernetesIntegrationDataset bool
	Override                     bool
}

// Option allows configuring the behavior of the kubernetes remapper.
type Option func(config) config

func newConfig(opts ...Option) (cfg config) {
	for _, opt := range opts {
		cfg = opt(cfg)
	}
	return cfg
}

// WithKubernetesIntegrationDataset sets the dataset of the remapped metrics as
// as per the kubernetes integration. Example: kubernetes.pod
func WithKubernetesIntegrationDataset(b bool, override bool) Option {
	return func(c config) config {
		c.KubernetesIntegrationDataset = b
		c.Override = override
		return c
	}
}
