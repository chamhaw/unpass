package config

type Config struct {
	Detectors DetectorConfig `yaml:"detectors"`
}

type DetectorConfig struct {
	TwoFA   bool `yaml:"twofa"`
	Passkey bool `yaml:"passkey"`
}

func DefaultConfig() *Config {
	return &Config{
		Detectors: DetectorConfig{
			TwoFA:   true,
			Passkey: true,
		},
	}
} 