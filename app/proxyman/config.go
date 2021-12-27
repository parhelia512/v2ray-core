package proxyman

func (s *AllocationStrategy) GetConcurrencyValue() uint32 {
	if s == nil || s.Concurrency == nil {
		return 3
	}
	return s.Concurrency.Value
}

func (s *AllocationStrategy) GetRefreshValue() uint32 {
	if s == nil || s.Refresh == nil {
		return 5
	}
	return s.Refresh.Value
}

func (c *ReceiverConfig) GetEffectiveSniffingSettings() *SniffingConfig {
	if c.SniffingSettings != nil {
		return c.SniffingSettings
	}

	if len(c.DomainOverride) > 0 {
		var p []string
		for _, kd := range c.DomainOverride {
			switch kd {
			case KnownProtocols_HTTP:
				p = append(p, "http")
			case KnownProtocols_TLS:
				p = append(p, "tls")
			}
		}
		return &SniffingConfig{
			Enabled:             true,
			DestinationOverride: p,
		}
	}

	return nil
}

func (x *SenderConfig) UseIP() bool {
	return x.DomainStrategy == DomainStrategy_USE_IP || x.DomainStrategy == DomainStrategy_USE_IP4 || x.DomainStrategy == DomainStrategy_USE_IP6
}

func (x *SenderConfig) IsAdvanced() bool {
	return x.Via4 != nil || x.Via6 != nil || x.DomainStrategy != DomainStrategy_AS_IS || x.FallbackDelayMs != 0
}
