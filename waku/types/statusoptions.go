package types

type StatusOption interface {
	PoWRequirement() *uint64
	BloomFilter() []byte
	LightNodeEnabled() *bool
	ConfirmationsEnabled() *bool
	RateLimits() *RateLimits
	TopicInterest() []TopicType
}
