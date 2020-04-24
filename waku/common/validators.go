package common

// ValidateDataIntegrity returns false if the data have the wrong or contains all zeros,
// which is the simplest and the most common bug.
func ValidateDataIntegrity(k []byte, expectedSize int) bool {
	if len(k) != expectedSize {
		return false
	}
	if expectedSize > 3 && ContainsOnlyZeros(k) {
		return false
	}
	return true
}
