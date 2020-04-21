package types

import (
	"fmt"
	"github.com/ethereum/go-ethereum/common"
)

// GenerateRandomID generates a random string, which is then returned to be used as a key id
func GenerateRandomID() (id string, err error) {
	buf, err := GenerateSecureRandomData(KeyIDSize)
	if err != nil {
		return "", err
	}
	if !ValidateDataIntegrity(buf, KeyIDSize) {
		return "", fmt.Errorf("error in generateRandomID: crypto/rand failed to generate random data")
	}
	id = common.Bytes2Hex(buf)
	return id, err
}
