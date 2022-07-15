package vm

import (
	"github.com/ethereum/go-ethereum/common"
	"testing"
)

func TestGetSlot(t *testing.T) {
	expectSlot := common.HexToHash("0xada5013122d395ba3c54772283fb069b10426056ef8ca54750cb9bb552a59e7d")
	slotID := GetSlot()
	if expectSlot != slotID {
		t.Error("slot err")
	}
	t.Log("SLOT", slotID)
}
