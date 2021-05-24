package test

import (
	"fmt"
	"math/big"
	"testing"
)

func TestBigintToHex(t *testing.T) {
	// 10000000000000000000000000000
	tmp := big.NewInt(0)
	Reward       := new(big.Int).Mul(big.NewInt(10000000000), big.NewInt(1e+18))
	fmt.Printf("0x%x\n",Reward)
	//str := fmt.Sprintf("%x",Reward)
	//var hexReward = "200000000000000000000000000000000000000000000000000000000000000"
	//i := new(big.Int)
	tmp.SetString("5fc51700", 16)
	fmt.Println(tmp)

}



