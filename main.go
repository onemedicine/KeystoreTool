package main

import (
	"context"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	gfigure "github.com/common-nighthawk/go-figure"
	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"io"
	"io/ioutil"
	"log"
	"math"
	"math/big"
	"os"
	"runtime/debug"
	"strconv"
	"strings"

	//"gopkg.in/urfave/cli.v1"
	"github.com/ethereum/go-ethereum/accounts/keystore"
)

var (
	datadir = flag.String("datadir", "./keystore", "Keystore directory")
	url     = flag.String("url", "http://127.0.0.1:8545", "RPC URL:http://127.0.0.1:8545 or IPC path://.//pipe//geth.ipc")
)

var (
	RpcClient *ethclient.Client
	Ks        *keystore.KeyStore
	LogInfo   *log.Logger
)

//var Index = make(chan int)

func accountList() {
	var index int
	for _, account := range Ks.Accounts() {
		fmt.Printf("Account index#%d: {%x} %s\n", index, account.Address, account.URL.Path)
		index++
	}
}

func getBalance() {
	if RpcClient == nil {
		LogInfo.Println("Not set RPCURL!")
		return
	}
	fbalance := new(big.Float)

	for _, account := range Ks.Accounts() {
		balance, err := RpcClient.BalanceAt(context.Background(), account.Address, nil)
		if err != nil {
			LogInfo.Println(err)
			return
		}
		fbalance.SetString(balance.String())
		ethValue := new(big.Float).Quo(fbalance, big.NewFloat(math.Pow10(18)))
		fmt.Printf("Account {%s}: %v eth - (%d wei)\n", account.Address.Hex(), ethValue, balance)
	}

}

func createKeystore() {
	var password string
	fmt.Println("    a. Customize")
	fmt.Println("    b. Random")
	index := int(phraseScanfHex("", false))
	switch index {
	case 10:
		password = utils.GetPassPhrase("", true)
	case 11:
		password = randPasswd(16)
	default:
		return
	}

	account, err := Ks.NewAccount(password)
	if err != nil {
		LogInfo.Println(err)
		return
	}

	LogInfo.Println(account.Address.Hex())

	file, _ := os.OpenFile("password", os.O_CREATE|os.O_APPEND, 0666)
	defer file.Close()
	file.WriteString(account.Address.Hex() + " " + password + "\n")

}

func makePasswordList(path string) []string {

	if path == "" {
		return nil
	}
	text, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Printf("Failed to read password file: %v", err)
	}
	lines := strings.Split(string(text), "\n")
	// Sanitise DOS line endings.
	for i := range lines {
		lines[i] = strings.TrimRight(lines[i], "\r")
	}
	return lines
}

func unlockKeystore() {
	var err error

	index := int(phraseScanfHex("AccountIndex:", true))
	if index > len(Ks.Accounts()) {
		LogInfo.Printf("Could not list accounts!\n")
		return
	}

	account := Ks.Accounts()[index]

	for trials := 0; trials < 3; trials++ {
		password := utils.GetPassPhrase("", false)
		err = Ks.Unlock(account, password)
		if err == nil {
			LogInfo.Printf("Succeeded unlocked account: %s\n", account.Address.Hex())
			return
		}
		if _, ok := err.(*keystore.AmbiguousAddrError); ok {
			LogInfo.Printf("Succeeded unlocked account: %s\n", account.Address.Hex())
			return
		}
		if err != keystore.ErrDecrypt {
			// No need to prompt again if the error is not decryption-related.
			break
		}
	}
	LogInfo.Printf("Failed to unlock account %s (%v)\n", account.Address.Hex(), err)

}

func showPrivateKey() {

	index := int(phraseScanfHex("AccountIndex:", true))
	if index > len(Ks.Accounts()) {
		LogInfo.Printf("Could not list accounts!\n")
		return
	}
	account := Ks.Accounts()[index]

	keyjson, err := ioutil.ReadFile(account.URL.Path)
	if err != nil {
		LogInfo.Println(err)
		return
	}
	password := utils.GetPassPhrase("", false)
	key, err := keystore.DecryptKey(keyjson, password)
	if err != nil {
		LogInfo.Println(err)
		return
	}

	address := key.Address.Hex()
	privateKey := hex.EncodeToString(crypto.FromECDSA(key.PrivateKey))
	fmt.Printf("\033[1;31;40m%s\033[0m\n", "Note: Never disclose this private key. Anyone who has your private key can steal any assets in your account !")
	LogInfo.Printf("Address:\t%s\nPrivateKey:\t%s\n", address, privateKey)

}

func setRpcurl() {
	var url string
	if RpcClient != nil {
		RpcClient.Close()
		RpcClient = nil
	}
	fmt.Print("Please input a URL:")
	_, err := fmt.Scanln(&url)
	if err != nil {
		LogInfo.Println(err)
		return
	}

	RpcClient, err = ethclient.Dial(url)
	if err != nil {
		LogInfo.Println(err)
		return
	}
	_, err = RpcClient.SyncProgress(context.Background())
	if err != nil {
		LogInfo.Printf("No connection: %v\n", err)
		RpcClient.Close()
		RpcClient = nil
		return
	}
	LogInfo.Printf("Connected: %s\n", url)
}

func panicDeal() {
	if err := recover(); err != nil {
		LogInfo.Println(err)
		LogInfo.Println(string(debug.Stack()))
	}
}

func sendTx() {
	//defer panicDeal()
	var err error
	if RpcClient == nil {
		LogInfo.Println("Not set RPCURL!")
		return
	}

	index := int(phraseScanfHex("FromAccountIndex:", true))
	if index > len(Ks.Accounts()) {
		fmt.Printf("Could not list accounts!\n")
		return
	}

	account := Ks.Accounts()[index]

	fromAddress := account.Address
	nonce, err := RpcClient.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		LogInfo.Println(err)
		return
	}

	var tmp string
	fmt.Print("value(wei):")
	_, err = fmt.Scanln(&tmp)
	if err != nil {
		LogInfo.Println(err)
		return
	}
	value := big.NewInt(0)
	value.SetString(tmp, 10)

	gasLimit := uint64(21000)
	gasPrice, err := RpcClient.SuggestGasPrice(context.Background())
	if err != nil {
		LogInfo.Println(err)
		return
	}

	fmt.Print("toAddress:")
	_, err = fmt.Scanln(&tmp)
	if err != nil {
		LogInfo.Println(err)
		return
	}
	toAddress := common.HexToAddress(tmp)

	var data []byte
	tx := types.NewTransaction(nonce, toAddress, value, gasLimit, gasPrice, data)

	chainID, err := RpcClient.NetworkID(context.Background())
	if err != nil {
		LogInfo.Println(err)
		return
	}

	signedTx, err := Ks.SignTx(account, tx, chainID)
	if err != nil {
		LogInfo.Println(err)
		return
	}
	err = RpcClient.SendTransaction(context.Background(), signedTx)
	if err != nil {
		LogInfo.Println(err)
		return
	}

	LogInfo.Printf("Txhash sent: %s\n", signedTx.Hash().Hex())
}

func randPasswd(length int) string {
	b := make([]byte, 32)
	_, err := crand.Read(b)
	if err != nil {
		LogInfo.Printf("ERROR: %v\n", err)
		return ""
	}
	return base64.URLEncoding.EncodeToString(b)[:length]
}

func loopScan() int {
	index := int(phraseScanfHex("", false))
	return index
}

func init() {
	infoFile, err := os.OpenFile("log.txt", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Println(err)
	}
	LogInfo = log.New(io.MultiWriter(os.Stderr, infoFile), "Info:", log.Ldate|log.Ltime)

	flag.Parse()
	if 2 != flag.NArg() {
		flag.Usage()
	}

	gfigure.NewColorFigure("Keystore Tool", "", "green", true).Print()
	fmt.Print(
		"1: Account list\n" +
			"2: Unlock account\n" +
			"3: Account balance\n" +
			"4: Show privateKey\n" +
			"5: Set RPCURL\n" +
			"6: Create account\n" +
			"7: Send ETH\n")

}

func phraseScanfHex(text string, decimal bool) int64 {
	var value string
	var err error
	var index int64
	if text == "" {
		fmt.Print(">>")
	} else {
		fmt.Print(text)
	}

	_, err = fmt.Scanln(&value)
	if err != nil {
		LogInfo.Println(err)
		return 0
	}

	if decimal {
		index, err = strconv.ParseInt(value, 10, 64)
	} else {
		index, err = strconv.ParseInt(value, 16, 64)
	}
	if err != nil {
		LogInfo.Println(err)
		return 0
	}

	return index
}

func main() {

	Ks = keystore.NewKeyStore(*datadir, keystore.StandardScryptN, keystore.StandardScryptP)
	RpcClient, _ = ethclient.Dial(*url)

	for {
		index := loopScan()
		switch index {
		case 0:
			continue
		case 1:
			accountList()
		case 2:
			unlockKeystore()
			//password := makePasswordList("./password.txt")
		case 3:
			getBalance()
		case 4:
			showPrivateKey()
		case 5:
			setRpcurl()
		case 6:
			createKeystore()
		case 7:
			sendTx()
		default:
			fmt.Println("No matching!")
		}
	}
}
