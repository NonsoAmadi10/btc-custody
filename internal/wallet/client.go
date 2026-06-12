package wallet

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// BlockchainClient queries blockchain data from an external API.
type BlockchainClient interface {
	// GetUTXOs fetches all UTXOs for an address.
	GetUTXOs(ctx context.Context, address string) ([]*UTXO, error)

	// GetBalance returns confirmed and unconfirmed balances.
	GetBalance(ctx context.Context, address string) (confirmed, unconfirmed int64, err error)

	// BroadcastTx submits a signed transaction to the network.
	BroadcastTx(ctx context.Context, txHex string) (txid string, err error)

	// GetTxStatus checks if a transaction is confirmed.
	GetTxStatus(ctx context.Context, txid string) (confirmed bool, blockHeight uint32, err error)
}

// MempoolClient implements BlockchainClient using mempool.space API.
// Works with both mainnet and testnet.
type MempoolClient struct {
	baseURL    string
	httpClient *http.Client
}

// NewMempoolClient creates a client for mempool.space.
//
// For testnet: NewMempoolClient(true)
// For mainnet: NewMempoolClient(false)
func NewMempoolClient(testnet bool) *MempoolClient {
	baseURL := "https://mempool.space/api"
	if testnet {
		baseURL = "https://mempool.space/testnet/api"
	}

	return &MempoolClient{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// NewMempoolClientWithURL creates a client with a custom API URL.
// Useful for local mempool instances or alternative APIs.
func NewMempoolClientWithURL(baseURL string) *MempoolClient {
	return &MempoolClient{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// mempoolUTXO is the JSON structure from mempool.space /address/:addr/utxo
type mempoolUTXO struct {
	TxID   string `json:"txid"`
	Vout   uint32 `json:"vout"`
	Status struct {
		Confirmed   bool   `json:"confirmed"`
		BlockHeight uint32 `json:"block_height"`
	} `json:"status"`
	Value int64 `json:"value"`
}

// GetUTXOs fetches all UTXOs for an address from mempool.space.
func (c *MempoolClient) GetUTXOs(ctx context.Context, address string) ([]*UTXO, error) {
	url := fmt.Sprintf("%s/address/%s/utxo", c.baseURL, address)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching UTXOs: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	var mempoolUTXOs []mempoolUTXO
	if err := json.NewDecoder(resp.Body).Decode(&mempoolUTXOs); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	utxos := make([]*UTXO, len(mempoolUTXOs))
	for i, mu := range mempoolUTXOs {
		confirmations := 0
		if mu.Status.Confirmed {
			// Approximate confirmations (would need current block height for accuracy)
			confirmations = 1
		}

		utxos[i] = &UTXO{
			TxID:          mu.TxID,
			Vout:          mu.Vout,
			Amount:        mu.Value,
			Address:       address,
			Confirmations: confirmations,
			BlockHeight:   mu.Status.BlockHeight,
			Timestamp:     time.Now(),
		}
	}

	return utxos, nil
}

// mempoolAddressStats is the JSON structure from mempool.space /address/:addr
type mempoolAddressStats struct {
	ChainStats struct {
		FundedSum int64 `json:"funded_txo_sum"`
		SpentSum  int64 `json:"spent_txo_sum"`
	} `json:"chain_stats"`
	MempoolStats struct {
		FundedSum int64 `json:"funded_txo_sum"`
		SpentSum  int64 `json:"spent_txo_sum"`
	} `json:"mempool_stats"`
}

// GetBalance returns confirmed and unconfirmed balances for an address.
func (c *MempoolClient) GetBalance(ctx context.Context, address string) (confirmed, unconfirmed int64, err error) {
	url := fmt.Sprintf("%s/address/%s", c.baseURL, address)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("creating request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, 0, fmt.Errorf("fetching balance: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return 0, 0, fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	var stats mempoolAddressStats
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		return 0, 0, fmt.Errorf("parsing response: %w", err)
	}

	confirmed = stats.ChainStats.FundedSum - stats.ChainStats.SpentSum
	unconfirmed = stats.MempoolStats.FundedSum - stats.MempoolStats.SpentSum

	return confirmed, unconfirmed, nil
}

// BroadcastTx submits a raw transaction to the Bitcoin network.
func (c *MempoolClient) BroadcastTx(ctx context.Context, txHex string) (string, error) {
	url := fmt.Sprintf("%s/tx", c.baseURL)

	// Validate hex
	if _, err := hex.DecodeString(txHex); err != nil {
		return "", fmt.Errorf("invalid transaction hex: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, nil)
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "text/plain")

	// Set body manually since we're sending raw hex
	req, err = http.NewRequestWithContext(ctx, "POST", url, 
		io.NopCloser(stringReader(txHex)))
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "text/plain")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("broadcasting tx: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("broadcast failed %d: %s", resp.StatusCode, string(body))
	}

	// Response is just the txid
	return string(body), nil
}

// mempoolTxStatus is the JSON structure from mempool.space /tx/:txid/status
type mempoolTxStatus struct {
	Confirmed   bool   `json:"confirmed"`
	BlockHeight uint32 `json:"block_height"`
	BlockHash   string `json:"block_hash"`
}

// GetTxStatus checks if a transaction is confirmed.
func (c *MempoolClient) GetTxStatus(ctx context.Context, txid string) (bool, uint32, error) {
	url := fmt.Sprintf("%s/tx/%s/status", c.baseURL, txid)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false, 0, fmt.Errorf("creating request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, 0, fmt.Errorf("fetching tx status: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return false, 0, nil // Not found = not confirmed
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return false, 0, fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	var status mempoolTxStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return false, 0, fmt.Errorf("parsing response: %w", err)
	}

	return status.Confirmed, status.BlockHeight, nil
}

// stringReader wraps a string as an io.Reader.
type stringReaderType struct {
	s string
	i int
}

func stringReader(s string) io.Reader {
	return &stringReaderType{s: s}
}

func (r *stringReaderType) Read(p []byte) (n int, err error) {
	if r.i >= len(r.s) {
		return 0, io.EOF
	}
	n = copy(p, r.s[r.i:])
	r.i += n
	return n, nil
}

// MockClient is a test implementation of BlockchainClient.
type MockClient struct {
	UTXOs     map[string][]*UTXO // address -> UTXOs
	Balances  map[string]int64   // address -> confirmed balance
	Broadcast func(txHex string) (string, error)
}

// NewMockClient creates a mock client for testing.
func NewMockClient() *MockClient {
	return &MockClient{
		UTXOs:    make(map[string][]*UTXO),
		Balances: make(map[string]int64),
	}
}

func (c *MockClient) GetUTXOs(ctx context.Context, address string) ([]*UTXO, error) {
	return c.UTXOs[address], nil
}

func (c *MockClient) GetBalance(ctx context.Context, address string) (int64, int64, error) {
	return c.Balances[address], 0, nil
}

func (c *MockClient) BroadcastTx(ctx context.Context, txHex string) (string, error) {
	if c.Broadcast != nil {
		return c.Broadcast(txHex)
	}
	return "mock-txid-" + txHex[:8], nil
}

func (c *MockClient) GetTxStatus(ctx context.Context, txid string) (bool, uint32, error) {
	return false, 0, nil
}
