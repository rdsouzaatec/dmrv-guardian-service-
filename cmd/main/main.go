package main

import (
	"bytes"
	"crypto/ed25519"
	"database/sql"

	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"

	"net/http"
	"os"
	"time"

	"strings"

	_ "github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"github.com/mr-tron/base58"
)

// Config structure to hold the configuration details
type Config struct {
	URL        string
	DID        string
	PolicyID   string
	Ref        string
	Installer  string
	PolicyTag  string
	Type       string
	Context    []string
	PrivateKey string
}

// CredentialSubject represents the subject of the credential
type CredentialSubject struct {
	Type     string              `json:"type"`
	Context  []string            `json:"@context"`
	Field0   []map[string]string `json:"field0"`
	PolicyID string              `json:"policyId"`
	Ref      string              `json:"ref"`
}

// VC represents the Verifiable Credential structure
type VC struct {
	ID                string              `json:"id"`
	Type              []string            `json:"type"`
	Issuer            string              `json:"issuer"`
	IssuanceDate      string              `json:"issuanceDate"`
	Context           []string            `json:"@context"`
	CredentialSubject []CredentialSubject `json:"credentialSubject"`
	Proof             Proof               `json:"proof,omitempty"`
}

// Proof represents the proof structure
type Proof struct {
	Type               string `json:"type"`
	Created            string `json:"created"`
	VerificationMethod string `json:"verificationMethod"`
	ProofPurpose       string `json:"proofPurpose"`
	JWS                string `json:"jws"`
}

// VCGenerator handles credential generation and signing
type VCGenerator struct {
	Config     Config
	SigningKey ed25519.PrivateKey
}

// LoadConfig loads configuration from .env variables
func LoadConfig() (Config, error) {
	err := godotenv.Load()
	if err != nil {
		return Config{}, fmt.Errorf("error loading .env file")
	}

	// Load environment variables into Config struct
	config := Config{
		URL:        os.Getenv("URL"),
		DID:        os.Getenv("DID"),
		PolicyID:   os.Getenv("POLICY_ID"),
		Ref:        os.Getenv("REF"),
		Installer:  os.Getenv("INSTALLER"),
		PolicyTag:  os.Getenv("POLICY_TAG"),
		Type:       os.Getenv("TYPE"),
		Context:    strings.Split(os.Getenv("CONTEXT_URLS"), ","),
		PrivateKey: os.Getenv("PRIVATE_KEY_BASE58"),
	}

	if config.URL == "" || config.DID == "" || config.PolicyID == "" || config.Ref == "" ||
		config.Installer == "" || config.PolicyTag == "" || config.Type == "" ||
		config.Context[0] == "" || config.PrivateKey == "" {
		return config, fmt.Errorf("missing required environment variables")
	}

	return config, nil
}

// NewVCGenerator initializes the VC generator with config and signing key
func NewVCGenerator() (*VCGenerator, error) {
	config, err := LoadConfig()
	if err != nil {
		return nil, err
	}

	// Decode private key
	privateKeyBytes, err := base58.Decode(config.PrivateKey)
	if err != nil {
		return nil, err
	}
	signingKey := ed25519.PrivateKey(privateKeyBytes)
	return &VCGenerator{Config: config, SigningKey: signingKey}, nil
}

// CreateCredentialSubject creates the credential subject
func (gen *VCGenerator) CreateCredentialSubject(devices []map[string]string) []CredentialSubject {
	subject := CredentialSubject{
		Type:     gen.Config.Type,
		Context:  []string{gen.Config.Context[0]},
		Field0:   devices,
		PolicyID: gen.Config.PolicyID,
		Ref:      gen.Config.Ref,
	}
	return []CredentialSubject{subject}
}

// CreateVC creates and signs the Verifiable Credential
func (gen *VCGenerator) CreateVC(devices []map[string]string) VC {
	vc := VC{
		ID:                "urn:uuid:" + uuid.NewString(),
		Type:              []string{"VerifiableCredential"},
		Issuer:            gen.Config.DID,
		IssuanceDate:      time.Now().UTC().Format(time.RFC3339Nano),
		Context:           []string{"https://www.w3.org/2018/credentials/v1"},
		CredentialSubject: gen.CreateCredentialSubject(devices),
	}
	vc.Proof = gen.CreateProof(vc)
	return vc
}

// CreateProof generates a proof for the VC
func (gen *VCGenerator) CreateProof(vc VC) Proof {
	vcCopy := vc
	vcCopy.Proof = Proof{} // remove proof field for signing

	payload, _ := json.Marshal(vcCopy)
	header := `{"alg":"EdDSA","b64":false,"crit":["b64"]}`
	headerB64 := base64.RawURLEncoding.EncodeToString([]byte(header))
	signingInput := headerB64 + "." + string(payload)

	// Sign payload
	signature := ed25519.Sign(gen.SigningKey, []byte(signingInput))
	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

	return Proof{
		Type:               "Ed25519Signature2018",
		Created:            time.Now().UTC().Format(time.RFC3339),
		VerificationMethod: gen.Config.DID + "#did-root-key",
		ProofPurpose:       "assertionMethod",
		JWS:                headerB64 + ".." + signatureB64,
	}
}

// SendVC sends the VC to the specified URL
func (gen *VCGenerator) SendVC(vc VC) error {
	payload := map[string]interface{}{
		"document":  vc,
		"ref":       gen.Config.Ref,
		"owner":     gen.Config.Installer,
		"policyTag": gen.Config.PolicyTag,
	}

	// Marshal the payload to JSON
	payloadBytes, _ := json.Marshal(payload)

	// Print the payload as a JSON string for debugging purposes
	log.Printf("Sending payload: %s", string(payloadBytes))

	req, err := http.NewRequest("POST", gen.Config.URL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	log.Printf("Response Status: %s, Body: %s\n", resp.Status, body)
	return nil
}

func getDevices() []map[string]string {
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s)/%s", os.Getenv("DB_USER"), os.Getenv("DB_PASS"), os.Getenv("DB_HOST"), os.Getenv("DB_NAME")))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Get today's date in YYYY-MM-DD format
	today := time.Now().Format("2006-01-02")

	// Query the database for data on today's date
	rows, err := db.Query(`
		SELECT
			d.unit_number AS device_id,
			d.calendar_date AS date,
			d.daily_power_consumption AS EG_p_d_y
		FROM
			tbl_daily_compiled_usage_data d
		JOIN
			tbl_accounts a
		ON
			d.unit_number = a.account_number
		WHERE
			d.calendar_date = ?`, today)

	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	// Prepare the result to store the data
	var devices []map[string]string

	// Iterate through the rows
	for rows.Next() {
		var deviceID, date, egPDY string
		if err := rows.Scan(&deviceID, &date, &egPDY); err != nil {
			log.Println("Error scanning row:", err)
			continue
		}

		// Add the device data to the result slice
		device := map[string]string{
			"device_id": deviceID,
			"date":      date,
			"eg_p_d_y":  egPDY,
		}
		devices = append(devices, device)
	}

	// Check for any row errors
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}

	return devices
}

// Example data for devices
// func getDevices() []map[string]string {
// 	now := time.Now().Format("2006-01-02")
// 	return []map[string]string{
// 		{"device_id": "device_001", "date": now, "eg_p_d_y": fmt.Sprintf("%d", rand.Intn(200)+100)},
// 		{"device_id": "device_002", "date": now, "eg_p_d_y": fmt.Sprintf("%d", rand.Intn(200)+100)},
// 		{"device_id": "device_003", "date": now, "eg_p_d_y": fmt.Sprintf("%d", rand.Intn(200)+100)},
// 	}
// }

func main() {
	log.Println("Starting Daily MRV Guardian Service")

	// Initialize the VC Generator
	generator, err := NewVCGenerator()
	if err != nil {
		log.Fatalf("Error initializing generator: %v", err)
	}

	// Calculate the next 12:05 PM UTC
	for {
		now := time.Now().UTC()
		nextRun := time.Date(now.Year(), now.Month(), now.Day(), 3, 26, 0, 0, time.UTC)
		if now.After(nextRun) {
			// If the current time is past today's 12:05 PM, schedule for the next day
			nextRun = nextRun.Add(24 * time.Hour)
		}

		// Calculate the duration until the next run time
		durationUntilNextRun := nextRun.Sub(now)
		log.Printf("Next scheduled run at: %s\n", nextRun)

		// Wait until the next scheduled run time
		timer := time.NewTimer(durationUntilNextRun)
		<-timer.C

		// Execute the task
		log.Println("Executing scheduled task")
		devices := getDevices()
		vc := generator.CreateVC(devices)
		if err := generator.SendVC(vc); err != nil {
			log.Printf("Error sending VC: %v\n", err)
		} else {
			log.Println("VC sent successfully")
		}

		// Log completion of task
		log.Println("Task completed")
	}
}
