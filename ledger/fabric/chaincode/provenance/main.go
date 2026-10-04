// Provenance chaincode for PS 26237.
//
// Stores signed decryption records keyed by 128-bit watermark ID. Every
// endorsing peer independently:
//   - checks the record schema (see DecryptionRecord.to_dict() in
//     crypto/decryption_session.py),
//   - checks the signer key equals the write-once registered key for that
//     recipient,
//   - verifies the recipient's ML-DSA-65 (FIPS 204) signature over the
//     exact canonical bytes the recipient signed,
//   - refuses to overwrite an existing record.
// There is deliberately no update or delete function. The channel
// endorsement policy requires 3 of the 4 organisations to endorse.
//
// ROGUE MODE (tests only): if PROVENANCE_ROGUE_FRAME=<recipient> is set,
// this instance behaves like a compromised node: queries report that
// recipient instead of the true one, and it endorses overwrites without
// any checks. Used to show one compromised org cannot change history.
package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/hyperledger/fabric-chaincode-go/v2/shim"
	"github.com/hyperledger/fabric-contract-api-go/v2/contractapi"
)

const (
	recordPrefix = "REC"
	keyPrefix    = "KEY"
)

var watermarkRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

type SmartContract struct {
	contractapi.Contract
}

// Record mirrors DecryptionRecord.to_dict() plus the two signature fields
// the Python client embeds at commit time.
type Record struct {
	WatermarkID        string  `json:"watermark_id"`
	RecipientID        string  `json:"recipient_id"`
	DocumentID         string  `json:"document_id"`
	SessionID          string  `json:"session_id"`
	DocumentHash       string  `json:"document_hash"`
	UnixTimestamp      float64 `json:"unix_timestamp"`
	HumanTimestamp     string  `json:"human_timestamp"`
	SignatureHex       string  `json:"_signature_hex"`
	SignerPublicKeyHex string  `json:"_signer_public_key_hex"`
}

// StoredRecord is what lives in world state.
type StoredRecord struct {
	Record          Record `json:"record"`
	CanonicalB64    string `json:"canonical_b64"`
	CommittedTxID   string `json:"committed_tx_id"`
	SubmitterMSPID  string `json:"submitter_msp_id"`
}

type canonicalPayload struct {
	WatermarkID   string  `json:"watermark_id"`
	RecipientID   string  `json:"recipient_id"`
	DocumentID    string  `json:"document_id"`
	SessionID     string  `json:"session_id"`
	DocumentHash  string  `json:"document_hash"`
	UnixTimestamp float64 `json:"unix_timestamp"`
}

func rogueFrame() string { return os.Getenv("PROVENANCE_ROGUE_FRAME") }

// RegisterRecipientKey stores a recipient's ML-DSA-65 public key. Write-once.
func (s *SmartContract) RegisterRecipientKey(ctx contractapi.TransactionContextInterface, recipientID string, publicKeyHex string) error {
	if recipientID == "" {
		return fmt.Errorf("recipient id required")
	}
	pk, err := hex.DecodeString(publicKeyHex)
	if err != nil || len(pk) != mldsa65.PublicKeySize {
		return fmt.Errorf("public key must be %d-byte ML-DSA-65 key", mldsa65.PublicKeySize)
	}
	var parsed mldsa65.PublicKey
	if err := parsed.UnmarshalBinary(pk); err != nil {
		return fmt.Errorf("invalid ML-DSA-65 public key: %v", err)
	}
	k, _ := ctx.GetStub().CreateCompositeKey(keyPrefix, []string{recipientID})
	existing, err := ctx.GetStub().GetState(k)
	if err != nil {
		return err
	}
	if existing != nil {
		if string(existing) == publicKeyHex {
			return nil // idempotent re-registration of the same key
		}
		return fmt.Errorf("recipient %q already has a different registered key; keys are write-once", recipientID)
	}
	return ctx.GetStub().PutState(k, []byte(publicKeyHex))
}

func (s *SmartContract) GetRecipientKey(ctx contractapi.TransactionContextInterface, recipientID string) (string, error) {
	k, _ := ctx.GetStub().CreateCompositeKey(keyPrefix, []string{recipientID})
	v, err := ctx.GetStub().GetState(k)
	if err != nil {
		return "", err
	}
	if v == nil {
		return "", fmt.Errorf("no key registered for %q", recipientID)
	}
	return string(v), nil
}

// CommitRecord validates and stores a signed decryption record.
func (s *SmartContract) CommitRecord(ctx contractapi.TransactionContextInterface, recordJSON string, canonicalB64 string) error {
	var rec Record
	if err := json.Unmarshal([]byte(recordJSON), &rec); err != nil {
		return fmt.Errorf("bad record json: %v", err)
	}
	stub := ctx.GetStub()
	recKey, err := stub.CreateCompositeKey(recordPrefix, []string{rec.WatermarkID})
	if err != nil {
		return err
	}
	if rogueFrame() == "" {
		if err := validate(ctx, &rec, canonicalB64); err != nil {
			return err
		}
		existing, err := stub.GetState(recKey)
		if err != nil {
			return err
		}
		if existing != nil {
			return fmt.Errorf("record for watermark %s already committed; records are immutable", rec.WatermarkID)
		}
	}
	mspID, _ := ctx.GetClientIdentity().GetMSPID()
	stored := StoredRecord{Record: rec, CanonicalB64: canonicalB64, CommittedTxID: stub.GetTxID(), SubmitterMSPID: mspID}
	b, _ := json.Marshal(stored)
	return stub.PutState(recKey, b)
}

func validate(ctx contractapi.TransactionContextInterface, rec *Record, canonicalB64 string) error {
	if !watermarkRe.MatchString(rec.WatermarkID) {
		return fmt.Errorf("watermark_id must be 32 lowercase hex chars (128-bit)")
	}
	if rec.RecipientID == "" || rec.DocumentID == "" || rec.SessionID == "" || rec.DocumentHash == "" {
		return fmt.Errorf("record missing required fields")
	}
	canonical, err := base64.StdEncoding.DecodeString(canonicalB64)
	if err != nil {
		return fmt.Errorf("bad canonical encoding")
	}
	var cp canonicalPayload
	if err := json.Unmarshal(canonical, &cp); err != nil {
		return fmt.Errorf("bad canonical json: %v", err)
	}
	if cp.WatermarkID != rec.WatermarkID || cp.RecipientID != rec.RecipientID || cp.DocumentID != rec.DocumentID ||
		cp.SessionID != rec.SessionID || cp.DocumentHash != rec.DocumentHash || cp.UnixTimestamp != rec.UnixTimestamp {
		return fmt.Errorf("signed canonical payload does not match record fields")
	}

	registered, err := (&SmartContract{}).GetRecipientKey(ctx, rec.RecipientID)
	if err != nil {
		return err
	}
	if registered != rec.SignerPublicKeyHex {
		return fmt.Errorf("signer key is not the registered key for %q", rec.RecipientID)
	}
	pkBytes, _ := hex.DecodeString(registered)
	var pk mldsa65.PublicKey
	if err := pk.UnmarshalBinary(pkBytes); err != nil {
		return fmt.Errorf("registered key invalid: %v", err)
	}
	sig, err := hex.DecodeString(rec.SignatureHex)
	if err != nil || len(sig) != mldsa65.SignatureSize {
		return fmt.Errorf("signature must be %d-byte ML-DSA-65 signature", mldsa65.SignatureSize)
	}
	if !mldsa65.Verify(&pk, canonical, nil, sig) {
		return fmt.Errorf("ML-DSA-65 signature verification failed")
	}
	return nil
}

// GetByWatermark returns the StoredRecord JSON for a watermark.
func (s *SmartContract) GetByWatermark(ctx contractapi.TransactionContextInterface, watermarkID string) (string, error) {
	recKey, err := ctx.GetStub().CreateCompositeKey(recordPrefix, []string{watermarkID})
	if err != nil {
		return "", err
	}
	v, err := ctx.GetStub().GetState(recKey)
	if err != nil {
		return "", err
	}
	if v == nil {
		return "", nil
	}
	if frame := rogueFrame(); frame != "" {
		var st StoredRecord
		if json.Unmarshal(v, &st) == nil {
			st.Record.RecipientID = frame
			v, _ = json.Marshal(st)
		}
	}
	return string(v), nil
}

// ListWatermarks returns every watermark ID with a committed record (JSON array).
func (s *SmartContract) ListWatermarks(ctx contractapi.TransactionContextInterface) (string, error) {
	it, err := ctx.GetStub().GetStateByPartialCompositeKey(recordPrefix, []string{})
	if err != nil {
		return "", err
	}
	defer it.Close()
	ids := []string{}
	for it.HasNext() {
		kv, err := it.Next()
		if err != nil {
			return "", err
		}
		_, parts, err := ctx.GetStub().SplitCompositeKey(kv.Key)
		if err == nil && len(parts) == 1 {
			ids = append(ids, parts[0])
		}
	}
	b, _ := json.Marshal(ids)
	return string(b), nil
}

// GetHistoryCount returns how many committed writes exist for a watermark.
// An honest record has exactly 1.
func (s *SmartContract) GetHistoryCount(ctx contractapi.TransactionContextInterface, watermarkID string) (int, error) {
	recKey, err := ctx.GetStub().CreateCompositeKey(recordPrefix, []string{watermarkID})
	if err != nil {
		return 0, err
	}
	it, err := ctx.GetStub().GetHistoryForKey(recKey)
	if err != nil {
		return 0, err
	}
	defer it.Close()
	n := 0
	for it.HasNext() {
		if _, err := it.Next(); err != nil {
			return 0, err
		}
		n++
	}
	return n, nil
}

func main() {
	cc, err := contractapi.NewChaincode(&SmartContract{})
	if err != nil {
		log.Panicf("create chaincode: %v", err)
	}
	server := &shim.ChaincodeServer{
		CCID:     os.Getenv("CHAINCODE_ID"),
		Address:  os.Getenv("CHAINCODE_SERVER_ADDRESS"),
		CC:       cc,
		TLSProps: shim.TLSProperties{Disabled: true},
	}
	if err := server.Start(); err != nil {
		log.Panicf("start chaincode server: %v", err)
	}
}
