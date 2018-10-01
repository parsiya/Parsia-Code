package keystore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// KeyStore represents the encrypted keystore.
type KeyStore struct {
	key    []byte
	iv     []byte
	path   string
	Values map[string]string
}

// MakeKeyStore creates a new keystore.
func MakeKeyStore(key, path string) (*KeyStore, error) {

	ks := &KeyStore{}

	// Check if key is empty.
	if len(key) == 0 {
		return nil, fmt.Errorf("keystore.MakeKeyStore - key empty")
	}
	// To create a key, we are going to SHA-256 the key to get 32 bytes.
	hashedKey := sha256.Sum256([]byte(key))

	ks.key = hashedKey[:]

	// Then check if the file exists. If so, return an error.
	exists, err := fileExists(path)
	if err != nil {
		return nil, fmt.Errorf("keystore.MakeKeyStore fileExists: %v", err.Error())
	}
	if exists {
		return nil, fmt.Errorf("keystore.MakeKeyStore: %s file exists", path)
	}

	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("keystore.MakeKeyStore os.Create: %s", err.Error())
	}
	defer f.Close()

	// Create IV.
	iv := make([]byte, aes.BlockSize)
	n, err := rand.Read(iv)
	if err != nil {
		return nil, fmt.Errorf("keystore.MakeKeyStore rand.Read: %s", err.Error())
	}
	if n != aes.BlockSize {
		return nil, fmt.Errorf("keystore.MakeKeyStore: could not read IV")
	}

	ks.iv = iv
	ks.path = path
	ks.Values = make(map[string]string)

	sw, err := ks.Encrypter(f)
	if err != nil {
		return nil, fmt.Errorf("keystore.MakeKeyStore ks.Encrypter: %v", err.Error())
	}

	// Write empty values to file.
	if err := ks.serialize(sw); err != nil {
		return nil, fmt.Errorf("keystore.MakeKeyStore ks.serialize: %v", err.Error())
	}

	return ks, nil
}

// String() is the stringer for KeyStore.
func (k KeyStore) String() string {
	return fmt.Sprintf("KeyStore:\nPath: %s\nNumber of keys:%d\n",
		k.path, len(k.Values))
}

// GetKeyStore opens an already existing keystore.
func GetKeyStore(key, path string) (*KeyStore, error) {
	ks := &KeyStore{}

	// Check if key is empty.
	if len(key) == 0 {
		return nil, fmt.Errorf("keystore.GetKeyStore - key empty")
	}
	// To create a key, we are going to SHA-256 the key to get 32 bytes.
	hashedKey := sha256.Sum256([]byte(key))

	ks.key = hashedKey[:]

	// Then check if the file exists. If not, return errors.
	exists, err := fileExists(path)
	if err != nil {
		return nil, fmt.Errorf("keystore.GetKeyStore fileExists: %v", err.Error())
	}
	if !exists {
		return nil, fmt.Errorf("keystore.GetKeyStore: %s file not found", path)
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("keystore.GetKeyStore os.Open: %s", err.Error())
	}
	defer f.Close()

	ks.path = path
	ks.Values = make(map[string]string)

	sr, err := ks.Decrypter(f)
	if err != nil {
		return nil, fmt.Errorf("keystore.GetKeyStore ks.Decrypter: %s", err.Error())
	}
	// IV should be set now.

	// Read values from file.
	if err := ks.deserialize(sr); err != nil {
		return nil, fmt.Errorf("keystore.GetKeyStore ks.deserialize: %s", err.Error())
	}
	return ks, nil
}

// SaveKeyStore save the keystore to disk.
func (k *KeyStore) SaveKeyStore() error {

	// Check if key is empty.
	if len(k.key) == 0 {
		return fmt.Errorf("keystore.SaveKeyStore - keystore not initialized")
	}

	f, err := os.Create(k.path)
	if err != nil {
		return fmt.Errorf("keystore.SaveKeyStore os.Create: %s", err.Error())
	}
	defer f.Close()

	sw, err := k.Encrypter(f)
	if err != nil {
		return fmt.Errorf("keystore.SaveKeyStore k.Encrypter: %s", err.Error())
	}
	defer sw.Close()

	// Write values to file.
	if err := k.serialize(sw); err != nil {
		return fmt.Errorf("keystore.SaveKeyStore k.serialize: %s", err.Error())
	}

	return nil
}

// Get returns the value of a specific key.
func (k *KeyStore) Get(key string) (string, error) {

	if k.path == "" || len(k.key) == 0 {
		return "", fmt.Errorf("keystore.Get: keystore not initialized")
	}

	v, exists := k.Values[key]
	if !exists {
		return "", fmt.Errorf("keystore.Get: %s key does not exist", key)
	}
	return v, nil
}

// Set assigns a value to a key, if key does not exist, it's added.
func (k *KeyStore) Set(key, val string) error {
	k.Values[key] = val
	return k.SaveKeyStore()
}

// Delete removes a key from values.
func (k *KeyStore) Delete(key string) {
	delete(k.Values, key)
	k.SaveKeyStore()
}

// List returns a string listing all valid keys.
func (k *KeyStore) List() []string {
	var keys []string
	for k := range k.Values {
		keys = append(keys, k)
	}
	return keys
}

// serialize converts keystore values to JSON and writes them to an io.Writer.
// Remember json.NewEncoder/NewDecoder from lessons learned?
func (k *KeyStore) serialize(w io.Writer) error {
	enc := json.NewEncoder(w)
	return enc.Encode(k.Values)
}

// deserialize reads keystore values from an io.Reader and unmarshals them
// from JSON.
func (k *KeyStore) deserialize(r io.Reader) error {
	dec := json.NewDecoder(r)
	return dec.Decode(&k.Values)
}

// encrypt returns encrypted ciphertext.
// Example: https://golang.org/pkg/crypto/cipher/#NewCFBEncrypter
func encrypt(key, iv, plaintext []byte) ([]byte, error) {

	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("keystore.encrypt: IV not %d bytes", aes.BlockSize)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("keystore.encrypt: key not 32 bytes")
	}

	bl, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("keystore.encrypt aes.NewCipher: %v", err.Error())
	}

	// Write IV to the start of ciphertext.
	ciphertext := make([]byte, len(plaintext)+aes.BlockSize)
	copy(ciphertext[:aes.BlockSize], iv)

	stream := cipher.NewCFBEncrypter(bl, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)
	return ciphertext, nil
}

// Encrypt performs encryption using the keystore's key and IV.
func (k *KeyStore) Encrypt(plaintext string) ([]byte, error) {

	if len(k.key) == 0 || len(k.iv) == 0 {
		return nil, fmt.Errorf("keystore.Encrypt: keystore not initialized")
	}
	plainBytes := []byte(plaintext)

	return encrypt(k.key, k.iv, plainBytes)
}

// Encrypter wants to do interface chaining for io.Writer.
func (k *KeyStore) Encrypter(w io.Writer) (*cipher.StreamWriter, error) {
	if len(k.key) == 0 || len(k.iv) == 0 {
		return nil, fmt.Errorf("keystore.Encrypter: keystore not initialized")
	}

	bl, err := aes.NewCipher(k.key)
	if err != nil {
		return nil, fmt.Errorf("keystore.Encrypter aes.NewCipher: %v", err.Error())
	}

	// Write IV to the start of writer.
	n, err := w.Write(k.iv)
	if err != nil {
		return nil, fmt.Errorf("keystore.Encrypter w.Write IV: %v", err.Error())
	}
	if n != aes.BlockSize {
		return nil, fmt.Errorf("keystore.Encrypter: could not write IV to writer")
	}

	stream := cipher.NewCFBEncrypter(bl, k.iv)

	return &cipher.StreamWriter{S: stream, W: w}, nil
}

// decrypt returns plaintext.
// https://golang.org/pkg/crypto/cipher/#NewCFBDecrypter
func decrypt(key, ciphertext []byte) (string, error) {

	if len(key) != 32 {
		return "", fmt.Errorf("keystore.decrypt: key not 32 bytes")
	}

	if len(ciphertext) < aes.BlockSize {
		return "", fmt.Errorf("keystore.decrypt: ciphertext too short")
	}

	bl, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("keystore.decrypt aes.NewCipher: %v", err.Error())
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(bl, iv)
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)

	return string(plaintext), nil
}

// Decrypt performs decryption using the keystore's key and iv.
func (k *KeyStore) Decrypt(ciphertext []byte) (string, error) {

	if len(k.key) == 0 || len(k.iv) == 0 {
		return "", fmt.Errorf("keystore.Decrypt: keystore not initialized")
	}

	return decrypt(k.key, ciphertext)
}

// Decrypter wants to do interface chaining for io.Reader.
func (k *KeyStore) Decrypter(r io.Reader) (*cipher.StreamReader, error) {
	if len(k.key) == 0 {
		return nil, fmt.Errorf("keystore.Decrypter: keystore not initialized")
	}

	bl, err := aes.NewCipher(k.key)
	if err != nil {
		return nil, fmt.Errorf("keystore.Decrypter aes.NewCipher: %v", err.Error())
	}

	iv := make([]byte, aes.BlockSize)
	// Read IV from reader.
	n, err := r.Read(iv)
	if err != nil {
		return nil, fmt.Errorf("keystore.Decrypter r.Read IV: %v", err.Error())
	}
	if n != aes.BlockSize {
		return nil, fmt.Errorf("keystore.Decrypter: could not write IV to writer")
	}
	// Add IV to keystore.
	k.iv = iv

	stream := cipher.NewCFBDecrypter(bl, iv)

	return &cipher.StreamReader{S: stream, R: r}, nil
}

// fileExists checks if a file exists.
func fileExists(path string) (bool, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
