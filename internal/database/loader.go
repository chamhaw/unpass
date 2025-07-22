package database

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"github.com/yourorg/unpass/internal/types"
)

type DatabaseLoader struct {
	basePath string
}

func NewDatabaseLoader(basePath string) *DatabaseLoader {
	return &DatabaseLoader{
		basePath: basePath,
	}
}

func (dl *DatabaseLoader) LoadTwoFADatabase() (*types.TwoFADatabase, error) {
	filePath := filepath.Join(dl.basePath, "2fa_database.json")
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read 2FA database: %w", err)
	}

	var db types.TwoFADatabase
	if err := json.Unmarshal(data, &db); err != nil {
		return nil, fmt.Errorf("failed to parse 2FA database: %w", err)
	}

	return &db, nil
}

func (dl *DatabaseLoader) LoadPasskeyDatabase() (*types.PasskeyDatabase, error) {
	filePath := filepath.Join(dl.basePath, "passkey_database.json")
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read Passkey database: %w", err)
	}

	var db types.PasskeyDatabase
	if err := json.Unmarshal(data, &db); err != nil {
		return nil, fmt.Errorf("failed to parse Passkey database: %w", err)
	}

	return &db, nil
}

func (dl *DatabaseLoader) LoadPwnedPasswordDatabase() (*types.PwnedPasswordDatabase, error) {
	filePath := filepath.Join(dl.basePath, "pwned_passwords_database.json")
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read pwned password database: %w", err)
	}

	var db types.PwnedPasswordDatabase
	if err := json.Unmarshal(data, &db); err != nil {
		return nil, fmt.Errorf("failed to parse pwned password database: %w", err)
	}

	return &db, nil
} 