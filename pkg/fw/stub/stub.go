package stub

import (
	"encoding/json"
	"fmt"

	"github.com/HT4w5/flux/pkg/dto"
)

type StubDriver struct{}

func (d *StubDriver) Install(rules []dto.BanRule) error {
	jsonBytes, err := json.MarshalIndent(rules, "", "    ")
	if err != nil {
		return err
	}
	fmt.Println(string(jsonBytes))
	return nil
}

func (d *StubDriver) Reset() error { return nil }
