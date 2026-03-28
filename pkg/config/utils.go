package config

import (
	"reflect"

	"github.com/docker/go-units"
	"github.com/go-viper/mapstructure/v2"
)

func ByteSizeHookFunc() mapstructure.DecodeHookFunc {
	return func(f reflect.Type, t reflect.Type, data interface{}) (interface{}, error) {
		if f.Kind() != reflect.String || t.Kind() != reflect.Int64 {
			return data, nil
		}

		s := data.(string)
		res, err := units.FromHumanSize(s)
		return res, err
	}
}
