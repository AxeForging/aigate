package helpers

import (
	"os"

	"github.com/rs/zerolog"
)

var Log zerolog.Logger

func SetupLogger(level string) {
	var l zerolog.Level
	switch level {
	case "debug":
		l = zerolog.DebugLevel
	case "info":
		l = zerolog.InfoLevel
	case "warn":
		l = zerolog.WarnLevel
	case "error":
		l = zerolog.ErrorLevel
	default:
		l = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(l)
}

func init() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	output := zerolog.ConsoleWriter{
		Out:        os.Stderr,
		TimeFormat: "\033[90m15:04:05\033[0m",
		NoColor:    false,
		PartsOrder: []string{
			zerolog.TimestampFieldName,
			zerolog.LevelFieldName,
			zerolog.MessageFieldName,
		},
		FormatLevel: func(i interface{}) string {
			level := "????"
			if s, ok := i.(string); ok {
				switch s {
				case "debug":
					level = "\033[36mDEBUG\033[0m"
				case "info":
					level = "\033[32mINFO \033[0m"
				case "warn":
					level = "\033[33mWARN \033[0m"
				case "error":
					level = "\033[31mERROR\033[0m"
				case "fatal":
					level = "\033[31mFATAL\033[0m"
				}
			}
			return level
		},
		FormatMessage: func(i interface{}) string {
			if i == nil {
				return ""
			}
			return "  " + i.(string)
		},
	}
	Log = zerolog.New(output).With().Timestamp().Logger()
}
