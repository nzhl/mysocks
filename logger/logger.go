package logger

import (
	"fmt"
	"log"
	"os"

	_ "github.com/joho/godotenv/autoload"
)

var logger *log.Logger

func init() {
	enableDebug := os.Getenv("DEBUG")
	if enableDebug == "" {
		return
	}
	logFile, err := os.OpenFile("mysocks.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalln("open log file error: ", err)
	}
	logger = log.New(logFile, "", log.LstdFlags|log.Lshortfile)
}

func Debug(format string, v ...interface{}) {
	if logger == nil {
		return
	}
	err := logger.Output(2, fmt.Sprintf(format, v...))
	if err != nil {
		log.Fatalln("write log file error: ", err)
	}
}
