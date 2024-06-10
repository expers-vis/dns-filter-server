package dns_filter_server

import (
	"fmt"
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)


type queryLog struct {
	msg string
	level string
}

type Logger struct {
	buffer map[uint16][]queryLog
	log *zap.SugaredLogger
}


func NewLogger() (*Logger, error) {
	logger := &Logger{}

	zapLogger, err := createZapLogger()

	if err != nil {
		return nil, err
	}

	logger.log = zapLogger
	logger.buffer = map[uint16][]queryLog{}

	return logger, nil
}

func createZapLogger() (*zap.SugaredLogger, error) {
	// TODO: add support for log files
	// https://stackoverflow.com/questions/50933936/zap-logger-print-both-to-console-and-to-log-file
	logLevel := zap.InfoLevel
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.RFC3339TimeEncoder

	consoleEncoder := zapcore.NewConsoleEncoder(encoderConfig)

	core := zapcore.NewTee(
		zapcore.NewCore(consoleEncoder, zapcore.AddSync(os.Stderr), logLevel),
	)

	return zap.New(core).Sugar(), nil
}


func (log *Logger) StartQueryLog(id uint16) {
	msg := "Starting to process query " + fmt.Sprint(id)
	
	log.buffer[id] = append(log.buffer[id], queryLog{msg, "info"})
}

func (log *Logger) AddToQueryLog(id uint16, msg string, level string) {
	log.buffer[id] = append(log.buffer[id], queryLog{"\t" + msg, level})
}

func (log *Logger) FinishQueryLog(id uint16) {
	msg := "Finished processing query " + fmt.Sprint(id)
	
	log.buffer[id] = append(log.buffer[id], queryLog{msg, "info"})

	for _, qlog := range log.buffer[id] {
		log.printToLevel(qlog.msg, qlog.level)
	}

	delete(log.buffer, id)
}

func (l *Logger) printToLevel(msg string, level string) {
	switch level {
	case "info":
		l.log.Infoln(msg)
	case "warning":
		l.log.Warnln(msg)
	case "error":
		l.log.Errorln(msg)
	default:
		l.log.Infoln(msg)
	}
}
