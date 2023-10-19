package logger

type ILogger interface {
	All(v ...interface{})
	AllF(format string, v ...interface{})
	Debug(v ...interface{})
	DebugF(format string, v ...interface{})
	Info(v ...interface{})
	InfoF(format string, v ...interface{})
	Warning(v ...interface{})
	WarningF(format string, v ...interface{})
	Error(v ...interface{})
	ErrorF(format string, v ...interface{})
}

type ExampleLogger struct{}

func (t *ExampleLogger) All(v ...interface{}) {

}

func (t *ExampleLogger) AllF(format string, v ...interface{}) {

}

func (t *ExampleLogger) Debug(v ...interface{}) {

}

func (t *ExampleLogger) DebugF(format string, v ...interface{}) {

}

func (t *ExampleLogger) Info(v ...interface{}) {

}

func (t *ExampleLogger) InfoF(format string, v ...interface{}) {

}

func (t *ExampleLogger) Warning(v ...interface{}) {

}

func (t *ExampleLogger) WarningF(format string, v ...interface{}) {

}

func (t *ExampleLogger) Error(v ...interface{}) {

}

func (t *ExampleLogger) ErrorF(format string, v ...interface{}) {

}

var (
	loggerInst ILogger = &ExampleLogger{}
)

func GetLoggerInstance() ILogger {
	return loggerInst
}

func SetLoggerInstance(logger ILogger) {
	loggerInst = logger
}
