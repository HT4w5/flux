package logsrc

type LogSource interface {
	Start()
	Shutdown()
}
