package logger

var shouldPublishCases = []shouldPublishCase{
	{CurrentLogLevel: Level("error"), LogLevel: Level("debug"), Expected: false},
	{CurrentLogLevel: Level("error"), LogLevel: Level("info"), Expected: false},
	{CurrentLogLevel: Level("error"), LogLevel: Level("warn"), Expected: false},
	{CurrentLogLevel: Level("info"), LogLevel: Level("debug"), Expected: false},
	{CurrentLogLevel: Level("warn"), LogLevel: Level("debug"), Expected: false},
	{CurrentLogLevel: Level("warn"), LogLevel: Level("info"), Expected: false},
	{CurrentLogLevel: Level("debug"), LogLevel: Level("debug"), Expected: true},
	{CurrentLogLevel: Level("debug"), LogLevel: Level("error"), Expected: true},
	{CurrentLogLevel: Level("debug"), LogLevel: Level("info"), Expected: true},
	{CurrentLogLevel: Level("debug"), LogLevel: Level("warn"), Expected: true},
	{CurrentLogLevel: Level("error"), LogLevel: Level("error"), Expected: true},
	{CurrentLogLevel: Level("info"), LogLevel: Level("error"), Expected: true},
	{CurrentLogLevel: Level("info"), LogLevel: Level("info"), Expected: true},
	{CurrentLogLevel: Level("info"), LogLevel: Level("warn"), Expected: true},
	{CurrentLogLevel: Level("warn"), LogLevel: Level("error"), Expected: true},
	{CurrentLogLevel: Level("warn"), LogLevel: Level("warn"), Expected: true},
}
