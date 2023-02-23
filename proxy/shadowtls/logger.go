package shadowtls

import (
	"context"

	"github.com/sagernet/sing/common/logger"

	"github.com/v2fly/v2ray-core/v5/common/errors"
)

var _ logger.ContextLogger = (*v2rayLogger)(nil)

type v2rayLogger struct {
	newError func(values ...any) *errors.Error
}

func newLogger(newErrorFunc func(values ...any) *errors.Error) *v2rayLogger {
	return &v2rayLogger{
		newErrorFunc,
	}
}

func (l *v2rayLogger) Trace(args ...any) {
}

func (l *v2rayLogger) Debug(args ...any) {
	l.newError(args...).AtDebug().WriteToLog()
}

func (l *v2rayLogger) Info(args ...any) {
	l.newError(args...).AtInfo().WriteToLog()
}

func (l *v2rayLogger) Warn(args ...any) {
	l.newError(args...).AtWarning().WriteToLog()
}

func (l *v2rayLogger) Error(args ...any) {
	l.newError(args...).AtError().WriteToLog()
}

func (l *v2rayLogger) Fatal(args ...any) {
}

func (l *v2rayLogger) Panic(args ...any) {
}

func (l *v2rayLogger) TraceContext(ctx context.Context, args ...any) {
}

func (l *v2rayLogger) DebugContext(ctx context.Context, args ...any) {
	l.newError(args...).AtDebug().WriteToLog()
}

func (l *v2rayLogger) InfoContext(ctx context.Context, args ...any) {
	l.newError(args...).AtInfo().WriteToLog()
}

func (l *v2rayLogger) WarnContext(ctx context.Context, args ...any) {
	l.newError(args...).AtWarning().WriteToLog()
}

func (l *v2rayLogger) ErrorContext(ctx context.Context, args ...any) {
	l.newError(args...).AtError().WriteToLog()
}

func (l *v2rayLogger) FatalContext(ctx context.Context, args ...any) {
}

func (l *v2rayLogger) PanicContext(ctx context.Context, args ...any) {
}
