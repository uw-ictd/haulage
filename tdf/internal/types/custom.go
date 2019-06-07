package types

import (
	"time"
)

type Parameters struct {
	flowLogInterval time.Duration
	userLogInterval time.Duration
	pollInterval    time.Duration
}

type UserContext struct {
	DataBalance int64
}

func (context *UserContext) ShouldLogNow(outstandingData int64) bool {
	return (outstandingData >= context.DataBalance) && (context.DataBalance > 0)
}
