package provider

import (
	"fmt"
)

type CodeError struct {
	code    int
	message string
	err     error
}

func (e CodeError) Error() string {
	return fmt.Sprintf(" [%d] :%s (%s)", e.code, e.message, e.err.Error())
}
