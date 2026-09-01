package obs

import "reflect"

// IsNil reports whether l carries no usable logger.
//
// It is true for an untyped nil interface AND for a typed nil — an interface
// holding a nil pointer, such as the (*T)(nil) a caller gets from a constructor
// that failed:
//
//	logger, err := zap.New(cfg) // err != nil, logger == (*zap.Logger)(nil)
//	client := middleware.NewAuthClient(addr, true, logger)
//
// A typed nil is NOT equal to nil, so a plain `l != nil` check accepts it and
// the library then stores a logger whose every method call dereferences a nil
// receiver. lib-observability's own adapters happen to guard that internally,
// but this contract is deliberately open to ANY implementation, and an ordinary
// hand-written one dereferences its receiver and panics. Treating a typed nil
// as unset is what keeps that promise safe to make.
func IsNil(l Logger) bool {
	if l == nil {
		return true
	}

	switch v := reflect.ValueOf(l); v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Map,
		reflect.Pointer, reflect.Slice, reflect.UnsafePointer:
		return v.IsNil()
	default:
		return false
	}
}
