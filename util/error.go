package util

// EP panics with the given error, if it is non-nil.
func EP(err error) {
	if err != nil {
		panic(err)
	}
}
