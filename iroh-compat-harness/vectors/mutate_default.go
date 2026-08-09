//go:build !mutcanary

package vectors

func mutate(name, text string, data []byte) (string, []byte) { return text, data }
