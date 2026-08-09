//go:build mutcanary

package vectors

import "os"

func mutate(name, text string, data []byte) (string, []byte) {
	if os.Getenv("PARITY_MUTATION") != name {
		return text, data
	}
	switch name {
	case "ticket-prefix":
		return "mutated" + text, data
	case "postcard-varint", "pkarr-signer":
		out := append([]byte(nil), data...)
		if len(out) != 0 {
			if name == "pkarr-signer" && len(out) > 32 {
				out[32] ^= 1
			} else {
				out[0] ^= 1
			}
		}
		return text, out
	default:
		return text, data
	}
}
