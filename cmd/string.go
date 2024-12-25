package cmd

import "fmt"

func humanizeSize(size uint64) string {
	if size < 1024 {
		return fmt.Sprintf("%d B", size)
	}
	size >>= 10
	if size < 1024 {
		return fmt.Sprintf("%d KiB", size)
	}
	size >>= 10
	if size < 1024 {
		return fmt.Sprintf("%d MiB", size)
	}
	size >>= 10
	if size < 1024 {
		return fmt.Sprintf("%d GiB", size)
	}
	size >>= 10
	return fmt.Sprintf("%d TiB", size)
}
