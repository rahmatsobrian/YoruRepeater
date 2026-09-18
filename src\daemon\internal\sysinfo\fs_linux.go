//go:build linux

package sysinfo

import "syscall"

// statfs returns total/free/available bytes for a mount point using the statfs
// syscall (no external `df` dependency, and independent of Toybox formatting
// differences between Android releases).
func statfs(path string) (total, free, avail uint64, err error) {
	var st syscall.Statfs_t
	if err = syscall.Statfs(path, &st); err != nil {
		return 0, 0, 0, err
	}
	bsize := uint64(st.Bsize)
	total = st.Blocks * bsize
	free = st.Bfree * bsize
	avail = st.Bavail * bsize
	return total, free, avail, nil
}
