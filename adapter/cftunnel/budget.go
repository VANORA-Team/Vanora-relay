package cftunnel

import (
	"sync/atomic"
)

const DefaultAssemblyBudget = 128 << 20

var processAssemblyBudget = NewAssemblyBudget(DefaultAssemblyBudget)

// AssemblyBudget bounds reassembly across all peers that share it.
type AssemblyBudget struct {
	limit int64
	used  atomic.Int64
}

func NewAssemblyBudget(limit int64) *AssemblyBudget {
	return &AssemblyBudget{limit: limit}
}

func (b *AssemblyBudget) Used() int64 { return b.used.Load() }

func (b *AssemblyBudget) acquire(size int) bool {
	for {
		used := b.used.Load()
		if int64(size) > b.limit-used {
			return false
		}
		if b.used.CompareAndSwap(used, used+int64(size)) {
			return true
		}
	}
}

func (b *AssemblyBudget) release(size int) { b.used.Add(-int64(size)) }
