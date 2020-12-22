// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package common

import (
	"fmt"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/mem"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"time"
)

// Report gives off a warning requesting the user to submit an issue to the github tracker.
func Report(extra ...interface{}) {
	fmt.Fprintln(os.Stderr, "You've encountered a sought after, hard to reproduce bug. Please report this to the developers <3 https://github.com/ethereum/go-ethereum/issues")
	fmt.Fprintln(os.Stderr, extra...)

	_, file, line, _ := runtime.Caller(1)
	fmt.Fprintf(os.Stderr, "%v:%v\n", file, line)

	debug.PrintStack()

	fmt.Fprintln(os.Stderr, "#### BUG! PLEASE REPORT ####")
}

// PrintDepricationWarning prinst the given string in a box using fmt.Println.
func PrintDepricationWarning(str string) {
	line := strings.Repeat("#", len(str)+4)
	emptyLine := strings.Repeat(" ", len(str))
	fmt.Printf(`
%s
# %s #
# %s #
# %s #
%s

`, line, emptyLine, str, emptyLine, line)
}

type DebugTime struct {
	ExecuteTx     time.Duration
	ValidateBlock time.Duration
	WriteBlock    time.Duration
	CommitTrie    time.Duration
	TxLen         int
}

func NewDebugTime() *DebugTime {
	d := &DebugTime{
		ExecuteTx:     time.Duration(0),
		ValidateBlock: time.Duration(0),
		WriteBlock:    time.Duration(0),
		CommitTrie:    time.Duration(0),
	}
	go d.cpuAndMem()
	return d

}

func (d *DebugTime) cpuAndMem() {
	for true {
		v, _ := mem.VirtualMemory()
		res, _ := cpu.Times(false)
		fmt.Println("mem info", v)
		fmt.Println("cpu info", res)
		time.Sleep(10 * time.Minute)
	}
}

func (d *DebugTime) Print() {
	fmt.Println("总的交易数目", d.TxLen)

	fmt.Println("执行区块用时", d.ExecuteTx)
	fmt.Println("验证区块用时", d.ValidateBlock)
	fmt.Println("写入区块用时", d.WriteBlock)
	fmt.Println("写入trie用时", d.CommitTrie)
}

var (
	DebugInfo         = NewDebugTime()
	BlockExecuteBatch = int(1)
)
