// Command exec-monitor loads the exec_monitor eBPF program, attaches it to
// sched_process_exec (falling back to sys_enter_execve), reads exec events
// from the ring buffer, and flags a simple reverse-shell pattern:
//
//	comm in {bash,sh,dash,nc,ncat,python3} AND parent_comm in {nginx,apache2,sshd,httpd}
//
// Scope is intentionally minimal: one event type, one rule, no config file.
package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Wno-unused-variable" -target amd64 ExecMonitor ../bpf/exec_monitor.bpf.c -- -I../bpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// event mirrors struct event in bpf/exec_monitor.bpf.c.
type event struct {
	Pid        uint32
	Ppid       uint32
	Comm       [16]int8
	ParentComm [16]int8
}

var shellComms = map[string]bool{
	"bash":    true,
	"sh":      true,
	"dash":    true,
	"nc":      true,
	"ncat":    true,
	"python3": true,
}

var suspiciousParents = map[string]bool{
	"nginx":   true,
	"apache2": true,
	"sshd":    true,
	"httpd":   true,
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("removing memlock rlimit: %v", err)
	}

	objs := ExecMonitorObjects{}
	if err := LoadExecMonitorObjects(&objs, nil); err != nil {
		log.Fatalf("loading eBPF objects: %v", err)
	}
	defer objs.Close()

	lnk, mode := attach(&objs)
	defer lnk.Close()
	log.Printf("attached via %s, monitoring process exec events (Ctrl-C to stop)", mode)

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("opening ring buffer reader: %v", err)
	}
	defer rd.Close()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	go func() {
		<-stop
		rd.Close()
	}()

	var ev event
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("shutting down")
				return
			}
			log.Printf("reading ring buffer: %v", err)
			continue
		}

		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &ev); err != nil {
			log.Printf("parsing event: %v", err)
			continue
		}

		comm := int8ToString(ev.Comm[:])
		parentComm := int8ToString(ev.ParentComm[:])
		ts := time.Now().Format(time.RFC3339)

		if shellComms[comm] && suspiciousParents[parentComm] {
			fmt.Printf("[ALERT][T1059] ts=%s pid=%d ppid=%d parent_comm=%s comm=%s reason=\"shell spawned by network-facing process\"\n",
				ts, ev.Pid, ev.Ppid, parentComm, comm)
			continue
		}

		fmt.Printf("ts=%s pid=%d ppid=%d parent_comm=%s comm=%s\n",
			ts, ev.Pid, ev.Ppid, parentComm, comm)
	}
}

// attach tries the CO-RE tp_btf/sched_process_exec program first (works on
// modern kernels with BTF); if that fails it falls back to the classic
// tracepoint/syscalls/sys_enter_execve program.
func attach(objs *ExecMonitorObjects) (link.Link, string) {
	lnk, err := link.AttachTracing(link.TracingOptions{
		Program: objs.OnSchedProcessExec,
	})
	if err == nil {
		return lnk, "tp_btf/sched_process_exec"
	}
	log.Printf("tp_btf/sched_process_exec unavailable (%v), falling back to sys_enter_execve", err)

	lnk, err = link.Tracepoint("syscalls", "sys_enter_execve", objs.OnSysEnterExecve, nil)
	if err != nil {
		log.Fatalf("attaching fallback tracepoint: %v", err)
	}
	return lnk, "tracepoint/syscalls/sys_enter_execve"
}

func int8ToString(arr []int8) string {
	b := make([]byte, len(arr))
	for i, c := range arr {
		if c == 0 {
			b = b[:i]
			break
		}
		b[i] = byte(c)
	}
	return string(b)
}
