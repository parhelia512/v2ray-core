//go:build !confonly
// +build !confonly

package external

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/v2fly/v2ray-core/v4/common/errors"
	"github.com/v2fly/v2ray-core/v4/common/platform"
	"github.com/v2fly/v2ray-core/v4/common/signal/done"
	"github.com/v2fly/v2ray-core/v4/proxy/sip003"
)

//go:generate go run github.com/v2fly/v2ray-core/v4/common/errors/errorgen

var _ sip003.Plugin = (*Plugin)(nil)

func init() {
	sip003.SetPluginLoader(func(plugin string) sip003.Plugin {
		return &Plugin{Plugin: plugin}
	})
}

type Plugin struct {
	Plugin        string
	pluginProcess *exec.Cmd
	done          *done.Instance
}

func (p *Plugin) Init(localHost string, localPort string, remoteHost string, remotePort string, pluginOpts string, pluginArgs []string) error {
	p.done = done.New()
	path, err := exec.LookPath(p.Plugin)
	if err != nil {
		return newError("plugin ", p.Plugin, " not found").Base(err)
	}
	_, name := filepath.Split(path)
	proc := &exec.Cmd{
		Path: path,
		Args: pluginArgs,
		Env: []string{
			"SS_REMOTE_HOST=" + remoteHost,
			"SS_REMOTE_PORT=" + remotePort,
			"SS_LOCAL_HOST=" + localHost,
			"SS_LOCAL_PORT=" + localPort,
		},
		Stdout: &pluginOutWriter{
			name: name,
		},
		Stderr: &pluginErrWriter{
			name: name,
		},
	}
	if pluginOpts != "" {
		proc.Env = append(proc.Env, "SS_PLUGIN_OPTIONS="+pluginOpts)
	}
	proc.Env = append(proc.Env, os.Environ()...)

	if err := p.startPlugin(proc); err != nil {
		return err
	}

	return nil
}

func (p *Plugin) startPlugin(oldProc *exec.Cmd) *errors.Error {
	if p.done.Done() {
		return newError("closed")
	}

	proc := &exec.Cmd{
		Path:   oldProc.Path,
		Args:   oldProc.Args,
		Stdout: oldProc.Stdout,
		Stderr: oldProc.Stderr,
		Env:    oldProc.Env,
	}

	newError("start process ", proc.Path, " ", strings.Join(proc.Args, " ")).AtInfo().WriteToLog()

	err := proc.Start()
	if err != nil {
		return newError("failed to start sip003 plugin ", proc.Path).Base(err)
	}

	go func() {
		time.Sleep(time.Second)
		err = platform.CheckChildProcess(proc.Process)
		if err != nil {
			newError("sip003 plugin ", proc.Path, " exits too fast").Base(err).WriteToLog()
			return
		}
		go p.waitPlugin()
	}()

	p.pluginProcess = proc

	return nil
}

func (p *Plugin) waitPlugin() {
	status, err := p.pluginProcess.Process.Wait()

	if p.done.Done() {
		return
	}

	if err != nil {
		newError("failed to get sip003 plugin status").Base(err).WriteToLog()
	} else {
		newError("sip003 plugin exited with code %d, try restart", status.ExitCode()).WriteToLog()
	}

	time.Sleep(time.Second)

	if restartErr := p.startPlugin(p.pluginProcess); restartErr != nil {
		restartErr.WriteToLog()
	} else {
		go p.waitPlugin()
	}
}

func (p *Plugin) Close() error {
	p.done.Close()
	proc := p.pluginProcess
	if proc != nil && proc.Process != nil {
		proc.Process.Kill()
	}
	return nil
}
