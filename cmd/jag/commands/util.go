// Copyright (C) 2021 Toitware ApS. All rights reserved.
// Use of this source code is governed by an MIT-style license that can be
// found in the LICENSE file.

package commands

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/toitlang/jaguar/cmd/jag/directory"
	"github.com/xtgo/uuid"
	"golang.org/x/crypto/ssh/terminal"
	"gopkg.in/yaml.v2"
)

type SDK struct {
	Path    string
	Version string
}

func GetSDK(ctx context.Context) (*SDK, error) {
	toit, err := directory.GetSDKPath()
	if err != nil {
		return nil, err
	}

	versionPath := filepath.Join(toit, "VERSION")

	version := ""
	versionBytes, err := ioutil.ReadFile(versionPath)
	if err == nil {
		version = strings.TrimSpace(string(versionBytes))
	}

	res := &SDK{
		Path:    toit,
		Version: version,
	}
	info := GetInfo(ctx)
	// If we're running a development build, we skip the SDK version checks
	// if the SDK is pulled in through the JAG_TOIT_REPO_PATH environment
	// variable. This make it much easier to work with. For release builds,
	// we always check and deliberately ignore the environment variable.
	skipVersionCheck := false
	if !directory.IsReleaseBuild {
		_, skipVersionCheck = os.LookupEnv(directory.ToitRepoPathEnv)
	}
	return res, res.validate(info, skipVersionCheck)
}

func (s *SDK) ToitCompilePath() string {
	return filepath.Join(s.Path, "bin", directory.Executable("toit.compile"))
}

func (s *SDK) ToitRunPath() string {
	return filepath.Join(s.Path, "bin", directory.Executable("toit.run"))
}

func (s *SDK) ToitLspPath() string {
	return filepath.Join(s.Path, "bin", directory.Executable("toit.lsp"))
}

func (s *SDK) VersionPath() string {
	return filepath.Join(s.Path, "VERSION")
}

func (s *SDK) DownloaderInfoPath() string {
	return filepath.Join(s.Path, "JAGUAR")
}

func (s *SDK) SystemMessagePath() string {
	return filepath.Join(s.Path, "tools", directory.Executable("system_message"))
}

func (s *SDK) SnapshotToImagePath() string {
	return filepath.Join(s.Path, "tools", directory.Executable("snapshot_to_image"))
}

func (s *SDK) InjectConfigPath() string {
	return filepath.Join(s.Path, "tools", directory.Executable("inject_config"))
}

func (s *SDK) StacktracePath() string {
	return filepath.Join(s.Path, "tools", directory.Executable("stacktrace"))
}

func (s *SDK) validate(info Info, skipSDKVersionCheck bool) error {
	if !skipSDKVersionCheck {
		if s.Version == "" {
			return fmt.Errorf("SDK in '%s' is too old. Jaguar %s needs version %s.\nRun 'jag setup' to fix this.", s.Path, info.Version, info.SDKVersion)
		} else if info.SDKVersion != s.Version {
			return fmt.Errorf("SDK in '%s' is version %s, but Jaguar %s needs version %s.\nRun 'jag setup' to fix this.", s.Path, s.Version, info.Version, info.SDKVersion)
		}

		downloaderInfoBytes, err := ioutil.ReadFile(s.DownloaderInfoPath())
		if err != nil {
			return fmt.Errorf("SDK in '%s' was not downloaded by Jaguar.\nRun 'jag setup' to fix this.", s.Path)
		}

		downloaderInfo := Info{}
		err = json.Unmarshal(downloaderInfoBytes, &downloaderInfo)
		if err != nil {
			return fmt.Errorf("SDK in '%s' was not downloaded by Jaguar.\nRun 'jag setup' to fix this.", s.Path)
		}

		if downloaderInfo != info {
			return fmt.Errorf("SDK in '%s' was not downloaded by this version of Jaguar.\nRun 'jag setup' to fix this.", s.Path)
		}
	}

	paths := []string{
		s.ToitCompilePath(),
		s.ToitRunPath(),
		s.ToitLspPath(),
		s.VersionPath(),
		s.SystemMessagePath(),
		s.SnapshotToImagePath(),
		s.InjectConfigPath(),
		s.StacktracePath(),
	}
	for _, p := range paths {
		if err := checkFilepath(p, "invalid Toit SDK"); err != nil {
			return fmt.Errorf("%w.\nRun 'jag setup' to fix this.", err)
		}
	}

	return nil
}

func checkFilepath(p string, invalidMsg string) error {
	if stat, err := os.Stat(p); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%s, missing '%s'", invalidMsg, p)
		}
		return fmt.Errorf("%s, failed to load '%s', reason: %w", invalidMsg, p, err)
	} else if stat.IsDir() {
		return fmt.Errorf("%s, '%s' was a directory", invalidMsg, p)
	}
	return nil
}

func (s *SDK) ToitCompile(ctx context.Context, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, s.ToitCompilePath(), args...)
}

func (s *SDK) ToitRun(ctx context.Context, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, s.ToitRunPath(), args...)
}

func (s *SDK) ToitLsp(ctx context.Context, args []string) *exec.Cmd {
	return exec.CommandContext(ctx, s.ToitLspPath(), args...)
}

func (s *SDK) SnapshotToImage(ctx context.Context, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, s.SnapshotToImagePath(), args...)
}

func (s *SDK) SystemMessage(ctx context.Context, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, s.SystemMessagePath(), args...)
}

func (s *SDK) Stacktrace(ctx context.Context, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, s.StacktracePath(), args...)
}

func (s *SDK) InjectConfig(ctx context.Context, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, s.InjectConfigPath(), args...)
}

func (s *SDK) Compile(ctx context.Context, snapshot string, entrypoint string) error {
	buildSnap := s.ToitCompile(ctx, "-w", snapshot, entrypoint)
	buildSnap.Stderr = os.Stderr
	buildSnap.Stdout = os.Stdout
	if err := buildSnap.Run(); err != nil {
		return err
	}
	return nil
}

func (s *SDK) Build(ctx context.Context, device *Device, snapshot string) ([]byte, error) {
	image, err := os.CreateTemp("", "*.image")
	if err != nil {
		return nil, err
	}
	image.Close()
	defer os.Remove(image.Name())

	bits := "-m32"
	if device.WordSize == 8 {
		bits = "-m64"
	}

	buildImage := s.SnapshotToImage(ctx, "--binary", bits, "--output", image.Name(), snapshot)
	buildImage.Stderr = os.Stderr
	buildImage.Stdout = os.Stdout
	if err := buildImage.Run(); err != nil {
		return nil, err
	}

	return ioutil.ReadFile(image.Name())
}

type gzipReader struct {
	*gzip.Reader
	inner io.ReadCloser
}

func newGZipReader(r io.ReadCloser) (*gzipReader, error) {
	res, err := gzip.NewReader(r)
	if err != nil {
		return nil, err
	}
	return &gzipReader{
		Reader: res,
		inner:  r,
	}, nil
}

func (r *gzipReader) Close() error {
	gzipErr := r.Reader.Close()
	rErr := r.inner.Close()
	if gzipErr != nil {
		return gzipErr
	}
	return rErr
}

func extractTarFile(fileReader io.Reader, destDir string, subDir string) error {
	tarBallReader := tar.NewReader(fileReader)

	// Extract the input tar file
	for {
		header, err := tarBallReader.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		if !strings.HasPrefix(header.Name, subDir) {
			continue
		}

		dirPath := filepath.Join(destDir, strings.TrimPrefix(header.Name, subDir))

		switch header.Typeflag {
		case tar.TypeDir:
			// handle directory
			err = os.MkdirAll(dirPath, os.FileMode(header.Mode))
			if err != nil {
				return err
			}

		case tar.TypeReg:
			// handle files
			path := dirPath
			file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_TRUNC, os.FileMode(header.Mode))
			if err != nil {
				return err
			}

			if _, err := io.Copy(file, tarBallReader); err != nil {
				file.Close()
				return err
			}

			if err := file.Close(); err != nil {
				return err
			}
		}
	}

	return nil
}

func ReadLine() (string, error) {
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	return strings.TrimSpace(line), err
}

func ReadPassword() ([]byte, error) {
	fd := int(os.Stdin.Fd())
	oldState, err := terminal.MakeRaw(fd)
	if err != nil {
		return nil, err
	}
	defer func() {
		terminal.Restore(fd, oldState)
		fmt.Printf("******\n")
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	defer signal.Stop(c)
	defer func() { close(c) }()
	go func() {
		select {
		case _, ok := <-c:
			if ok {
				terminal.Restore(fd, oldState)
				fmt.Printf("\n")
				os.Exit(1)
			}
		}
	}()

	return terminal.ReadPassword(fd)
}

type encoder interface {
	Encode(interface{}) error
}

func parseRunDefinesFlags(cmd *cobra.Command, flagName string) (string, error) {
	if !cmd.Flags().Changed(flagName) {
		return "", nil
	}

	definesFlags, err := cmd.Flags().GetStringArray(flagName)
	if err != nil {
		return "", err
	}

	definesMap := make(map[string]interface{})
	for _, element := range definesFlags {
		indexOfAssign := strings.Index(element, "=")
		if indexOfAssign < 0 {
			key := strings.TrimSpace(element)
			definesMap[key] = true
		} else {
			key := strings.TrimSpace(element[0:indexOfAssign])
			value := strings.TrimSpace(element[indexOfAssign+1:])

			// Try to parse the value as a JSON value and avoid turning
			// it into a string if it is valid.
			var unmarshalled interface{}
			err := json.Unmarshal([]byte(value), &unmarshalled)
			if err == nil {
				definesMap[key] = unmarshalled
			} else {
				definesMap[key] = value
			}
		}
	}
	if len(definesMap) == 0 {
		return "", nil
	}

	marshalled, err := json.Marshal(definesMap)
	if err != nil {
		return "", err
	}
	return string(marshalled), nil
}

func parseOutputFlag(cmd *cobra.Command) (encoder, error) {
	list, err := cmd.Flags().GetBool("list")
	if err != nil {
		return nil, err
	}
	if !list {
		return nil, nil
	}
	output, err := cmd.Flags().GetString("output")
	if err != nil {
		return nil, err
	}

	switch strings.ToLower(output) {
	case "json":
		return json.NewEncoder(os.Stdout), nil
	case "yaml":
		return yaml.NewEncoder(os.Stdout), nil
	case "short":
		return newShortEncoder(os.Stdout), nil
	default:
		return nil, fmt.Errorf("--ouput flag '%s' was not recognized. Must be either json, yaml or short.", output)
	}
}

func parseDeviceFlag(cmd *cobra.Command) (deviceSelect, error) {
	if !cmd.Flags().Changed("device") {
		return nil, nil
	}

	d, err := cmd.Flags().GetString("device")
	if err != nil {
		return nil, err
	}
	return parseDeviceSelection(d), nil
}

func parseDeviceSelection(d string) deviceSelect {
	if _, err := uuid.Parse(d); err == nil {
		return deviceIDSelect(d)
	}
	if ip := net.ParseIP(d); ip != nil {
		return deviceAddressSelect(d)
	}
	return deviceNameSelect(d)
}

type shortEncoder struct {
	w io.Writer
}

func newShortEncoder(w io.Writer) *shortEncoder {
	return &shortEncoder{
		w: w,
	}
}

type Elements interface {
	Elements() []Short
}

type Short interface {
	Short() string
}

func (s *shortEncoder) Encode(v interface{}) error {
	es, ok := v.(Elements)
	if !ok {
		return fmt.Errorf("value type %T was not compatible with the Elements interface", v)
	}
	for _, e := range es.Elements() {
		fmt.Fprintln(s.w, e.Short())
	}
	return nil
}

func getWifiCredentials(cmd *cobra.Command) (string, string, error) {
	var wifiSSID string
	var err error

	cfg, err := directory.GetUserConfig()
	if err != nil {
		return "", "", err
	}

	if cmd.Flags().Changed("wifi-ssid") {
		wifiSSID, err = cmd.Flags().GetString("wifi-ssid")
		if err != nil {
			return "", "", err
		}
	} else if v, ok := os.LookupEnv(directory.WifiSSIDEnv); ok {
		wifiSSID = v
	} else if cfg.IsSet(WifiCfgKey + "." + WifiSSIDCfgKey) {
		wifiSSID = cfg.GetString(WifiCfgKey + "." + WifiSSIDCfgKey)
	} else {
		fmt.Printf("Enter WiFi network (SSID): ")
		wifiSSID, err = ReadLine()
		if err != nil {
			return "", "", err
		}
	}

	var wifiPassword string
	if cmd.Flags().Changed("wifi-password") {
		wifiPassword, err = cmd.Flags().GetString("wifi-password")
		if err != nil {
			return "", "", err
		}
	} else if v, ok := os.LookupEnv(directory.WifiPasswordEnv); ok {
		wifiPassword = v
	} else if cfg.IsSet(WifiCfgKey + "." + WifiPasswordCfgKey) {
		wifiPassword = cfg.GetString(WifiCfgKey + "." + WifiPasswordCfgKey)
	} else {
		fmt.Printf("Enter WiFi password for '%s': ", wifiSSID)
		pw, err := ReadPassword()
		if err != nil {
			fmt.Printf("\n")
			return "", "", err
		}
		wifiPassword = string(pw)
	}
	return wifiSSID, wifiPassword, nil
}
