// Copyright (C) 2021 Toitware ApS. All rights reserved.
// Use of this source code is governed by an MIT-style license that can be
// found in the LICENSE file.

package commands

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/mitchellh/mapstructure"
	"github.com/spf13/cobra"
	"github.com/toitlang/jaguar/cmd/jag/directory"
	"github.com/toitware/ubjson"
)

func DecodeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "decode <message>",
		Short: "Decode a stack trace received from a Jaguar device",
		Long: "Decode a stack trace received from a Jaguar device. Stack traces are encoded\n" +
			"using base64 and are easy to copy from the serial output.",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			disassemble, _ := cmd.Flags().GetBool("disassemble")
			return serialDecode(cmd, args[0], disassemble)
		},
	}
	cmd.Flags().Bool("disassemble", false, "disassemble when there are native crashes")
	cmd.Flags().MarkHidden("disassemble")
	return cmd
}

func serialDecode(cmd *cobra.Command, message string, disassemble bool) error {
	if strings.HasPrefix(message, "Backtrace:") {
		return crashDecode(cmd, message, disassemble)
	} else {
		if strings.HasPrefix(message, "jag decode ") {
			return jagDecode(cmd, message[11:])
		} else {
			return jagDecode(cmd, message)
		}
	}
}

func jagDecode(cmd *cobra.Command, base64Message string) error {
	ctx := cmd.Context()
	sdk, err := GetSDK(ctx)
	if err != nil {
		return err
	}

	message, err := base64.StdEncoding.DecodeString(base64Message)
	if err != nil {
		return err
	}

	var decoded []interface{}
	if err = ubjson.Unmarshal(message, &decoded); err != nil {
		return fmt.Errorf("failed to parse message as ubjson, reason: %v", err)
	}

	if len(decoded) != 4 && len(decoded) != 5 {
		return fmt.Errorf("message did not have correct format")
	}

	i := 0
	if v, ok := decoded[i].(int64); !ok || rune(v) != 'X' {
		return fmt.Errorf("message did not have correct format")
	}
	i++

	_, ok := decoded[i].(string)
	if !ok {
		return fmt.Errorf("message did not have correct format")
	}
	i++

	if len(decoded) == 5 {
		if _, ok := decoded[i].(string); !ok {
			return fmt.Errorf("message did not have correct format")
		}
		i++
	}

	var programIdBytes []byte
	if mapstructure.Decode(decoded[i], &programIdBytes) != nil {
		return fmt.Errorf("message did not have correct format")
	}

	programId, err := uuid.FromBytes(programIdBytes)
	if err != nil {
		return fmt.Errorf("failed to parse program id: %v", err)
	}

	snapshotsCache, err := directory.GetSnapshotsCachePath()
	if err != nil {
		return err
	}

	snapshot := ""

	if programId == uuid.Nil {
		snapshot = "nosnapshot"
	} else {
		snapshot = filepath.Join(snapshotsCache, programId.String()+".snapshot")
		if _, err := os.Stat(snapshot); errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(os.Stderr, "No such file: %s\n", snapshot)
			return fmt.Errorf("cannot find snapshot for program: %s", programId.String())
		}
	}

	decodeCommand := sdk.ToitRun(ctx, sdk.SystemMessageSnapshotPath(), snapshot, "-b", base64Message)
	decodeCommand.Stderr = os.Stderr
	decodeCommand.Stdout = os.Stdout
	return decodeCommand.Run()
}

func crashDecode(cmd *cobra.Command, backtrace string, disassemble bool) error {
	ctx := cmd.Context()
	sdk, err := GetSDK(ctx)
	if err != nil {
		return err
	}

	elf, err := directory.GetESP32ImagePath()
	if err != nil {
		return err
	}
	elf = filepath.Join(elf, "toit.elf")

	objdump, err := exec.LookPath("xtensa-esp32-elf-objdump")
	if err != nil && !disassemble {
		objdump, err = exec.LookPath("objdump")
	}
	if err != nil {
		return err
	}
	disassembleString := ""
	if disassemble {
		disassembleString = "--disassemble"
	} else {
		disassembleString = "--"
	}
	stacktraceCommand := sdk.ToitRun(ctx, sdk.StacktracePath(), "--objdump", objdump, "--backtrace", backtrace, disassembleString, elf)
	stacktraceCommand.Stderr = os.Stderr
	stacktraceCommand.Stdout = os.Stdout
	fmt.Println("Crash in native code:")
	fmt.Println(backtrace)
	return stacktraceCommand.Run()
}
