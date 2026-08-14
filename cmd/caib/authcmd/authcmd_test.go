package authcmd

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/clilog"
	. "github.com/onsi/ginkgo/v2" //nolint:revive
	. "github.com/onsi/gomega"    //nolint:revive
)

func TestAuthCmd(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "AuthCmd Suite")
}

var _ = Describe("formatDuration", func() {
	It("should format hours and minutes", func() {
		Expect(formatDuration(2*time.Hour + 30*time.Minute)).To(Equal("2h 30m"))
	})

	It("should format only hours when minutes are zero", func() {
		Expect(formatDuration(3 * time.Hour)).To(Equal("3h 0m"))
	})

	It("should format only minutes when less than an hour", func() {
		Expect(formatDuration(45 * time.Minute)).To(Equal("45m"))
	})

	It("should format seconds when less than a minute", func() {
		Expect(formatDuration(30 * time.Second)).To(Equal("30s"))
	})

	It("should handle zero duration", func() {
		Expect(formatDuration(0)).To(Equal("0s"))
	})

	It("should handle negative duration (absolute value)", func() {
		Expect(formatDuration(-2*time.Hour - 15*time.Minute)).To(Equal("2h 15m"))
	})

	It("should handle negative minutes", func() {
		Expect(formatDuration(-10 * time.Minute)).To(Equal("10m"))
	})

	It("should handle large durations", func() {
		Expect(formatDuration(48*time.Hour + 59*time.Minute)).To(Equal("48h 59m"))
	})
})

func captureStdout(fn func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	fn()
	_ = w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	return buf.String()
}

var _ = Describe("printTokenStatus quiet mode", func() {
	AfterEach(func() {
		clilog.SetQuiet(false)
	})

	It("should suppress output in quiet mode", func() {
		clilog.SetQuiet(true)
		out := captureStdout(func() {
			printTokenStatus(2*time.Hour, "2h 0m")
		})
		Expect(out).To(BeEmpty())
	})

	It("should show output when not quiet", func() {
		clilog.SetQuiet(false)
		out := captureStdout(func() {
			printTokenStatus(2*time.Hour, "2h 0m")
		})
		Expect(out).NotTo(BeEmpty())
		Expect(out).To(ContainSubstring("Valid"))
	})

	It("should suppress expired status in quiet mode", func() {
		clilog.SetQuiet(true)
		out := captureStdout(func() {
			printTokenStatus(-1*time.Hour, "1h 0m")
		})
		Expect(out).To(BeEmpty())
	})
})

var _ = Describe("NewAuthCmd", func() {
	It("should create auth command with status and refresh subcommands", func() {
		cmd := NewAuthCmd()
		Expect(cmd.Use).To(Equal("auth"))

		subCommands := cmd.Commands()
		names := make([]string, len(subCommands))
		for i, c := range subCommands {
			names[i] = c.Use
		}
		Expect(names).To(ContainElement("status"))
		Expect(names).To(ContainElement("refresh"))
	})

	It("should have --verbose flag on status subcommand", func() {
		cmd := NewAuthCmd()
		for _, sub := range cmd.Commands() {
			if sub.Use == "status" {
				flag := sub.Flags().Lookup("verbose")
				Expect(flag).NotTo(BeNil())
				Expect(flag.DefValue).To(Equal("false"))
				return
			}
		}
		Fail("status subcommand not found")
	})
})
