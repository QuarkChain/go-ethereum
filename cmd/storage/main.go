package main

import (
	"fmt"
	"io"
	"os"

	"github.com/ethereum/go-ethereum/log"
	"github.com/mattn/go-colorable"
	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
)

var (
	filename      *string
	chunkIdxStart *uint64
	chunkIdxLen   *uint64

	verbosity *int
)

var CreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a storage file",
	Run:   runCreate,
}

func init() {
	chunkIdxStart = CreateCmd.Flags().Uint64("start", 0, "Chunk idx start")
	chunkIdxLen = CreateCmd.Flags().Uint64("len", 0, "Chunk idx len")
	filename = CreateCmd.Flags().String("filename", "", "Data filename")

	verbosity = CreateCmd.Flags().Int("verbosity", 3, "Logging verbosity: 0=silent, 1=error, 2=warn, 3=info, 4=debug, 5=detail")
}

func runCreate(cmd *cobra.Command, args []string) {
	glogger := log.NewGlogHandler(log.StreamHandler(os.Stderr, log.TerminalFormat(false)))
	glogger.Verbosity(log.Lvl(*verbosity))
	log.Root().SetHandler(glogger)

	// setup logger
	var ostream log.Handler
	output := io.Writer(os.Stderr)

	usecolor := (isatty.IsTerminal(os.Stderr.Fd()) || isatty.IsCygwinTerminal(os.Stderr.Fd())) && os.Getenv("TERM") != "dumb"
	if usecolor {
		output = colorable.NewColorableStderr()
	}
	ostream = log.StreamHandler(output, log.TerminalFormat(usecolor))

	glogger.SetHandler(ostream)

	_, err := Create(*filename, *chunkIdxStart, *chunkIdxLen, MASK_KECCAK_256)
	if err != nil {
		log.Crit("create failed", "error", err)
	}
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "storage",
	Short: "Storage tools",
}

func init() {
	rootCmd.AddCommand(CreateCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
