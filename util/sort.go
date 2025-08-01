package util

import (
	"fmt"
	"github.com/projectdiscovery/gologger"
	fileutil "github.com/projectdiscovery/utils/file"
	"github.com/wjlin0/masscan-go/scanner"
	"os"
	"path/filepath"
	"sort"
)

// SortResults 对扫描结果进行排序
func SortResults(results []scanner.ScanResult) {
	sort.SliceStable(results, func(i, j int) bool {
		if results[i].IP == results[j].IP {
			return results[i].Port < results[j].Port
		}
		return results[i].IP < results[j].IP
	})
}

// PrintResults 打印扫描结果
func PrintResults(results []scanner.ScanResult) {
	if len(results) == 0 {
		gologger.Warning().Msgf("No open ports found")
		return
	}

	fmt.Println("\nScan results:")
	for _, res := range results {
		fmt.Printf("%s:%d\n", res.IP, res.Port)
	}
}

func OutputResults(results []scanner.ScanResult, filename string) error {
	gologger.Info().Msgf("Writing results to %s\n", filename)
	err := fileutil.CreateFolder(filepath.Dir(filename))
	if err != nil {
		return err
	}
	// 写入文件
	// 如果存在 删除
	if fileutil.FileExists(filename) {
		err = os.Remove(filename)
		if err != nil {
			return err
		}
	}
	var (
		file *os.File
	)

	if fileutil.FileExists(filename) {
		file, err = os.OpenFile(filename, os.O_RDWR, 0777)
		if err != nil {
			return err
		}
	}

	file, err = os.OpenFile(filename, os.O_RDWR|os.O_CREATE, 0777)
	if err != nil {
		return err
	}
	for _, res := range results {
		_, _ = file.WriteString(fmt.Sprintf("%s:%d\n", res.IP, res.Port))
	}
	return nil

}
