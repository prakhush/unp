package main

import (
	"archive/tar"
	"archive/zip"
	"compress/bzip2"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	bzip2_compress "github.com/dsnet/compress/bzip2"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
	"github.com/ulikunitz/xz"
	passwordzip "github.com/yeka/zip"
)

type Config struct {
	KeepSource   bool
	OutputDir    string
	Verbose      bool
	CompressType string
	OutputFile   string
	Password     string
	Progress     bool
}

var config Config

func main() {
	var rootCmd = &cobra.Command{
		Use:   "unp [files...]",
		Short: "通用归档提取器和压缩器",
		Long:  "一款通用的归档工具，可以提取和压缩各种文件格式",
		Args:  cobra.MinimumNArgs(1),
		Run:   processFiles,
	}

	rootCmd.Flags().BoolVarP(&config.KeepSource, "keep", "k", false, "提取/压缩后保留源文件")
	rootCmd.Flags().StringVarP(&config.OutputDir, "output", "o", "", "输出目录（默认：当前目录）")
	rootCmd.Flags().BoolVarP(&config.Verbose, "verbose", "v", false, "详细输出")
	rootCmd.Flags().StringVarP(&config.CompressType, "type", "t", "", "创建归档的压缩类型（zip、tar、tar.gz、tar.bz2、tar.xz）")
	rootCmd.Flags().StringVarP(&config.OutputFile, "file", "f", "", "输出归档文件名（使用-t时必需）")
	rootCmd.Flags().StringVarP(&config.Password, "password", "p", "", "ZIP加密/解密密码")
	rootCmd.Flags().BoolVar(&config.Progress, "progress", true, "显示进度条")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func processFiles(cmd *cobra.Command, args []string) {
	if config.CompressType != "" {
		if config.OutputFile == "" {
			fmt.Fprintf(os.Stderr, "错误：使用压缩类型（-t）时需要输出文件（-f）\n")
			os.Exit(1)
		}
		compressFiles(args)
	} else {
		extractFiles(args)
	}
}

func extractFiles(args []string) {
	for _, file := range args {
		if config.Verbose {
			fmt.Printf("Processing: %s\n", file)
		}

		if err := extractFile(file); err != nil {
			fmt.Fprintf(os.Stderr, "Error extracting %s: %v\n", file, err)
			continue
		}

		if config.Verbose {
			fmt.Printf("Successfully extracted: %s\n", file)
		}

		if !config.KeepSource {
			if err := os.Remove(file); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Could not remove source file %s: %v\n", file, err)
			}
		}
	}
}

func extractFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("could not open file: %w", err)
	}
	defer file.Close()

	format, err := detectFormat(file)
	if err != nil {
		return fmt.Errorf("could not detect format: %w", err)
	}

	if config.Verbose {
		fmt.Printf("Detected format: %s\n", format)
	}

	_, err = file.Seek(0, 0)
	if err != nil {
		return fmt.Errorf("could not seek to beginning: %w", err)
	}

	// Get file size for progress bar
	fileInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("could not get file info: %w", err)
	}
	fileSize := fileInfo.Size()

	// Create progress bar if enabled and not in verbose mode
	var bar *progressbar.ProgressBar
	if config.Progress && !config.Verbose {
		bar = progressbar.DefaultBytes(
			fileSize,
			fmt.Sprintf("Extracting %s", filepath.Base(filename)),
		)
	}

	var reader io.Reader = file
	if bar != nil {
		progressReader := progressbar.NewReader(file, bar)
		reader = &progressReader
	}

	outputDir := config.OutputDir
	if outputDir == "" {
		outputDir = filepath.Dir(filename)
	}

	switch format {
	case "zip":
		// ZIP needs special handling as it requires random access
		// Calculate uncompressed size for ZIP files
		if bar != nil {
			uncompressedSize, err := calculateZipUncompressedSize(filename)
			if err == nil && uncompressedSize > 0 {
				// Create a new progress bar with correct size
				bar = progressbar.DefaultBytes(
					uncompressedSize,
					fmt.Sprintf("Extracting %s", filepath.Base(filename)),
				)
			}
		}
		return extractZipWithProgress(filename, outputDir, bar)
	case "tar":
		return extractTar(reader, outputDir)
	case "tar.gz", "tgz":
		return extractTarGz(reader, outputDir)
	case "tar.bz2", "tbz2":
		return extractTarBz2(reader, outputDir)
	case "tar.xz", "txz":
		return extractTarXz(reader, outputDir)
	case "gz":
		return extractGz(reader, filename, outputDir)
	case "bz2":
		return extractBz2(reader, filename, outputDir)
	case "xz":
		return extractXz(reader, filename, outputDir)
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
}

func detectFormat(file *os.File) (string, error) {
	buffer := make([]byte, 512)
	n, err := file.Read(buffer)
	if err != nil && err != io.EOF {
		return "", err
	}
	buffer = buffer[:n]

	filename := file.Name()
	ext := strings.ToLower(filepath.Ext(filename))

	if strings.HasSuffix(strings.ToLower(filename), ".tar.gz") {
		return "tar.gz", nil
	}
	if strings.HasSuffix(strings.ToLower(filename), ".tar.bz2") {
		return "tar.bz2", nil
	}
	if strings.HasSuffix(strings.ToLower(filename), ".tar.xz") {
		return "tar.xz", nil
	}

	switch {
	case len(buffer) >= 4 && buffer[0] == 0x50 && buffer[1] == 0x4B && buffer[2] == 0x03 && buffer[3] == 0x04:
		return "zip", nil
	case len(buffer) >= 4 && buffer[0] == 0x50 && buffer[1] == 0x4B && buffer[2] == 0x05 && buffer[3] == 0x06:
		return "zip", nil
	case len(buffer) >= 4 && buffer[0] == 0x50 && buffer[1] == 0x4B && buffer[2] == 0x07 && buffer[3] == 0x08:
		return "zip", nil
	case len(buffer) >= 262 && string(buffer[257:262]) == "ustar":
		return "tar", nil
	case len(buffer) >= 3 && buffer[0] == 0x1F && buffer[1] == 0x8B && buffer[2] == 0x08:
		if strings.Contains(strings.ToLower(filename), ".tar.") || ext == ".tgz" {
			return "tar.gz", nil
		}
		return "gz", nil
	case len(buffer) >= 3 && buffer[0] == 0x42 && buffer[1] == 0x5A && buffer[2] == 0x68:
		if strings.Contains(strings.ToLower(filename), ".tar.") || ext == ".tbz2" {
			return "tar.bz2", nil
		}
		return "bz2", nil
	case len(buffer) >= 6 && string(buffer[0:6]) == "\xFD7zXZ\x00":
		if strings.Contains(strings.ToLower(filename), ".tar.") || ext == ".txz" {
			return "tar.xz", nil
		}
		return "xz", nil
	default:
		switch ext {
		case ".zip":
			return "zip", nil
		case ".tar":
			return "tar", nil
		case ".gz":
			if strings.HasSuffix(strings.ToLower(filename), ".tar.gz") || ext == ".tgz" {
				return "tar.gz", nil
			}
			return "gz", nil
		case ".bz2":
			if strings.HasSuffix(strings.ToLower(filename), ".tar.bz2") || ext == ".tbz2" {
				return "tar.bz2", nil
			}
			return "bz2", nil
		case ".xz":
			if strings.HasSuffix(strings.ToLower(filename), ".tar.xz") || ext == ".txz" {
				return "tar.xz", nil
			}
			return "xz", nil
		case ".tgz":
			return "tar.gz", nil
		case ".tbz2":
			return "tar.bz2", nil
		case ".txz":
			return "tar.xz", nil
		default:
			return "", fmt.Errorf("unknown format")
		}
	}
}

func calculateZipUncompressedSize(filename string) (int64, error) {
	reader, err := zip.OpenReader(filename)
	if err != nil {
		return 0, err
	}
	defer reader.Close()

	var totalSize int64
	for _, file := range reader.File {
		if !file.FileInfo().IsDir() {
			totalSize += int64(file.UncompressedSize64)
		}
	}
	return totalSize, nil
}

func extractZipWithProgress(filename, outputDir string, bar *progressbar.ProgressBar) error {
	if config.Password != "" {
		return extractPasswordZipWithProgress(filename, outputDir, config.Password, bar)
	}

	reader, err := zip.OpenReader(filename)
	if err != nil {
		return err
	}
	defer reader.Close()

	for _, file := range reader.File {
		if strings.Contains(file.Name, "..") {
			return fmt.Errorf("invalid file path: %s", file.Name)
		}

		path := filepath.Join(outputDir, file.Name)

		if file.FileInfo().IsDir() {
			os.MkdirAll(path, file.FileInfo().Mode())
			continue
		}

		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return err
		}

		fileReader, err := file.Open()
		if err != nil {
			return err
		}
		defer fileReader.Close()

		targetFile, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.FileInfo().Mode())
		if err != nil {
			return err
		}
		defer targetFile.Close()

		if bar != nil {
			progressReader := progressbar.NewReader(fileReader, bar)
			_, err = io.Copy(targetFile, &progressReader)
		} else {
			_, err = io.Copy(targetFile, fileReader)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func extractPasswordZipWithProgress(filename, outputDir, password string, bar *progressbar.ProgressBar) error {
	reader, err := passwordzip.OpenReader(filename)
	if err != nil {
		return err
	}
	defer reader.Close()

	for _, file := range reader.File {
		if strings.Contains(file.Name, "..") {
			return fmt.Errorf("invalid file path: %s", file.Name)
		}

		path := filepath.Join(outputDir, file.Name)

		if file.FileInfo().IsDir() {
			os.MkdirAll(path, file.FileInfo().Mode())
			continue
		}

		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return err
		}

		file.SetPassword(password)
		fileReader, err := file.Open()
		if err != nil {
			return fmt.Errorf("failed to open file with password: %w", err)
		}
		defer fileReader.Close()

		targetFile, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.FileInfo().Mode())
		if err != nil {
			return err
		}
		defer targetFile.Close()

		if bar != nil {
			progressReader := progressbar.NewReader(fileReader, bar)
			_, err = io.Copy(targetFile, &progressReader)
		} else {
			_, err = io.Copy(targetFile, fileReader)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func extractZip(filename, outputDir string) error {
	if config.Password != "" {
		return extractPasswordZip(filename, outputDir, config.Password)
	}

	reader, err := zip.OpenReader(filename)
	if err != nil {
		return err
	}
	defer reader.Close()

	for _, file := range reader.File {
		if strings.Contains(file.Name, "..") {
			return fmt.Errorf("invalid file path: %s", file.Name)
		}

		path := filepath.Join(outputDir, file.Name)

		if file.FileInfo().IsDir() {
			os.MkdirAll(path, file.FileInfo().Mode())
			continue
		}

		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return err
		}

		fileReader, err := file.Open()
		if err != nil {
			return err
		}
		defer fileReader.Close()

		targetFile, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.FileInfo().Mode())
		if err != nil {
			return err
		}
		defer targetFile.Close()

		_, err = io.Copy(targetFile, fileReader)
		if err != nil {
			return err
		}
	}
	return nil
}

func extractPasswordZip(filename, outputDir, password string) error {
	reader, err := passwordzip.OpenReader(filename)
	if err != nil {
		return err
	}
	defer reader.Close()

	for _, file := range reader.File {
		if strings.Contains(file.Name, "..") {
			return fmt.Errorf("invalid file path: %s", file.Name)
		}

		path := filepath.Join(outputDir, file.Name)

		if file.FileInfo().IsDir() {
			os.MkdirAll(path, file.FileInfo().Mode())
			continue
		}

		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return err
		}

		file.SetPassword(password)
		fileReader, err := file.Open()
		if err != nil {
			return fmt.Errorf("failed to open file with password: %w", err)
		}
		defer fileReader.Close()

		targetFile, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.FileInfo().Mode())
		if err != nil {
			return err
		}
		defer targetFile.Close()

		_, err = io.Copy(targetFile, fileReader)
		if err != nil {
			return err
		}
	}
	return nil
}

func extractTar(reader io.Reader, outputDir string) error {
	tarReader := tar.NewReader(reader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		if strings.Contains(header.Name, "..") {
			return fmt.Errorf("invalid file path: %s", header.Name)
		}

		path := filepath.Join(outputDir, header.Name)

		info := header.FileInfo()
		if info.IsDir() {
			if err := os.MkdirAll(path, info.Mode()); err != nil {
				return err
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return err
		}

		file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, info.Mode())
		if err != nil {
			return err
		}
		defer file.Close()

		_, err = io.Copy(file, tarReader)
		if err != nil {
			return err
		}
	}
	return nil
}

func extractTarGz(reader io.Reader, outputDir string) error {
	gzReader, err := gzip.NewReader(reader)
	if err != nil {
		return err
	}
	defer gzReader.Close()

	return extractTar(gzReader, outputDir)
}

func extractTarBz2(reader io.Reader, outputDir string) error {
	bz2Reader := bzip2.NewReader(reader)
	return extractTar(bz2Reader, outputDir)
}

func extractTarXz(reader io.Reader, outputDir string) error {
	xzReader, err := xz.NewReader(reader)
	if err != nil {
		return err
	}
	return extractTar(xzReader, outputDir)
}

func extractGz(reader io.Reader, filename, outputDir string) error {
	gzReader, err := gzip.NewReader(reader)
	if err != nil {
		return err
	}
	defer gzReader.Close()

	outputFile := strings.TrimSuffix(filepath.Base(filename), ".gz")
	outputPath := filepath.Join(outputDir, outputFile)

	file, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = io.Copy(file, gzReader)
	return err
}

func extractBz2(reader io.Reader, filename, outputDir string) error {
	bz2Reader := bzip2.NewReader(reader)

	outputFile := strings.TrimSuffix(filepath.Base(filename), ".bz2")
	outputPath := filepath.Join(outputDir, outputFile)

	file, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = io.Copy(file, bz2Reader)
	return err
}

func extractXz(reader io.Reader, filename, outputDir string) error {
	xzReader, err := xz.NewReader(reader)
	if err != nil {
		return err
	}

	outputFile := strings.TrimSuffix(filepath.Base(filename), ".xz")
	outputPath := filepath.Join(outputDir, outputFile)

	file, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = io.Copy(file, xzReader)
	return err
}

func compressFiles(files []string) {
	if config.Verbose {
		fmt.Printf("Creating %s archive: %s\n", config.CompressType, config.OutputFile)
	}

	// Calculate total size for progress bar
	var totalSize int64
	if config.Progress && !config.Verbose {
		totalSize = calculateTotalSize(files)
	}

	// Create progress bar if enabled and not in verbose mode
	var bar *progressbar.ProgressBar
	if config.Progress && !config.Verbose && totalSize > 0 {
		bar = progressbar.DefaultBytes(
			totalSize,
			fmt.Sprintf("Creating %s", config.OutputFile),
		)
	}

	var err error
	switch strings.ToLower(config.CompressType) {
	case "zip":
		err = compressZip(files, config.OutputFile, bar)
	case "tar":
		err = compressTar(files, config.OutputFile, bar)
	case "tar.gz", "tgz":
		err = compressTarGz(files, config.OutputFile, bar)
	case "tar.bz2", "tbz2":
		err = compressTarBz2(files, config.OutputFile, bar)
	case "tar.xz", "txz":
		err = compressTarXz(files, config.OutputFile, bar)
	default:
		fmt.Fprintf(os.Stderr, "Error: Unsupported compression type: %s\n", config.CompressType)
		fmt.Fprintf(os.Stderr, "Supported types: zip, tar, tar.gz, tar.bz2, tar.xz\n")
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating archive: %v\n", err)
		os.Exit(1)
	}

	if config.Verbose {
		fmt.Printf("Successfully created: %s\n", config.OutputFile)
	}

	if !config.KeepSource {
		for _, file := range files {
			if err := removeFileOrDir(file); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Could not remove source %s: %v\n", file, err)
			}
		}
	}
}

func removeFileOrDir(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return os.RemoveAll(path)
	}
	return os.Remove(path)
}

func calculateTotalSize(files []string) int64 {
	var totalSize int64
	for _, file := range files {
		size := calculateDirSize(file)
		totalSize += size
	}
	return totalSize
}

func calculateDirSize(path string) int64 {
	var size int64
	filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	return size
}

func compressZip(files []string, outputFile string, bar *progressbar.ProgressBar) error {
	if config.Password != "" {
		return compressPasswordZip(files, outputFile, config.Password, bar)
	}

	zipFile, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer zipFile.Close()

	writer := zip.NewWriter(zipFile)
	defer writer.Close()

	for _, file := range files {
		if err := addToZip(writer, file, "", bar); err != nil {
			return err
		}
	}
	return nil
}

func compressPasswordZip(files []string, outputFile, password string, bar *progressbar.ProgressBar) error {
	zipFile, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer zipFile.Close()

	writer := passwordzip.NewWriter(zipFile)
	defer writer.Close()

	for _, file := range files {
		if err := addToPasswordZip(writer, file, "", password, bar); err != nil {
			return err
		}
	}
	return nil
}

func addToZip(writer *zip.Writer, filePath, baseInZip string, bar *progressbar.ProgressBar) error {
	info, err := os.Stat(filePath)
	if err != nil {
		return err
	}

	if info.IsDir() {
		entries, err := os.ReadDir(filePath)
		if err != nil {
			return err
		}

		var newBaseInZip string
		if baseInZip == "" {
			newBaseInZip = filepath.Base(filePath)
		} else {
			newBaseInZip = filepath.Join(baseInZip, filepath.Base(filePath))
		}

		for _, entry := range entries {
			path := filepath.Join(filePath, entry.Name())
			if err := addToZip(writer, path, newBaseInZip, bar); err != nil {
				return err
			}
		}
		return nil
	}

	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	var zipPath string
	if baseInZip == "" {
		zipPath = filepath.Base(filePath)
	} else {
		zipPath = filepath.Join(baseInZip, filepath.Base(filePath))
	}

	fileInZip, err := writer.Create(zipPath)
	if err != nil {
		return err
	}

	if bar != nil {
		progressReader := progressbar.NewReader(file, bar)
		_, err = io.Copy(fileInZip, &progressReader)
	} else {
		_, err = io.Copy(fileInZip, file)
	}
	return err
}

func addToPasswordZip(writer *passwordzip.Writer, filePath, baseInZip, password string, bar *progressbar.ProgressBar) error {
	info, err := os.Stat(filePath)
	if err != nil {
		return err
	}

	if info.IsDir() {
		entries, err := os.ReadDir(filePath)
		if err != nil {
			return err
		}

		var newBaseInZip string
		if baseInZip == "" {
			newBaseInZip = filepath.Base(filePath)
		} else {
			newBaseInZip = filepath.Join(baseInZip, filepath.Base(filePath))
		}

		for _, entry := range entries {
			path := filepath.Join(filePath, entry.Name())
			if err := addToPasswordZip(writer, path, newBaseInZip, password, bar); err != nil {
				return err
			}
		}
		return nil
	}

	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	var zipPath string
	if baseInZip == "" {
		zipPath = filepath.Base(filePath)
	} else {
		zipPath = filepath.Join(baseInZip, filepath.Base(filePath))
	}

	fileInZip, err := writer.Encrypt(zipPath, password, passwordzip.AES256Encryption)
	if err != nil {
		return err
	}

	if bar != nil {
		progressReader := progressbar.NewReader(file, bar)
		_, err = io.Copy(fileInZip, &progressReader)
	} else {
		_, err = io.Copy(fileInZip, file)
	}
	return err
}

func compressTar(files []string, outputFile string, bar *progressbar.ProgressBar) error {
	tarFile, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer tarFile.Close()

	writer := tar.NewWriter(tarFile)
	defer writer.Close()

	for _, file := range files {
		if err := addToTar(writer, file, "", bar); err != nil {
			return err
		}
	}
	return nil
}

func addToTar(writer *tar.Writer, filePath, baseInTar string, bar *progressbar.ProgressBar) error {
	info, err := os.Stat(filePath)
	if err != nil {
		return err
	}

	var tarPath string
	if baseInTar == "" {
		tarPath = filepath.Base(filePath)
	} else {
		tarPath = filepath.Join(baseInTar, filepath.Base(filePath))
	}

	header := &tar.Header{
		Name:    tarPath,
		Size:    info.Size(),
		Mode:    int64(info.Mode().Perm()), // Only preserve permission bits, not file type bits
		ModTime: info.ModTime(),
	}

	if info.IsDir() {
		header.Typeflag = tar.TypeDir
		if err := writer.WriteHeader(header); err != nil {
			return err
		}

		entries, err := os.ReadDir(filePath)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			path := filepath.Join(filePath, entry.Name())
			newBaseInTar := tarPath // 使用tarPath而不是重复添加filepath.Base(filePath)
			if err := addToTar(writer, path, newBaseInTar, bar); err != nil {
				return err
			}
		}
		return nil
	}

	header.Typeflag = tar.TypeReg
	if err := writer.WriteHeader(header); err != nil {
		return err
	}

	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	if bar != nil {
		progressReader := progressbar.NewReader(file, bar)
		_, err = io.Copy(writer, &progressReader)
	} else {
		_, err = io.Copy(writer, file)
	}
	return err
}

func compressTarGz(files []string, outputFile string, bar *progressbar.ProgressBar) error {
	tarGzFile, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer tarGzFile.Close()

	gzWriter := gzip.NewWriter(tarGzFile)
	defer gzWriter.Close()

	tarWriter := tar.NewWriter(gzWriter)
	defer tarWriter.Close()

	for _, file := range files {
		if err := addToTar(tarWriter, file, "", bar); err != nil {
			return err
		}
	}
	return nil
}

func compressTarBz2(files []string, outputFile string, bar *progressbar.ProgressBar) error {
	tarBz2File, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer tarBz2File.Close()

	bz2Writer, err := bzip2_compress.NewWriter(tarBz2File, &bzip2_compress.WriterConfig{
		Level: bzip2_compress.DefaultCompression,
	})
	if err != nil {
		return err
	}
	defer bz2Writer.Close()

	tarWriter := tar.NewWriter(bz2Writer)
	defer tarWriter.Close()

	for _, file := range files {
		if err := addToTar(tarWriter, file, "", bar); err != nil {
			return err
		}
	}
	return nil
}

func compressTarXz(files []string, outputFile string, bar *progressbar.ProgressBar) error {
	tarXzFile, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer tarXzFile.Close()

	xzWriter, err := xz.NewWriter(tarXzFile)
	if err != nil {
		return err
	}
	defer xzWriter.Close()

	tarWriter := tar.NewWriter(xzWriter)
	defer tarWriter.Close()

	for _, file := range files {
		if err := addToTar(tarWriter, file, "", bar); err != nil {
			return err
		}
	}
	return nil
}
