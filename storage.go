package storage

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/leads-su/logger"
)

// Storage represents storage manager configuration structure
type Storage struct {
	workingDirectory string
}

// Options represents storage manager options structure
type Options struct {
	WorkingDirectory string
}

// NewStorage creates new instance of storage manager
func NewStorage(options Options) *Storage {
	storage := &Storage{
		workingDirectory: options.WorkingDirectory,
	}

	return storage
}

// Exists will return true if given path exists
func (storage *Storage) Exists(path string) bool {
	if _, err := os.Stat(path); err == nil {
		return true
	}
	return false
}

// Size get size of the file
func (storage *Storage) Size(path string) (int64, error) {
	fileStat, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return fileStat.Size(), nil
}

// CreateDirectory creates directories recursively if they do not exist
func (storage *Storage) CreateDirectory(path string) error {
	directoryName := filepath.Dir(path)
	if !storage.Exists(directoryName) {
		return os.MkdirAll(directoryName, os.ModePerm)
	}
	return nil
}

// CreateFile creates new file or returns error if something went wrong
func (storage *Storage) CreateFile(path string) error {
	if err := storage.CreateDirectory(path); err != nil {
		return err
	}

	if !storage.Exists(path) {
		fileHandle, err := os.Create(path)
		if err != nil {
			logger.Errorf("storage", "failed to create new file - %s", err.Error())
			return err
		}
		err = fileHandle.Close()
		if err != nil {
			logger.Errorf("storage", "failed to close file handle - %s", err.Error())
			return err
		}
	}
	return nil
}

// DeleteFile delete specified file
func (storage *Storage) DeleteFile(path string) error {
	if !storage.Exists(path) {
		return fmt.Errorf("`%s` does not exists", path)
	}
	return os.Remove(path)
}

// CopyFile copies file from one place to another
func (storage *Storage) CopyFile(sourcePath, destinationPath string, permissions fs.FileMode) (bool, error) {
	err := storage.CreateDirectory(destinationPath)
	if err != nil {
		return false, err
	}

	source, err := ioutil.ReadFile(sourcePath)
	if err != nil {
		return false, err
	}

	err = ioutil.WriteFile(destinationPath, source, permissions)
	if err != nil {
		return false, err
	}
	return true, nil
}

// MoveFile moves file from one place to another
func (storage *Storage) MoveFile(sourcePath, destinationPath string) error {
	return os.Rename(sourcePath, destinationPath)
}

// ComputeFileHash computes SHA256 hash for a given file
func (storage *Storage) ComputeFileHash(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// CompareFileHash compare given file hash with hash of specified file
func (storage *Storage) CompareFileHash(path string, hash string) (bool, error) {
	fileHash, err := storage.ComputeFileHash(path)
	if err != nil {
		return false, err
	}
	return fileHash == hash, nil
}

// ReadFileToBytesArray reads file to bytes array
func (storage *Storage) ReadFileToBytesArray(path string) ([]byte, error) {
	return ioutil.ReadFile(path)
}

// WriteBytesArrayToFile writes array of bytes to file
func (storage *Storage) WriteBytesArrayToFile(path string, contents []byte, permissions fs.FileMode) error {
	err := storage.CreateFile(path)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(path, contents, permissions)
}

// AppendBytesArrayToFile allows to append array of bytes to specified file
func (storage *Storage) AppendBytesArrayToFile(path string, contents []byte, permissions fs.FileMode) error {
	err := storage.CreateFile(path)
	if err != nil {
		return err
	}
	handle, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, permissions)
	if err != nil {
		return err
	}
	defer handle.Close()
	if _, err = handle.Write(contents); err != nil {
		return err
	}
	return nil
}

// ReadFileToStringsArray reads file line by line into array of strings
func (storage *Storage) ReadFileToStringsArray(path string) ([]string, error) {
	var lines []string

	reader, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return lines, nil

}

// WriteStringsArrayToFile writes array of strings to file
func (storage *Storage) WriteStringsArrayToFile(path string, contents []string, flags int, permissions fs.FileMode) error {
	err := storage.CreateFile(path)
	if err != nil {
		return err
	}

	file, err := os.OpenFile(path, flags, permissions)
	if err != nil {
		return err
	}

	dataWriter := bufio.NewWriter(file)

	for _, line := range contents {
		_, err := dataWriter.WriteString(line + "\n")
		if err != nil {
			return err
		}
	}

	if err = dataWriter.Flush(); err != nil {
		return err
	}

	if err = file.Close(); err != nil {
		return err
	}

	return nil
}

// AppendStringsArrayToFile allows to append array of strings to specified file
func (storage *Storage) AppendStringsArrayToFile(path string, contents []string, permissions fs.FileMode) error {
	err := storage.CreateFile(path)
	if err != nil {
		return err
	}
	handle, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, permissions)
	if err != nil {
		return err
	}
	defer handle.Close()

	for _, value := range contents {
		if _, err = handle.WriteString(value); err != nil {
			return err
		}
	}

	return nil
}

// AbsolutePath returns absolute path for given `path` and working directory
func (storage *Storage) AbsolutePath(path string) string {
	return fmt.Sprintf(
		"%s%s%s",
		storage.workingDirectory,
		string(os.PathSeparator),
		path,
	)
}

// AbsoluteTempPath returns absolute `path` path inside temporary directory
func (storage *Storage) AbsoluteTempPath(path string) string {
	return fmt.Sprintf(
		"%s%s%s",
		os.TempDir(),
		string(os.PathSeparator),
		path,
	)
}
