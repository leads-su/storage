<!-- Code generated by gomarkdoc. DO NOT EDIT -->

# storage

```go
import "github.com/leads-su/storage"
```

## Index

- [type Options](<#type-options>)
- [type Storage](<#type-storage>)
  - [func NewStorage(options Options) *Storage](<#func-newstorage>)
  - [func (storage *Storage) AbsolutePath(path string) string](<#func-storage-absolutepath>)
  - [func (storage *Storage) AbsoluteTempPath(path string) string](<#func-storage-absolutetemppath>)
  - [func (storage *Storage) CompareFileHash(path string, hash string) (bool, error)](<#func-storage-comparefilehash>)
  - [func (storage *Storage) ComputeFileHash(path string) (string, error)](<#func-storage-computefilehash>)
  - [func (storage *Storage) CopyFile(sourcePath, destinationPath string, permissions fs.FileMode) (bool, error)](<#func-storage-copyfile>)
  - [func (storage *Storage) CreateDirectory(path string) error](<#func-storage-createdirectory>)
  - [func (storage *Storage) CreateFile(path string) error](<#func-storage-createfile>)
  - [func (storage *Storage) DeleteFile(path string) error](<#func-storage-deletefile>)
  - [func (storage *Storage) Exists(path string) bool](<#func-storage-exists>)
  - [func (storage *Storage) MoveFile(sourcePath, destinationPath string) error](<#func-storage-movefile>)
  - [func (storage *Storage) ReadFileToBytesArray(path string) ([]byte, error)](<#func-storage-readfiletobytesarray>)
  - [func (storage *Storage) ReadFileToStringsArray(path string) ([]string, error)](<#func-storage-readfiletostringsarray>)
  - [func (storage *Storage) Size(path string) (int64, error)](<#func-storage-size>)
  - [func (storage *Storage) WriteBytesArrayToFile(path string, contents []byte, permissions fs.FileMode) error](<#func-storage-writebytesarraytofile>)
  - [func (storage *Storage) WriteStringsArrayToFile(path string, contents []string, flags int, permissions fs.FileMode) error](<#func-storage-writestringsarraytofile>)


## type Options

Options represents storage manager options structure

```go
type Options struct {
    WorkingDirectory string
}
```

## type Storage

Storage represents storage manager configuration structure

```go
type Storage struct {
    // contains filtered or unexported fields
}
```

### func NewStorage

```go
func NewStorage(options Options) *Storage
```

NewStorage creates new instance of storage manager

### func \(\*Storage\) AbsolutePath

```go
func (storage *Storage) AbsolutePath(path string) string
```

AbsolutePath returns absolute path for given \`path\` and working directory

### func \(\*Storage\) AbsoluteTempPath

```go
func (storage *Storage) AbsoluteTempPath(path string) string
```

AbsoluteTempPath returns absolute \`path\` path inside temporary directory

### func \(\*Storage\) CompareFileHash

```go
func (storage *Storage) CompareFileHash(path string, hash string) (bool, error)
```

CompareFileHash compare given file hash with hash of specified file

### func \(\*Storage\) ComputeFileHash

```go
func (storage *Storage) ComputeFileHash(path string) (string, error)
```

ComputeFileHash computes SHA256 hash for a given file

### func \(\*Storage\) CopyFile

```go
func (storage *Storage) CopyFile(sourcePath, destinationPath string, permissions fs.FileMode) (bool, error)
```

CopyFile copies file from one place to another

### func \(\*Storage\) CreateDirectory

```go
func (storage *Storage) CreateDirectory(path string) error
```

CreateDirectory creates directories recursively if they do not exist

### func \(\*Storage\) CreateFile

```go
func (storage *Storage) CreateFile(path string) error
```

CreateFile creates new file or returns error if something went wrong

### func \(\*Storage\) DeleteFile

```go
func (storage *Storage) DeleteFile(path string) error
```

DeleteFile delete specified file

### func \(\*Storage\) Exists

```go
func (storage *Storage) Exists(path string) bool
```

Exists will return true if given path exists

### func \(\*Storage\) MoveFile

```go
func (storage *Storage) MoveFile(sourcePath, destinationPath string) error
```

MoveFile moves file from one place to another

### func \(\*Storage\) ReadFileToBytesArray

```go
func (storage *Storage) ReadFileToBytesArray(path string) ([]byte, error)
```

ReadFileToBytesArray reads file to bytes array

### func \(\*Storage\) ReadFileToStringsArray

```go
func (storage *Storage) ReadFileToStringsArray(path string) ([]string, error)
```

ReadFileToStringsArray reads file line by line into array of strings

### func \(\*Storage\) Size

```go
func (storage *Storage) Size(path string) (int64, error)
```

Size get size of the file

### func \(\*Storage\) WriteBytesArrayToFile

```go
func (storage *Storage) WriteBytesArrayToFile(path string, contents []byte, permissions fs.FileMode) error
```

WriteBytesArrayToFile writes array of bytes to file

### func \(\*Storage\) WriteStringsArrayToFile

```go
func (storage *Storage) WriteStringsArrayToFile(path string, contents []string, flags int, permissions fs.FileMode) error
```

WriteStringsArrayToFile writes array of strings to file
