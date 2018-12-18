package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/md5"
	"io"
	"bufio"
	"encoding/hex"
	"github.com/hashicorp/packer/common"
	"github.com/hashicorp/packer/helper/config"
	"github.com/hashicorp/packer/packer"
	"github.com/hashicorp/packer/template/interpolate"
	"strings"
	"bytes"
	"errors"
	"crypto/sha512"
)

type Config struct {
	BoxName     string  `mapstructure:"box_name"`
	BoxDir      string  `mapstructure:"box_dir"`
	BoxProvider string  `mapstructure:"box_provider"`
	Version     string  `mapstructure:"version"`
	BlobURL     string  `mapstructure:"url"`
	Repo        string  `mapstructure:"repo"`
	AuthKey     string  `mapstructure:"key"`
	common.PackerConfig `mapstructure:",squash"`

	ctx interpolate.Context
}

type PostProcessor struct {
	config Config
}

func (p *PostProcessor) Configure(raws ...interface{}) error {
	err := config.Decode(&p.config, &config.DecodeOpts{
		Interpolate:        true,
		InterpolateContext: &p.config.ctx,
		InterpolateFilter: &interpolate.RenderFilter{
			Exclude: []string{"output"},
		},
	}, raws...)
	if err != nil {
		return err
	}

	errs := new(packer.MultiError)

	// required configuration
	templates := map[string]*string{
		"url": &p.config.BlobURL,
	}

	for key, ptr := range templates {
		if *ptr == "" {
			errs = packer.MultiErrorAppend(errs, fmt.Errorf("Artifactory plugin %s must be set", key))
		}
	}

	// Template process
	for key, ptr := range templates {
		if err = interpolate.Validate(*ptr, &p.config.ctx); err != nil {
			errs = packer.MultiErrorAppend(
				errs, fmt.Errorf("Error parsing %s template: %s", key, err))
		}
	}
	if len(errs.Errors) > 0 {
		return errs
	}

	return nil
}

func (p *PostProcessor) PostProcess(ui packer.Ui, artifact packer.Artifact) (packer.Artifact, bool, error) {
	if artifact.BuilderId() != "mitchellh.virtualbox" {
		return nil, false, fmt.Errorf("Unknown artifact type, requires box from vagrant post-processor: %s", artifact.BuilderId())
	}
	box := artifact.Files()[0]
	if !strings.HasSuffix(box, ".box") {
		return nil, false, fmt.Errorf("Unknown files in artifact from vagrant post-processor: %s", artifact.Files())
	}

	provider := providerFromBuilderName(artifact.Id())
	ui.Say(fmt.Sprintf("Preparing to upload box for '%s' provider to Artifactory repositories '%s'/'%s'", provider, p.config.BlobURL, p.config.Repo))

	// determine box size
	boxStat, err := os.Stat(box)
	if err != nil {
		return nil, false, err
	}

	// determine version
	version := p.config.Version

	ui.Message(fmt.Sprintf("Box to upload: %s (%d bytes) Version: %s", box, boxStat.Size(), version))

	ui.Message("Generating checksums")


	f, err := os.OpenFile(box, os.O_RDONLY, 0)
	if err != nil {
		log.Fatalln("Cannot open file: %s", box)
	}
	defer f.Close()
	info := CalculateBasicHashes(f)

	ui.Message(fmt.Sprintf("md5    :", info.Md5))
	ui.Message(fmt.Sprintf("sha1   :", info.Sha1))
	ui.Message(fmt.Sprintf("sha256 :", info.Sha256))
	ui.Message(fmt.Sprintf("sha512 :", info.Sha512))

	//upload the box to artifactory
	err = p.uploadBox(box, ui, info)

	if err != nil {
		return nil, false, err
	}
	return nil, true, nil
}

func (p *PostProcessor) uploadBox(box string, ui packer.Ui, hashInfo HashInfo) error {
	// open the file for reading
	file, err := os.Open(box)
	if err != nil {
		return err
	}

	defer file.Close()
	importRepo := p.config.BlobURL
	AuthKey := p.config.AuthKey
	repo := p.config.Repo
	if err != nil {
		return err
	}

	if importRepo == "" {
		importRepo = fmt.Sprintf("http://localhost:8080/'%s'/'%s'", repo, box)
	} else {
		importRepo = fmt.Sprintf("%s/%s/%s/%s-%s-%s.box"+";box_name=%s;box_provider=%s;box_version=%s", importRepo, repo, p.config.BoxDir, p.config.BoxName, p.config.BoxProvider, p.config.Version, p.config.BoxName, p.config.BoxProvider, p.config.Version)
	}

	ui.Message(importRepo)

	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	resp, err := http.NewRequest("PUT", importRepo, file)
	resp.Header.Set("X-JFrog-Art-Api", AuthKey)
	resp.Header.Set("X-Checksum-Sha1", hashInfo.Sha1)
	resp.Header.Set("X-Checksum-Sha256", hashInfo.Sha256)
	resp.Header.Set("X-Checksum-Md5", hashInfo.Md5)
	if err != nil {
		log.Fatal(err)
	}
	resp.Header.Set("Content-Type", "text/plain")

	client := &http.Client{}
	res, err := client.Do(resp)
	if err != nil {
		log.Fatal(err)
	}
	defer res.Body.Close()

	scanner := bufio.NewScanner(res.Body)
	scanner.Split(bufio.ScanBytes)
	var buffer bytes.Buffer
	for scanner.Scan() {
		buffer.WriteString(scanner.Text())
	}
	ui.Message(buffer.String())

	if (res.StatusCode != 201) {
		return errors.New("Error uploading File")
	}
	return err
}

type HashInfo struct {
	Md5    string `json:"md5"`
	Sha1   string `json:"sha1"`
	Sha256 string `json:"sha256"`
	Sha512 string `json:"sha512"`
}

func CalculateBasicHashes(rd io.Reader) HashInfo {

	hMd5 := md5.New()
	hSha1 := sha1.New()
	hSha256 := sha256.New()
	hSha512 := sha512.New()

	// For optimum speed, Getpagesize returns the underlying system's memory page size.
	pagesize := os.Getpagesize()

	// wraps the Reader object into a new buffered reader to read the files in chunks
	// and buffering them for performance.
	reader := bufio.NewReaderSize(rd, pagesize)

	// creates a multiplexer Writer object that will duplicate all write
	// operations when copying data from source into all different hashing algorithms
	// at the same time
	multiWriter := io.MultiWriter(hMd5, hSha1, hSha256, hSha512)

	// Using a buffered reader, this will write to the writer multiplexer
	// so we only traverse through the file once, and can calculate all hashes
	// in a single byte buffered scan pass.
	//
	_, err := io.Copy(multiWriter, reader)
	if err != nil {
		panic(err.Error())
	}

	var info HashInfo

	info.Md5 = hex.EncodeToString(hMd5.Sum(nil))
	info.Sha1 = hex.EncodeToString(hSha1.Sum(nil))
	info.Sha256 = hex.EncodeToString(hSha256.Sum(nil))
	info.Sha512 = hex.EncodeToString(hSha512.Sum(nil))

	return info
}

// converts a packer builder name to the corresponding vagrant provider
func providerFromBuilderName(name string) string {
	switch name {
	case "vmware":
		return "vmware_desktop"
	default:
		return name
	}
}
