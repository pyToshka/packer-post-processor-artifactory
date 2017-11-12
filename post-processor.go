package main

import (
    "fmt"
    "log"
    "net/http"
    "os"
    "crypto/sha256"
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
)

type Config struct {
    BoxName             string `mapstructure:"box_name"`
    BoxDir              string `mapstructure:"box_dir"`
    BoxProvider         string `mapstructure:"box_provider"`
    Version             string `mapstructure:"version"`
    BlobURL             string `mapstructure:"url"`
    Repo                string `mapstructure:"repo"`
    AuthKey             string `mapstructure:"key"`
    common.PackerConfig `mapstructure:",squash"`

    ctx interpolate.Context
}

type PostProcessor struct {
    config     Config
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
        "url":             &p.config.BlobURL,

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
        if artifact.BuilderId() != "mitchellh.post-processor.vagrant" {
            return nil, false, fmt.Errorf("Unknown artifact type, requires box from vagrant post-processor: %s", artifact.BuilderId())
        }
        box := artifact.Files()[0]
        if !strings.HasSuffix(box, ".box") {
            return nil, false, fmt.Errorf("Unknown files in artifact from vagrant post-processor: %s", artifact.Files())
        }

        provider := providerFromBuilderName(artifact.Id())
        ui.Say(fmt.Sprintf("Preparing to upload box for '%s' provider to Artifactory repositories '%s'/'%s'", provider,p.config.BlobURL,p.config.Repo))

        // determine box size
        boxStat, err := os.Stat(box)
        if err != nil {
            return nil, false, err
        }

        // determine version
        version := p.config.Version

        ui.Message(fmt.Sprintf("Box to upload: %s (%d bytes) Version: %s", box, boxStat.Size(), version))

        ui.Message("Generating checksum")
        checksum, err := sum256(box)
        if err != nil {
            return nil, false, err
        }
        ui.Message(fmt.Sprintf("Checksum is %s", checksum))

        //upload the box to artifactory
        err = p.uploadBox(box, ui, checksum)

        if err != nil {
            return nil, false, err
        }
        return nil, true, nil
    }




    func (p *PostProcessor) uploadBox(box string, ui packer.Ui, checkSum string) error {
        // open the file for reading
        file, err := os.Open(box)
        if err != nil {
            return err
        }

        defer file.Close()
        importRepo :=p.config.BlobURL
        AuthKey :=p.config.AuthKey
        repo :=p.config.Repo
        if err != nil {
            return err
        }

        if importRepo == "" {
            importRepo = fmt.Sprintf("http://localhost:8080/'%s'/'%s'", repo, box)
        }else{
            importRepo=fmt.Sprintf("%s/%s/%s/%s-%s-%s.box" +";box_name=%s;box_provider=%s;box_version=%s", importReo, repo, p.config.BoxName, p.config.BoxName, p.config.BoxProvider, p.config.Version, p.config.BoxName, p.config.BoxProvider, p.config.Version)
        }

        ui.Message(importRepo)

        if err != nil {
            log.Fatal(err)
        }
        defer file.Close()
        resp, err := http.NewRequest("PUT", importRepo, file)
        resp.Header.Set("X-JFrog-Art-Api", AuthKey)
        resp.Header.Set("X-Checksum-Sha256", checkSum)
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

        if(res.StatusCode != 201) {
            return errors.New("Error uploading File")
        }
        
        return err
    }




    // calculates a sha256 checksum of the file
    func sum256(filePath string) (string, error) {
        // open the file for reading
        file, err := os.Open(filePath)

        if err != nil {
            return "", err
        }

        defer file.Close()

        h := sha256.New()
        if _, err := io.Copy(h, file); err != nil {
            return "", err
        }
        return hex.EncodeToString(h.Sum(nil)), nil
    }

    // converts a packer builder name to the corresponding vagrant provider
    func providerFromBuilderName(name string) string {
        switch name {
        case "aws":
            return "aws"
        case "digitalocean":
            return "digitalocean"
        case "virtualbox":
            return "virtualbox"
        case "vmware":
            return "vmware_desktop"
        case "parallels":
            return "parallels"
        default:
            return name
        }
    }
