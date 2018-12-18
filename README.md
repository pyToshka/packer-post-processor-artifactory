Packer post-processor. This post-processor can help you to upload you Vagrant box to Jfrog Artifactory. 

Building
```
cd $GOPATH/src
clone repos
go build  -o packer-post-processor-artifactory
$ mkdir $HOME/.packer.d/plugins
$ cp $GOPATH/bin/packer-post-processor-artifactory $HOME/.packer.d/plugins


```
or 
```
go get github.com/pyToshka/packer-post-processor-artifactory
```

Usage

```
"post-processors": [[
    {
      "type": "vagrant"
    },
    {
      "type":"artifactory",
      "url": "http://localhost:8080/artifactory",
      "repo": "repo-name",
      "key": "artifactory-key"

    }]
  ]
```
Automation step-by-step

```git
git clone https://github.com/pyToshka/packer-post-processor-artifactory
vi example/packer.json
Change url,repo name and key for artifactory 
run 

buid.sh
```
After building you get Ubuntu 16.04 Vagrant box, and post processor will  uploaded it to your artifactory server.

I written it Just for Fun :)

