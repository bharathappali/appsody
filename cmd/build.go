// Copyright © 2019 IBM Corporation and others.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

type buildCommandConfig struct {
	*RootCommandConfig
	tag                string
	dockerBuildOptions string
	criu			   bool
}

func checkDockerBuildOptions(options []string) error {
	buildOptionsTest := "(^((-t)|(--tag)|(-f)|(--file))((=?$)|(=.*)))"

	blackListedBuildOptionsRegexp := regexp.MustCompile(buildOptionsTest)
	for _, value := range options {
		isInBlackListed := blackListedBuildOptionsRegexp.MatchString(value)
		if isInBlackListed {
			return errors.Errorf("%s is not allowed in --docker-options", value)

		}
	}
	return nil

}

func newBuildCmd(rootConfig *RootCommandConfig) *cobra.Command {
	config := &buildCommandConfig{RootCommandConfig: rootConfig}
	// buildCmd provides the ability run local builds, or setup/delete Tekton builds, for an appsody project
	var buildCmd = &cobra.Command{
		Use:   "build",
		Short: "Locally build a docker image of your appsody project",
		Long:  `This allows you to build a local Docker image from your Appsody project. Extract is run before the docker build.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return build(config)
		},
	}

	buildCmd.PersistentFlags().StringVarP(&config.tag, "tag", "t", "", "Docker image name testing and optionally a tag in the 'name:tag' format")
	buildCmd.PersistentFlags().StringVar(&config.dockerBuildOptions, "docker-options", "", "Specify the docker build options to use.  Value must be in \"\".")
	buildCmd.PersistentFlags().BoolVar(&config.criu, "criu", false, "Makes appsody to build a startup optimized image")

	buildCmd.AddCommand(newBuildDeleteCmd(config))
	buildCmd.AddCommand(newSetupCmd(config))
	return buildCmd
}

func DownloadFile(filepath string, url string) error {

	// Get the data
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Create the file
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	return err
}

func build(config *buildCommandConfig) error {
	// This needs to do:
	// 1. appsody Extract
	// 2. docker build -t <project name> -f Dockerfile ./extracted

	extractConfig := &extractCommandConfig{RootCommandConfig: config.RootCommandConfig}
	extractErr := extract(extractConfig)
	if extractErr != nil {
		return extractErr
	}

	projectName, perr := getProjectName(config.RootCommandConfig)
	if perr != nil {
		return errors.Errorf("%v", perr)
	}
	extractDir := filepath.Join(getHome(config.RootCommandConfig), "extract", projectName)
	dockerfile := filepath.Join(extractDir, "Dockerfile")
	buildImage := projectName //Lowercased
	// If a tag is specified, change the buildImage
	if config.tag != "" {
		buildImage = config.tag
	}

	if config.criu {
		dockerfile_url := "https://raw.githubusercontent.com/bharathappali/appsody-criu/master/Dockerfile_criu"
		if err := DownloadFile(filepath.Join(extractDir,"Dockerfile_criu"), dockerfile_url); err != nil {
			panic(err)
		}
		criu_checkpoint_script_url := "https://raw.githubusercontent.com/bharathappali/appsody-criu/master/criu-launcher.sh"
		if err := DownloadFile(filepath.Join(extractDir,"criu-launcher.sh"), criu_checkpoint_script_url); err != nil {
			panic(err)
		}
		criu_launcher_script := filepath.Join(extractDir, "criu-launcher.sh")
		exec.Command("/bin/sh", criu_launcher_script)
	} else {
		//cmdName := "docker"
		cmdArgs := []string{"-t", buildImage}

		if config.dockerBuildOptions != "" {
			dockerBuildOptions := strings.TrimPrefix(config.dockerBuildOptions, " ")
			dockerBuildOptions = strings.TrimSuffix(dockerBuildOptions, " ")
			options := strings.Split(dockerBuildOptions, " ")
			err := checkDockerBuildOptions(options)
			if err != nil {
				return err
			}
			cmdArgs = append(cmdArgs, options...)

		}
		cmdArgs = append(cmdArgs, "-f", dockerfile, extractDir)
		Debug.log("final cmd args", cmdArgs)
		execError := DockerBuild(cmdArgs, DockerLog, config.Verbose, config.Dryrun)

		if execError != nil {
			return execError
		}
		if !config.Dryrun {
			Info.log("Built docker image ", buildImage)
		}
	}
	return nil
}
