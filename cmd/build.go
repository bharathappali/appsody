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
	"bufio"
	"fmt"
	"io"
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
	criu               bool
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

	buildCmd.PersistentFlags().StringVarP(&config.tag, "tag", "t", "", "Docker image name and optionally a tag in the 'name:tag' format")
	buildCmd.PersistentFlags().BoolVar(&config.criu, "criu", false, "Makes appsody to build a startup optimized image")
	buildCmd.PersistentFlags().StringVar(&config.dockerBuildOptions, "docker-options", "", "Specify the docker build options to use.  Value must be in \"\".")

	buildCmd.AddCommand(newBuildDeleteCmd(config))
	buildCmd.AddCommand(newSetupCmd(config))
	return buildCmd
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
		return perr
	}

	extractDir := filepath.Join(getHome(config.RootCommandConfig), "extract", projectName)
	dockerfile := filepath.Join(extractDir, "Dockerfile")
	buildImage := projectName //Lowercased

	// If a tag is specified, change the buildImage
	if config.tag != "" {
		buildImage = config.tag
	}

    if config.criu {
        docker_capabilities := "--cap-add AUDIT_CONTROL --cap-add DAC_READ_SEARCH --cap-add NET_ADMIN --cap-add SYS_ADMIN  --cap-add SYS_PTRACE --cap-add SYS_RESOURCE --security-opt apparmor=unconfined --security-opt seccomp=unconfined"
        docker_run_command := `docker run --rm `+ docker_capabilities +` --name="kaniko-image-builder" -v `+ extractDir +`:/kaniko-space -i gcr.io/kaniko-project/executor --dockerfile=Dockerfile_CRIU --context=/kaniko-space --no-push  --tarPath=/kaniko-space/`+ projectName +`.tar.gz --destination=`+ projectName
        cmd := exec.Command("/bin/sh", "-c", docker_run_command)

        logger := DockerLog
		// Create io pipes for the command
		run_logReader, run_logWriter := io.Pipe()
		run_consoleReader, run_consoleWriter := io.Pipe()
		cmd.Stdout = io.MultiWriter(run_logWriter, run_consoleWriter)
		cmd.Stderr = io.MultiWriter(run_logWriter, run_consoleWriter)

		// Create a scanner for both the log and the console
		// The log will be written when a newline is encountered
		run_logScanner := bufio.NewScanner(run_logReader)
		run_logScanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		go func() {
			for run_logScanner.Scan() {
				logger.LogSkipConsole(run_logScanner.Text())
			}
		}()

		// The console will be written on every byte
		run_consoleScanner := bufio.NewScanner(run_consoleReader)
		run_consoleScanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		run_consoleScanner.Split(bufio.ScanBytes)
		go func() {
			lastByteNewline := true
			for run_consoleScanner.Scan() {
				text := run_consoleScanner.Text()
				if lastByteNewline && (config.Verbose || logger != Info) {
					os.Stdout.WriteString("[" + logger.name + "] ")
				}
				os.Stdout.WriteString(text)
				lastByteNewline = text == "\n"
			}
		}()

        err := cmd.Start()
        if err != nil {
            return err
        }
        cmd.Wait()

        docker_load_command := `docker load -i ` + extractDir + `/` + projectName + `.tar.gz`
        cmd_load := exec.Command("/bin/sh", "-c", docker_load_command)


		// Create io pipes for the command
		load_logReader, load_logWriter := io.Pipe()
		load_consoleReader, load_consoleWriter := io.Pipe()
		cmd_load.Stdout = io.MultiWriter(load_logWriter, load_consoleWriter)
		cmd_load.Stderr = io.MultiWriter(load_logWriter, load_consoleWriter)

		// Create a scanner for both the log and the console
		// The log will be written when a newline is encountered
		load_logScanner := bufio.NewScanner(load_logReader)
		load_logScanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		go func() {
			for run_logScanner.Scan() {
				logger.LogSkipConsole(run_logScanner.Text())
			}
		}()

		// The console will be written on every byte
		load_consoleScanner := bufio.NewScanner(load_consoleReader)
		load_consoleScanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		load_consoleScanner.Split(bufio.ScanBytes)
		go func() {
			lastByteNewline := true
			for load_consoleScanner.Scan() {
				text := load_consoleScanner.Text()
				if lastByteNewline && (config.Verbose || logger != Info) {
					os.Stdout.WriteString("[" + logger.name + "] ")
				}
				os.Stdout.WriteString(text)
				lastByteNewline = text == "\n"
			}
		}()


        load_err := cmd_load.Start()
        if load_err != nil {
            return load_err
        }
        cmd_load.Wait()
        return nil

    } else {
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

        labels, err := getLabels(config)
        if err != nil {
            return err
        }

        // It would be nicer to only call the --label flag once. Could also use the --label-file flag.
        for _, label := range labels {
            cmdArgs = append(cmdArgs, "--label", label)
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

func getLabels(config *buildCommandConfig) ([]string, error) {
	var labels []string

	stackLabels, err := getStackLabels(config.RootCommandConfig)
	if err != nil {
		return labels, err
	}

	configLabels, err := getConfigLabels(config.RootCommandConfig)
	if err != nil {
		return labels, err
	}

	gitLabels, err := getGitLabels(config.RootCommandConfig)
	if err != nil {
		Warning.log(err)
	}

	for key, value := range stackLabels {

		key = strings.Replace(key, "org.opencontainers.image", "dev.appsody.stack", -1)

		// This is temporarily until we update the labels in stack dockerfile
		if key == "appsody.stack" {
			key = "dev.appsody.stack.id"
		}

		delete(configLabels, key)

		labelString := fmt.Sprintf("%s=%s", key, value)
		labels = append(labels, labelString)
	}

	for key, value := range configLabels {
		labelString := fmt.Sprintf("%s=%s", key, value)
		labels = append(labels, labelString)
	}

	for key, value := range gitLabels {
		labelString := fmt.Sprintf("%s=%s", key, value)
		labels = append(labels, labelString)
	}

	return labels, nil
}
