// Copyright 2019 DeepMap, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"runtime/debug"
	"strings"

	"gopkg.in/yaml.v2"

	"github.com/12kmps/codegen-go/pkg/codegen"
	"github.com/12kmps/codegen-go/pkg/util"
	"github.com/iancoleman/strcase"
)

func errExit(format string, args ...interface{}) {
	_, _ = fmt.Fprintf(os.Stderr, format, args...)
	os.Exit(1)
}

var (
	flagPackageName    string
	flagServiceName    string
	flagGenerate       string
	flagOutputFile     string
	flagClusterName    string
	flagIncludeTags    string
	flagExcludeTags    string
	flagTemplatesDir   string
	flagImportMapping  string
	flagExcludeSchemas string
	flagConfigFile     string
	flagAliasTypes     bool
	flagPrintVersion   bool
)

type configuration struct {
	PackageName     string            `yaml:"package"`
	GenerateTargets []string          `yaml:"generate"`
	OutputFile      string            `yaml:"output"`
	IncludeTags     []string          `yaml:"include-tags"`
	ExcludeTags     []string          `yaml:"exclude-tags"`
	TemplatesDir    string            `yaml:"templates"`
	ImportMapping   map[string]string `yaml:"import-mapping"`
	ExcludeSchemas  []string          `yaml:"exclude-schemas"`
}

func main() {

	flag.StringVar(&flagPackageName, "package", "", "The package name for generated code")
	flag.StringVar(&flagClusterName, "cluster", "", "The API cluster name for generated code")
	flag.StringVar(&flagServiceName, "service", "", "The service name (used as the project/module name)")
	flag.StringVar(&flagGenerate, "generate", "types,client",
		`Comma-separated list of code to generate; valid options: "types", "client", "bootstrap", "service", "repository", "endpoint", "transport"`)
	flag.StringVar(&flagOutputFile, "o", "", "Where to output generated code, stdout is default")
	flag.StringVar(&flagIncludeTags, "include-tags", "", "Only include operations with the given tags. Comma-separated list of tags.")
	flag.StringVar(&flagExcludeTags, "exclude-tags", "", "Exclude operations that are tagged with the given tags. Comma-separated list of tags.")
	flag.StringVar(&flagTemplatesDir, "templates", "", "Path to directory containing user templates")
	flag.StringVar(&flagImportMapping, "import-mapping", "", "A dict from the external reference to golang package path")
	flag.StringVar(&flagExcludeSchemas, "exclude-schemas", "", "A comma separated list of schemas which must be excluded from generation")
	flag.StringVar(&flagConfigFile, "config", "", "a YAML config file that controls oapi-codegen behavior")
	flag.BoolVar(&flagAliasTypes, "alias-types", false, "Alias type declarations of possible")
	flag.BoolVar(&flagPrintVersion, "version", false, "when specified, print version and exit")
	flag.Parse()

	if flagPrintVersion {
		bi, ok := debug.ReadBuildInfo()
		if !ok {
			fmt.Fprintln(os.Stderr, "error reading build info")
			os.Exit(1)
		}
		fmt.Println(bi.Main.Path + "/cmd/baas-codegen")
		fmt.Println(bi.Main.Version)
		return
	}

	if flag.NArg() < 1 {
		fmt.Println("Please specify a path to a OpenAPI 3.0 spec file")
		os.Exit(1)
	}

	if len(flagOutputFile) == 0 {
		fmt.Println("Please specify an output path with the -o option")
		os.Exit(1)
	}

	if len(flagClusterName) == 0 {
		fmt.Println("Please specify a cluster name with the -cluster option")
		os.Exit(1)
	}

	swagger, err := util.LoadSwagger(flag.Arg(0))
	if err != nil {
		errExit("error loading swagger spec in %s\n: %s", flag.Arg(0), err)
	}

	cfg := configFromFlags()

	opts := codegen.Options{
		AliasTypes: flagAliasTypes,
	}
	for _, g := range cfg.GenerateTargets {
		switch g {
		case "client":
			opts.GenerateClient = true
		case "types":
			opts.GenerateTypes = true
		case "service":
			opts.GenerateService = true
		case "repository":
			opts.GenerateRepository = true
		case "endpoints":
			opts.GenerateEndpoints = true
		case "transport":
			opts.GenerateTransports = true
		case "project":
			opts.GenerateProject = true
		case "bootstrap":
			opts.GenerateClient = true
			opts.GenerateEndpoints = true
			opts.GenerateProject = true
			opts.GenerateRepository = true
			opts.GenerateService = true
			opts.GenerateTransports = true
			opts.GenerateTypes = true
		default:
			fmt.Printf("unknown generate option %s\n", g)
			flag.PrintDefaults()
			os.Exit(1)
		}
	}

	opts.ExcludeTags = cfg.ExcludeTags
	opts.ExcludeSchemas = cfg.ExcludeSchemas

	path := flag.Arg(0)
	baseName := filepath.Base(path)
	// Split the base name on '.' to get the first part of the file.
	nameParts := strings.Split(baseName, ".")
	var projectName string
	if len(flagServiceName) > 0 {
		projectName = flagServiceName
	} else {
		projectName = strcase.ToKebab(nameParts[0])
	}

	tags := util.UniquePathTags(swagger)
	for _, t := range tags {
		// Only include code related to this tag
		opts.IncludeTags = []string{t}

		// If the package name has not been specified, we will use the name of the
		// tag as the package name
		if cfg.PackageName == "" {
			cfg.PackageName = strings.ToLower(t)
		}

		templates, err := loadTemplateOverrides(cfg.TemplatesDir)
		if err != nil {
			errExit("error loading template overrides: %s\n", err)
		}

		opts.UserTemplates = templates
		// opts.ImportMapping = cfg.ImportMapping

		code, err := codegen.Generate(flag.Arg(0), projectName, strings.ToLower(t), t, opts)
		if err != nil {
			errExit("error generating code: %s\n", err)
		}

		err = os.Mkdir(cfg.OutputFile+"/internal", 0755)
		if err != nil && !os.IsExist(err) {
			errExit("error creating /internal output path: %s", err)
		}

		err = os.Mkdir(cfg.OutputFile+"/internal/app", 0755)
		if err != nil && !os.IsExist(err) {
			errExit("error creating /internal/app output path: %s", err)
		}

		tagPath := cfg.OutputFile + "/internal/app/" + strings.ToLower(t)
		err = os.Mkdir(tagPath, 0755)
		if err != nil && !os.IsExist(err) {
			errExit("error creating tag-specific output path: %s", err)
		}
		err = os.Mkdir(tagPath+"/policies", 0755)
		if err != nil && !os.IsExist(err) {
			errExit("error creating tag-specific policies output path: %s", err)
		}

		if opts.GenerateTypes {
			err = ioutil.WriteFile(tagPath+"/types.go", []byte(code.Types), 0644)
			if err != nil {
				errExit("error writing generated types code to file: %s", err)
			}
		}

		if opts.GenerateClient {
			err = ioutil.WriteFile(tagPath+"/client.go", []byte(code.Client), 0644)
			if err != nil {
				errExit("error writing generated client code to file: %s", err)
			}
		}

		if opts.GenerateService {
			err = ioutil.WriteFile(tagPath+"/service.go", []byte(code.Service), 0644)
			if err != nil {
				errExit("error writing generated service code to file: %s", err)
			}
		}

		if opts.GenerateTransports {
			err = ioutil.WriteFile(tagPath+"/transport.go", []byte(code.Transports), 0644)
			if err != nil {
				errExit("error writing generated transport code to file: %s", err)
			}
		}

		if opts.GenerateEndpoints {
			err = ioutil.WriteFile(tagPath+"/endpoint.go", []byte(code.Endpoints), 0644)
			if err != nil {
				errExit("error writing generated endpoint code to file: %s", err)
			}
			err = ioutil.WriteFile(tagPath+"/policies/endpoint.rego", []byte(code.EndpointPolicies), 0644)
			if err != nil {
				errExit("error writing generated endpoint code to file: %s", err)
			}
		}

		if opts.GenerateRepository {
			err = ioutil.WriteFile(tagPath+"/repository.go", []byte(code.Repository), 0644)
			if err != nil {
				errExit("error writing generated repository code to file: %s", err)
			}
			err = ioutil.WriteFile(tagPath+"/repository-gorm.go", []byte(code.RepositoryGORM), 0644)
			if err != nil {
				errExit("error writing generated repository GORM code to file: %s", err)
			}
		}
		// println("-------------------------------------")
	}

	if opts.GenerateProject {
		main, err := codegen.GenerateMain(flag.Arg(0), projectName, tags, opts)
		if err != nil {
			errExit("error generating main code: %s\n", err)
		}

		err = os.Mkdir(cfg.OutputFile+"/cmd/", 0755)
		if err != nil && !os.IsExist(err) {
			errExit("error creating /cmd/ output path: %s", err)
		}

		err = os.Mkdir(cfg.OutputFile+"/cmd/"+projectName, 0755)
		if err != nil && !os.IsExist(err) {
			errExit("error creating project-name specific /cmd/ output path: %s", err)
		}

		err = ioutil.WriteFile(cfg.OutputFile+"/cmd/"+projectName+"/main.go", []byte(*main), 0644)
		if err != nil {
			errExit("error writing generated main code to file: %s", err)
		}

		project, err := codegen.GenerateProject(flag.Arg(0), projectName, opts)
		if err != nil {
			errExit("error generating project code: %s\n", err)
		}

		err = ioutil.WriteFile(cfg.OutputFile+"/go.mod", []byte(*project), 0644)
		if err != nil {
			errExit("error writing generated main code to file: %s", err)
		}

		docker, err := codegen.GenerateDocker(flag.Arg(0), projectName, flagClusterName, tags, opts)
		if err != nil {
			errExit("error generating docker code: %s\n", err)
		}

		err = ioutil.WriteFile(cfg.OutputFile+"/docker-compose.yaml", []byte(docker.DockerCompose), 0644)
		if err != nil {
			errExit("error writing generated main code to file: %s", err)
		}

		err = ioutil.WriteFile(cfg.OutputFile+"/Dockerfile", []byte(docker.Dockerfile), 0644)
		if err != nil {
			errExit("error writing generated main code to file: %s", err)
		}

		gitignore, err := codegen.GenerateGitIgnore(flag.Arg(0), projectName, opts)
		if err != nil {
			errExit("error generating gitignore code: %s\n", err)
		}

		err = ioutil.WriteFile(cfg.OutputFile+"/.gitignore", []byte(*gitignore), 0644)
		if err != nil {
			errExit("error writing generated gitignore to file: %s", err)
		}

	}
}

func loadTemplateOverrides(templatesDir string) (map[string]string, error) {
	var templates = make(map[string]string)

	if templatesDir == "" {
		return templates, nil
	}

	files, err := ioutil.ReadDir(templatesDir)
	if err != nil {
		return nil, err
	}

	for _, f := range files {
		data, err := ioutil.ReadFile(path.Join(templatesDir, f.Name()))
		if err != nil {
			return nil, err
		}
		templates[f.Name()] = string(data)
	}

	return templates, nil
}

// configFromFlags parses the flags and the config file. Anything which is
// a zerovalue in the configuration file will be replaced with the flag
// value, this means that the config file overrides flag values.
func configFromFlags() *configuration {
	var cfg configuration

	// Load the configuration file first.
	if flagConfigFile != "" {
		f, err := os.Open(flagConfigFile)
		if err != nil {
			errExit("failed to open config file with error: %v\n", err)
		}
		defer f.Close()
		err = yaml.NewDecoder(f).Decode(&cfg)
		if err != nil {
			errExit("error parsing config file: %v\n", err)
		}
	}

	if cfg.PackageName == "" {
		cfg.PackageName = flagPackageName
	}
	if cfg.GenerateTargets == nil {
		cfg.GenerateTargets = util.ParseCommandLineList(flagGenerate)
	}
	if cfg.IncludeTags == nil {
		cfg.IncludeTags = util.ParseCommandLineList(flagIncludeTags)
	}
	if cfg.ExcludeTags == nil {
		cfg.ExcludeTags = util.ParseCommandLineList(flagExcludeTags)
	}
	if cfg.TemplatesDir == "" {
		cfg.TemplatesDir = flagTemplatesDir
	}
	if cfg.ImportMapping == nil && flagImportMapping != "" {
		var err error
		cfg.ImportMapping, err = util.ParseCommandlineMap(flagImportMapping)
		if err != nil {
			errExit("error parsing import-mapping: %s\n", err)
		}
	}
	if cfg.ExcludeSchemas == nil {
		cfg.ExcludeSchemas = util.ParseCommandLineList(flagExcludeSchemas)
	}
	if cfg.OutputFile == "" {
		cfg.OutputFile = flagOutputFile
	}
	return &cfg
}
