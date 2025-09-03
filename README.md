# Crypto Broker Client

## Usage

The Crypto Broker Client is a library written in Golang that allows users to interact with a Crypto Broker Server running on the same machine. The library is a lightweight wrapper around the communication protocol (gRPC) and the basic structures used to call the server from a Go client.

### Installation

Run this command in your Go repository in order to install the library:

```shell
go get https://github.com/open-crypto-broker/crypto-broker-client-go
```

### Library Usage

This code serves as an example on how to call the library's basic functions. Please add your own error Handling and other functions as necessary.
For signing, the library excepts the raw content read by any compatible `io.Reader`.

```go
// Import
import "github.com/open-crypto-broker/crypto-broker-client-go"

// ...existing code...

// Library creation
lib, err := cryptobrokerclientgo.NewLibrary()
if err != nil {
    panic(err)
}

defer lib.Close()
ctx = context.Background()

payload := cryptobrokerclientgo.HashDataPayload{
  Input:   []byte("Hello world"),
  Profile: "Default",
  Metadata: &cryptobrokerclientgo.Metadata{
    Id:        uuid.New().String(),
    CreatedAt: time.Now().UTC().Format(time.RFC3339),
  },
}
responseBody, err := lib.HashData(ctx, payload)
if err != nil {
  panic(err)
}
fmt.Printf("Hashed string: %s\n", responseBody.hashValue)

// Signing
payload := cryptobrokerclientgo.SignCertificatePayload{
  Profile:      Profile,
  CSR:          rawContentCSR,
  CAPrivateKey: rawContentSigningKey,
  CACert:       rawContentCACert,
  Subject:      &customSubject,
  Metadata: &cryptobrokerclientgo.Metadata{
    Id:        uuid.New().String(),
    CreatedAt: time.Now().UTC().Format(time.RFC3339),
  },
}
responseBody, err := lib.SignCertificate(ctx, opts)
if err != nil {
  panic(err)
}
fmt.Printf("Signed certificate: %s\n", responseBody.signedCertificate)
```

## Development

This section covers how to contribute to the project and develop it further.

### Pre-requisites

A version of [Golang](https://go.dev/doc/install) > 1.24 installed on your local machine is required in order to run it locally from terminal. For building the Docker image, you need to have Docker/Docker Desktop or any other alternative (e.g. Podman) installed.

For running the commands using the `Taskfile` tool, you need to have Taskfile installed. Please check the documentation on [how to install Taskfile](https://taskfile.dev/installation/). If you don't have Taskfile support, you can directly use the commands specified in the Taskfile on your local terminal, provided you meet the requirements.

To contribute to this project please configure the custom githooks for this project:

```bash
git config core.hooksPath .githooks
```

This commit hook will make sure the code follows the standard formatting and keep everything consistent.

Additionally, please download all required tools for project development. This may require using "sudo". Please read docs of [tools](./Taskfile.yaml) for more info.  

```bash
task tools
```

### Building

#### Compiling the Go binaries

For testing the application, you can build the local CLI with the following command:

```shell
task build-go
```

This will also save a checksum of all the file `sources` in the Taskfile cache `.task`. This means that, if no new changes are done, re-running the task will not build the app again.

This repository uses a submodule for the proto files in `/protobuf` directory.

To reload the `/protobuf` files to the latest `main` commit and recompile them, run the following:

```shell
task proto
```

#### Building the Docker image

For building the image for local use, you can use the command:

```shell
task build [TAG=opt]
```

The TAG argument is optional and will apply a custom image tag to the built images. If not specified, it defaults to `latest`. This will create a local image tagged as `server_app:TAG`, which will be saved in your local Docker repository. If you want to modify or append args to the build command, please refer to the one from the Taskfile.

Note that, by default, Taskfile will import a local `.env` file located in the directory. This is optional and can be used to push images to private repositories or injecting variables in the system.

### Testing

The client is meant to be tested using the standard Golang Testing `go test`. Due to the library using a server, during testing, the responses from the server are mocked to test the client's functionality.  The purpose of this testing is thus to ensure compliance project-wide and that the client follows the general [library's specification](https://github.com/open-crypto-broker/crypto-broker-documentation/blob/main/spec/0003-library.md).
For a full end to end testing, please check the [deployment repository](https://github.com/open-crypto-broker/crypto-broker-deployment).

If you want to additionally invoke the local pipeline for code formatting, you can run all of these commands with:

```shell
task ci
```

You can do a local end2end testing of the application yourself with the provided CLI. To run the CLI, you first need to have the [Crypto Broker server](https://github.com/open-crypto-broker/crypto-broker-server/) running in your Unix localhost environment. Once done, you can run one of the following in another terminal:

```shell
task run-hash
# or
task run-sign
```

For the sign command, you need to have the [deployment repository](https://github.com/open-crypto-broker/crypto-broker-deployment) in the same parent directory as this repository. Check the command definitions in the `Taskfile` file to run your own custom commands.

More thorough testing is also provided in the deployment repository. The same pipeline will run in GitHub Actions when submitting a Pull Request, so it is recommended to also clone and run the testing of the deployment repository.

## Support, Feedback, Contributing

This project is open to feature requests/suggestions, bug reports etc. via [GitHub issues](https://github.com/open-crypto-broker/crypto-broker-client-go/issues). Contribution and feedback are encouraged and always welcome. For more information about how to contribute, the project structure, as well as additional contribution information, see our [Contribution Guidelines](CONTRIBUTING.md).

## Security / Disclosure

If you find any bug that may be a security problem, please follow our instructions at [in our security policy](https://github.com/open-crypto-broker/crypto-broker-client-go/security/policy) on how to report it. Please do not create GitHub issues for security-related doubts or problems.

## Code of Conduct

We as members, contributors, and leaders pledge to make participation in our community a harassment-free experience for everyone. By participating in this project, you agree to abide by its [Code of Conduct](https://github.com/open-crypto-broker/.github/blob/main/CODE_OF_CONDUCT.md) at all times.

## Licensing

Copyright 2025 SAP SE or an SAP affiliate company and Open Crypto Broker contributors. Please see our [LICENSE](LICENSE) for copyright and license information. Detailed information including third-party components and their licensing/copyright information is available [via the REUSE tool](https://api.reuse.software/info/github.com/open-crypto-broker/crypto-broker-client-go).
