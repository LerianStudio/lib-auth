# E-ctare HTTP Lib
This library offers basic http utilities for Golang projects, focusing on core functionalities and integration with our internal systems.

## Table of Contents
- [Features](#features)
- [Getting Started](#getting-started)
- [Commit Guidelines](#commit-guidelines)
- [Internal Dependencies](#internal-dependencies)
- [Contributing](#contributing)

## Features
- Health check implementation.
- Default client setup for Fiber v2.
- Default external resources request function
- CORS default configuration
- Default handlers for `/health` and `/swagger`.
- Standardized error response body.
- Utility methods for token and request ID retrieval.

## Getting Started
1. Clone the repository:
   ```
   git clone git@github.com:E-ctare/ectare-http-lib.git
   
   cd ectare-http-lib

   go mod download
   ```
   
2. Create a new branch in the format `taskname/brief-description`. For example: `ECD-26/create-readme`
   
3. Make your desired changes, [commit](#commit-guidelines) and push

4. Open a Pull Request in order to discuss and review the changes with others

### How to use
The projects are already configured to use the internal libs correctly, but if you want to use and test them in your projects locally, follow the steps:

1. Set the Golang environment variable `GOPRIVATE` with the command: `go env GOPRIVATE -w 'github.com/E-ctare/*'`. This will allow your dependencies to be fetched from private internal repositories.

2. Edit your .gitconfig file (usually located in `~/.gitconfig`) to use SSH:
    ```
    [url "ssh://git@github.com/"]
            insteadOf = https://github.com/
    ```

3. Now that you have both Go and Git configuration ready, you can use this library in your project with:
    ```
    go get github.com/E-ctare/ectare-http-lib
    ```

### Example of usage
After installing the library in your project, you must define it inside your `main.go` file to:

- Start a health check handler:
    ```
    healthHandler := health.NewHealthHandler(&health.DefaultConfig, &health.Dependencies{
            Redis: redisConfig.Client,
            DB:    databaseClient,
        })
    ```
- Start the http client:
    ```
    httpClient := http.Setup(&http.Config{
            HealthHandler: healthHandler,
        })
    ```

And, if you need to inject the httpClient for a controller/handler class for example, you can just use it:
```
controller.MakeExampleController(httpClient.App)
```

### Default handlers
This library will come with two default handlers, one for health check and another for swagger documentation. The default endpoints are:

- GET - `/health`
- GET - `/swagger/*`

In order to access the swagger index, use this address: `applicationaddress/swagger/index.html`.

## Commit Guidelines
To maintain semantic versioning through commits, please adhere to the following commit message format:

```
type(scope): description
```
- *type*: Specifies the type of commit (e.g., feat, fix, chore).
- *scope*: Optional. Defines the section or component affected by the commit.
- *description*: A concise description of the changes made.

Example:

```
feat(auth): add token verification
```

You can see more about this [here](https://www.conventionalcommits.org/en/v1.0.0/).

## Internal Dependencies
This library depends on some other internal libraries. Please be cautious when making changes to or deleting any of these dependent libraries as it may impact this project. The list of current internal libs dependencies is:

- [E-ctare Database lib](https://github.com/E-ctare/ectare-database-lib)

## Contributing
Feel free to submit pull requests or raise issues. Before making significant changes, it's always good to discuss your intentions in an issue or channel first.
