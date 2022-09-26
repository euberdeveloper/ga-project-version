# ga-project-version
This github action gets from the package manager json file (package.json, composer.json, ...), or in case an xml one, the version of the project and exposes it.

## Project purpose

Sometimes, for instance when you publish a github release or a dockerhub image through a github action, you need a properly way to choose the version. If you are using `npm` with **NodeJS** or `composer` with **PHP**, you will have a `package.json` or `composer.json` file where you can easily put the version of the project. If you are using `Maven` with `java` you will be using a `pom.xml` file. This can be extended to other languages/package managers, as long as they have a **.json** or **.xml** file. This project consists in a **github action** that automatically exposes the **version** contained in those json/xml files, so that they can be used by other steps of the action you are adding.

## Example

```yml
name: release

on:
  push:
    branches: [ main ]

jobs:
  build:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v2
      
      # This is how you use the ga-project-version action
      - name: Get version of the project
        id: project-version
        uses: 'euberdeveloper/ga-project-version@main'
        with:
          package-manager: 'composer'

      # In this step the exposed version is used as tag of a github release to publish
      - name: Add release
        uses: "marvinpinto/action-automatic-releases@latest"
        with:
          repo_token: "${{ secrets.GITHUB_TOKEN }}"
          # This is how you access the exposed version
          automatic_release_tag: "${{ steps.project-version.outputs.version }}"
          title: "Deploy"
          files: |
            backend.tar.gz

```

## API

### Supported Parameters

| Parameter         | Description                                                                                                                                        | Default     |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- | ----------- |
| `package-manager` | The package manager of your project (`npm`, `composer` or `maven`).                                                                                | `npm`       |
| `root-directory`  | The root directory (containing your `.json/.xml` file)                                                                                             | `./`        |
| `path`            | If you have a custom json file containing the version of the project, you can specify its full path.                                               | `undefined` |
| `version-prop`    | If in the json file the property containing the version is not called `version`, you can set it here. The key can be nested, like in `uno.due.tre` | `version`   |

**Note:** If `path` is specified, `package-manager` and `root-directory` are ignored.

### Outputs

The following output values can be accessed via `${{ steps.<step-id>.outputs.<output-name> }}`:

| Name      | Description           | Type   |
| --------- | --------------------- | ------ |
| `version` | The extracted version | string |

### How does it work

Internally, the action is written in **Typescript** and bundled with **Webpack**.

The action uses directly `path` if specified, otherwise it guesses the file name by `package-manager` and the location by `root-directory`. After that, it requires the json file and inspects the `version` property (or `version-prop` if specified) and adds it as an output.

### Possible improvements

Some improvements could be:
1. Add support for more package managers.
2. Add support for `version-prop` in case it is nested in other objects.

Feel free to make pull requests
